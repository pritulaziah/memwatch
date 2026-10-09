//! JavaScript page metrics collected over the Chrome DevTools Protocol.
//!
//! The collector polls the local DevTools endpoint in its own thread, so the
//! run's main loop is never blocked. Only the loopback endpoint is contacted:
//! the target list is fetched from `127.0.0.1` and every page WebSocket URL
//! comes from that list.

use std::collections::{BTreeMap, HashMap};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow};
use serde::Deserialize;
use tungstenite::client::client;
use tungstenite::{Message, WebSocket};

use crate::collect::FailureCounter;
use crate::log::RunLog;
use crate::meta::CollectorStatus;
use crate::sampler::StopHandle;
use crate::store::{CdpRow, CsvTable};

/// Total budget of a target list request or one page sampling attempt.
const IO_TIMEOUT: Duration = Duration::from_secs(2);

/// How often the `cdp.csv` file is synced to the storage device.
const FSYNC_INTERVAL: Duration = Duration::from_secs(60);

/// One debuggable page from the DevTools target list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdpPage {
    /// DevTools target id of the page.
    pub id: String,
    /// URL of the page.
    pub url: String,
    /// WebSocket URL of the page's debugger endpoint.
    pub web_socket_debugger_url: String,
}

/// One entry of the DevTools target list as returned by `/json/list`.
#[derive(Deserialize)]
struct TargetListEntry {
    /// Target type, for example `page` or `service_worker`.
    #[serde(rename = "type")]
    kind: String,
    /// Target id.
    id: String,
    /// Target URL.
    url: String,
    /// Debugger WebSocket URL; absent for targets that cannot be debugged.
    #[serde(rename = "webSocketDebuggerUrl")]
    web_socket_debugger_url: Option<String>,
}

/// Parses the DevTools target list and keeps the debugger pages.
///
/// Only entries with `type == "page"` and a non-empty `webSocketDebuggerUrl`
/// are kept, in their original order. A body that is not a JSON array of
/// target entries is an error.
pub fn parse_pages(body: &str) -> anyhow::Result<Vec<CdpPage>> {
    let entries: Vec<TargetListEntry> =
        serde_json::from_str(body).context("cannot parse the DevTools target list")?;
    Ok(entries
        .into_iter()
        .filter(|entry| entry.kind == "page")
        .filter_map(|entry| {
            let web_socket_debugger_url = entry.web_socket_debugger_url?;
            if web_socket_debugger_url.is_empty() {
                return None;
            }
            Some(CdpPage {
                id: entry.id,
                url: entry.url,
                web_socket_debugger_url,
            })
        })
        .collect())
}

/// One metric of a `Performance.getMetrics` reply.
#[derive(Debug, Clone, Deserialize)]
pub struct CdpMetric {
    /// Metric name as reported by the browser.
    pub name: String,
    /// Metric value.
    pub value: f64,
}

/// JavaScript and DOM metrics of one page.
///
/// Every field is `None` when the browser did not report the metric.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct CdpMetrics {
    /// Used JavaScript heap in bytes.
    pub js_heap_used_bytes: Option<u64>,
    /// Total JavaScript heap in bytes.
    pub js_heap_total_bytes: Option<u64>,
    /// DOM nodes in the page.
    pub nodes: Option<u64>,
    /// Documents in the page.
    pub documents: Option<u64>,
    /// Frames in the page.
    pub frames: Option<u64>,
    /// JavaScript event listeners in the page.
    pub js_event_listeners: Option<u64>,
    /// Layouts performed (cumulative).
    pub layout_count: Option<u64>,
    /// Style recalculations performed (cumulative).
    pub recalc_style_count: Option<u64>,
    /// Layout time in milliseconds (cumulative).
    pub layout_duration_ms: Option<u64>,
    /// Style recalculation time in milliseconds (cumulative).
    pub recalc_style_duration_ms: Option<u64>,
    /// Script execution time in milliseconds (cumulative).
    pub script_duration_ms: Option<u64>,
    /// Task execution time in milliseconds (cumulative).
    pub task_duration_ms: Option<u64>,
}

/// Maps `Performance.getMetrics` entries to the `cdp.csv` fields.
///
/// Unknown metric names are ignored and missing metrics stay empty. The four
/// duration metrics are reported in seconds and are converted to cumulative
/// milliseconds; every other metric is rounded to whole units.
pub fn map_metrics(metrics: &[CdpMetric]) -> CdpMetrics {
    let mut mapped = CdpMetrics::default();
    for metric in metrics {
        let Some(slot) = metric_slot(&mut mapped, &metric.name) else {
            continue;
        };
        *slot = to_whole(metric);
    }
    mapped
}

/// Returns the field of `mapped` that belongs to the metric name.
fn metric_slot<'a>(mapped: &'a mut CdpMetrics, name: &str) -> Option<&'a mut Option<u64>> {
    match name {
        "JSHeapUsedSize" => Some(&mut mapped.js_heap_used_bytes),
        "JSHeapTotalSize" => Some(&mut mapped.js_heap_total_bytes),
        "Nodes" => Some(&mut mapped.nodes),
        "Documents" => Some(&mut mapped.documents),
        "Frames" => Some(&mut mapped.frames),
        "JSEventListeners" => Some(&mut mapped.js_event_listeners),
        "LayoutCount" => Some(&mut mapped.layout_count),
        "RecalcStyleCount" => Some(&mut mapped.recalc_style_count),
        "LayoutDuration" => Some(&mut mapped.layout_duration_ms),
        "RecalcStyleDuration" => Some(&mut mapped.recalc_style_duration_ms),
        "ScriptDuration" => Some(&mut mapped.script_duration_ms),
        "TaskDuration" => Some(&mut mapped.task_duration_ms),
        _ => None,
    }
}

/// Converts one metric value to the whole number written to `cdp.csv`.
///
/// A duration metric comes in seconds and becomes cumulative milliseconds;
/// every other metric is rounded to whole units.
fn to_whole(metric: &CdpMetric) -> Option<u64> {
    if !metric.value.is_finite() || metric.value < 0.0 {
        return None;
    }
    let scaled = match metric.name.as_str() {
        "LayoutDuration" | "RecalcStyleDuration" | "ScriptDuration" | "TaskDuration" => {
            metric.value * 1000.0
        }
        _ => metric.value,
    };
    (scaled.is_finite() && scaled >= 0.0).then(|| scaled.round() as u64)
}

/// A reply frame of the DevTools protocol.
#[derive(Deserialize)]
struct CdpReply {
    /// Id of the request the reply belongs to; absent on events.
    id: Option<u64>,
    /// Result of the call, when it succeeded.
    result: Option<CdpResult>,
    /// Error of the call, when it failed.
    error: Option<CdpError>,
    /// Event name; absent on ordinary request replies.
    method: Option<String>,
    /// Event payload, including frame identity for navigation events.
    params: Option<serde_json::Value>,
}

/// Identifies a main-frame navigation without treating child frames as boundaries.
fn is_main_frame_navigation(reply: &CdpReply) -> bool {
    if reply.method.as_deref() != Some("Page.frameNavigated") {
        return false;
    }
    let Some(frame) = reply
        .params
        .as_ref()
        .and_then(|params| params.get("frame"))
        .and_then(serde_json::Value::as_object)
    else {
        return false;
    };
    frame
        .get("parentId")
        .is_none_or(|parent| parent.as_str() == Some(""))
}

/// The result of a successful DevTools call.
#[derive(Deserialize)]
struct CdpResult {
    /// Metrics of `Performance.getMetrics`; empty for other calls.
    #[serde(default)]
    metrics: Vec<CdpMetric>,
}

/// The error of a failed DevTools call.
#[derive(Deserialize)]
struct CdpError {
    /// Human-readable error message.
    #[serde(default)]
    message: String,
}

/// Why the exchange with one page failed.
enum PageError {
    /// The page could not be reached: TCP connect or WebSocket handshake.
    Connection(anyhow::Error),
    /// The page was reached, but the protocol exchange failed.
    Protocol(anyhow::Error),
    /// The collector was asked to stop during the attempt.
    Stopped,
    /// Navigation or a cumulative decrease ended the measurement segment.
    Reset,
}

impl PageError {
    /// Gives cancellation precedence over an underlying transport error.
    fn unless_stopped(self, stop: &StopHandle) -> Self {
        if stop.is_stopped() {
            Self::Stopped
        } else {
            self
        }
    }
}

/// TCP adapter that shares one deadline across the handshake and all calls.
struct DeadlineStream {
    stream: TcpStream,
    stop: StopHandle,
    deadline: Instant,
}

impl DeadlineStream {
    /// Returns the remaining budget, with cancellation taking precedence.
    fn check_budget(&self) -> io::Result<Duration> {
        remaining_budget(&self.stop, self.deadline)
    }

    /// Starts the next attempt's budget on an existing connection.
    fn set_deadline(&mut self, deadline: Instant) {
        self.deadline = deadline;
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            let remaining = self.check_budget()?;
            self.stream
                .set_read_timeout(Some(remaining.min(Duration::from_millis(100))))?;
            match self.stream.read(buffer) {
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) => {}
                result => return result,
            }
        }
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        loop {
            let remaining = self.check_budget()?;
            self.stream
                .set_write_timeout(Some(remaining.min(Duration::from_millis(100))))?;
            match self.stream.write(buffer) {
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) => {}
                result => return result,
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.check_budget()?;
        self.stream.flush()
    }
}

/// Checks a page's total budget even when WebSocket frames are buffered.
fn remaining_budget(stop: &StopHandle, deadline: Instant) -> io::Result<Duration> {
    if stop.is_stopped() {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "CDP polling stopped",
        ));
    }
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "CDP attempt deadline elapsed"))
}

/// Checks cancellation and the deadline at protocol boundaries.
fn check_exchange_budget(stop: &StopHandle, deadline: Instant) -> Result<Duration, PageError> {
    remaining_budget(stop, deadline)
        .map_err(|err| PageError::Protocol(err.into()).unless_stopped(stop))
}

/// Establishes a loopback page connection within the attempt's shared budget.
fn connect_page(
    page: &CdpPage,
    stop: &StopHandle,
    deadline: Instant,
) -> Result<WebSocket<DeadlineStream>, PageError> {
    check_exchange_budget(stop, deadline)?;
    let address = socket_address(&page.web_socket_debugger_url).map_err(PageError::Protocol)?;
    let remaining = check_exchange_budget(stop, deadline)?;
    let stream = TcpStream::connect_timeout(&address, remaining).map_err(|err| {
        PageError::Connection(anyhow!("cannot connect to the page: {err}")).unless_stopped(stop)
    })?;
    check_exchange_budget(stop, deadline)?;
    let stream = DeadlineStream {
        stream,
        stop: stop.clone(),
        deadline,
    };
    let (socket, _response) =
        client(page.web_socket_debugger_url.as_str(), stream).map_err(|err| {
            PageError::Connection(anyhow!("the WebSocket handshake failed: {err}"))
                .unless_stopped(stop)
        })?;
    check_exchange_budget(stop, deadline)?;
    Ok(socket)
}

/// Persistent protocol state belonging to one live debugger connection.
struct TargetSession {
    socket: WebSocket<DeadlineStream>,
    session_id: u64,
    debugger_url: String,
    next_request_id: u64,
    initialized: bool,
    cumulative: BTreeMap<&'static str, f64>,
}

impl TargetSession {
    /// Sends a fresh request and waits only for its matching reply.
    fn request(
        &mut self,
        method: &str,
        stop: &StopHandle,
        deadline: Instant,
    ) -> Result<Vec<CdpMetric>, PageError> {
        check_exchange_budget(stop, deadline)?;
        self.socket.get_mut().set_deadline(deadline);
        let id = self.next_request_id;
        self.next_request_id = id
            .checked_add(1)
            .ok_or_else(|| PageError::Protocol(anyhow!("CDP request identity exhausted")))?;
        let request = serde_json::json!({"id": id, "method": method}).to_string();
        self.socket.send(Message::text(request)).map_err(|err| {
            PageError::Protocol(anyhow!("cannot send {method}: {err}")).unless_stopped(stop)
        })?;
        read_reply(&mut self.socket, id, stop, deadline)
    }

    /// Enables both domains once, then samples on the same connection.
    fn sample(&mut self, stop: &StopHandle, deadline: Instant) -> Result<CdpMetrics, PageError> {
        if !self.initialized {
            self.request("Performance.enable", stop, deadline)?;
            self.request("Page.enable", stop, deadline)?;
            self.initialized = true;
        }
        let metrics = self.request("Performance.getMetrics", stop, deadline)?;
        check_exchange_budget(stop, deadline)?;
        if cumulative_reset(&self.cumulative, &metrics) {
            check_exchange_budget(stop, deadline)?;
            return Err(PageError::Reset);
        }
        remember_cumulative(&mut self.cumulative, &metrics);
        Ok(map_metrics(&metrics))
    }
}

/// Returns a usable raw cumulative value under its canonical metric name.
fn cumulative_metric(metric: &CdpMetric) -> Option<(&'static str, f64)> {
    if !metric.value.is_finite() || metric.value < 0.0 {
        return None;
    }
    let name = match metric.name.as_str() {
        "LayoutCount" => "LayoutCount",
        "RecalcStyleCount" => "RecalcStyleCount",
        "LayoutDuration" => "LayoutDuration",
        "RecalcStyleDuration" => "RecalcStyleDuration",
        "ScriptDuration" => "ScriptDuration",
        "TaskDuration" => "TaskDuration",
        _ => return None,
    };
    Some((name, metric.value))
}

/// Compares raw counters so sub-millisecond decreases are not hidden by rounding.
fn cumulative_reset(previous: &BTreeMap<&'static str, f64>, metrics: &[CdpMetric]) -> bool {
    metrics
        .iter()
        .filter_map(cumulative_metric)
        .any(|(name, value)| previous.get(name).is_some_and(|baseline| value < *baseline))
}

/// Keeps the last reported baseline when a counter is missing or unusable.
fn remember_cumulative(previous: &mut BTreeMap<&'static str, f64>, metrics: &[CdpMetric]) {
    for (name, value) in metrics.iter().filter_map(cumulative_metric) {
        previous.insert(name, value);
    }
}

/// Outcome of an attempt, including identity established before a failure.
struct PageAttempt {
    session_id: Option<u64>,
    result: Result<CdpMetrics, PageError>,
}

/// Resolves the TCP address of a DevTools WebSocket URL.
fn socket_address(url: &str) -> anyhow::Result<SocketAddr> {
    let rest = url
        .strip_prefix("ws://")
        .ok_or_else(|| anyhow!("the debugger endpoint must use ws://"))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("the WebSocket URL has no port: {url}"))?;
    let port: u16 = port
        .parse()
        .with_context(|| format!("the WebSocket URL has an invalid port: {url}"))?;
    let ip = if host == "localhost" {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host);
        host.parse::<IpAddr>()
            .context("the debugger host must be a numeric loopback address or localhost")?
    };
    if !ip.is_loopback() {
        return Err(anyhow!("the debugger host must be loopback"));
    }
    Ok(SocketAddr::new(ip, port))
}

/// Reads frames until the reply with the expected request id arrives.
///
/// Main-frame navigation ends the segment. Other events, non-text frames and
/// replies to other requests are skipped. Protocol errors fail the exchange;
/// cancellation and the shared deadline take precedence over buffered frames.
fn read_reply(
    socket: &mut WebSocket<DeadlineStream>,
    id: u64,
    stop: &StopHandle,
    deadline: Instant,
) -> Result<Vec<CdpMetric>, PageError> {
    loop {
        check_exchange_budget(stop, deadline)?;
        let message = socket.read().map_err(|err| {
            PageError::Protocol(anyhow!("cannot read a reply: {err}")).unless_stopped(stop)
        })?;
        check_exchange_budget(stop, deadline)?;
        if matches!(message, Message::Close(_)) {
            return Err(PageError::Protocol(anyhow!("the debugger socket closed")));
        }
        let Message::Text(text) = message else {
            continue;
        };
        let reply: CdpReply = serde_json::from_str(text.as_str())
            .map_err(|err| PageError::Protocol(anyhow!("cannot parse a reply: {err}")))?;
        check_exchange_budget(stop, deadline)?;
        if is_main_frame_navigation(&reply) {
            check_exchange_budget(stop, deadline)?;
            return Err(PageError::Reset);
        }
        if reply.id != Some(id) {
            continue;
        }
        check_exchange_budget(stop, deadline)?;
        if let Some(error) = reply.error {
            return Err(PageError::Protocol(anyhow!(
                "the DevTools call failed: {}",
                error.message
            )));
        }
        check_exchange_budget(stop, deadline)?;
        return Ok(reply
            .result
            .map(|result| result.metrics)
            .unwrap_or_default());
    }
}

/// Polls the JavaScript metrics of the DevTools pages in its own thread.
///
/// The thread asks the local DevTools endpoint for the page list and runs a
/// performance exchange with every page on each interval. It stops when
/// [`CdpCollector::stop`] is called or after ten consecutive protocol
/// failures; the run's main loop keeps ticking in either case.
pub struct CdpCollector {
    status: Arc<Mutex<CollectorStatus>>,
    stop: StopHandle,
    finished: Receiver<()>,
    handle: Option<JoinHandle<()>>,
    table: Option<CsvTable>,
}

impl CdpCollector {
    /// Starts the polling thread for the DevTools endpoint on `port`.
    ///
    /// The thread samples every `interval`, times its rows from `started` and
    /// owns `table` until it ends; the collector itself keeps no table.
    pub fn start(
        port: u16,
        interval: Duration,
        started: Instant,
        table: CsvTable,
        log: RunLog,
    ) -> CdpCollector {
        let status = Arc::new(Mutex::new(CollectorStatus::Waiting));
        let stop = StopHandle::new();
        let (sender, finished) = mpsc::channel();
        let handle = thread::spawn({
            let status = Arc::clone(&status);
            let stop = stop.clone();
            move || {
                let mut polling = Polling {
                    port,
                    started,
                    table,
                    log,
                    status,
                    stop,
                    counter: FailureCounter::new(),
                    last_fsync: None,
                    sessions: HashMap::new(),
                    next_session_id: 1,
                };
                polling.run(interval);
                let _ = sender.send(());
            }
        });

        CdpCollector {
            status,
            stop,
            finished,
            handle: Some(handle),
            table: None,
        }
    }

    /// Creates a collector that is switched off and only owns its table.
    pub fn disabled(table: CsvTable) -> CdpCollector {
        let (_, finished) = mpsc::channel();
        CdpCollector {
            status: Arc::new(Mutex::new(CollectorStatus::Disabled)),
            stop: StopHandle::new(),
            finished,
            handle: None,
            table: Some(table),
        }
    }

    /// Returns the current collector status.
    pub fn status(&self) -> CollectorStatus {
        self.status
            .lock()
            .expect("the CDP status mutex is not poisoned")
            .clone()
    }

    /// Asks the polling thread to stop; a no-op for a disabled collector.
    pub fn stop(&self) {
        if self.handle.is_some() {
            self.stop.stop();
        }
    }

    /// Waits for the polling thread to finish, at most `timeout`.
    ///
    /// Returns `true` when the thread has finished, including by panic; on a
    /// timeout the thread is detached and `false` is returned. A disabled
    /// collector is always finished.
    pub fn join(&mut self, timeout: Duration) -> bool {
        if self.handle.is_none() {
            return true;
        }
        match self.finished.recv_timeout(timeout) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                if let Some(handle) = self.handle.take() {
                    let _ = handle.join();
                }
                true
            }
            Err(RecvTimeoutError::Timeout) => false,
        }
    }

    /// Flushes the collector's own table.
    ///
    /// Only a disabled collector keeps its table; the polling thread flushes
    /// its table itself, so for a started collector this is a no-op.
    pub fn flush(&mut self, durable: bool) -> io::Result<()> {
        match &mut self.table {
            Some(table) => table.flush(durable),
            None => Ok(()),
        }
    }
}

/// State of the polling thread.
struct Polling {
    port: u16,
    started: Instant,
    table: CsvTable,
    log: RunLog,
    status: Arc<Mutex<CollectorStatus>>,
    stop: StopHandle,
    counter: FailureCounter,
    last_fsync: Option<Instant>,
    sessions: HashMap<String, TargetSession>,
    next_session_id: u64,
}

impl Polling {
    /// Runs the polling loop until a stop or ten consecutive failures.
    fn run(&mut self, interval: Duration) {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(IO_TIMEOUT))
            .build()
            .into();

        loop {
            if self.stop.is_stopped() {
                break;
            }
            if !self.cycle(&agent) {
                break;
            }

            let durable = self
                .last_fsync
                .is_none_or(|at| at.elapsed() >= FSYNC_INTERVAL);
            if durable {
                self.last_fsync = Some(Instant::now());
            }
            if let Err(err) = self.table.flush(durable) {
                self.log
                    .error("cdp", format!("cannot flush cdp.csv: {err}"));
            }

            if self.stop.wait_timeout(interval) {
                break;
            }
        }

        self.sessions.clear();
        if let Err(err) = self.table.flush(true) {
            self.log
                .error("cdp", format!("cannot flush cdp.csv: {err}"));
        }
    }

    /// Runs one poll of the target list and every page.
    ///
    /// Returns `false` when ten consecutive failures end the collector.
    fn cycle(&mut self, agent: &ureq::Agent) -> bool {
        let url = format!("http://127.0.0.1:{}/json/list", self.port);
        let body = match agent
            .get(&url)
            .call()
            .and_then(|mut response| response.body_mut().read_to_string())
        {
            Ok(body) => body,
            Err(err) => {
                self.log.warn_once(
                    "cdp-list",
                    "cdp",
                    format!("cannot read the DevTools target list: {err}"),
                );
                self.set_status(CollectorStatus::Waiting);
                return true;
            }
        };

        let pages = match parse_pages(&body) {
            Ok(pages) => pages,
            Err(err) => {
                self.log.error(
                    "cdp",
                    format!("cannot parse the DevTools target list: {err}"),
                );
                self.counter.record_err(err.to_string());
                if self.counter.is_failed() {
                    self.set_status(self.counter.status());
                    return false;
                }
                self.set_status(CollectorStatus::Waiting);
                return true;
            }
        };

        let live: HashMap<&str, &str> = pages
            .iter()
            .map(|page| (page.id.as_str(), page.web_socket_debugger_url.as_str()))
            .collect();
        self.sessions.retain(|id, session| {
            live.get(id.as_str())
                .is_some_and(|url| *url == session.debugger_url)
        });

        if pages.is_empty() {
            self.set_status(CollectorStatus::Waiting);
            return true;
        }

        let mut completed = false;
        for page in &pages {
            if self.stop.is_stopped() {
                self.finish_cycle(completed);
                return false;
            }
            let attempt = self.poll_page(page);
            if self.stop.is_stopped() {
                self.finish_cycle(completed);
                return false;
            }
            match attempt.result {
                Ok(metrics) => {
                    if let Err(err) = self.write_row(page, &metrics, attempt.session_id) {
                        self.log
                            .error("cdp", format!("cannot write cdp.csv: {err}"));
                        self.counter.record_err(err.to_string());
                    } else {
                        completed = true;
                    }
                }
                Err(PageError::Connection(err)) => {
                    self.log.warn_once(
                        &format!("cdp-connect-{}", page.id),
                        "cdp",
                        format!("cannot connect to page {}: {err}", page.url),
                    );
                    self.write_failed_row(page, attempt.session_id);
                }
                Err(PageError::Protocol(err)) => {
                    self.log.error("cdp", format!("page {}: {err}", page.url));
                    self.counter.record_err(err.to_string());
                    self.write_failed_row(page, attempt.session_id);
                }
                Err(PageError::Stopped) => {
                    self.finish_cycle(completed);
                    return false;
                }
                Err(PageError::Reset) => {
                    self.write_failed_row(page, attempt.session_id);
                }
            }
            // Identity exhaustion is fatal even when another target succeeded.
            if matches!(
                *self
                    .status
                    .lock()
                    .expect("the CDP status mutex is not poisoned"),
                CollectorStatus::Failed(_)
            ) {
                return false;
            }
        }

        self.finish_cycle(completed)
    }

    /// Publishes completed attempt outcomes even when the next attempt is canceled.
    fn finish_cycle(&mut self, completed: bool) -> bool {
        // A fatal identity error must not be overwritten by another page's success.
        if matches!(
            *self
                .status
                .lock()
                .expect("the CDP status mutex is not poisoned"),
            CollectorStatus::Failed(_)
        ) {
            return false;
        }
        if completed {
            self.counter.record_ok();
            self.set_status(CollectorStatus::Ok);
        } else if self.counter.is_failed() {
            self.set_status(self.counter.status());
            return false;
        } else {
            self.set_status(CollectorStatus::Waiting);
        }
        true
    }

    /// Samples a cached connection, allocating identity only after handshake.
    fn poll_page(&mut self, page: &CdpPage) -> PageAttempt {
        let deadline = Instant::now() + IO_TIMEOUT;
        if !self.sessions.contains_key(&page.id) {
            let socket = match connect_page(page, &self.stop, deadline) {
                Ok(socket) => socket,
                Err(err) => {
                    return PageAttempt {
                        session_id: None,
                        result: Err(err),
                    };
                }
            };
            let session_id = self.next_session_id;
            let Some(next) = session_id.checked_add(1) else {
                let reason = "CDP session identity exhausted";
                self.set_status(CollectorStatus::Failed(reason.to_owned()));
                return PageAttempt {
                    session_id: None,
                    result: Err(PageError::Protocol(anyhow!(reason))),
                };
            };
            self.next_session_id = next;
            self.sessions.insert(
                page.id.clone(),
                TargetSession {
                    socket,
                    session_id,
                    debugger_url: page.web_socket_debugger_url.clone(),
                    next_request_id: 1,
                    initialized: false,
                    cumulative: BTreeMap::new(),
                },
            );
        }
        let session = self
            .sessions
            .get_mut(&page.id)
            .expect("the page connection was established");
        let session_id = Some(session.session_id);
        let result = session.sample(&self.stop, deadline);
        if matches!(&result, Err(PageError::Reset)) {
            self.log.info(
                "cdp",
                format!(
                    "measurement session {} ended for target {}",
                    session.session_id, page.id
                ),
            );
        }
        if result.is_err() {
            self.sessions.remove(&page.id);
        }
        PageAttempt { session_id, result }
    }

    /// Preserves a failed known target without treating it as a success.
    fn write_failed_row(&mut self, page: &CdpPage, session_id: Option<u64>) {
        if let Err(err) = self.write_row(page, &CdpMetrics::default(), session_id) {
            self.log
                .error("cdp", format!("cannot write cdp.csv: {err}"));
            self.counter.record_err(err.to_string());
        }
    }

    /// Writes one target attempt using its own completion time and identity.
    fn write_row(
        &mut self,
        page: &CdpPage,
        metrics: &CdpMetrics,
        session_id: Option<u64>,
    ) -> io::Result<()> {
        let row = CdpRow {
            t_ms: self.started.elapsed().as_millis() as u64,
            unix_ms: unix_ms_now(),
            target_id: page.id.clone(),
            url: page.url.clone(),
            js_heap_used_bytes: metrics.js_heap_used_bytes,
            js_heap_total_bytes: metrics.js_heap_total_bytes,
            nodes: metrics.nodes,
            documents: metrics.documents,
            frames: metrics.frames,
            js_event_listeners: metrics.js_event_listeners,
            layout_count: metrics.layout_count,
            recalc_style_count: metrics.recalc_style_count,
            layout_duration_ms: metrics.layout_duration_ms,
            recalc_style_duration_ms: metrics.recalc_style_duration_ms,
            script_duration_ms: metrics.script_duration_ms,
            task_duration_ms: metrics.task_duration_ms,
            session_id,
        };
        self.table.write(&row)
    }

    /// Replaces the shared collector status.
    fn set_status(&self, value: CollectorStatus) {
        *self
            .status
            .lock()
            .expect("the CDP status mutex is not poisoned") = value;
    }
}

/// Returns the current wall-clock time in milliseconds since the epoch.
fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    use tempfile::TempDir;
    use tungstenite::{Message, WebSocket, protocol::Role};

    use crate::collect::cdp::{
        CdpCollector, CdpMetric, CdpMetrics, CdpPage, DeadlineStream, PageError, TargetSession,
        map_metrics, parse_pages, socket_address,
    };
    use crate::meta::CollectorStatus;
    use crate::sampler::StopHandle;
    use crate::store::{CDP_COLUMNS, CsvTable};

    struct SessionMockGuard {
        stop: StopHandle,
        stream: TcpStream,
        handle: Option<JoinHandle<()>>,
    }

    impl Drop for SessionMockGuard {
        fn drop(&mut self) {
            self.stop.stop();
            let _ = self.stream.shutdown(Shutdown::Both);
            if let Some(handle) = self.handle.take() {
                let deadline = Instant::now() + Duration::from_secs(3);
                while !handle.is_finished() && Instant::now() < deadline {
                    thread::park_timeout(Duration::from_millis(1));
                }
                if handle.is_finished() {
                    let result = handle.join();
                    if !thread::panicking() {
                        result.unwrap();
                    }
                } else if !thread::panicking() {
                    panic!("session mock exceeded its cleanup budget");
                }
            }
        }
    }

    fn mock_session(samples: Vec<Vec<CdpMetric>>) -> (TargetSession, SessionMockGuard) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let stream =
            TcpStream::connect_timeout(&listener.local_addr().unwrap(), Duration::from_secs(1))
                .unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let server = loop {
            match listener.accept() {
                Ok((server, _)) => break server,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "session mock accept timed out");
                    thread::park_timeout(Duration::from_millis(1));
                }
                Err(err) => panic!("session mock accept failed: {err}"),
            }
        };
        server
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        server
            .set_write_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let stop = StopHandle::new();
        let guard_stream = server.try_clone().unwrap();
        let handle = thread::spawn({
            let stop = stop.clone();
            move || {
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut socket = WebSocket::from_raw_socket(server, Role::Server, None);
                for metrics in samples {
                    let request = loop {
                        if stop.is_stopped() || Instant::now() >= deadline {
                            return;
                        }
                        match socket.read() {
                            Ok(Message::Text(text)) => break text,
                            Ok(Message::Close(_)) => return,
                            Ok(_) => (),
                            Err(tungstenite::Error::Io(err))
                                if matches!(
                                    err.kind(),
                                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                                ) => {}
                            Err(_) => return,
                        }
                    };
                    let request: serde_json::Value =
                        serde_json::from_str(request.as_str()).unwrap();
                    let metrics: Vec<_> = metrics.iter().map(|metric| {
                        serde_json::json!({"name": metric.name, "value": metric.value})
                    }).collect();
                    if socket
                        .send(Message::text(
                            serde_json::json!({
                                "id": request["id"], "result": {"metrics": metrics}
                            })
                            .to_string(),
                        ))
                        .is_err()
                    {
                        return;
                    }
                }
            }
        });
        (
            TargetSession {
                socket: WebSocket::from_raw_socket(
                    DeadlineStream {
                        stream,
                        stop: stop.clone(),
                        deadline: Instant::now() + Duration::from_secs(2),
                    },
                    Role::Client,
                    None,
                ),
                session_id: 1,
                debugger_url: "ws://127.0.0.1:1/test".to_owned(),
                next_request_id: 1,
                initialized: true,
                cumulative: std::collections::BTreeMap::new(),
            },
            SessionMockGuard {
                stop,
                stream: guard_stream,
                handle: Some(handle),
            },
        )
    }

    #[test]
    fn map_metrics_rejects_nonfinite_and_negative_values() {
        let names = [
            "JSHeapUsedSize",
            "JSHeapTotalSize",
            "Nodes",
            "Documents",
            "Frames",
            "JSEventListeners",
            "LayoutCount",
            "RecalcStyleCount",
            "LayoutDuration",
            "RecalcStyleDuration",
            "ScriptDuration",
            "TaskDuration",
        ];
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0, -0.0001] {
            let metrics: Vec<_> = names
                .iter()
                .map(|name| CdpMetric {
                    name: (*name).to_owned(),
                    value,
                })
                .collect();
            assert_eq!(
                map_metrics(&metrics),
                CdpMetrics::default(),
                "invalid raw value {value}"
            );
        }
        let metrics: Vec<_> = names
            .iter()
            .map(|name| CdpMetric {
                name: (*name).to_owned(),
                value: 0.0,
            })
            .collect();
        assert_eq!(
            map_metrics(&metrics),
            CdpMetrics {
                js_heap_used_bytes: Some(0),
                js_heap_total_bytes: Some(0),
                nodes: Some(0),
                documents: Some(0),
                frames: Some(0),
                js_event_listeners: Some(0),
                layout_count: Some(0),
                recalc_style_count: Some(0),
                layout_duration_ms: Some(0),
                recalc_style_duration_ms: Some(0),
                script_duration_ms: Some(0),
                task_duration_ms: Some(0),
            }
        );
        for name in [
            "LayoutDuration",
            "RecalcStyleDuration",
            "ScriptDuration",
            "TaskDuration",
        ] {
            assert_eq!(
                map_metrics(&[CdpMetric {
                    name: name.to_owned(),
                    value: f64::MAX,
                }]),
                CdpMetrics::default(),
                "nonfinite scaled value must be rejected"
            );
        }
    }

    #[test]
    fn cumulative_reset_uses_unrounded_values() {
        let metric = |name: &str, value| CdpMetric {
            name: name.to_owned(),
            value,
        };
        for name in [
            "LayoutDuration",
            "RecalcStyleDuration",
            "ScriptDuration",
            "TaskDuration",
        ] {
            let (mut session, guard) = mock_session(vec![
                vec![
                    metric(name, 0.00049),
                    metric("JSHeapUsedSize", 100.0),
                    metric("UnknownCounter", 10.0),
                ],
                vec![
                    metric(name, 0.00049),
                    metric("JSHeapUsedSize", 50.0),
                    metric("UnknownCounter", 9.0),
                ],
                vec![metric(name, 0.00048)],
            ]);
            let first = session
                .sample(&guard.stop, Instant::now() + Duration::from_secs(2))
                .ok()
                .expect("first metrics must establish a baseline");
            let second = session
                .sample(&guard.stop, Instant::now() + Duration::from_secs(2))
                .ok()
                .expect("gauges and unknown names must not end the segment");
            assert_eq!(first.js_heap_used_bytes, Some(100));
            assert_eq!(second.js_heap_used_bytes, Some(50));
            assert_eq!(
                map_metrics(&[metric(name, 0.00049)]),
                map_metrics(&[metric(name, 0.00048)])
            );
            let decreased = session.sample(&guard.stop, Instant::now() + Duration::from_secs(2));
            assert!(
                matches!(decreased, Err(PageError::Reset)),
                "raw decrease of {name} must end the segment despite identical CSV rounding"
            );
        }
    }

    #[test]
    fn socket_address_rejects_non_loopback_endpoints() {
        for url in [
            "ws://192.0.2.1:9222/page",
            "ws://[2001:db8::1]:9222/page",
            "ws://example.invalid:9222/page",
            "wss://127.0.0.1:9222/page",
            "http://127.0.0.1:9222/page",
            "127.0.0.1:9222/page",
        ] {
            assert!(
                socket_address(url).is_err(),
                "non-loopback or non-WebSocket endpoint must be rejected: {url}"
            );
        }
        for url in [
            "ws://127.0.0.1:9222/page",
            "ws://localhost:9222/page",
            "ws://[::1]:9222/page",
        ] {
            assert!(socket_address(url).unwrap().ip().is_loopback());
        }
    }

    #[test]
    fn parse_pages_keeps_only_page_targets() {
        let body = r#"[
            {
                "id": "page-1",
                "type": "page",
                "url": "http://127.0.0.1:5173/",
                "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/page-1"
            },
            {
                "id": "worker-1",
                "type": "service_worker",
                "url": "http://127.0.0.1:5173/sw.js",
                "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/worker-1"
            },
            {
                "id": "page-2",
                "type": "page",
                "url": "about:blank"
            },
            {
                "id": "page-3",
                "type": "page",
                "url": "http://127.0.0.1:5173/#/settings",
                "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/page-3"
            }
        ]"#;

        let pages = parse_pages(body).expect("the target list must parse");
        assert_eq!(
            pages,
            vec![
                CdpPage {
                    id: "page-1".to_string(),
                    url: "http://127.0.0.1:5173/".to_string(),
                    web_socket_debugger_url: "ws://127.0.0.1:9222/devtools/page/page-1".to_string(),
                },
                CdpPage {
                    id: "page-3".to_string(),
                    url: "http://127.0.0.1:5173/#/settings".to_string(),
                    web_socket_debugger_url: "ws://127.0.0.1:9222/devtools/page/page-3".to_string(),
                },
            ],
            "only pages with a debugger URL must be kept, in their original order"
        );
    }

    #[test]
    fn parse_pages_rejects_invalid_json() {
        for body in ["not json", "{}"] {
            assert!(parse_pages(body).is_err(), "`{body}` must be rejected");
        }
    }

    #[test]
    fn map_metrics_converts_durations_to_milliseconds() {
        let metrics = vec![
            CdpMetric {
                name: "Timestamp".to_string(),
                value: 123.456,
            },
            CdpMetric {
                name: "JSHeapUsedSize".to_string(),
                value: 42.0,
            },
            CdpMetric {
                name: "JSHeapTotalSize".to_string(),
                value: 84.0,
            },
            CdpMetric {
                name: "Nodes".to_string(),
                value: 7.0,
            },
            CdpMetric {
                name: "Documents".to_string(),
                value: 3.0,
            },
            CdpMetric {
                name: "Frames".to_string(),
                value: 2.0,
            },
            CdpMetric {
                name: "JSEventListeners".to_string(),
                value: 11.0,
            },
            CdpMetric {
                name: "LayoutCount".to_string(),
                value: 5.0,
            },
            CdpMetric {
                name: "RecalcStyleCount".to_string(),
                value: 6.0,
            },
            CdpMetric {
                name: "LayoutDuration".to_string(),
                value: 1.25,
            },
            CdpMetric {
                name: "RecalcStyleDuration".to_string(),
                value: 0.25,
            },
            CdpMetric {
                name: "ScriptDuration".to_string(),
                value: 1.5,
            },
            CdpMetric {
                name: "TaskDuration".to_string(),
                value: 0.0005,
            },
        ];

        let mapped = map_metrics(&metrics);
        assert_eq!(
            mapped.layout_duration_ms,
            Some(1250),
            "duration seconds must become milliseconds"
        );
        assert_eq!(mapped.recalc_style_duration_ms, Some(250));
        assert_eq!(mapped.script_duration_ms, Some(1500));
        assert_eq!(
            mapped.task_duration_ms,
            Some(1),
            "duration milliseconds must be rounded"
        );
        assert_eq!(mapped.js_heap_used_bytes, Some(42));
        assert_eq!(mapped.js_heap_total_bytes, Some(84));
        assert_eq!(mapped.nodes, Some(7));
        assert_eq!(mapped.documents, Some(3));
        assert_eq!(mapped.frames, Some(2));
        assert_eq!(mapped.js_event_listeners, Some(11));
        assert_eq!(mapped.layout_count, Some(5));
        assert_eq!(mapped.recalc_style_count, Some(6));
    }

    #[test]
    fn map_metrics_leaves_missing_metrics_empty() {
        let metrics = vec![CdpMetric {
            name: "Nodes".to_string(),
            value: 9.0,
        }];

        let mapped = map_metrics(&metrics);
        assert_eq!(mapped.nodes, Some(9), "the reported metric must be kept");
        assert_eq!(mapped.js_heap_used_bytes, None);
        assert_eq!(mapped.js_heap_total_bytes, None);
        assert_eq!(mapped.documents, None);
        assert_eq!(mapped.frames, None);
        assert_eq!(mapped.js_event_listeners, None);
        assert_eq!(mapped.layout_count, None);
        assert_eq!(mapped.recalc_style_count, None);
        assert_eq!(mapped.layout_duration_ms, None);
        assert_eq!(mapped.recalc_style_duration_ms, None);
        assert_eq!(mapped.script_duration_ms, None);
        assert_eq!(mapped.task_duration_ms, None);
    }

    #[test]
    fn disabled_collector_reports_disabled() {
        let dir = TempDir::new().expect("the temporary directory must be created");
        let path = dir.path().join("cdp.csv");
        let table = CsvTable::create(&path, CDP_COLUMNS).expect("the table must be created");

        let mut collector = CdpCollector::disabled(table);
        assert_eq!(collector.status(), CollectorStatus::Disabled);
        collector.flush(true).expect("the flush must succeed");

        let content = fs::read_to_string(&path).expect("cdp.csv must be readable");
        assert_eq!(
            content.trim_end(),
            CDP_COLUMNS.join(","),
            "the disabled collector must leave only the header"
        );

        assert!(
            collector.join(Duration::from_millis(1)),
            "a disabled collector must join immediately"
        );
    }
}
