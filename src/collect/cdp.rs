//! JavaScript page metrics collected over the Chrome DevTools Protocol.
//!
//! The collector polls the local DevTools endpoint in its own thread, so the
//! run's main loop is never blocked. Only the loopback endpoint is contacted:
//! the target list is fetched from `127.0.0.1` and every page WebSocket URL
//! comes from that list.

use std::io;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
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

/// Timeout of one network operation: the target list request, a TCP connect,
/// the WebSocket handshake or a frame read or write.
const IO_TIMEOUT: Duration = Duration::from_secs(2);

/// How often the `cdp.csv` file is synced to the storage device.
const FSYNC_INTERVAL: Duration = Duration::from_secs(60);

/// Request that turns on the performance metrics domain.
const ENABLE_PERFORMANCE: &str = r#"{"id":1,"method":"Performance.enable"}"#;

/// Request that returns the performance metrics of a page.
const GET_METRICS: &str = r#"{"id":2,"method":"Performance.getMetrics"}"#;

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
        *slot = Some(to_whole(metric));
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
fn to_whole(metric: &CdpMetric) -> u64 {
    match metric.name.as_str() {
        "LayoutDuration" | "RecalcStyleDuration" | "ScriptDuration" | "TaskDuration" => {
            (metric.value * 1000.0).round() as u64
        }
        _ => metric.value.round() as u64,
    }
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
}

/// Opens a WebSocket to a page and runs the performance exchange.
///
/// The exchange enables the performance domain, requests the metrics and
/// returns them mapped to the `cdp.csv` fields.
fn exchange_page(page: &CdpPage) -> Result<CdpMetrics, PageError> {
    let address = socket_address(&page.web_socket_debugger_url).map_err(PageError::Protocol)?;
    let stream = TcpStream::connect_timeout(&address, IO_TIMEOUT)
        .map_err(|err| PageError::Connection(anyhow!("cannot connect to the page: {err}")))?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
        .map_err(|err| PageError::Protocol(anyhow!("cannot set the socket timeouts: {err}")))?;

    let (mut socket, _response) = client(page.web_socket_debugger_url.as_str(), stream)
        .map_err(|err| PageError::Connection(anyhow!("the WebSocket handshake failed: {err}")))?;

    socket
        .send(Message::text(ENABLE_PERFORMANCE))
        .map_err(|err| {
            PageError::Protocol(anyhow!("cannot enable the performance metrics: {err}"))
        })?;
    read_reply(&mut socket, 1)?;

    socket.send(Message::text(GET_METRICS)).map_err(|err| {
        PageError::Protocol(anyhow!("cannot request the performance metrics: {err}"))
    })?;
    let metrics = read_reply(&mut socket, 2)?;
    Ok(map_metrics(&metrics))
}

/// Resolves the TCP address of a DevTools WebSocket URL.
fn socket_address(url: &str) -> anyhow::Result<SocketAddr> {
    let rest = url.strip_prefix("ws://").unwrap_or(url);
    let authority = rest.split('/').next().unwrap_or_default();
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("the WebSocket URL has no port: {url}"))?;
    let port: u16 = port
        .parse()
        .with_context(|| format!("the WebSocket URL has an invalid port: {url}"))?;
    (host, port)
        .to_socket_addrs()
        .with_context(|| format!("cannot resolve the WebSocket host: {url}"))?
        .next()
        .ok_or_else(|| anyhow!("the WebSocket host has no address: {url}"))
}

/// Reads frames until the reply with the expected request id arrives.
///
/// Frames that are not text, and text frames of other requests and events,
/// are skipped. A reply that reports an error, and a text frame that is not a
/// protocol reply, fail the exchange.
fn read_reply(socket: &mut WebSocket<TcpStream>, id: u64) -> Result<Vec<CdpMetric>, PageError> {
    loop {
        let message = socket
            .read()
            .map_err(|err| PageError::Protocol(anyhow!("cannot read a reply: {err}")))?;
        let Message::Text(text) = message else {
            continue;
        };
        let reply: CdpReply = serde_json::from_str(text.as_str())
            .map_err(|err| PageError::Protocol(anyhow!("cannot parse a reply: {err}")))?;
        if reply.id != Some(id) {
            continue;
        }
        if let Some(error) = reply.error {
            return Err(PageError::Protocol(anyhow!(
                "the DevTools call failed: {}",
                error.message
            )));
        }
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
                return true;
            }
        };

        if pages.is_empty() {
            self.set_status(CollectorStatus::Waiting);
            return true;
        }

        let mut completed = false;
        let mut failed = false;
        for page in &pages {
            if self.stop.is_stopped() {
                break;
            }
            match exchange_page(page) {
                Ok(metrics) => {
                    if let Err(err) = self.write_row(page, &metrics) {
                        self.log
                            .error("cdp", format!("cannot write cdp.csv: {err}"));
                        self.counter.record_err(err.to_string());
                        failed = true;
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
                    self.set_status(CollectorStatus::Waiting);
                }
                Err(PageError::Protocol(err)) => {
                    self.log.error("cdp", format!("page {}: {err}", page.url));
                    self.counter.record_err(err.to_string());
                    failed = true;
                }
            }
        }

        if completed {
            self.counter.record_ok();
            self.set_status(CollectorStatus::Ok);
        } else if failed && self.counter.is_failed() {
            self.set_status(self.counter.status());
            return false;
        }
        true
    }

    /// Writes one `cdp.csv` row for a completed page exchange.
    fn write_row(&mut self, page: &CdpPage, metrics: &CdpMetrics) -> io::Result<()> {
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
    use std::time::Duration;

    use tempfile::TempDir;

    use crate::collect::cdp::{CdpCollector, CdpMetric, CdpPage, map_metrics, parse_pages};
    use crate::meta::CollectorStatus;
    use crate::store::{CDP_COLUMNS, CsvTable};

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
