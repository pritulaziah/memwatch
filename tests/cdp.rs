//! Bounded loopback regressions for the synchronous DevTools collector.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use memwatch::collect::cdp::CdpCollector;
use memwatch::log::RunLog;
use memwatch::meta::{CollectorStatus, EndReason, Host, Meta};
use memwatch::options::RunOptions;
use memwatch::report::{self, Lang, ReportOptions};
use memwatch::sampler::StopHandle;
use memwatch::store::{
    CDP_COLUMNS, CsvTable, GPU_COLUMNS, JOB_COLUMNS, PROCESS_COLUMNS, PROCESSES_COLUMNS,
    SYSTEM_COLUMNS,
};
use serde_json::{Value, json};
use tempfile::TempDir;
use tungstenite::{Message, WebSocket};

const WAIT: Duration = Duration::from_secs(3);
const HANDLER_BUDGET: Duration = Duration::from_secs(5);

struct MockServerGuard {
    stop: StopHandle,
    streams: Arc<Mutex<Vec<TcpStream>>>,
    handle: Option<JoinHandle<()>>,
    finished: Receiver<()>,
}

impl MockServerGuard {
    fn start(handler: impl Fn(TcpStream, StopHandle) + Send + Sync + 'static) -> (u16, Self) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let stop = StopHandle::new();
        let streams = Arc::new(Mutex::new(Vec::<TcpStream>::new()));
        let (sender, finished) = mpsc::channel();
        let handle = thread::spawn({
            let stop = stop.clone();
            let streams = Arc::clone(&streams);
            let handler = Arc::new(handler);
            move || {
                let deadline = Instant::now() + Duration::from_secs(30);
                let mut workers = Vec::new();
                while !stop.is_stopped() && Instant::now() < deadline {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stream
                                .set_read_timeout(Some(Duration::from_millis(100)))
                                .unwrap();
                            stream
                                .set_write_timeout(Some(Duration::from_millis(100)))
                                .unwrap();
                            streams.lock().unwrap().push(stream.try_clone().unwrap());
                            let handler = Arc::clone(&handler);
                            let stop = stop.clone();
                            workers.push(thread::spawn(move || handler(stream, stop)));
                        }
                        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                            stop.wait_timeout(Duration::from_millis(2));
                        }
                        Err(_) => break,
                    }
                }
                stop.stop();
                for stream in streams.lock().unwrap().iter() {
                    let _ = stream.shutdown(Shutdown::Both);
                }
                let deadline = Instant::now() + WAIT;
                let mut handlers_ok = true;
                for worker in workers {
                    while !worker.is_finished() && Instant::now() < deadline {
                        thread::park_timeout(Duration::from_millis(1));
                    }
                    assert!(
                        worker.is_finished(),
                        "mock handler exceeded its cleanup budget"
                    );
                    // Join every handler before propagating a handler panic.
                    handlers_ok &= worker.join().is_ok();
                }
                assert!(handlers_ok, "a mock handler panicked");
                let _ = sender.send(());
            }
        });
        (
            port,
            Self {
                stop,
                streams,
                handle: Some(handle),
                finished,
            },
        )
    }
}

impl Drop for MockServerGuard {
    fn drop(&mut self) {
        let deadline = Instant::now() + WAIT;
        self.stop.stop();
        for stream in self.streams.lock().unwrap().iter() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        let completed = !matches!(
            self.finished
                .recv_timeout(deadline.saturating_duration_since(Instant::now())),
            Err(mpsc::RecvTimeoutError::Timeout)
        );
        if completed {
            if let Some(handle) = self.handle.take() {
                while !handle.is_finished() && Instant::now() < deadline {
                    thread::park_timeout(Duration::from_millis(1));
                }
                if handle.is_finished() {
                    let result = handle.join();
                    if !thread::panicking() {
                        result.unwrap();
                    }
                } else if !thread::panicking() {
                    panic!("mock server exceeded its cleanup budget");
                }
            }
        } else if !thread::panicking() {
            panic!("mock server exceeded its cleanup budget");
        }
    }
}

struct MockSocket {
    url: String,
    guard: MockServerGuard,
}

impl MockSocket {
    fn start(handler: impl Fn(WebSocket<TcpStream>, StopHandle) + Send + Sync + 'static) -> Self {
        let (port, guard) = MockServerGuard::start(move |stream, stop| {
            if let Ok(socket) = tungstenite::accept(stream) {
                handler(socket, stop);
            }
        });
        Self {
            url: format!("ws://127.0.0.1:{port}/devtools/page/test"),
            guard,
        }
    }
}

struct MockList {
    port: u16,
    guard: MockServerGuard,
}

impl MockList {
    fn start(bodies: Vec<String>) -> Self {
        assert!(!bodies.is_empty());
        let index = AtomicUsize::new(0);
        let (port, guard) = MockServerGuard::start(move |mut stream, stop| {
            let deadline = Instant::now() + HANDLER_BUDGET;
            let mut request = Vec::new();
            let mut buffer = [0; 1024];
            while !stop.is_stopped() && Instant::now() < deadline {
                match stream.read(&mut buffer) {
                    Ok(0) => return,
                    Ok(count) => request.extend_from_slice(&buffer[..count]),
                    Err(err) if timed_out(&err) => continue,
                    Err(_) => return,
                }
                if request.windows(4).any(|part| part == b"\r\n\r\n") {
                    break;
                }
                if request.len() > 8192 {
                    return;
                }
            }
            if stop.is_stopped() || Instant::now() >= deadline {
                return;
            }
            let (status, body) = if request.starts_with(b"GET /json/list ") {
                let at = index.fetch_add(1, Ordering::SeqCst).min(bodies.len() - 1);
                ("200 OK", bodies[at].as_str())
            } else {
                ("404 Not Found", "")
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        });
        Self { port, guard }
    }
}

struct CollectorGuard(CdpCollector);

impl CollectorGuard {
    fn start(dir: &Path, port: u16, interval: Duration) -> Self {
        let table = CsvTable::create(&dir.join("cdp.csv"), CDP_COLUMNS).unwrap();
        let log = RunLog::create(&dir.join("memwatch.log")).unwrap();
        Self(CdpCollector::start(
            port,
            interval,
            Instant::now(),
            table,
            log,
        ))
    }

    fn finish(&mut self) {
        self.0.stop();
        assert!(
            self.0.join(WAIT),
            "collector did not finish within three seconds"
        );
    }
}

impl Drop for CollectorGuard {
    fn drop(&mut self) {
        self.0.stop();
        let completed = self.0.join(WAIT);
        if !thread::panicking() {
            assert!(completed, "collector cleanup exceeded three seconds");
        }
    }
}

fn timed_out(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

fn read_request(
    socket: &mut WebSocket<TcpStream>,
    stop: &StopHandle,
    deadline: Instant,
) -> Option<Value> {
    while !stop.is_stopped() && Instant::now() < deadline {
        match socket.read() {
            Ok(Message::Text(text)) => return serde_json::from_str(text.as_str()).ok(),
            Ok(Message::Close(_)) => return None,
            Ok(_) => (),
            Err(tungstenite::Error::Io(err)) if timed_out(&err) => (),
            Err(_) => return None,
        }
    }
    None
}

fn reply(socket: &mut WebSocket<TcpStream>, id: &Value, heap: u64) -> bool {
    socket
        .send(Message::text(
            json!({"id": id, "result": {"metrics": [
                {"name": "JSHeapUsedSize", "value": heap}, {"name": "Nodes", "value": 7}
            ]}})
            .to_string(),
        ))
        .is_ok()
}

fn pages(targets: &[(&str, &str)]) -> String {
    Value::Array(
        targets
            .iter()
            .map(|(id, url)| {
                json!({
                    "type": "page", "id": id, "url": "about:blank", "webSocketDebuggerUrl": url
                })
            })
            .collect(),
    )
    .to_string()
}

fn read_cdp(path: &Path) -> Vec<BTreeMap<String, String>> {
    let mut reader = csv::Reader::from_path(path).unwrap();
    let headers = reader.headers().unwrap().clone();
    reader
        .records()
        .map(|row| {
            headers
                .iter()
                .zip(row.unwrap().iter())
                .map(|(key, value)| (key.to_owned(), value.to_owned()))
                .collect()
        })
        .collect()
}

fn wait_until(mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        if condition() {
            return true;
        }
        thread::park_timeout(Duration::from_millis(2));
    }
    condition()
}

fn write_report_inputs(dir: &Path, cdp_status: CollectorStatus) {
    let options = RunOptions {
        name: "protocol-failure".into(),
        out_dir: dir.to_path_buf(),
        labels: BTreeMap::new(),
        interval: Duration::from_secs(1),
        duration: None,
        gpu_interval: Duration::from_secs(2),
        cdp_interval: Duration::from_millis(20),
        cdp_port: Some(9222),
        allow_sleep: true,
        command: vec!["app.exe".into()],
    };
    let started = time::OffsetDateTime::parse(
        "2026-10-07T16:05:09+03:00",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    let mut meta = Meta::new(
        &options,
        started,
        Host {
            os: "Windows".into(),
            cpu: "Test CPU".into(),
            logical_cpus: 8,
            ram_bytes: 8_589_934_592,
            gpus: vec![],
        },
    );
    meta.ended_at = Some("2026-10-07T16:06:09+03:00".into());
    meta.end_reason = Some(EndReason::AppExited);
    meta.exit_code = Some(0);
    meta.collectors.insert("cdp".into(), cdp_status);
    meta.write_atomic(dir).unwrap();
    for (file, columns) in [
        ("processes.csv", PROCESSES_COLUMNS),
        ("process.csv", PROCESS_COLUMNS),
        ("job.csv", JOB_COLUMNS),
        ("gpu.csv", GPU_COLUMNS),
        ("system.csv", SYSTEM_COLUMNS),
    ] {
        if !dir.join(file).exists() {
            let mut table = CsvTable::create(&dir.join(file), columns).unwrap();
            table.flush(true).unwrap();
        }
    }
}

#[test]
fn protocol_failure_details_stay_in_log_not_report() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let socket = MockSocket::start({
        let attempts = Arc::clone(&attempts);
        move |mut socket, stop| {
            let deadline = Instant::now() + HANDLER_BUDGET;
            while let Some(request) = read_request(&mut socket, &stop, deadline) {
                if request["method"] == "Performance.getMetrics" {
                    let error = json!({"id": request["id"], "error": {"code": -32000, "message": r"https://private.invalid/url-secret C:\private\path-secret\app.exe --token=command-secret"}});
                    if socket.send(Message::text(error.to_string())).is_ok() {
                        attempts.fetch_add(1, Ordering::SeqCst);
                    }
                    return;
                }
                if !metric_reply(&mut socket, &request["id"], &[]) {
                    return;
                }
            }
        }
    });
    let list = MockList::start(vec![pages(&[("A", &socket.url)])]);
    let dir = TempDir::new().unwrap();
    let mut collector = CollectorGuard::start(dir.path(), list.port, Duration::from_millis(20));
    let deadline = Instant::now() + Duration::from_secs(5);
    while !matches!(collector.0.status(), CollectorStatus::Failed(_)) && Instant::now() < deadline {
        thread::park_timeout(Duration::from_millis(2));
    }
    let status = collector.0.status();
    collector.finish();
    assert_eq!(attempts.load(Ordering::SeqCst), 10);
    assert!(
        matches!(status, CollectorStatus::Failed(_)),
        "ten protocol failures must retain the existing status: {status:?}"
    );
    let log = fs::read_to_string(dir.path().join("memwatch.log")).unwrap();
    let markers = ["url-secret", "path-secret", "command-secret"];
    for marker in markers {
        assert!(log.contains(marker), "detail missing from log: {marker}");
    }
    write_report_inputs(dir.path(), status);
    for lang in [Lang::En, Lang::Ru] {
        let out = dir.path().join(match lang {
            Lang::En => "en",
            Lang::Ru => "ru",
        });
        let path = report::write(
            dir.path(),
            &ReportOptions {
                lang,
                warmup: Duration::ZERO,
            },
            Some(&out),
        )
        .unwrap();
        let document = fs::read_to_string(path).unwrap();
        for marker in markers {
            assert!(
                !document.contains(marker),
                "private marker leaked into report: {marker}"
            );
        }
        let copy = match lang {
            Lang::En => "failed (details in memwatch.log)",
            Lang::Ru => "сбой (подробности в memwatch.log)",
        };
        let header = document
            .lines()
            .find(|line| {
                line.starts_with(match lang {
                    Lang::En => "- **Collectors**",
                    Lang::Ru => "- **Сборщики**",
                })
            })
            .unwrap();
        let warning = document
            .lines()
            .find(|line| {
                line.starts_with(match lang {
                    Lang::En => "- collector cdp:",
                    Lang::Ru => "- сборщик cdp:",
                })
            })
            .unwrap();
        assert!(header.contains(copy));
        assert!(warning.contains(copy));
    }
}

fn successful_rows(dir: &Path) -> Vec<BTreeMap<String, String>> {
    read_cdp(&dir.join("cdp.csv"))
        .into_iter()
        .filter(|row| !row["js_heap_used_bytes"].is_empty())
        .collect()
}

fn session(row: &BTreeMap<String, String>) -> u64 {
    row["session_id"]
        .parse()
        .expect("a successful handshake must have a positive session id")
}

fn metric_reply(socket: &mut WebSocket<TcpStream>, id: &Value, metrics: &[Value]) -> bool {
    socket
        .send(Message::text(
            json!({"id": id, "result": {"metrics": metrics}}).to_string(),
        ))
        .is_ok()
}

fn gauges(heap: u64) -> Vec<Value> {
    vec![
        json!({"name": "JSHeapUsedSize", "value": heap}),
        json!({"name": "Nodes", "value": heap}),
    ]
}

fn navigation(parent: Option<&str>) -> Value {
    let mut frame = json!({"id": "frame-1"});
    if let Some(parent) = parent {
        frame["parentId"] = json!(parent);
    }
    json!({"method": "Page.frameNavigated", "params": {"frame": frame}})
}

struct ScriptedSocket {
    socket: MockSocket,
    connections: Arc<AtomicUsize>,
    domains: Arc<Mutex<Vec<(usize, String)>>>,
}

impl ScriptedSocket {
    fn start(steps: Vec<(Option<Value>, Vec<Value>)>) -> Self {
        assert!(!steps.is_empty());
        let connections = Arc::new(AtomicUsize::new(0));
        let domains = Arc::new(Mutex::new(Vec::new()));
        let socket = MockSocket::start({
            let connections = Arc::clone(&connections);
            let domains = Arc::clone(&domains);
            let index = AtomicUsize::new(0);
            move |mut socket, stop| {
                let connection = connections.fetch_add(1, Ordering::SeqCst);
                let deadline = Instant::now() + HANDLER_BUDGET;
                while let Some(request) = read_request(&mut socket, &stop, deadline) {
                    let method = request["method"].as_str().unwrap();
                    if method != "Performance.getMetrics" {
                        domains
                            .lock()
                            .unwrap()
                            .push((connection, method.to_owned()));
                        if !metric_reply(&mut socket, &request["id"], &[]) {
                            return;
                        }
                        continue;
                    }
                    let at = index.fetch_add(1, Ordering::SeqCst).min(steps.len() - 1);
                    let (event, metrics) = &steps[at];
                    if let Some(event) = event {
                        for _ in 0..32 {
                            if stop.is_stopped() || Instant::now() >= deadline {
                                return;
                            }
                            if socket
                                .send(Message::text(
                                    r#"{"method":"Runtime.consoleAPICalled","params":{}}"#,
                                ))
                                .is_err()
                            {
                                return;
                            }
                        }
                        if socket.send(Message::text(event.to_string())).is_err() {
                            return;
                        }
                    }
                    if !metric_reply(&mut socket, &request["id"], metrics) {
                        return;
                    }
                }
            }
        });
        Self {
            socket,
            connections,
            domains,
        }
    }

    fn assert_connections(&self, count: usize) {
        assert_eq!(self.connections.load(Ordering::SeqCst), count);
        let domains = self.domains.lock().unwrap();
        for connection in 0..count {
            for domain in ["Performance.enable", "Page.enable"] {
                assert_eq!(
                    domains
                        .iter()
                        .filter(|(id, method)| *id == connection && method == domain)
                        .count(),
                    1,
                    "each domain must be enabled once on connection {connection}"
                );
            }
        }
    }
}

fn assert_empty_attempt(row: &BTreeMap<String, String>) {
    assert!(
        CDP_COLUMNS[4..16]
            .iter()
            .all(|column| row[*column].is_empty()),
        "a segment boundary must not preserve any metrics: {row:?}"
    );
}

#[test]
fn main_frame_navigation_starts_new_measurement_session() {
    for parent in [None, Some("")] {
        let dir = TempDir::new_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        let socket = ScriptedSocket::start(vec![
            (None, gauges(42)),
            (Some(navigation(parent)), gauges(999)),
            (None, gauges(43)),
        ]);
        let list = MockList::start(vec![pages(&[("A", &socket.socket.url)])]);
        let mut collector = CollectorGuard::start(dir.path(), list.port, Duration::from_millis(30));
        assert!(wait_until(
            || read_cdp(&dir.path().join("cdp.csv")).len() >= 3
        ));
        collector.finish();
        let rows = read_cdp(&dir.path().join("cdp.csv"));
        assert_eq!(rows[0]["js_heap_used_bytes"], "42");
        assert_empty_attempt(&rows[1]);
        assert_eq!(session(&rows[0]), session(&rows[1]));
        assert_eq!(rows[2]["js_heap_used_bytes"], "43");
        assert!(session(&rows[2]) > session(&rows[1]));
        socket.assert_connections(2);
        let log = fs::read_to_string(dir.path().join("memwatch.log")).unwrap();
        assert!(
            !log.contains(" ERROR cdp:"),
            "navigation is not a protocol error"
        );
        assert!(log.contains("measurement session 1 ended for target A"));
        assert_eq!(collector.0.status(), CollectorStatus::Ok);
    }
}

#[test]
fn child_frame_navigation_keeps_measurement_session() {
    let dir = TempDir::new_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let socket = ScriptedSocket::start(vec![
        (None, gauges(42)),
        (Some(navigation(Some("main-frame"))), gauges(43)),
        (None, gauges(44)),
        (Some(navigation(None)), gauges(999)),
        (Some(navigation(Some("main-frame"))), gauges(45)),
    ]);
    let list = MockList::start(vec![pages(&[("A", &socket.socket.url)])]);
    let mut collector = CollectorGuard::start(dir.path(), list.port, Duration::from_millis(30));
    assert!(wait_until(
        || read_cdp(&dir.path().join("cdp.csv")).len() >= 5
    ));
    collector.finish();
    let rows = read_cdp(&dir.path().join("cdp.csv"));
    assert_eq!(rows[1]["js_heap_used_bytes"], "43");
    assert!(
        rows[..4]
            .iter()
            .all(|row| session(row) == session(&rows[0]))
    );
    assert_empty_attempt(&rows[3]);
    assert_eq!(rows[4]["js_heap_used_bytes"], "45");
    assert!(session(&rows[4]) > session(&rows[3]));
    assert!(
        rows[4..]
            .iter()
            .all(|row| session(row) == session(&rows[4]))
    );
    socket.assert_connections(2);
}

#[test]
fn cumulative_decrease_restarts_measurement_session() {
    for name in [
        "LayoutCount",
        "RecalcStyleCount",
        "LayoutDuration",
        "RecalcStyleDuration",
        "ScriptDuration",
        "TaskDuration",
    ] {
        let dir = TempDir::new_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        let steps = [10.0, 9.0, 11.0]
            .into_iter()
            .enumerate()
            .map(|(at, value)| {
                let mut metrics = gauges(42 + at as u64);
                metrics.push(json!({"name": name, "value": value}));
                (None, metrics)
            })
            .collect();
        let socket = ScriptedSocket::start(steps);
        let list = MockList::start(vec![pages(&[("A", &socket.socket.url)])]);
        let mut collector = CollectorGuard::start(dir.path(), list.port, Duration::from_millis(30));
        assert!(wait_until(
            || read_cdp(&dir.path().join("cdp.csv")).len() >= 3
        ));
        collector.finish();
        let rows = read_cdp(&dir.path().join("cdp.csv"));
        assert_empty_attempt(&rows[1]);
        assert_eq!(session(&rows[0]), session(&rows[1]), "{name}");
        assert!(session(&rows[2]) > session(&rows[1]), "{name}");
        assert_eq!(rows[2]["js_heap_used_bytes"], "44");
        socket.assert_connections(2);
        let log = fs::read_to_string(dir.path().join("memwatch.log")).unwrap();
        assert!(
            !log.contains(" ERROR cdp:"),
            "counter reset is not a protocol error"
        );
        assert!(log.contains("measurement session 1 ended for target A"));
    }
}

#[test]
fn missing_cumulative_value_keeps_last_baseline() {
    let dir = TempDir::new_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let steps = [Some(10.0), None, Some(9.0), Some(11.0)]
        .into_iter()
        .enumerate()
        .map(|(at, value)| {
            let mut metrics = gauges(42 + at as u64);
            if let Some(value) = value {
                metrics.push(json!({"name": "LayoutCount", "value": value}));
            }
            (None, metrics)
        })
        .collect();
    let socket = ScriptedSocket::start(steps);
    let list = MockList::start(vec![pages(&[("A", &socket.socket.url)])]);
    let mut collector = CollectorGuard::start(dir.path(), list.port, Duration::from_millis(30));
    assert!(wait_until(
        || read_cdp(&dir.path().join("cdp.csv")).len() >= 4
    ));
    collector.finish();
    let rows = read_cdp(&dir.path().join("cdp.csv"));
    assert_eq!(rows[0]["layout_count"], "10");
    assert_eq!(rows[1]["js_heap_used_bytes"], "43");
    assert!(rows[1]["layout_count"].is_empty());
    assert_eq!(session(&rows[0]), session(&rows[1]));
    assert_empty_attempt(&rows[2]);
    assert_eq!(session(&rows[0]), session(&rows[2]));
    assert_eq!(rows[3]["js_heap_used_bytes"], "45");
    assert!(session(&rows[3]) > session(&rows[2]));
    socket.assert_connections(2);
}

#[test]
fn heap_decrease_does_not_restart_measurement_session() {
    let dir = TempDir::new_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let mut steps: Vec<_> = [100, 50, 0]
        .into_iter()
        .enumerate()
        .map(|(at, heap)| {
            let mut metrics = gauges(heap);
            for name in [
                "LayoutCount",
                "RecalcStyleCount",
                "LayoutDuration",
                "RecalcStyleDuration",
                "ScriptDuration",
                "TaskDuration",
            ] {
                metrics.push(json!({"name": name, "value": 10 + at}));
            }
            (None, metrics)
        })
        .collect();
    let mut decreased = gauges(10);
    decreased.push(json!({"name": "TaskDuration", "value": 11}));
    steps.push((None, decreased));
    let mut restarted = gauges(20);
    restarted.push(json!({"name": "TaskDuration", "value": 1}));
    steps.push((None, restarted));
    let socket = ScriptedSocket::start(steps);
    let list = MockList::start(vec![pages(&[("A", &socket.socket.url)])]);
    let mut collector = CollectorGuard::start(dir.path(), list.port, Duration::from_millis(30));
    assert!(wait_until(
        || read_cdp(&dir.path().join("cdp.csv")).len() >= 5
    ));
    collector.finish();
    let rows = read_cdp(&dir.path().join("cdp.csv"));
    assert_eq!(rows[1]["js_heap_used_bytes"], "50");
    assert_eq!(rows[2]["js_heap_used_bytes"], "0");
    assert!(
        rows[..4]
            .iter()
            .all(|row| session(row) == session(&rows[0]))
    );
    assert_empty_attempt(&rows[3]);
    assert_eq!(rows[4]["js_heap_used_bytes"], "20");
    assert!(session(&rows[4]) > session(&rows[3]));
    socket.assert_connections(2);
}

#[test]
fn navigation_events_obey_stop_and_reply_deadline() {
    let dir = TempDir::new_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let mut steps = vec![(Some(navigation(None)), gauges(999)); 12];
    steps.push((None, gauges(42)));
    let socket = ScriptedSocket::start(steps);
    let (sender, blocked) = mpsc::channel();
    let blocker = MockSocket::start(move |mut socket, stop| {
        let deadline = Instant::now() + HANDLER_BUDGET;
        while let Some(request) = read_request(&mut socket, &stop, deadline) {
            if request["method"] == "Performance.getMetrics" {
                // The current cycle has already written A's real sample before polling B.
                let _ = sender.send(());
                let _ = read_request(&mut socket, &stop, deadline);
                return;
            }
            if !metric_reply(&mut socket, &request["id"], &[]) {
                return;
            }
        }
    });
    let mut bodies = vec![pages(&[("A", &socket.socket.url)]); 13];
    bodies.push(pages(&[("A", &socket.socket.url), ("B", &blocker.url)]));
    let list = MockList::start(bodies);
    let mut collector = CollectorGuard::start(dir.path(), list.port, Duration::from_millis(10));
    blocked.recv_timeout(WAIT).unwrap();
    collector.finish();
    let rows = read_cdp(&dir.path().join("cdp.csv"));
    for row in &rows[..12] {
        assert_empty_attempt(row);
    }
    assert!(
        rows[..13]
            .windows(2)
            .all(|pair| session(&pair[0]) < session(&pair[1]))
    );
    assert_eq!(rows[12]["js_heap_used_bytes"], "42");
    socket.assert_connections(13);
    assert_eq!(collector.0.status(), CollectorStatus::Ok);
    assert!(
        !fs::read_to_string(dir.path().join("memwatch.log"))
            .unwrap()
            .contains(" ERROR cdp:")
    );

    // Hold navigation behind a busy stream until cancellation or the reply budget expires.
    for cancel in [true, false] {
        let dir = TempDir::new_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let (sender, events) = mpsc::channel();
        let release = StopHandle::new();
        let socket = MockSocket::start({
            let connections = Arc::clone(&connections);
            let release = release.clone();
            move |mut socket, stop| {
                connections.fetch_add(1, Ordering::SeqCst);
                let deadline = Instant::now() + HANDLER_BUDGET;
                while let Some(request) = read_request(&mut socket, &stop, deadline) {
                    if request["method"] != "Performance.getMetrics" {
                        if !metric_reply(&mut socket, &request["id"], &[]) {
                            return;
                        }
                        continue;
                    }
                    let at = Instant::now();
                    let _ = sender.send(at);
                    let late_at = at + Duration::from_millis(2100);
                    while !stop.is_stopped() && Instant::now() < deadline {
                        if (cancel && release.is_stopped())
                            || (!cancel && Instant::now() >= late_at)
                        {
                            let _ = socket.send(Message::text(navigation(None).to_string()));
                            let _ = metric_reply(&mut socket, &request["id"], &gauges(999));
                            return;
                        }
                        if socket
                            .send(Message::text(navigation(Some("main-frame")).to_string()))
                            .is_err()
                        {
                            return;
                        }
                    }
                    return;
                }
            }
        });
        let list = MockList::start(vec![pages(&[("A", &socket.url)])]);
        let mut collector = CollectorGuard::start(dir.path(), list.port, Duration::from_secs(20));
        let at = events.recv_timeout(WAIT).unwrap();
        if cancel {
            collector.0.stop();
            release.stop();
            collector.finish();
            assert!(at.elapsed() <= WAIT);
            assert!(read_cdp(&dir.path().join("cdp.csv")).is_empty());
        } else {
            assert!(wait_until(
                || !read_cdp(&dir.path().join("cdp.csv")).is_empty()
            ));
            assert!(at.elapsed() <= Duration::from_millis(2500));
            collector.finish();
            let rows = read_cdp(&dir.path().join("cdp.csv"));
            assert_eq!(rows.len(), 1);
            assert_empty_attempt(&rows[0]);
            assert!(session(&rows[0]) > 0);
        }
        assert_eq!(connections.load(Ordering::SeqCst), 1);
        assert_ne!(collector.0.status(), CollectorStatus::Ok);
        let log = fs::read_to_string(dir.path().join("memwatch.log")).unwrap();
        assert!(
            !log.contains("measurement session"),
            "cancellation and deadline must win over late navigation"
        );
        if cancel {
            assert!(
                !log.contains(" ERROR cdp:"),
                "stop must not become a protocol error"
            );
        } else {
            assert!(
                log.contains("CDP attempt deadline elapsed"),
                "late navigation must not replace the deadline error: {log}"
            );
        }
    }
}

#[test]
fn collector_reuses_socket_and_enables_domains_once() {
    let dir = TempDir::new_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let (sender, samples) = mpsc::channel();
    let socket = MockSocket::start({
        let connections = Arc::clone(&connections);
        let requests = Arc::clone(&requests);
        move |mut socket, stop| {
            connections.fetch_add(1, Ordering::SeqCst);
            let deadline = Instant::now() + HANDLER_BUDGET;
            while let Some(request) = read_request(&mut socket, &stop, deadline) {
                let method = request["method"].as_str().unwrap().to_owned();
                requests
                    .lock()
                    .unwrap()
                    .push((method.clone(), request["id"].as_u64().unwrap()));
                if !reply(&mut socket, &request["id"], 42) {
                    break;
                }
                if method == "Performance.getMetrics" {
                    let _ = sender.send(());
                }
            }
        }
    });
    let list = MockList::start(vec![pages(&[("A", &socket.url)])]);
    assert!(!socket.guard.stop.is_stopped() && !list.guard.stop.is_stopped());
    let mut collector = CollectorGuard::start(dir.path(), list.port, Duration::from_millis(30));
    for _ in 0..3 {
        samples.recv_timeout(WAIT).unwrap();
    }
    assert!(wait_until(|| successful_rows(dir.path()).len() >= 3));
    collector.finish();
    assert_eq!(
        connections.load(Ordering::SeqCst),
        1,
        "polls must reuse one handshake"
    );
    let requests = requests.lock().unwrap();
    for domain in ["Performance.enable", "Page.enable"] {
        assert_eq!(
            requests
                .iter()
                .filter(|(method, _)| method == domain)
                .count(),
            1
        );
    }
    assert!(requests.windows(2).all(|pair| pair[0].1 < pair[1].1));
    let rows = successful_rows(dir.path());
    assert!(session(&rows[0]) > 0);
    assert!(rows.iter().all(|row| session(row) == session(&rows[0])));
}

#[test]
fn collector_reconnects_after_socket_close() {
    let dir = TempDir::new_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let (sender, samples) = mpsc::channel();
    let socket = MockSocket::start(move |mut socket, stop| {
        let deadline = Instant::now() + HANDLER_BUDGET;
        while let Some(request) = read_request(&mut socket, &stop, deadline) {
            if !reply(&mut socket, &request["id"], 42) {
                break;
            }
            if request["method"] == "Performance.getMetrics" {
                let _ = sender.send(());
                let _ = socket.close(None);
                break;
            }
        }
    });
    let list = MockList::start(vec![pages(&[("A", &socket.url)])]);
    let mut collector = CollectorGuard::start(dir.path(), list.port, Duration::from_millis(30));
    for _ in 0..2 {
        samples.recv_timeout(WAIT).unwrap();
    }
    assert!(wait_until(|| successful_rows(dir.path()).len() >= 2));
    collector.finish();
    let rows = successful_rows(dir.path());
    assert!(
        session(&rows[1]) > session(&rows[0]),
        "reconnect must allocate a new identity"
    );
}

#[test]
fn collector_drops_removed_targets_without_reusing_sessions() {
    let dir = TempDir::new_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let (sender, closed) = mpsc::channel();
    let socket = MockSocket::start({
        let connections = Arc::clone(&connections);
        move |mut socket, stop| {
            let number = connections.fetch_add(1, Ordering::SeqCst);
            let deadline = Instant::now() + HANDLER_BUDGET;
            while let Some(request) = read_request(&mut socket, &stop, deadline) {
                if !reply(&mut socket, &request["id"], 42) {
                    break;
                }
            }
            if number == 0 {
                let _ = sender.send(());
            }
        }
    });
    let body = pages(&[("A", &socket.url)]);
    let list = MockList::start(vec![body.clone(), "[]".into(), body]);
    let mut collector = CollectorGuard::start(dir.path(), list.port, Duration::from_millis(80));
    closed.recv_timeout(WAIT).unwrap();
    assert!(wait_until(|| successful_rows(dir.path()).len() >= 2));
    collector.finish();
    let rows = successful_rows(dir.path());
    assert!(
        session(&rows[1]) > session(&rows[0]),
        "reappearing targets must not resume their old session"
    );
    assert_eq!(connections.load(Ordering::SeqCst), 2);
}

#[test]
fn collector_preserves_failed_target_attempts() {
    let bad = MockSocket::start(|mut socket, stop| {
        if let Some(request) = read_request(&mut socket, &stop, Instant::now() + HANDLER_BUDGET) {
            let _ = socket.send(Message::text(
                json!({"id": request["id"], "error": {"message": "enable refused"}}).to_string(),
            ));
        }
    });
    let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
    let missing = format!(
        "ws://127.0.0.1:{}/missing",
        reservation.local_addr().unwrap().port()
    );
    drop(reservation);
    let dir = TempDir::new_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let list = MockList::start(vec![pages(&[
        ("unreachable", &missing),
        ("protocol", &bad.url),
    ])]);
    let mut collector = CollectorGuard::start(dir.path(), list.port, Duration::from_millis(80));
    assert!(
        wait_until(|| read_cdp(&dir.path().join("cdp.csv")).len() >= 2),
        "known failures must preserve empty rows"
    );
    collector.finish();
    assert_ne!(collector.0.status(), CollectorStatus::Ok);
    let rows = read_cdp(&dir.path().join("cdp.csv"));
    assert_eq!(rows[0]["target_id"], "unreachable");
    assert!(rows[0]["session_id"].is_empty());
    assert_eq!(rows[1]["target_id"], "protocol");
    assert!(session(&rows[1]) > 0);
    for row in &rows {
        assert!(
            CDP_COLUMNS[4..16]
                .iter()
                .all(|column| row[*column].is_empty())
        );
    }

    let good = MockSocket::start(|mut socket, stop| {
        let deadline = Instant::now() + HANDLER_BUDGET;
        while let Some(request) = read_request(&mut socket, &stop, deadline) {
            if !reply(&mut socket, &request["id"], 42) {
                break;
            }
        }
    });
    let dir = TempDir::new_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let list = MockList::start(vec![pages(&[("good", &good.url), ("bad", &bad.url)])]);
    let mut collector = CollectorGuard::start(dir.path(), list.port, Duration::from_millis(80));
    assert!(wait_until(
        || read_cdp(&dir.path().join("cdp.csv")).len() >= 2
    ));
    collector.finish();
    let rows = read_cdp(&dir.path().join("cdp.csv"));
    assert_eq!(rows[0]["js_heap_used_bytes"], "42");
    assert_eq!(rows[1]["target_id"], "bad");
    assert!(rows[1]["js_heap_used_bytes"].is_empty());
    assert_eq!(collector.0.status(), CollectorStatus::Ok);
}

#[test]
fn collector_list_failure_does_not_fabricate_targets() {
    let dir = TempDir::new_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let socket = MockSocket::start({
        let connections = Arc::clone(&connections);
        move |mut socket, stop| {
            connections.fetch_add(1, Ordering::SeqCst);
            let deadline = Instant::now() + HANDLER_BUDGET;
            while let Some(request) = read_request(&mut socket, &stop, deadline) {
                if !reply(&mut socket, &request["id"], 42) {
                    break;
                }
            }
        }
    });
    let body = pages(&[("A", &socket.url)]);
    let list = MockList::start(vec![body.clone(), "not JSON".into(), body]);
    let mut collector = CollectorGuard::start(dir.path(), list.port, Duration::from_millis(500));
    assert!(wait_until(|| {
        fs::read_to_string(dir.path().join("memwatch.log"))
            .unwrap()
            .contains("cannot parse the DevTools target list")
            && collector.0.status() == CollectorStatus::Waiting
    }));
    assert_eq!(
        collector.0.status(),
        CollectorStatus::Waiting,
        "failed lists must clear stale success status"
    );
    assert_eq!(
        read_cdp(&dir.path().join("cdp.csv")).len(),
        1,
        "a failed list must not invent attempts"
    );
    assert!(wait_until(|| successful_rows(dir.path()).len() >= 2));
    collector.finish();
    let rows = successful_rows(dir.path());
    assert_eq!(
        connections.load(Ordering::SeqCst),
        1,
        "list errors must not evict live sessions"
    );
    assert_eq!(session(&rows[0]), session(&rows[1]));

    let dir = TempDir::new_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let list = MockList::start(vec!["not JSON".into()]);
    let mut collector = CollectorGuard::start(dir.path(), list.port, Duration::from_millis(500));
    assert!(wait_until(|| fs::read_to_string(
        dir.path().join("memwatch.log")
    )
    .unwrap()
    .contains("cannot parse the DevTools target list")));
    collector.finish();
    assert!(read_cdp(&dir.path().join("cdp.csv")).is_empty());
    assert_eq!(collector.0.status(), CollectorStatus::Waiting);
}

#[test]
fn collector_matches_replies_by_request_identity() {
    let dir = TempDir::new_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let socket = MockSocket::start(|mut socket, stop| {
        let deadline = Instant::now() + HANDLER_BUDGET;
        let mut previous = None;
        let mut value = 40;
        while let Some(request) = read_request(&mut socket, &stop, deadline) {
            if request["method"] == "Performance.getMetrics" {
                let _ = socket.send(Message::text(
                    json!({"method": "Runtime.consoleAPICalled", "params": {}}).to_string(),
                ));
                if !reply(&mut socket, &json!(999999), 999) {
                    break;
                }
                if let Some(id) = previous
                    && !reply(&mut socket, &json!(id), 888)
                {
                    break;
                }
                value += 1;
                previous = request["id"].as_u64();
            }
            if !reply(&mut socket, &request["id"], value) {
                break;
            }
        }
    });
    let list = MockList::start(vec![pages(&[("A", &socket.url)])]);
    let mut collector = CollectorGuard::start(dir.path(), list.port, Duration::from_millis(40));
    assert!(wait_until(|| successful_rows(dir.path()).len() >= 3));
    collector.finish();
    let rows = successful_rows(dir.path());
    assert_eq!(
        rows.iter()
            .take(3)
            .map(|row| row["js_heap_used_bytes"].as_str())
            .collect::<Vec<_>>(),
        ["41", "42", "43"],
        "stale replies must not satisfy later requests"
    );
}

#[test]
fn collector_deadline_bounds_queued_events() {
    let dir = TempDir::new_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let (sender, events) = mpsc::channel();
    let socket = MockSocket::start(move |mut socket, stop| {
        let deadline = Instant::now() + HANDLER_BUDGET;
        while let Some(request) = read_request(&mut socket, &stop, deadline) {
            if request["method"] != "Performance.getMetrics" {
                if !reply(&mut socket, &request["id"], 42) {
                    break;
                }
                continue;
            }
            let _ = sender.send(Instant::now());
            while !stop.is_stopped() && Instant::now() < deadline {
                if socket
                    .send(Message::text(
                        r#"{"method":"Runtime.consoleAPICalled","params":{}}"#,
                    ))
                    .is_err()
                {
                    break;
                }
            }
            break;
        }
    });
    let list = MockList::start(vec![pages(&[("A", &socket.url)])]);
    let mut collector = CollectorGuard::start(dir.path(), list.port, Duration::from_secs(20));
    let at = events.recv_timeout(WAIT).unwrap();
    assert!(
        wait_until(|| !read_cdp(&dir.path().join("cdp.csv")).is_empty()),
        "queued events must not extend the reply deadline"
    );
    assert!(at.elapsed() <= Duration::from_millis(2500));
    collector.finish();
    assert_ne!(collector.0.status(), CollectorStatus::Ok);
    let rows = read_cdp(&dir.path().join("cdp.csv"));
    assert_eq!(rows.len(), 1);
    assert!(rows[0]["js_heap_used_bytes"].is_empty());
    assert!(session(&rows[0]) > 0);
}

#[test]
fn collector_stop_interrupts_queued_events() {
    let dir = TempDir::new_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let (sender, events) = mpsc::channel();
    let socket = MockSocket::start(move |mut socket, stop| {
        let deadline = Instant::now() + HANDLER_BUDGET;
        while let Some(request) = read_request(&mut socket, &stop, deadline) {
            if request["method"] != "Performance.getMetrics" {
                if !reply(&mut socket, &request["id"], 42) {
                    break;
                }
                continue;
            }
            let _ = sender.send(());
            while !stop.is_stopped() && Instant::now() < deadline {
                if socket
                    .send(Message::text(
                        r#"{"method":"Runtime.consoleAPICalled","params":{}}"#,
                    ))
                    .is_err()
                {
                    return;
                }
            }
            let _ = reply(&mut socket, &request["id"], 999);
            break;
        }
    });
    let list = MockList::start(vec![pages(&[("A", &socket.url)])]);
    let mut collector = CollectorGuard::start(dir.path(), list.port, Duration::from_secs(20));
    events.recv_timeout(WAIT).unwrap();
    let at = Instant::now();
    collector.finish();
    assert!(at.elapsed() <= WAIT);
    assert!(
        read_cdp(&dir.path().join("cdp.csv")).is_empty(),
        "stop must not accept a late usable reply or invent a failed attempt"
    );
    assert!(!matches!(collector.0.status(), CollectorStatus::Failed(_)));
}

#[test]
fn collector_stop_finalizes_failed_current_cycle() {
    let dir = TempDir::new_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let (release, proceed) = mpsc::channel();
    let proceed = Mutex::new(proceed);
    let first = MockSocket::start(move |mut socket, stop| {
        let deadline = Instant::now() + HANDLER_BUDGET;
        let mut samples = 0;
        while let Some(request) = read_request(&mut socket, &stop, deadline) {
            if request["method"] == "Performance.getMetrics" {
                samples += 1;
                if samples == 2 {
                    // The previous cycle must be observed as successful before this failure.
                    loop {
                        if stop.is_stopped() || Instant::now() >= deadline {
                            return;
                        }
                        match proceed.lock().unwrap().recv_timeout(
                            Duration::from_millis(100)
                                .min(deadline.saturating_duration_since(Instant::now())),
                        ) {
                            Ok(()) => break,
                            Err(mpsc::RecvTimeoutError::Timeout) => (),
                            Err(mpsc::RecvTimeoutError::Disconnected) => return,
                        }
                    }
                    let _ = socket.send(Message::text(
                        json!({"id": request["id"], "error": {"message": "sample refused"}})
                            .to_string(),
                    ));
                    return;
                }
            }
            if !reply(&mut socket, &request["id"], 42) {
                break;
            }
        }
    });
    let (sender, blocked) = mpsc::channel();
    let second = MockSocket::start(move |mut socket, stop| {
        let deadline = Instant::now() + HANDLER_BUDGET;
        while let Some(request) = read_request(&mut socket, &stop, deadline) {
            if request["method"] == "Performance.getMetrics" {
                // Reaching B proves that A's failure row has already been written.
                let _ = sender.send(());
                let _ = read_request(&mut socket, &stop, deadline);
                return;
            }
            if !reply(&mut socket, &request["id"], 99) {
                break;
            }
        }
    });
    let list = MockList::start(vec![
        pages(&[("A", &first.url)]),
        pages(&[("A", &first.url), ("B", &second.url)]),
    ]);
    let mut collector = CollectorGuard::start(dir.path(), list.port, Duration::from_millis(10));
    assert!(wait_until(|| {
        collector.0.status() == CollectorStatus::Ok && successful_rows(dir.path()).len() == 1
    }));
    release.send(()).unwrap();
    blocked.recv_timeout(WAIT).unwrap();
    collector.finish();

    let rows = read_cdp(&dir.path().join("cdp.csv"));
    assert_eq!(rows.len(), 2, "canceled B must not invent an attempt row");
    assert!(rows.iter().all(|row| row["target_id"] == "A"));
    assert_eq!(rows[0]["js_heap_used_bytes"], "42");
    assert!(
        CDP_COLUMNS[4..16]
            .iter()
            .all(|column| rows[1][*column].is_empty())
    );
    assert_eq!(session(&rows[0]), session(&rows[1]));
    let log = fs::read_to_string(dir.path().join("memwatch.log")).unwrap();
    assert_eq!(
        log.lines()
            .filter(|line| line.contains(" ERROR cdp:"))
            .count(),
        1
    );
    assert!(log.contains("sample refused"));
    assert_eq!(
        collector.0.status(),
        CollectorStatus::Waiting,
        "a stopped cycle without an actual success must not retain the previous Ok"
    );
}

#[test]
fn collector_stop_preserves_successful_current_cycle() {
    let dir = TempDir::new_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let first = MockSocket::start(|mut socket, stop| {
        let deadline = Instant::now() + HANDLER_BUDGET;
        while let Some(request) = read_request(&mut socket, &stop, deadline) {
            if !reply(&mut socket, &request["id"], 42) {
                break;
            }
        }
    });
    let (sender, blocked) = mpsc::channel();
    let second = MockSocket::start(move |mut socket, stop| {
        let deadline = Instant::now() + HANDLER_BUDGET;
        while let Some(request) = read_request(&mut socket, &stop, deadline) {
            if request["method"] == "Performance.getMetrics" {
                // Reaching B proves that A's real sample has already been written.
                let _ = sender.send(());
                let _ = read_request(&mut socket, &stop, deadline);
                return;
            }
            if !reply(&mut socket, &request["id"], 99) {
                break;
            }
        }
    });
    let list = MockList::start(vec![pages(&[("A", &first.url), ("B", &second.url)])]);
    let mut collector = CollectorGuard::start(dir.path(), list.port, Duration::from_secs(20));
    blocked.recv_timeout(WAIT).unwrap();
    collector.finish();

    let rows = read_cdp(&dir.path().join("cdp.csv"));
    assert_eq!(rows.len(), 1, "canceled B must not invent an attempt row");
    assert_eq!(rows[0]["target_id"], "A");
    assert_eq!(rows[0]["js_heap_used_bytes"], "42");
    assert!(session(&rows[0]) > 0);
    let log = fs::read_to_string(dir.path().join("memwatch.log")).unwrap();
    assert!(
        !log.contains(" ERROR cdp:"),
        "cancellation must not count as a protocol failure"
    );
    assert_eq!(
        collector.0.status(),
        CollectorStatus::Ok,
        "stopping B must preserve A's actual success in the current cycle"
    );
}

#[test]
fn collector_keeps_sample_times_per_target() {
    let dir = TempDir::new_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let (sender, first_sample) = mpsc::channel();
    let first = MockSocket::start(move |mut socket, stop| {
        let deadline = Instant::now() + HANDLER_BUDGET;
        while let Some(request) = read_request(&mut socket, &stop, deadline) {
            if !reply(&mut socket, &request["id"], 10) {
                break;
            }
            if request["method"] == "Performance.getMetrics" {
                let _ = sender.send(());
            }
        }
    });
    let second = MockSocket::start(move |mut socket, stop| {
        let deadline = Instant::now() + HANDLER_BUDGET;
        while let Some(request) = read_request(&mut socket, &stop, deadline) {
            if request["method"] == "Performance.getMetrics" {
                // Hold the second reply for a measured interval after the first reply.
                if stop.wait_timeout(Duration::from_millis(40)) {
                    break;
                }
            }
            if !reply(&mut socket, &request["id"], 20) {
                break;
            }
        }
    });
    let list = MockList::start(vec![pages(&[("A", &first.url), ("B", &second.url)])]);
    let mut collector = CollectorGuard::start(dir.path(), list.port, Duration::from_secs(20));
    first_sample.recv_timeout(WAIT).unwrap();
    assert!(wait_until(|| successful_rows(dir.path()).len() >= 2));
    collector.finish();
    let rows = successful_rows(dir.path());
    assert_eq!(rows[0]["target_id"], "A");
    assert_eq!(rows[1]["target_id"], "B");
    let first: u64 = rows[0]["t_ms"].parse().unwrap();
    let second: u64 = rows[1]["t_ms"].parse().unwrap();
    assert!(
        second >= first + 30,
        "targets must retain their own actual sample times"
    );
    assert!(session(&rows[0]) > 0 && session(&rows[1]) > session(&rows[0]));
}
