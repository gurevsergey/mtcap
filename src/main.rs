//! mtcap — live packet capture from MikroTik routers into Wireshark.

mod api;
mod capture;
mod config;
mod report;
mod secret;

use api::{Api, Row};
use config::{Config, Device, Preset};
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, IsTerminal, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::time::{Duration, Instant};

const HELP: &str = "\
mtcap — live packet capture from MikroTik routers into Wireshark.

mtcap                       pick a device, a filter preset and an interface, then capture
mtcap <device> [preset]     capture from a device (preset defaults to \"all\")
mtcap listen <ip> [preset]  only receive a stream that is already being sent from <ip>
mtcap report [file.pcap]    summary of a capture (the latest one by default)

mtcap devices               list devices
mtcap presets               list filter presets
mtcap add <name> <host> <user> [port]
                            add a device to the config
mtcap stop <device>         stop the sniffer and restore its settings after a crash
mtcap forget <device>       remove the stored password

what the router sends:
  -i, --interface <name>    only this router interface (\"?\" to pick from a list)
      --ip <addr[/mask]>    only packets from or to this address
      --port <list>         these TCP/UDP ports instead of the preset's, e.g. 53 or 80,443
      --proto <list>        these IP protocols instead of the preset's, e.g. tcp,icmp
      --headers             headers only, no payload (the default when nothing narrows the capture)
      --full                whole packets even then
limits and output:
  -t, --time <seconds>      stop after this long (default 600, 0 = no limit)
  -w, --write <file.pcap>   save here instead of ~/captures/<device>-<preset>-<time>.pcap
      --no-save             do not save
      --tshark              show packets in the terminal even if Wireshark is installed
      --no-view             no viewer, only the file
      --force               take over a running sniffer; ignore the router's CPU load

Ctrl-C (or closing Wireshark's capture) stops the sniffer and puts its settings back.
A watchdog on the router does the same if this computer disappears.
config: ~/.config/mtcap/config.toml";

/// Stop after this long unless -t says otherwise.
const DEFAULT_SECONDS: u64 = 600;
/// Refuse to start above this router CPU load, and stop when it stays above the second one.
const CPU_START_LIMIT: u32 = 80;
const CPU_RUN_LIMIT: u32 = 90;
const TICK: Duration = Duration::from_secs(15);

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: i32) {
    STOP.store(true, Ordering::SeqCst);
}

extern "C" {
    fn signal(signum: i32, handler: extern "C" fn(i32)) -> usize;
}

#[derive(PartialEq, Clone, Copy)]
enum View {
    Auto,
    Wireshark,
    Tshark,
    None,
}

struct Opts {
    positional: Vec<String>,
    interface: Option<String>,
    ip: Option<String>,
    port: Option<String>,
    proto: Option<String>,
    write: Option<PathBuf>,
    seconds: Option<u64>,
    view: View,
    force: bool,
    headers: bool,
    full: bool,
    no_save: bool,
}

fn parse_args(args: Vec<String>) -> Result<Opts, String> {
    let mut opts = Opts {
        positional: Vec::new(), interface: None, ip: None, port: None, proto: None,
        write: None, seconds: None, view: View::Auto, force: false, headers: false, full: false, no_save: false,
    };
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let mut value = |name: &str| args.next().ok_or_else(|| format!("{name} needs a value"));
        match arg.as_str() {
            "-i" | "--interface" => opts.interface = Some(value("--interface")?),
            "--ip" => opts.ip = Some(value("--ip")?),
            "--port" => opts.port = Some(value("--port")?),
            "--proto" => opts.proto = Some(value("--proto")?),
            "-w" | "--write" => opts.write = Some(PathBuf::from(value("--write")?)),
            "-t" | "--time" => {
                opts.seconds = Some(value("--time")?.parse().map_err(|_| "--time needs a number of seconds")?)
            }
            "--tshark" => opts.view = View::Tshark,
            "--no-view" => opts.view = View::None,
            "--force" => opts.force = true,
            "--headers" => opts.headers = true,
            "--full" => opts.full = true,
            "--no-save" => opts.no_save = true,
            other if other.starts_with('-') && other.len() > 1 => return Err(format!("unknown option {other}")),
            _ => opts.positional.push(arg),
        }
    }
    Ok(opts)
}

fn on_path(program: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|paths| std::env::split_paths(&paths).any(|dir| dir.join(program).is_file()))
}

fn interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

/// Lets the user pick one of `labels`: fzf when available, a numbered list otherwise.
fn choose(prompt: &str, labels: &[String]) -> Result<usize, String> {
    if !interactive() {
        return Err(format!("{prompt}: not a terminal, give it on the command line"));
    }
    if on_path("fzf") {
        let mut child = Command::new("fzf")
            .args(["--height=40%", "--reverse", "--no-sort", &format!("--prompt={prompt} › ")])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| format!("cannot run fzf: {e}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(labels.join("\n").as_bytes());
        }
        let out = child.wait_with_output().map_err(|e| e.to_string())?;
        let picked = String::from_utf8_lossy(&out.stdout);
        let picked = picked.trim_end_matches('\n');
        return labels.iter().position(|l| l == picked).ok_or_else(|| "nothing chosen".to_string());
    }
    for (i, label) in labels.iter().enumerate() {
        eprintln!("{:3}  {label}", i + 1);
    }
    eprint!("{prompt} [1-{}]: ", labels.len());
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    let n: usize = line.trim().parse().map_err(|_| "nothing chosen")?;
    if (1..=labels.len()).contains(&n) { Ok(n - 1) } else { Err("nothing chosen".into()) }
}

// ---------- router ----------

fn password_for(device: &Device) -> Result<(String, bool), String> {
    if let Ok(password) = std::env::var("MTCAP_PASSWORD") {
        return Ok((password, false));
    }
    if let Some(password) = secret::lookup(&device.name) {
        return Ok((password, true));
    }
    if !interactive() {
        return Err(format!("no stored password for {}: run mtcap in a terminal once, or set MTCAP_PASSWORD", device.name));
    }
    Ok((secret::prompt(&format!("password for {}@{}: ", device.user, device.host))?, false))
}

fn connect(device: &Device, password: &str) -> Result<Api, String> {
    let mut api = Api::connect(&device.host, device.port)?;
    api.login(&device.user, password).map_err(|e| format!("login to {} failed: {e}", device.name))?;
    Ok(api)
}

/// Connects, asking for the password when needed and offering to remember it.
fn open(device: &Device) -> Result<(Api, String), String> {
    let (password, stored) = password_for(device)?;
    let api = connect(device, &password).map_err(|e| {
        if stored { format!("{e} (the stored password was used; `mtcap forget {}` removes it)", device.name) } else { e }
    })?;
    if !stored && std::env::var_os("MTCAP_PASSWORD").is_none() && on_path("secret-tool")
        && secret::ask_yes("remember this password in the keyring?")
        && !secret::store(&device.name, &password)
    {
        eprintln!("mtcap: the keyring did not take it; the password will be asked again");
    }
    Ok((api, password))
}

fn sniffer(api: &mut Api) -> Result<Row, String> {
    api.run(&["/tool/sniffer/print"])?.into_iter().next().ok_or_else(|| "the router returned no sniffer settings".into())
}

fn sniffer_set(api: &mut Api, changes: &BTreeMap<String, String>) -> Result<(), String> {
    if changes.is_empty() {
        return Ok(());
    }
    // RouterOS prints lists with ";" but takes them with ","
    let words: Vec<String> = changes.iter()
        .map(|(k, v)| if k.starts_with("filter-") { format!("={k}={}", v.replace(';', ",")) } else { format!("={k}={v}") })
        .collect();
    let mut sentence = vec!["/tool/sniffer/set"];
    sentence.extend(words.iter().map(String::as_str));
    api.run(&sentence).map(|_| ())
}

fn same(a: &str, b: &str) -> bool {
    let norm = |v: &str| match v {
        "true" => "yes".to_string(),
        "false" => "no".to_string(),
        other => other.replace(';', ","),
    };
    norm(a) == norm(b)
}

/// The sniffer settings to change for this capture, and remarks for the user.
///
/// How RouterOS combines filters: several values of one property mean "any of them"
/// (`filter-operator-between-entries=or`), and different properties narrow each other.
/// So the preset and the command line simply add up; a command-line value replaces the
/// preset's value of the same property. With no filter at all only headers are streamed.
fn plan(current: &Row, preset: &Preset, opts: &Opts, target: Ipv4Addr) -> (BTreeMap<String, String>, Vec<String>) {
    let mut notes = Vec::new();
    let mut entries: BTreeMap<String, String> = preset.router.clone();
    for (key, value) in [("filter-interface", &opts.interface), ("filter-ip-address", &opts.ip),
                         ("filter-port", &opts.port), ("filter-ip-protocol", &opts.proto)] {
        if let Some(value) = value {
            entries.insert(key.to_string(), value.clone());
        }
    }
    // an interface alone still means every packet on it
    let unfiltered = !entries.iter().any(|(k, v)| k.starts_with("filter-") && k != "filter-interface" && !v.is_empty());
    let headers = !opts.full && (opts.headers || unfiltered);
    if unfiltered && headers {
        notes.push("nothing narrows the capture: headers only (--full for whole packets; a preset, --ip or --port to narrow)".to_string());
    } else if unfiltered {
        notes.push("nothing narrows the capture and --full is set: the router streams every packet whole".to_string());
    }

    let mut want: BTreeMap<String, String> = BTreeMap::new();
    // start from a clean slate: whatever filters were left on the router would hide packets
    for key in current.keys().filter(|k| k.starts_with("filter-")) {
        let neutral = match key.as_str() {
            "filter-direction" => "any",
            "filter-operator-between-entries" => "or",
            _ => "",
        };
        want.insert(key.clone(), neutral.to_string());
    }
    for (key, value) in &entries {
        if !current.contains_key(key) {
            notes.push(format!("this RouterOS has no sniffer property {key}; skipped"));
        }
        want.insert(key.clone(), value.clone());
    }
    // RouterOS 7 takes address:port, RouterOS 6 only an address
    let with_port = current.get("streaming-server").is_some_and(|s| s.contains(':'));
    let server = if with_port { format!("{target}:{}", capture::TZSP_PORT) } else { target.to_string() };
    want.insert("streaming-enabled".into(), "yes".into());
    want.insert("streaming-server".into(), server);
    want.insert("filter-stream".into(), "yes".into()); // do not capture the stream itself
    want.insert("only-headers".into(), if headers { "yes" } else { "no" }.into());
    want.insert("file-name".into(), String::new());
    want.retain(|key, value| current.get(key).is_some_and(|now| !same(now, value)));
    (want, notes)
}

// ---------- guards on the router ----------

const WATCHDOG: &str = "mtcap-watchdog";
/// Runs every 30 s and counts the comment down; mtcap keeps setting it back. At zero the
/// capture is orphaned: stop the sniffer, switch streaming off, remove the scheduler.
const WATCHDOG_SCRIPT: &str = ":local c [:tonum [/system scheduler get [find name=\"mtcap-watchdog\"] comment]]; \
:if ($c > 0) do={/system scheduler set [find name=\"mtcap-watchdog\"] comment=($c - 1)} \
else={/tool sniffer stop; /tool sniffer set streaming-enabled=no; /system scheduler remove [find name=\"mtcap-watchdog\"]}";
const WATCHDOG_LIVES: &str = "4";

fn watchdog_id(api: &mut Api) -> Option<String> {
    let rows = api.run(&["/system/scheduler/print", "=.proplist=.id", &format!("?name={WATCHDOG}")]).ok()?;
    rows.into_iter().find_map(|r| r.get(".id").cloned())
}

fn watchdog_remove(api: &mut Api) {
    while let Some(id) = watchdog_id(api) {
        if api.run(&["/system/scheduler/remove", &format!("=.id={id}")]).is_err() {
            break;
        }
    }
}

fn watchdog_arm(api: &mut Api) -> Result<(), String> {
    watchdog_remove(api);
    api.run(&["/system/scheduler/add", &format!("=name={WATCHDOG}"), "=interval=30s",
              &format!("=comment={WATCHDOG_LIVES}"), "=policy=read,write,sniff,test",
              &format!("=on-event={WATCHDOG_SCRIPT}")]).map(|_| ())
}

fn cpu_load(api: &mut Api) -> Option<u32> {
    let rows = api.run(&["/system/resource/print", "=.proplist=cpu-load"]).ok()?;
    rows.first()?.get("cpu-load")?.parse().ok()
}

/// What the capture loop asks of the far end.
trait Hooks {
    /// Everything local is ready: make the router send.
    fn start(&mut self) -> Result<(), String>;
    /// Called every `TICK`; an error ends the capture.
    fn tick(&mut self) -> Result<(), String>;
}

struct Idle;

impl Hooks for Idle {
    fn start(&mut self) -> Result<(), String> {
        Ok(())
    }
    fn tick(&mut self) -> Result<(), String> {
        Ok(())
    }
}

struct Router<'a> {
    api: &'a mut Api,
    changes: &'a BTreeMap<String, String>,
    watchdog: bool,
    hot: u32,
}

impl Hooks for Router<'_> {
    fn start(&mut self) -> Result<(), String> {
        let _ = self.api.run(&["/tool/sniffer/stop"]);
        sniffer_set(self.api, self.changes)?;
        match watchdog_arm(self.api) {
            Ok(()) => self.watchdog = true,
            Err(e) => eprintln!("mtcap: no watchdog on the router ({e}); if this computer dies, run mtcap stop later"),
        }
        self.api.run(&["/tool/sniffer/start"]).map(|_| ())
    }

    fn tick(&mut self) -> Result<(), String> {
        if self.watchdog {
            let id = watchdog_id(self.api).ok_or("the watchdog on the router fired or was removed; the sniffer is stopped")?;
            self.api.run(&["/system/scheduler/set", &format!("=.id={id}"), &format!("=comment={WATCHDOG_LIVES}")])?;
        }
        match cpu_load(self.api) {
            Some(load) if load >= CPU_RUN_LIMIT => self.hot += 1,
            _ => self.hot = 0,
        }
        if self.hot >= 2 {
            return Err(format!("the router's CPU stays above {CPU_RUN_LIMIT}%: capture stopped to spare it"));
        }
        Ok(())
    }
}

fn state_file(device: &str) -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
    home.join(".local").join("state").join("mtcap").join(format!("{device}.json"))
}

fn save_state(device: &str, saved: &BTreeMap<String, String>) -> Result<(), String> {
    let path = state_file(device);
    let text = serde_json::to_string_pretty(saved).map_err(|e| e.to_string())?;
    fs::create_dir_all(path.parent().unwrap_or(&path)).and_then(|_| fs::write(&path, text))
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

fn load_state(device: &str) -> Option<BTreeMap<String, String>> {
    serde_json::from_str(&fs::read_to_string(state_file(device)).ok()?).ok()
}

/// Stops the sniffer and puts the saved settings back, reconnecting if the session is gone.
fn restore(device: &Device, password: &str, api: Option<Api>, saved: &BTreeMap<String, String>) -> Result<(), String> {
    let attempt = |api: &mut Api| -> Result<(), String> {
        let _ = api.run(&["/tool/sniffer/stop"]);
        watchdog_remove(api);
        sniffer_set(api, saved)
    };
    if let Some(mut api) = api {
        if attempt(&mut api).is_ok() {
            let _ = fs::remove_file(state_file(&device.name));
            return Ok(());
        }
    }
    attempt(&mut connect(device, password)?)?;
    let _ = fs::remove_file(state_file(&device.name));
    Ok(())
}

// ---------- viewer ----------

fn resolve_view(opts: &Opts, saving: bool) -> Result<View, String> {
    let gui = std::env::var_os("WAYLAND_DISPLAY").is_some() || std::env::var_os("DISPLAY").is_some();
    let view = match opts.view {
        View::Auto if gui && on_path("wireshark") => View::Wireshark,
        View::Auto if on_path("tshark") => View::Tshark,
        View::Auto => View::None,
        chosen => chosen,
    };
    if view == View::None && !saving {
        return Err("nothing to do with the packets: neither a viewer nor a file".into());
    }
    Ok(view)
}

/// A Wireshark profile whose filter toolbar has one button per preset.
fn write_profile(presets: &[Preset]) -> bool {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
    let dir = home.join(".config").join("wireshark").join("profiles").join("mtcap");
    let quote = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    let mut text = String::from("# Generated by mtcap from its presets; rewritten at every start.\n");
    for p in presets.iter().filter(|p| !p.display.is_empty()) {
        text.push_str(&format!("\"TRUE\",\"{}\",\"{}\",\"{}\"\n", quote(&p.name), quote(&p.display), quote(&p.about)));
    }
    fs::create_dir_all(&dir).and_then(|_| fs::write(dir.join("dfilter_buttons"), text)).is_ok()
}

fn spawn_viewer(view: View, display: &str, presets: &[Preset]) -> Result<Option<Child>, String> {
    let mut cmd = match view {
        View::Wireshark => {
            let mut cmd = Command::new("wireshark");
            cmd.args(["-k", "-i", "-"]);
            if write_profile(presets) {
                cmd.args(["-C", "mtcap"]);
            }
            cmd.stdout(Stdio::null()).stderr(Stdio::null());
            cmd
        }
        View::Tshark => {
            let mut cmd = Command::new("tshark");
            cmd.args(["-Q", "-l", "-n", "-i", "-"]);
            // -Q also silences the packet lines unless they are asked for explicitly
            cmd.arg("-P");
            cmd
        }
        _ => return Ok(None),
    };
    if !display.is_empty() {
        cmd.args(["-Y", display]);
    }
    // own process group: Ctrl-C must reach us first, so that the viewer gets the last packets
    cmd.stdin(Stdio::piped()).process_group(0);
    cmd.spawn().map(Some).map_err(|e| format!("cannot start the viewer: {e}"))
}

fn human(bytes: u64) -> String {
    match bytes {
        0..=1023 => format!("{bytes} B"),
        1024..=1_048_575 => format!("{:.1} KiB", bytes as f64 / 1024.0),
        _ => format!("{:.1} MiB", bytes as f64 / 1_048_576.0),
    }
}

struct Stats {
    packets: u64,
    bytes: u64,
    seconds: u64,
}

/// Where this capture is saved: -w, or a named file in ~/captures unless --no-save.
fn save_path(opts: &Opts, label: &str) -> Option<PathBuf> {
    if let Some(path) = &opts.write {
        return Some(path.clone());
    }
    if opts.no_save {
        return None;
    }
    let stamp = Command::new("date").arg("+%Y%m%d-%H%M%S").output().ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default();
    Some(report::captures_dir().join(format!("{label}-{stamp}.pcap")))
}

/// Receives the stream from `source` and feeds the viewer and the file until stopped.
fn capture(source: Ipv4Addr, display: &str, opts: &Opts, presets: &[Preset], save: Option<&PathBuf>, hooks: &mut dyn Hooks) -> (Stats, Result<(), String>) {
    let mut stats = Stats { packets: 0, bytes: 0, seconds: 0 };
    let prepared = (|| {
        let view = resolve_view(opts, save.is_some())?;
        let interface = capture::interface_for(source)?;
        let (tx, rx) = channel();
        let mut receiver = capture::spawn(&interface, source, tx)?;
        std::thread::sleep(Duration::from_millis(400));
        if receiver.child.try_wait().ok().flatten().is_some() {
            let log = receiver.log.lock().unwrap().trim().to_string();
            return Err(format!("dumpcap could not capture on {interface}: {log}\n(is your user in the wireshark group?)"));
        }
        Ok((view, interface, rx, receiver))
    })();
    let (view, interface, rx, mut receiver) = match prepared {
        Ok(parts) => parts,
        Err(e) => return (stats, Err(e)),
    };

    let mut result = Ok(());
    let mut file = None;
    if let Some(path) = save {
        let created = fs::create_dir_all(path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(std::path::Path::new(".")))
            .and_then(|_| fs::File::create(path))
            .and_then(|mut f| f.write_all(&capture::pcap_header()).map(|_| f));
        match created {
            Ok(f) => file = Some(f),
            Err(e) => result = Err(format!("cannot write {}: {e}", path.display())),
        }
    }
    let mut viewer = None;
    if result.is_ok() {
        match spawn_viewer(view, display, presets) {
            Ok(child) => viewer = child,
            Err(e) => result = Err(e),
        }
    }
    let mut pipe = viewer.as_mut().and_then(|v| v.stdin.take());
    if let Some(p) = pipe.as_mut() {
        let _ = p.write_all(&capture::pcap_header());
    }
    if result.is_ok() {
        result = hooks.start();
    }

    let limit = match opts.seconds {
        None => Some(DEFAULT_SECONDS),
        Some(0) => None,
        Some(n) => Some(n),
    };
    let started = Instant::now();
    let mut shown = Instant::now();
    let mut ticked = Instant::now();
    let mut hinted = false;
    let quiet_terminal = view != View::Tshark && std::io::stderr().is_terminal();
    if result.is_ok() {
        let until = limit.map_or("until stopped".to_string(), |s| format!("for up to {s} s"));
        eprintln!("mtcap: capturing from {source} on {interface} {until}; Ctrl-C to stop");
    }
    while result.is_ok() && !STOP.load(Ordering::SeqCst) {
        if limit.is_some_and(|s| started.elapsed() >= Duration::from_secs(s)) {
            eprintln!("\nmtcap: time limit reached (-t changes it)");
            break;
        }
        if viewer.as_mut().is_some_and(|v| v.try_wait().ok().flatten().is_some()) {
            break; // the viewer was closed
        }
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(frame) => {
                stats.packets += 1;
                stats.bytes += u64::from(frame.orig);
                if let Some(f) = file.as_mut() {
                    if let Err(e) = capture::write_frame(f, &frame) {
                        result = Err(format!("writing the capture file failed: {e}"));
                    }
                }
                if let Some(p) = pipe.as_mut() {
                    if capture::write_frame(p, &frame).is_err() {
                        break; // the viewer stopped reading
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                let log = receiver.log.lock().unwrap().trim().to_string();
                result = Err(format!("dumpcap stopped: {log}"));
            }
        }
        if ticked.elapsed() >= TICK {
            ticked = Instant::now();
            if let Err(e) = hooks.tick() {
                result = Err(e);
            }
        }
        if quiet_terminal && shown.elapsed() >= Duration::from_secs(1) {
            eprint!("\r  {} packets, {}   ", stats.packets, human(stats.bytes));
            shown = Instant::now();
        }
        if !hinted && stats.packets == 0 && started.elapsed() >= Duration::from_secs(8) {
            hinted = true;
            eprintln!("\nmtcap: nothing yet. Either no traffic matches the filter, or it is fasttracked \
                       (the sniffer does not see fasttrack connections), or it is traffic between this computer \
                       and the router itself (hidden together with the stream), or the stream does not come from {source}.");
        }
    }

    let _ = receiver.child.kill();
    let _ = receiver.child.wait();
    drop(pipe); // end of capture for the viewer
    if view == View::Tshark {
        if let Some(mut v) = viewer {
            let _ = v.wait();
        }
    }
    if quiet_terminal {
        eprintln!();
    }
    stats.seconds = started.elapsed().as_secs();
    (stats, result)
}

/// Prints the totals; drops an empty file, or writes how the capture was made next to it.
fn finish(stats: &Stats, save: Option<&PathBuf>, note: serde_json::Value) {
    eprint!("mtcap: {} packets, {} in {} s", stats.packets, human(stats.bytes), stats.seconds);
    match save {
        Some(path) if stats.packets == 0 => {
            let _ = fs::remove_file(path);
            eprintln!(" (nothing to save)");
        }
        Some(path) => {
            let mut note = note;
            note["packets"] = stats.packets.into();
            note["bytes"] = stats.bytes.into();
            note["seconds"] = stats.seconds.into();
            let _ = fs::write(path.with_extension("json"), serde_json::to_string_pretty(&note).unwrap_or_default());
            eprintln!("\n       saved to {}\n       summary: mtcap report", path.display());
        }
        None => eprintln!(),
    }
}

fn ipv4(ip: Option<IpAddr>, what: &str) -> Result<Ipv4Addr, String> {
    match ip {
        Some(IpAddr::V4(ip)) => Ok(ip),
        _ => Err(format!("{what} is not an IPv4 address; set it in the config")),
    }
}

fn configured(value: &Option<String>, fallback: Option<IpAddr>, what: &str) -> Result<Ipv4Addr, String> {
    match value {
        Some(text) => text.parse().map_err(|_| format!("{what} in the config is not an IPv4 address: {text}")),
        None => ipv4(fallback, what),
    }
}

// ---------- commands ----------

fn pick_device<'a>(config: &'a Config, name: Option<&String>) -> Result<&'a Device, String> {
    if config.devices.is_empty() {
        return Err(format!("no devices yet: mtcap add <name> <host> <user>  (or edit {})", config::path().display()));
    }
    if let Some(name) = name {
        return config.device(name).ok_or_else(|| format!("no device {name}; see mtcap devices"));
    }
    let labels: Vec<String> = config.devices.iter().map(|d| format!("{:16} {}@{}", d.name, d.user, d.host)).collect();
    Ok(&config.devices[choose("device", &labels)?])
}

fn pick_preset<'a>(config: &'a Config, name: Option<&String>, ask: bool) -> Result<&'a Preset, String> {
    if let Some(name) = name {
        return config.preset(name).ok_or_else(|| format!("no preset {name}; see mtcap presets"));
    }
    if !ask {
        return config.preset("all").ok_or_else(|| "no preset all".to_string());
    }
    let labels: Vec<String> = config.presets.iter().map(|p| format!("{:14} {}", p.name, p.about)).collect();
    Ok(&config.presets[choose("filter", &labels)?])
}

fn pick_interface(api: &mut Api) -> Result<Option<String>, String> {
    let rows = api.run(&["/interface/print", "=.proplist=name,type,running"])?;
    let mut labels = vec!["(all interfaces)".to_string()];
    let names: Vec<&String> = rows.iter().filter_map(|r| r.get("name")).collect();
    for row in &rows {
        let get = |k: &str| row.get(k).map_or("", String::as_str);
        let state = if get("running") == "true" { "" } else { "  (down)" };
        labels.push(format!("{:24} {}{state}", get("name"), get("type")));
    }
    let i = choose("interface", &labels)?;
    Ok(if i == 0 { None } else { names.get(i - 1).map(|n| n.to_string()) })
}

fn cmd_capture(mut opts: Opts) -> Result<(), String> {
    let config = Config::load()?;
    let guided = opts.positional.is_empty();
    let device = pick_device(&config, opts.positional.first())?.clone();
    let preset = pick_preset(&config, opts.positional.get(1), guided)?.clone();
    let save = save_path(&opts, &format!("{}-{}", device.name, preset.name));
    resolve_view(&opts, save.is_some())?;
    let (mut api, password) = open(&device)?;

    if let Some(saved) = load_state(&device.name) {
        eprintln!("mtcap: the previous capture on {} was not closed cleanly; restoring the sniffer first", device.name);
        let _ = api.run(&["/tool/sniffer/stop"]);
        sniffer_set(&mut api, &saved)?;
        let _ = fs::remove_file(state_file(&device.name));
    }
    let current = sniffer(&mut api)?;
    if current.get("running").is_some_and(|r| r == "true") && !opts.force {
        return Err(format!("the sniffer on {} is already running; --force takes it over", device.name));
    }
    if let Some(load) = cpu_load(&mut api).filter(|load| *load >= CPU_START_LIMIT && !opts.force) {
        return Err(format!("the router's CPU is at {load}%; not adding a sniffer on top (--force to do it anyway)"));
    }
    if opts.interface.as_deref() == Some("?") || (guided && opts.interface.is_none()) {
        opts.interface = pick_interface(&mut api)?;
    }
    let target = configured(&device.stream_to, api.local_ip(), "this computer's address")?;
    let source = configured(&device.source, api.peer_ip(), "the router's address")?;

    let (changes, notes) = plan(&current, &preset, &opts, target);
    let saved: BTreeMap<String, String> =
        changes.keys().map(|k| (k.clone(), current.get(k).cloned().unwrap_or_default())).collect();
    save_state(&device.name, &saved)?;
    // the filter as the router will have it: what we set, plus what was already right
    let effective = |key: &str| changes.get(key).or_else(|| current.get(key)).cloned().unwrap_or_default();
    let mut filters: Vec<String> = current.keys()
        .filter(|k| k.starts_with("filter-") && !matches!(k.as_str(), "filter-stream" | "filter-direction" | "filter-operator-between-entries"))
        .map(|k| (k, effective(k))).filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| format!("{}={}", &k[7..], v.replace(';', ","))).collect();
    let headers = same(&effective("only-headers"), "yes");
    if filters.is_empty() {
        filters.push("everything".to_string());
    }
    let router_filter = filters.join(" and ");
    eprintln!("mtcap: {} → {target}, preset {}\n       router sends: {router_filter}{}", device.name, preset.name,
              if headers { ", headers only" } else { "" });
    for note in &notes {
        eprintln!("       note: {note}");
    }

    let (stats, result) = {
        let mut hooks = Router { api: &mut api, changes: &changes, watchdog: false, hot: 0 };
        capture(source, &preset.display, &opts, &config.presets, save.as_ref(), &mut hooks)
    };
    match restore(&device, &password, Some(api), &saved) {
        Ok(()) => eprintln!("mtcap: sniffer on {} stopped, settings restored", device.name),
        Err(e) => eprintln!("mtcap: COULD NOT RESTORE the sniffer on {}: {e}\n       run: mtcap stop {}", device.name, device.name),
    }
    finish(&stats, save.as_ref(), serde_json::json!({
        "device": device.name, "host": device.host, "preset": preset.name, "display": preset.display,
        "interface": opts.interface.clone().unwrap_or_else(|| "all".into()),
        "router_filter": router_filter, "headers_only": headers,
    }));
    result
}

fn cmd_listen(opts: Opts) -> Result<(), String> {
    let config = Config::load()?;
    let address = opts.positional.get(1).ok_or("usage: mtcap listen <ip> [preset]")?;
    let source: Ipv4Addr = address.parse().map_err(|_| "listen needs an IPv4 address")?;
    let preset = pick_preset(&config, opts.positional.get(2), false)?.clone();
    let save = save_path(&opts, &format!("listen-{address}"));
    let (stats, result) = capture(source, &preset.display, &opts, &config.presets, save.as_ref(), &mut Idle);
    finish(&stats, save.as_ref(), serde_json::json!({
        "device": address, "preset": preset.name, "display": preset.display,
        "interface": "-", "router_filter": "set by hand",
    }));
    result
}

fn cmd_stop(opts: Opts) -> Result<(), String> {
    let config = Config::load()?;
    let name = opts.positional.get(1).ok_or("usage: mtcap stop <device>")?;
    let device = config.device(name).ok_or_else(|| format!("no device {name}"))?.clone();
    let (api, password) = open(&device)?;
    let saved = load_state(&device.name).unwrap_or_else(|| BTreeMap::from([("streaming-enabled".to_string(), "no".to_string())]));
    restore(&device, &password, Some(api), &saved)?;
    println!("sniffer on {} stopped, {} settings restored", device.name, saved.len());
    Ok(())
}

fn run(opts: Opts) -> Result<(), String> {
    let arg = |i: usize| opts.positional.get(i).map(String::as_str);
    match arg(0) {
        Some("help") => println!("{HELP}"),
        Some("devices") => {
            for d in Config::load()?.devices {
                println!("{:16} {}@{}:{}", d.name, d.user, d.host, d.port);
            }
        }
        Some("presets") => {
            for p in Config::load()?.presets {
                let router: Vec<String> = p.router.iter().map(|(k, v)| format!("{k}={v}")).collect();
                println!("{:14} {}\n{:14}   view:   {}\n{:14}   router: {}", p.name, p.about, "",
                         if p.display.is_empty() { "everything" } else { &p.display }, "",
                         if router.is_empty() { "everything, headers only".to_string() } else { router.join(" and ") });
            }
        }
        Some("add") => {
            let (Some(name), Some(host), Some(user)) = (arg(1), arg(2), arg(3)) else {
                return Err("usage: mtcap add <name> <host> <user> [port]".into());
            };
            let port = match arg(4) {
                Some(p) => p.parse().map_err(|_| "the port must be a number")?,
                None => 8728,
            };
            config::add_device(name, host, user, port)?;
            println!("added {name}; the password is asked at the first capture");
        }
        Some("forget") => {
            secret::forget(arg(1).ok_or("usage: mtcap forget <device>")?);
            println!("forgotten");
        }
        Some("stop") => return cmd_stop(opts),
        Some("report") => return report::run(arg(1)),
        Some("listen") => return cmd_listen(opts),
        _ => return cmd_capture(opts),
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{HELP}");
        return;
    }
    // SIGINT, SIGTERM, SIGHUP: finish the loop and restore the router
    for sig in [2, 15, 1] {
        unsafe { signal(sig, on_signal) };
    }
    if let Err(e) = parse_args(args).and_then(run) {
        eprintln!("mtcap: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn current() -> Row {
        [("running", "false"), ("streaming-enabled", "false"), ("streaming-server", "0.0.0.0:37008"),
         ("filter-stream", "false"), ("file-name", ""), ("filter-dst-port", "53"), ("filter-port", ""),
         ("filter-interface", ""), ("filter-ip-address", ""), ("filter-ip-protocol", ""),
         ("filter-direction", "any"), ("filter-operator-between-entries", "or"), ("memory-limit", "100KiB"),
         ("only-headers", "false")]
            .iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn opts(args: &[&str]) -> Opts {
        parse_args(args.iter().map(|s| s.to_string()).collect()).unwrap()
    }

    fn preset(router: &[(&str, &str)]) -> Preset {
        Preset { name: "p".into(), about: String::new(), display: String::new(),
                 router: router.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect() }
    }

    fn planned(preset: &Preset, args: &[&str]) -> BTreeMap<String, String> {
        plan(&current(), preset, &opts(args), "192.0.2.10".parse().unwrap()).0
    }

    #[test]
    fn plan_clears_leftovers_and_enables_streaming() {
        let changes = planned(&preset(&[]), &[]);
        assert_eq!(changes["streaming-enabled"], "yes");
        assert_eq!(changes["streaming-server"], "192.0.2.10:37008");
        assert_eq!(changes["filter-stream"], "yes");
        assert_eq!(changes["filter-dst-port"], ""); // a filter left on the router is cleared
        assert_eq!(changes["only-headers"], "yes"); // nothing narrows it: headers only
        assert!(!changes.contains_key("filter-port")); // already empty: untouched
        assert!(!changes.contains_key("memory-limit"));
        assert!(!changes.contains_key("file-name"));
        assert!(!planned(&preset(&[]), &["--full"]).contains_key("only-headers")); // already off
    }

    #[test]
    fn command_line_adds_to_the_preset() {
        let web = preset(&[("filter-port", "80,443,53")]);
        let narrowed = planned(&web, &["--ip", "192.0.2.50", "-i", "bridge"]);
        assert_eq!(narrowed["filter-port"], "80,443,53");
        assert_eq!(narrowed["filter-ip-address"], "192.0.2.50");
        assert_eq!(narrowed["filter-interface"], "bridge");
        assert!(!narrowed.contains_key("only-headers")); // narrowed: whole packets, as the router has it
        assert_eq!(planned(&web, &["--port", "8443"])["filter-port"], "8443"); // replaces the preset's ports
    }

    #[test]
    fn an_interface_alone_is_still_everything() {
        let (changes, notes) = plan(&current(), &preset(&[]), &opts(&["-i", "ether1"]), "192.0.2.10".parse().unwrap());
        assert_eq!(changes["filter-interface"], "ether1");
        assert_eq!(changes["only-headers"], "yes");
        assert_eq!(notes.len(), 1);
    }

    #[test]
    fn a_stray_operator_is_reset() {
        let mut strict = current();
        strict.insert("filter-operator-between-entries".into(), "and".into());
        let changes = plan(&strict, &preset(&[("filter-port", "53")]), &opts(&[]), "192.0.2.10".parse().unwrap()).0;
        assert_eq!(changes["filter-operator-between-entries"], "or"); // lists must mean "any of"
    }

    #[test]
    fn watchdog_script_is_one_line() {
        assert_eq!(WATCHDOG_SCRIPT, ":local c [:tonum [/system scheduler get [find name=\"mtcap-watchdog\"] comment]]; :if ($c > 0) do={/system scheduler set [find name=\"mtcap-watchdog\"] comment=($c - 1)} else={/tool sniffer stop; /tool sniffer set streaming-enabled=no; /system scheduler remove [find name=\"mtcap-watchdog\"]}");
    }

    #[test]
    fn routeros6_gets_a_bare_address() {
        let mut old = current();
        old.insert("streaming-server".into(), "0.0.0.0".into());
        let changes = plan(&old, &preset(&[]), &opts(&[]), "192.0.2.10".parse().unwrap()).0;
        assert_eq!(changes["streaming-server"], "192.0.2.10");
    }

    #[test]
    fn lists_compare_regardless_of_separator() {
        assert!(same("http;https", "http,https") && same("true", "yes") && !same("53", "54"));
    }

    #[test]
    fn options() {
        let o = opts(&["home", "dns", "-w", "x.pcap", "-t", "30", "--tshark", "--force"]);
        assert_eq!(o.positional, ["home", "dns"]);
        assert_eq!(o.seconds, Some(30));
        assert!(o.view == View::Tshark && o.force);
        assert!(parse_args(vec!["--bogus".into()]).is_err());
        assert!(parse_args(vec!["-t".into()]).is_err());
    }
}
