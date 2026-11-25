//! `mtcap report`: a top-down summary of a capture file, computed with tshark.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

fn fields(file: &Path, filter: &str, names: &[&str]) -> Result<Vec<Vec<String>>, String> {
    let mut cmd = Command::new("tshark");
    cmd.arg("-n").arg("-r").arg(file).args(["-T", "fields", "-E", "occurrence=f"]);
    if !filter.is_empty() {
        cmd.args(["-Y", filter]);
    }
    for name in names {
        cmd.args(["-e", name]);
    }
    let out = cmd.output().map_err(|e| format!("cannot run tshark: {e}"))?;
    if !out.status.success() && out.stdout.is_empty() {
        return Err(format!("tshark: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|line| {
            let mut row: Vec<String> = line.split('\t').map(String::from).collect();
            row.resize(names.len(), String::new());
            row
        })
        .collect())
}

fn set(value: &str) -> bool {
    !matches!(value, "" | "0" | "False" | "false")
}

fn human(bytes: u64) -> String {
    match bytes {
        0..=1023 => format!("{bytes} B"),
        1024..=1_048_575 => format!("{:.1} KiB", bytes as f64 / 1024.0),
        _ => format!("{:.1} MiB", bytes as f64 / 1_048_576.0),
    }
}

/// The most frequent keys, largest first.
fn top<K: std::hash::Hash + Eq + Ord + Clone>(counts: &HashMap<K, u64>, n: usize) -> Vec<(K, u64)> {
    let mut list: Vec<(K, u64)> = counts.iter().map(|(k, v)| (k.clone(), *v)).collect();
    list.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    list.truncate(n);
    list
}

fn percent(part: u64, whole: u64) -> f64 {
    if whole == 0 { 0.0 } else { part as f64 * 100.0 / whole as f64 }
}

pub fn captures_dir() -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
    home.join("captures")
}

pub fn latest() -> Result<PathBuf, String> {
    let dir = captures_dir();
    let mut files: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(&dir)
        .map_err(|_| format!("no captures in {}", dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "pcap"))
        .filter_map(|p| Some((p.metadata().ok()?.modified().ok()?, p)))
        .collect();
    files.sort();
    files.pop().map(|(_, p)| p).ok_or_else(|| format!("no captures in {}", dir.display()))
}

pub fn run(file: Option<&str>) -> Result<(), String> {
    let file = match file {
        Some(f) => PathBuf::from(f),
        None => latest()?,
    };
    if !file.exists() {
        return Err(format!("no such file: {}", file.display()));
    }
    let mut findings: Vec<String> = Vec::new();
    println!("{}", file.display());

    // how it was captured, if mtcap left a note next to the file
    let note: Option<serde_json::Value> =
        std::fs::read_to_string(file.with_extension("json")).ok().and_then(|t| serde_json::from_str(&t).ok());
    if let Some(note) = &note {
        let text = |key: &str| note[key].as_str().unwrap_or("-").to_string();
        println!("  device {}, preset {}, interface {}, router filter: {}{}",
                 text("device"), text("preset"), text("interface"), text("router_filter"),
                 if note["headers_only"].as_bool() == Some(true) { ", headers only" } else { "" });
    }

    // ---- overview, protocols, talkers: one pass
    let rows = fields(&file, "", &["frame.time_epoch", "frame.len", "frame.protocols", "ip.src", "ip.dst", "ip.id"])?;
    if rows.is_empty() {
        println!("\nno packets");
        return Ok(());
    }
    let times: Vec<f64> = rows.iter().filter_map(|r| r[0].parse().ok()).collect();
    let duration = times.iter().cloned().fold(f64::MIN, f64::max) - times.iter().cloned().fold(f64::MAX, f64::min);
    let bytes: u64 = rows.iter().filter_map(|r| r[1].parse::<u64>().ok()).sum();
    let total = rows.len() as u64;
    println!("\nOVERVIEW\n  {total} packets, {} on the wire, {:.1} s, {:.0} packets/s",
             human(bytes), duration.max(0.0), if duration > 0.0 { total as f64 / duration } else { total as f64 });

    let mut protocols: HashMap<String, u64> = HashMap::new();
    let mut pairs: HashMap<(String, String), (u64, u64)> = HashMap::new();
    let mut seen: HashMap<(String, String, String, String), u64> = HashMap::new();
    let mut ip_packets = 0u64;
    for r in &rows {
        let last = r[2].rsplit(':').find(|p| *p != "data").unwrap_or("?");
        *protocols.entry(last.to_string()).or_default() += 1;
        if !r[3].is_empty() && !r[4].is_empty() {
            ip_packets += 1;
            let (a, b) = if r[3] <= r[4] { (&r[3], &r[4]) } else { (&r[4], &r[3]) };
            let pair = pairs.entry((a.clone(), b.clone())).or_default();
            pair.0 += 1;
            pair.1 += r[1].parse::<u64>().unwrap_or(0);
            *seen.entry((r[3].clone(), r[4].clone(), r[5].clone(), r[1].clone())).or_default() += 1;
        }
    }
    println!("\nPROTOCOLS");
    for (name, count) in top(&protocols, 10) {
        println!("  {name:14} {count:>8}  {:5.1}%", percent(count, total));
    }
    println!("\nTOP CONVERSATIONS");
    let mut list: Vec<(&(String, String), &(u64, u64))> = pairs.iter().collect();
    list.sort_by(|a, b| b.1 .1.cmp(&a.1 .1).then(a.0.cmp(b.0)));
    let shown: Vec<_> = list.into_iter().take(8).collect();
    let ends: Vec<String> = shown.iter().flat_map(|((a, b), _)| [a.clone(), b.clone()]).collect();
    let places = crate::geo::lookup(&ends);
    for ((a, b), (count, size)) in shown {
        let place = places.get(b).or_else(|| places.get(a)).map_or("", String::as_str);
        println!("  {a:>15} ↔ {b:<15} {count:>7} packets  {:>10}  {place}", human(*size));
    }
    let repeats: u64 = seen.values().filter(|n| **n > 1).map(|n| n - 1).sum();
    let duplicated = ip_packets > 20 && percent(repeats, ip_packets) > 25.0;
    if duplicated {
        findings.push(format!(
            "{:.0}% of the packets are copies of one another: the capture saw them on several interfaces \
             (bridge and its port). Capture with -i; the TCP figures below are inflated by this.",
            percent(repeats, ip_packets)));
    }

    // ---- TCP health
    let tcp = fields(&file, "tcp", &["tcp.stream", "tcp.analysis.retransmission", "tcp.analysis.fast_retransmission",
                                    "tcp.analysis.zero_window", "tcp.flags.reset", "ip.src", "ip.dst", "tcp.srcport"])?;
    if !tcp.is_empty() {
        let n = tcp.len() as u64;
        let count = |i: usize| tcp.iter().filter(|r| set(&r[i])).count() as u64;
        let streams = tcp.iter().map(|r| r[0].as_str()).collect::<std::collections::HashSet<_>>().len();
        let retransmitted = count(1) + count(2);
        let (zero, resets) = (count(3), count(4));
        println!("\nTCP\n  {n} packets in {streams} connections\n  retransmissions {retransmitted} ({:.2}%), zero windows {zero}, resets {resets}",
                 percent(retransmitted, n));
        let mut by_sender: HashMap<String, u64> = HashMap::new();
        for r in tcp.iter().filter(|r| set(&r[4])) {
            *by_sender.entry(format!("{}:{} → {}", r[5], r[7], r[6])).or_default() += 1;
        }
        for (who, count) in top(&by_sender, 5) {
            println!("    reset {count:>4}×  {who}");
        }
        if !duplicated && n >= 200 && percent(retransmitted, n) > 2.0 {
            findings.push(format!("{:.1}% of TCP packets are retransmissions: packets are being lost or badly delayed.", percent(retransmitted, n)));
        }
        if zero > 0 {
            findings.push(format!("{zero} zero-window packets: a receiver cannot keep up, the sender is being held back."));
        }
        if resets > 0 && percent(resets, n) > 1.0 {
            findings.push(format!("{resets} resets: connections are refused or cut; see who sends them above."));
        }
    }

    // ---- DNS
    let dns = fields(&file, "dns.flags.response == 1", &["dns.time", "dns.flags.rcode", "dns.qry.name"])?;
    if !dns.is_empty() {
        let mut delays: Vec<(f64, &str)> = dns.iter().filter_map(|r| Some((r[0].parse().ok()?, r[2].as_str()))).collect();
        delays.sort_by(|a, b| a.0.total_cmp(&b.0));
        let failed: Vec<&Vec<String>> = dns.iter().filter(|r| set(&r[1])).collect();
        print!("\nDNS\n  {} answers, {} failed", dns.len(), failed.len());
        if let Some((median, _)) = delays.get(delays.len() / 2) {
            print!(", median {:.0} ms, slowest {:.0} ms", median * 1000.0, delays.last().map_or(0.0, |d| d.0) * 1000.0);
        }
        println!();
        for (delay, name) in delays.iter().rev().take(3).filter(|(d, _)| *d > 0.2) {
            println!("    slow   {:>5.0} ms  {name}", delay * 1000.0);
        }
        let mut names: HashMap<String, u64> = HashMap::new();
        for r in &failed {
            *names.entry(format!("{} (rcode {})", r[2], r[1])).or_default() += 1;
        }
        for (name, count) in top(&names, 5) {
            println!("    failed {count:>4}×  {name}");
        }
        let slow = delays.iter().filter(|(d, _)| *d > 0.5).count();
        if slow > 0 {
            findings.push(format!("{slow} DNS answers took longer than 0.5 s: slow name resolution feels like a slow network."));
        }
        if failed.len() * 5 > dns.len() && failed.len() > 3 {
            findings.push(format!("{} of {} DNS answers are errors.", failed.len(), dns.len()));
        }
    }

    // ---- ICMP errors
    let icmp = fields(&file, "icmp.type == 3 || icmp.type == 11 || icmp.type == 5", &["ip.src", "icmp.type", "icmp.code"])?;
    if !icmp.is_empty() {
        println!("\nICMP ERRORS");
        let mut kinds: HashMap<String, u64> = HashMap::new();
        for r in &icmp {
            let what = match (r[1].as_str(), r[2].as_str()) {
                ("3", "0") => "network unreachable",
                ("3", "1") => "host unreachable",
                ("3", "3") => "port unreachable",
                ("3", "4") => "fragmentation needed (MTU)",
                ("3", "13") => "administratively prohibited",
                ("3", _) => "destination unreachable",
                ("11", _) => "TTL exceeded",
                _ => "redirect",
            };
            *kinds.entry(format!("{what} from {}", r[0])).or_default() += 1;
        }
        for (what, count) in top(&kinds, 6) {
            println!("  {count:>5}×  {what}");
        }
        if icmp.iter().any(|r| r[1] == "3" && r[2] == "4") {
            findings.push("\"fragmentation needed\" is being sent: an MTU problem on the path (typical for tunnels); check MSS clamping.".into());
        }
    }

    println!("\nFINDINGS");
    if findings.is_empty() {
        println!("  nothing stands out");
    }
    for finding in findings {
        println!("  • {finding}");
    }
    Ok(())
}
