//! The terminal view: tshark dissects, mtcap lays the lines out.
//!
//! One line fits the terminal: aligned columns, host names instead of addresses, colour by
//! protocol, trouble in red. A DNS question and its answer make one line; a line that repeats
//! the previous one is counted instead of printed again.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::Command;
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::time::{Duration, Instant};

/// tshark fields, in the order `Printer::feed` expects them.
pub const FIELDS: &[&str] = &[
    "frame.time_epoch", "_ws.col.def_src", "_ws.col.def_dst", "_ws.col.protocol", "frame.len",
    "dns.flags.response", "dns.flags.rcode", "dns.qry.type", "dns.qry.name", "dns.a", "dns.aaaa",
    "dns.cname", "dns.time", "tcp.flags.reset", "tcp.analysis.retransmission", "_ws.col.info", "dns.id",
    "ip.geoip.src_country_iso", "ip.geoip.src_org", "ip.geoip.dst_country_iso", "ip.geoip.dst_org",
];

/// A DNS question waits this long for its answer before it is shown as unanswered.
const ANSWER_WAIT: Duration = Duration::from_secs(3);
const HOST_WIDTH: usize = 15;
const PLACE_WIDTH: usize = 20;

#[derive(Clone, Copy, PartialEq)]
enum Paint {
    Plain,
    Dim,
    Red,
    Green,
    Yellow,
    Blue,
    Magenta,
    Cyan,
    Bold,
    BoldGreen,
}

impl Paint {
    fn code(self) -> &'static str {
        match self {
            Paint::Plain => "",
            Paint::Dim => "\x1b[2m",
            Paint::Red => "\x1b[31m",
            Paint::Green => "\x1b[32m",
            Paint::Yellow => "\x1b[33m",
            Paint::Blue => "\x1b[34m",
            Paint::Magenta => "\x1b[35m",
            Paint::Cyan => "\x1b[36m",
            Paint::Bold => "\x1b[1m",
            Paint::BoldGreen => "\x1b[1;32m",
        }
    }
}

type Parts = Vec<(String, Paint)>;

pub struct Layout {
    pub width: usize,
    pub color: bool,
    /// Local time offset from UTC, seconds.
    pub offset: i64,
    /// Address → name shown instead of it.
    pub names: HashMap<String, String>,
    /// Country and owner databases are there: show the "where" column.
    pub geo: bool,
    /// Follow the terminal as it is resized, instead of keeping `width`.
    pub follow: bool,
    /// Do not cut long lines.
    pub wide: bool,
}

/// The terminal's width right now.
fn terminal_width() -> Option<usize> {
    #[repr(C)]
    struct Size {
        rows: u16,
        cols: u16,
        x: u16,
        y: u16,
    }
    extern "C" {
        fn ioctl(fd: i32, request: std::ffi::c_ulong, ...) -> i32;
    }
    const TIOCGWINSZ: std::ffi::c_ulong = 0x5413;
    let mut size = Size { rows: 0, cols: 0, x: 0, y: 0 };
    // SAFETY: TIOCGWINSZ fills a winsize structure, which `Size` mirrors.
    let ok = unsafe { ioctl(1, TIOCGWINSZ, &mut size as *mut Size) } == 0;
    (ok && size.cols > 0).then_some(size.cols as usize)
}

fn local(address: &str) -> bool {
    match address.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(a)) => a.is_private() || a.is_link_local() || a.is_loopback(),
        Ok(std::net::IpAddr::V6(a)) => a.segments()[0] & 0xfe00 == 0xfc00 || a.segments()[0] & 0xffc0 == 0xfe80,
        Err(_) => false,
    }
}

fn group(address: &str) -> bool {
    match address.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(a)) => a.is_multicast() || a.is_broadcast() || a.octets()[3] == 255,
        Ok(std::net::IpAddr::V6(a)) => a.is_multicast(),
        Err(_) => false,
    }
}

/// tshark's summary of a packet, without the parts nobody reads, and its colour.
fn summary(protocol: &str, info: &str, trouble: bool) -> Parts {
    let mut text = String::new();
    for word in info.split(' ') {
        if !["TSval=", "TSecr=", "WS=", "MSS=", "SACK_PERM"].iter().any(|skip| word.starts_with(skip)) {
            if !text.is_empty() {
                text.push(' ');
            }
            text.push_str(word);
        }
    }
    if trouble {
        return vec![(text, Paint::Red)];
    }
    // the site name is what one looks for in a TLS hello
    if let Some((before, rest)) = text.split_once("(SNI=") {
        if let Some((name, after)) = rest.split_once(')') {
            return vec![(format!("{before}→ "), Paint::Plain), (name.to_string(), Paint::BoldGreen), (after.to_string(), Paint::Dim)];
        }
    }
    let paint = if protocol == "TCP" {
        if text.contains("[SYN") {
            Paint::Green
        } else if text.contains("[FIN") {
            Paint::Yellow
        } else if text.contains("Len=0") || text.contains("Keep-Alive") {
            Paint::Dim // bare acknowledgements: the bulk of any capture, and the least telling
        } else {
            Paint::Plain
        }
    } else if protocol.starts_with("HTTP") && (text.starts_with("GET ") || text.starts_with("POST ") || text.starts_with("PUT ")) {
        Paint::Bold
    } else if text == "Application Data" || text.starts_with("Protected Payload") || text.starts_with("Continuation") {
        Paint::Dim
    } else {
        Paint::Plain
    };
    vec![(text, paint)]
}

impl Layout {
    /// Terminal width and time zone of the current session.
    pub fn detect(color: bool, names: HashMap<String, String>, geo: bool, wide: bool) -> Layout {
        let run = |program: &str, args: &[&str]| {
            let out = Command::new(program).args(args).stdin(std::process::Stdio::inherit()).output().ok()?;
            out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
        };
        let width = run("stty", &["size"])
            .and_then(|s| s.split_whitespace().nth(1)?.parse().ok())
            .or_else(|| std::env::var("COLUMNS").ok()?.parse().ok())
            .unwrap_or(120);
        // "+0300" -> 10800
        let offset = run("date", &["+%z"])
            .and_then(|z| {
                let hours: i64 = z.get(1..3)?.parse().ok()?;
                let minutes: i64 = z.get(3..5)?.parse().ok()?;
                Some((hours * 3600 + minutes * 60) * if z.starts_with('-') { -1 } else { 1 })
            })
            .unwrap_or(0);
        Layout { width, color, offset, names, geo, follow: true, wide }
    }

    fn render(&self, parts: &[(String, Paint)]) -> String {
        let mut out = String::new();
        let mut room = if self.wide {
            usize::MAX
        } else if self.follow {
            terminal_width().unwrap_or(self.width)
        } else {
            self.width
        };
        for (text, paint) in parts {
            if room == 0 {
                break;
            }
            let len = text.chars().count();
            let shown: String = if len <= room {
                text.clone()
            } else {
                text.chars().take(room.saturating_sub(1)).chain(std::iter::once('…')).collect()
            };
            room = room.saturating_sub(len);
            if self.color && *paint != Paint::Plain {
                out.push_str(paint.code());
                out.push_str(&shown);
                out.push_str("\x1b[0m");
            } else {
                out.push_str(&shown);
            }
        }
        out
    }

    fn clock(&self, epoch: &str) -> String {
        let (seconds, fraction) = epoch.split_once('.').unwrap_or((epoch, "0"));
        let local = seconds.parse::<i64>().unwrap_or(0) + self.offset;
        let day = local.rem_euclid(86_400);
        format!("{:02}:{:02}:{:02}.{:.3}", day / 3600, day % 3600 / 60, day % 60, format!("{fraction:0<3}"))
    }

    fn host(&self, address: &str) -> String {
        let name = self.names.get(address).map_or(address, String::as_str);
        if name.chars().count() <= HOST_WIDTH {
            name.to_string()
        } else {
            name.chars().take(HOST_WIDTH - 1).chain(std::iter::once('…')).collect()
        }
    }

    /// This network's hosts stand out; group addresses fade.
    fn host_paint(&self, address: &str) -> Paint {
        if group(address) {
            Paint::Dim
        } else if self.names.contains_key(address) || local(address) {
            Paint::Blue
        } else {
            Paint::Plain
        }
    }

    fn header(&self) -> String {
        let place = if self.geo { format!("{:<PLACE_WIDTH$} ", "where") } else { String::new() };
        self.render(&[(format!("{:12}  {:>15}   {:<15}  {:<7} {place}{}", "time", "source", "destination", "proto", "what"), Paint::Dim)])
    }

    /// Time, source → destination, protocol: the start of every line.
    fn head(&self, time: &str, source: &str, destination: &str, protocol: &str, place: &str) -> Parts {
        let paint = match protocol {
            "DNS" | "MDNS" | "LLMNR" => Paint::Cyan,
            "ARP" => Paint::Magenta,
            "DHCP" | "DHCPv6" => Paint::Blue,
            "ICMP" | "ICMPv6" => Paint::Yellow,
            p if p.starts_with("TLS") || p.starts_with("HTTP") || p == "QUIC" => Paint::Green,
            _ => Paint::Plain,
        };
        let mut parts = vec![
            (time.to_string(), Paint::Dim),
            (format!("  {:>15} ", self.host(source)), self.host_paint(source)),
            ("→".to_string(), Paint::Dim),
            (format!(" {:<15}  ", self.host(destination)), self.host_paint(destination)),
            (format!("{protocol:<7} "), paint),
        ];
        if self.geo {
            let cut: String = if place.chars().count() <= PLACE_WIDTH {
                place.to_string()
            } else {
                place.chars().take(PLACE_WIDTH - 1).chain(std::iter::once('…')).collect()
            };
            parts.push((format!("{cut:<PLACE_WIDTH$} "), Paint::Magenta));
        }
        parts
    }
}

fn query_type(code: &str) -> String {
    match code {
        "1" => "A", "2" => "NS", "5" => "CNAME", "6" => "SOA", "12" => "PTR", "15" => "MX", "16" => "TXT",
        "28" => "AAAA", "33" => "SRV", "64" => "SVCB", "65" => "HTTPS", "255" => "ANY",
        other => return format!("#{other}"),
    }
    .to_string()
}

/// A DNS question whose answer has not come yet.
struct Question {
    key: String,
    since: Instant,
    time: String,
    source: String,
    destination: String,
    protocol: String,
    place: String,
    kind: String,
    name: String,
}

struct Shown {
    key: String,
    count: u32,
    parts: Parts,
}

/// Turns tshark's field lines into laid-out lines.
pub struct Printer<W: Write> {
    layout: Layout,
    out: W,
    /// The terminal can take a line back, so a repeated line is counted in place.
    rewrite: bool,
    waiting: Vec<Question>,
    last: Option<Shown>,
    started: bool,
}

impl<W: Write> Printer<W> {
    pub fn new(layout: Layout, out: W, rewrite: bool) -> Printer<W> {
        Printer { layout, out, rewrite, waiting: Vec::new(), last: None, started: false }
    }

    fn emit(&mut self, parts: Parts, key: String) {
        if !self.started {
            self.started = true;
            let _ = writeln!(self.out, "{}", self.layout.header());
        }
        if self.rewrite {
            if let Some(last) = self.last.as_mut().filter(|last| last.key == key) {
                last.count += 1;
                let mut again = last.parts.clone();
                again.push((format!("  ×{}", last.count), Paint::Yellow));
                let _ = writeln!(self.out, "\x1b[1A\x1b[2K{}", self.layout.render(&again));
                let _ = self.out.flush();
                return;
            }
        }
        let _ = writeln!(self.out, "{}", self.layout.render(&parts));
        let _ = self.out.flush();
        self.last = Some(Shown { key, count: 1, parts });
    }

    /// One line of tshark's output.
    pub fn feed(&mut self, row: &str, now: Instant) {
        let f: Vec<&str> = row.split('\t').collect();
        if f.len() < FIELDS.len() || f[0].is_empty() {
            return;
        }
        let first = |i: usize| f[i].split('|').next().unwrap_or("");
        let set = |i: usize| !matches!(first(i), "" | "0" | "False" | "false");
        let (source, destination, protocol, info) = (f[1], f[2], f[3], f[15]);
        let time = self.layout.clock(f[0]);
        // the far end: whichever side the databases know, the destination first
        let far = |country: usize, owner: usize| crate::geo::place(first(country), first(owner));
        let place = Some(far(19, 20)).filter(|p| !p.is_empty()).unwrap_or_else(|| far(17, 18));

        if f[8].is_empty() || f[5].is_empty() {
            let trouble = set(13) || set(14) || info.contains("unreachable") || info.contains("exceeded");
            let mut parts = self.layout.head(&time, source, destination, protocol, &place);
            parts.extend(summary(protocol, info, trouble));
            self.emit(parts, format!("{source}|{destination}|{protocol}|{info}"));
            return;
        }

        let kind = query_type(first(7));
        let name = first(8).to_string();
        let id = first(16);
        if !set(5) {
            let key = format!("{source}|{destination}|{id}|{kind}|{name}");
            if !self.waiting.iter().any(|q| q.key == key) {
                self.waiting.push(Question {
                    key, since: now, time, source: source.into(), destination: destination.into(),
                    protocol: protocol.into(), place, kind, name,
                });
            }
            return;
        }

        // an answer: shown on the line of its question, when that was seen
        let asked = self.waiting.iter().position(|q| q.key == format!("{destination}|{source}|{id}|{kind}|{name}"));
        let (mut parts, client, server, mark) = match asked.map(|i| self.waiting.remove(i)) {
            Some(q) => (self.layout.head(&q.time, &q.source, &q.destination, &q.protocol, &q.place), q.source, q.destination, "  "),
            None => (self.layout.head(&time, source, destination, protocol, &place), destination.to_string(), source.to_string(), "= "),
        };
        let error = match first(6) {
            "" | "0" => None,
            "1" => Some("FORMERR"),
            "2" => Some("SERVFAIL"),
            "3" => Some("NXDOMAIN"),
            "5" => Some("REFUSED"),
            _ => Some("ERROR"),
        };
        let outcome;
        match error {
            Some(error) => {
                outcome = error.to_string();
                parts.push(("✗ ".into(), Paint::Red));
                parts.push((format!("{kind:<5} {name}  {error}"), Paint::Red));
            }
            None => {
                let addresses: Vec<&str> = f[9].split('|').chain(f[10].split('|')).filter(|a| !a.is_empty()).collect();
                let (answer, paint) = match (addresses.first(), f[11].split('|').rfind(|c| !c.is_empty())) {
                    (Some(address), _) if addresses.len() > 1 => (format!("{address} +{}", addresses.len() - 1), Paint::Green),
                    (Some(address), _) => (address.to_string(), Paint::Green),
                    (None, Some(alias)) => (format!("{alias} (alias)"), Paint::Green),
                    (None, None) => ("no records".to_string(), Paint::Dim),
                };
                parts.push((mark.into(), Paint::Green));
                parts.push((format!("{kind:<5} "), Paint::Dim));
                parts.push((name.clone(), Paint::Plain));
                parts.push((" → ".into(), Paint::Dim));
                outcome = answer.clone();
                parts.push((answer, paint));
            }
        }
        if let Some(ms) = f[12].parse::<f64>().ok().map(|s| (s * 1000.0).round() as u64) {
            parts.push((format!("  {ms} ms"), if ms >= 200 { Paint::Yellow } else { Paint::Dim }));
        }
        self.emit(parts, format!("{client}|{server}|{kind}|{name}|{outcome}"));
    }

    /// Shows the questions that waited long enough; at the end of the capture, all of them.
    pub fn expire(&mut self, now: Instant, end: bool) {
        while let Some(i) = self.waiting.iter().position(|q| end || now.duration_since(q.since) >= ANSWER_WAIT) {
            let q = self.waiting.remove(i);
            let late = now.duration_since(q.since) >= ANSWER_WAIT;
            let mut parts = self.layout.head(&q.time, &q.source, &q.destination, &q.protocol, &q.place);
            parts.push(("? ".into(), if late { Paint::Yellow } else { Paint::Dim }));
            parts.push((format!("{:<5} ", q.kind), Paint::Dim));
            parts.push((q.name.clone(), Paint::Plain));
            if late {
                parts.push(("  no answer seen".into(), Paint::Yellow));
            }
            self.emit(parts, format!("{}|{}|{}|{}|?", q.source, q.destination, q.kind, q.name));
        }
    }
}

/// Reads tshark's field lines and prints laid-out ones until the input ends.
pub fn pump(input: impl Read + Send + 'static, layout: Layout, rewrite: bool) {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        for row in BufReader::new(input).lines().map_while(Result::ok) {
            if tx.send(row).is_err() {
                break;
            }
        }
    });
    let mut printer = Printer::new(layout, std::io::stdout(), rewrite);
    loop {
        match rx.recv_timeout(Duration::from_millis(300)) {
            Ok(row) => printer.feed(&row, Instant::now()),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        printer.expire(Instant::now(), false);
    }
    printer.expire(Instant::now(), true);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn printer(width: usize, color: bool, rewrite: bool) -> Printer<Vec<u8>> {
        let names = HashMap::from([("192.168.23.2".to_string(), "a-very-long-host-name".to_string())]);
        Printer::new(Layout { width, color, offset: 3 * 3600, names, geo: false, follow: false, wide: false }, Vec::new(), rewrite)
    }

    /// Lines printed so far, without the header.
    fn lines(p: &Printer<Vec<u8>>) -> Vec<String> {
        String::from_utf8(p.out.clone()).unwrap().lines().skip(1).map(str::to_string).collect()
    }

    fn dns(time: &str, from: &str, to: &str, response: bool, rcode: &str, kind: &str, name: &str, a: &str, cname: &str, took: &str, id: &str) -> String {
        [time, from, to, "DNS", "90", if response { "True" } else { "False" }, rcode, kind, name, a, "", cname, took, "", "", "info", id, "", "", "", ""].join("\t")
    }

    fn other(protocol: &str, reset: &str, info: &str) -> String {
        ["1.0", "192.0.2.1", "192.0.2.2", protocol, "60", "", "", "", "", "", "", "", "", reset, "", info, "", "", "", "US", "Example, Inc."].join("\t")
    }

    #[test]
    fn question_and_answer_make_one_line() {
        let mut p = printer(200, false, false);
        let now = Instant::now();
        p.feed(&dns("1795303703.233926000", "192.168.23.9", "192.168.23.1", false, "", "1", "example.com", "", "", "", "0x441a"), now);
        assert!(lines(&p).is_empty()); // waits for the answer
        p.feed(&dns("1795303703.246645000", "192.168.23.1", "192.168.23.9", true, "0", "1", "example.com",
                    "192.0.2.10|192.0.2.11|192.0.2.12", "www.example.net", "0.012719000", "0x441a"), now);
        assert_eq!(lines(&p), ["02:28:23.233     192.168.23.9 → 192.168.23.1     DNS       A     example.com → 192.0.2.10 +2  13 ms"]);
        p.expire(now + ANSWER_WAIT, true);
        assert_eq!(lines(&p).len(), 1); // nothing is left waiting
    }

    #[test]
    fn failures_aliases_and_stray_answers() {
        let mut p = printer(200, false, false);
        let now = Instant::now();
        p.feed(&dns("1.5", "a", "b", false, "", "28", "nope.example", "", "", "", "0x1"), now);
        p.feed(&dns("1.8", "b", "a", true, "3", "28", "nope.example", "", "", "0.3", "0x1"), now);
        p.feed(&dns("2.0", "b", "a", true, "0", "65", "x.example", "", "a.example|b.example", "", "0x2"), now);
        p.feed(&dns("2.1", "b", "a", true, "0", "65", "y.example", "", "", "", "0x3"), now);
        let out = lines(&p);
        assert!(out[0].ends_with("a → b                DNS     ✗ AAAA  nope.example  NXDOMAIN  300 ms"), "{}", out[0]);
        assert!(out[1].ends_with("b → a                DNS     = HTTPS x.example → b.example (alias)"), "{}", out[1]);
        assert!(out[2].ends_with("= HTTPS y.example → no records"));
    }

    #[test]
    fn unanswered_questions_show_up_later() {
        let mut p = printer(200, false, false);
        let now = Instant::now();
        p.feed(&dns("1.5", "a", "b", false, "", "1", "slow.example", "", "", "", "0x1"), now);
        p.feed(&dns("1.6", "a", "b", false, "", "1", "slow.example", "", "", "", "0x1"), now); // a retry
        p.expire(now + Duration::from_secs(1), false);
        assert!(lines(&p).is_empty());
        p.expire(now + ANSWER_WAIT, false);
        assert!(lines(&p)[0].ends_with("? A     slow.example  no answer seen"));
        p.feed(&dns("9.0", "a", "b", false, "", "1", "late.example", "", "", "", "0x2"), now);
        p.expire(now, true); // the capture ended right after it
        assert!(lines(&p)[1].ends_with("? A     late.example"));
    }

    #[test]
    fn names_replace_addresses_and_are_cut() {
        let mut p = printer(200, false, false);
        p.feed(&dns("1.0", "192.168.23.1", "192.168.23.2", true, "0", "1", "x.example", "192.0.2.1", "", "", "0x1"), Instant::now());
        assert!(lines(&p)[0].contains("    192.168.23.1 → a-very-long-ho…  DNS"), "{}", lines(&p)[0]);
    }

    #[test]
    fn repeats_are_counted_in_place_on_a_terminal() {
        let mut p = printer(200, false, true);
        for _ in 0..3 {
            p.feed(&other("ARP", "", "Who has 192.0.2.2? Tell 192.0.2.1"), Instant::now());
        }
        p.feed(&other("ARP", "", "something else"), Instant::now());
        let out = lines(&p);
        assert_eq!(out.len(), 4);
        assert!(out[1].starts_with("\x1b[1A\x1b[2K") && out[1].ends_with("Tell 192.0.2.1  ×2"));
        assert!(out[2].ends_with("  ×3"));
        assert!(out[3].ends_with("something else"));

        let mut plain = printer(200, false, false);
        for _ in 0..2 {
            plain.feed(&other("ARP", "", "Who has 192.0.2.2? Tell 192.0.2.1"), Instant::now());
        }
        assert!(!lines(&plain)[1].contains('×')); // a file or a pipe gets every line
    }

    #[test]
    fn the_far_end_gets_a_country_and_an_owner() {
        let mut p = printer(200, false, false);
        p.layout.geo = true;
        p.feed(&other("TCP", "", "443 → 5 [ACK]"), Instant::now());
        let out = String::from_utf8(p.out.clone()).unwrap();
        let rows: Vec<&str> = out.lines().collect();
        assert!(rows[0].ends_with("proto   where                what"), "{}", rows[0]);
        assert!(rows[1].ends_with("TCP     US Example, Inc.     443 → 5 [ACK]"), "{}", rows[1]);
    }

    #[test]
    fn summaries_lose_the_noise_and_get_colours() {
        let text = |parts: &Parts| parts.iter().map(|(t, _)| t.as_str()).collect::<String>();
        let syn = summary("TCP", "50686 → 81 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM TSval=1 TSecr=0 WS=128", false);
        assert_eq!(text(&syn), "50686 → 81 [SYN] Seq=0 Win=64240 Len=0");
        assert!(syn[0].1 == Paint::Green);
        assert!(summary("TCP", "443 → 5 [ACK] Seq=1 Ack=2 Win=10 Len=0", false)[0].1 == Paint::Dim);
        assert!(summary("TCP", "443 → 5 [ACK] Seq=1 Ack=2 Win=10 Len=1400", false)[0].1 == Paint::Plain);
        assert!(summary("TCP", "443 → 5 [FIN, ACK] Seq=1 Ack=2 Win=10 Len=0", false)[0].1 == Paint::Yellow);
        let hello = summary("TLSv1.3", "Client Hello (SNI=example.org)", false);
        assert_eq!(text(&hello), "Client Hello → example.org");
        assert!(hello[1].1 == Paint::BoldGreen);
        assert!(local("192.168.1.5") && !local("8.8.8.8") && group("224.0.0.251") && group("192.168.1.255"));

        let mut wide = printer(40, false, false);
        wide.layout.wide = true;
        wide.feed(&other("TCP", "", "443 → 51000 [ACK] Seq=1 Ack=1 Win=65535 Len=1460 and a lot more text after that"), Instant::now());
        assert!(lines(&wide)[0].ends_with("after that")); // not cut
    }

    #[test]
    fn long_lines_are_cut_and_trouble_is_red() {
        let mut p = printer(80, false, false);
        p.feed(&other("TCP", "", "443 → 51000 [ACK] Seq=1 Ack=1 Win=65535 Len=1460 Urg=0 Xyz=2 and a lot more text after that"), Instant::now());
        p.feed("garbage", Instant::now());
        let out = lines(&p);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].chars().count(), 80);
        assert!(out[0].ends_with('…'));

        let mut c = printer(200, true, false);
        c.feed(&other("TCP", "True", "443 → 5 [RST]"), Instant::now());
        assert!(lines(&c)[0].contains("\x1b[31m443 → 5 [RST]\x1b[0m"));
    }
}
