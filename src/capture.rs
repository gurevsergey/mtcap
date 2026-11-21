//! Receiving the stream: dumpcap on the local interface -> outer Ethernet/IPv4/UDP -> TZSP -> inner frames.
//!
//! dumpcap sees packets before the host firewall does, so no firewall rule is needed, and it
//! works for members of the `wireshark` group without root. The price is doing IP reassembly
//! here: full-size frames wrapped in TZSP do not fit the MTU and arrive fragmented.

use std::collections::HashMap;
use std::io::{BufReader, Read, Write};
use std::net::Ipv4Addr;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const TZSP_PORT: u16 = 37008;

pub struct Frame {
    pub sec: u32,
    pub usec: u32,
    pub data: Vec<u8>,
    /// Length on the wire; larger than `data` when the router sends headers only.
    pub orig: u32,
}

impl Frame {
    pub fn new(sec: u32, usec: u32, data: Vec<u8>) -> Frame {
        let orig = wire_len(&data);
        Frame { sec, usec, data, orig }
    }
}

/// The length the frame had on the wire, from its IP header; headers-only captures cut the rest off.
pub fn wire_len(frame: &[u8]) -> u32 {
    let captured = frame.len();
    let full = (|| {
        let mut at = 12;
        while matches!(be16(frame, at)?, 0x8100 | 0x88A8) {
            at += 4;
        }
        match be16(frame, at)? {
            0x0800 => Some(at + 2 + be16(frame, at + 4)?),
            0x86DD => Some(at + 2 + 40 + be16(frame, at + 6)?),
            _ => None,
        }
    })();
    full.filter(|n| *n > captured).unwrap_or(captured) as u32
}

struct Pieces {
    parts: Vec<(usize, Vec<u8>)>,
    total: Option<usize>,
    born: Instant,
}

/// IPv4 reassembly, just enough for one well-behaved sender.
#[derive(Default)]
pub struct Reassembler {
    pending: HashMap<(u32, u16), Pieces>,
}

impl Reassembler {
    fn add(&mut self, key: (u32, u16), offset: usize, more: bool, data: &[u8]) -> Option<Vec<u8>> {
        if self.pending.len() > 64 {
            self.pending.retain(|_, p| p.born.elapsed() < Duration::from_secs(5));
        }
        let entry = self.pending.entry(key).or_insert_with(|| Pieces { parts: Vec::new(), total: None, born: Instant::now() });
        entry.parts.push((offset, data.to_vec()));
        if !more {
            entry.total = Some(offset + data.len());
        }
        let total = entry.total?;
        entry.parts.sort_by_key(|(offset, _)| *offset);
        let mut whole = Vec::with_capacity(total);
        for (offset, part) in &entry.parts {
            if *offset > whole.len() {
                return None; // a hole: wait for the missing fragment
            }
            let skip = whole.len() - offset;
            if skip < part.len() {
                whole.extend_from_slice(&part[skip..]);
            }
        }
        if whole.len() < total {
            return None;
        }
        self.pending.remove(&key);
        Some(whole)
    }
}

fn be16(b: &[u8], at: usize) -> Option<usize> {
    Some(usize::from(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?])))
}

/// The UDP payload addressed to the TZSP port, if this Ethernet frame completes one.
pub fn outer_payload(frame: &[u8], reassembler: &mut Reassembler) -> Option<Vec<u8>> {
    let mut at = 12;
    while matches!(be16(frame, at)?, 0x8100 | 0x88A8) {
        at += 4; // VLAN tags
    }
    if be16(frame, at)? != 0x0800 {
        return None;
    }
    let ip = frame.get(at + 2..)?;
    let header = usize::from(ip.first()? & 0x0F) * 4;
    let total = be16(ip, 2)?;
    if ip.first()? >> 4 != 4 || header < 20 || total < header || *ip.get(9)? != 17 {
        return None;
    }
    let payload = ip.get(header..total.min(ip.len()))?;
    let id = be16(ip, 4)? as u16;
    let flags = be16(ip, 6)?;
    let (more, offset) = (flags & 0x2000 != 0, (flags & 0x1FFF) * 8);
    let source = u32::from_be_bytes(ip.get(12..16)?.try_into().ok()?);
    let datagram = if more || offset > 0 {
        reassembler.add((source, id), offset, more, payload)?
    } else {
        payload.to_vec()
    };
    if be16(&datagram, 2)? != usize::from(TZSP_PORT) {
        return None;
    }
    Some(datagram.get(8..)?.to_vec())
}

/// The Ethernet frame inside a TZSP packet.
pub fn tzsp_inner(packet: &[u8]) -> Option<&[u8]> {
    if *packet.first()? != 1 || be16(packet, 2)? != 1 {
        return None; // not TZSP v1 carrying Ethernet
    }
    let mut at = 4;
    loop {
        match *packet.get(at)? {
            0 => at += 1,               // padding
            1 => return packet.get(at + 1..), // end of tagged fields
            _ => at += 2 + usize::from(*packet.get(at + 1)?),
        }
    }
}

/// The interface the router's packets arrive on.
pub fn interface_for(router: Ipv4Addr) -> Result<String, String> {
    let out = Command::new("ip").args(["-o", "route", "get", &router.to_string()]).output()
        .map_err(|e| format!("cannot run ip: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let mut words = text.split_whitespace();
    words.find(|w| *w == "dev");
    words.next().map(String::from).ok_or_else(|| format!("no route to {router}"))
}

pub struct Receiver {
    pub child: Child,
    /// What dumpcap said on stderr, for error reports.
    pub log: Arc<Mutex<String>>,
}

/// Starts dumpcap and a thread that turns its output into inner frames on `tx`.
pub fn spawn(interface: &str, source: Ipv4Addr, tx: Sender<Frame>) -> Result<Receiver, String> {
    // the first fragment has the UDP header; the following ones match by their fragment offset
    let filter = format!("src host {source} and (udp dst port {TZSP_PORT} or (ip[6:2] & 0x1fff != 0))");
    let mut child = Command::new("dumpcap")
        .args(["-q", "-P", "-i", interface, "-f", &filter, "-w", "-"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run dumpcap: {e} (install wireshark-cli)"))?;
    let log = Arc::new(Mutex::new(String::new()));
    if let Some(mut stderr) = child.stderr.take() {
        let log = log.clone();
        std::thread::spawn(move || {
            let mut text = String::new();
            let _ = stderr.read_to_string(&mut text);
            *log.lock().unwrap() = text;
        });
    }
    let stdout = child.stdout.take().ok_or("dumpcap has no stdout")?;
    std::thread::spawn(move || {
        let _ = pump(BufReader::new(stdout), &tx);
    });
    Ok(Receiver { child, log })
}

/// Reads a classic pcap stream of the outer packets; sends the inner frames.
fn pump(mut input: impl Read, tx: &Sender<Frame>) -> Option<()> {
    let mut header = [0u8; 24];
    input.read_exact(&mut header).ok()?;
    let nanos = match u32::from_le_bytes(header[0..4].try_into().ok()?) {
        0xa1b2_c3d4 => false,
        0xa1b2_3c4d => true,
        _ => return None,
    };
    if u32::from_le_bytes(header[20..24].try_into().ok()?) != 1 {
        return None; // only Ethernet link type
    }
    let mut reassembler = Reassembler::default();
    loop {
        let mut record = [0u8; 16];
        input.read_exact(&mut record).ok()?;
        let field = |i: usize| u32::from_le_bytes(record[i..i + 4].try_into().unwrap());
        let mut packet = vec![0u8; field(8) as usize];
        input.read_exact(&mut packet).ok()?;
        let Some(payload) = outer_payload(&packet, &mut reassembler) else { continue };
        let Some(inner) = tzsp_inner(&payload) else { continue };
        let usec = if nanos { field(4) / 1000 } else { field(4) };
        tx.send(Frame::new(field(0), usec, inner.to_vec())).ok()?;
    }
}

pub fn pcap_header() -> Vec<u8> {
    let mut h = Vec::with_capacity(24);
    h.extend(0xa1b2_c3d4u32.to_le_bytes());
    h.extend(2u16.to_le_bytes());
    h.extend(4u16.to_le_bytes());
    h.extend([0u8; 8]);
    h.extend(262_144u32.to_le_bytes());
    h.extend(1u32.to_le_bytes()); // Ethernet
    h
}

pub fn write_frame(out: &mut impl Write, frame: &Frame) -> std::io::Result<()> {
    let mut record = Vec::with_capacity(16 + frame.data.len());
    for field in [frame.sec, frame.usec, frame.data.len() as u32, frame.orig] {
        record.extend(field.to_le_bytes());
    }
    record.extend(&frame.data);
    out.write_all(&record)?;
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::channel;

    /// Ethernet + IPv4 header in front of `payload`.
    fn ip_packet(id: u16, flags_offset: u16, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 12];
        p.extend([0x08, 0x00]);
        let total = (20 + payload.len()) as u16;
        p.extend([0x45, 0]);
        p.extend(total.to_be_bytes());
        p.extend(id.to_be_bytes());
        p.extend(flags_offset.to_be_bytes());
        p.extend([64, 17, 0, 0]);
        p.extend([192, 0, 2, 1]);
        p.extend([192, 0, 2, 2]);
        p.extend(payload);
        p
    }

    fn udp_tzsp(inner: &[u8]) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend(40000u16.to_be_bytes());
        d.extend(TZSP_PORT.to_be_bytes());
        d.extend(((8 + 5 + inner.len()) as u16).to_be_bytes());
        d.extend([0, 0]);
        d.extend([1, 0, 0, 1, 1]); // TZSP v1, received packet, Ethernet, end tag
        d.extend(inner);
        d
    }

    #[test]
    fn unwraps_a_whole_datagram() {
        let inner = b"inner ethernet frame";
        let payload = outer_payload(&ip_packet(7, 0, &udp_tzsp(inner)), &mut Reassembler::default()).unwrap();
        assert_eq!(tzsp_inner(&payload).unwrap(), inner);
    }

    #[test]
    fn skips_tagged_fields_and_padding() {
        let packet = [1, 0, 0, 1, 0, 10, 2, 0xAA, 0xBB, 0, 1, b'x', b'y'];
        assert_eq!(tzsp_inner(&packet).unwrap(), b"xy");
        assert!(tzsp_inner(&[2, 0, 0, 1, 1]).is_none());
        assert!(tzsp_inner(&[1, 0, 0, 1]).is_none());
    }

    #[test]
    fn reassembles_fragments_in_any_order() {
        let inner: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
        let datagram = udp_tzsp(&inner);
        let (a, rest) = datagram.split_at(1480);
        let (b, c) = rest.split_at(1480);
        let mut reassembler = Reassembler::default();
        // last, first, middle
        assert!(outer_payload(&ip_packet(9, (2960 / 8) as u16, c), &mut reassembler).is_none());
        assert!(outer_payload(&ip_packet(9, 0x2000, a), &mut reassembler).is_none());
        let payload = outer_payload(&ip_packet(9, 0x2000 | (1480 / 8) as u16, b), &mut reassembler).unwrap();
        assert_eq!(tzsp_inner(&payload).unwrap(), &inner[..]);
        assert!(reassembler.pending.is_empty());
    }

    #[test]
    fn wire_length_of_cut_frames() {
        let whole = ip_packet(1, 0, &[0u8; 100]);
        assert_eq!(wire_len(&whole), whole.len() as u32);
        assert_eq!(wire_len(&whole[..42]), whole.len() as u32); // headers only
        assert_eq!(wire_len(&[0u8; 10]), 10);
        let mut padded = ip_packet(1, 0, &[0u8; 8]);
        padded.extend([0u8; 18]); // Ethernet padding is not an underestimate
        assert_eq!(wire_len(&padded), padded.len() as u32);
    }

    #[test]
    fn ignores_other_traffic() {
        let mut other = udp_tzsp(b"x");
        other[2..4].copy_from_slice(&53u16.to_be_bytes());
        assert!(outer_payload(&ip_packet(1, 0, &other), &mut Reassembler::default()).is_none());
        assert!(outer_payload(&[0u8; 10], &mut Reassembler::default()).is_none());
    }

    #[test]
    fn pumps_a_pcap_stream() {
        let mut stream = pcap_header();
        let packet = ip_packet(3, 0, &udp_tzsp(b"hello"));
        write_frame(&mut stream, &Frame::new(100, 5, packet)).unwrap();
        let (tx, rx) = channel();
        pump(&stream[..], &tx);
        let frame = rx.try_recv().unwrap();
        assert_eq!((frame.sec, frame.usec, frame.data.as_slice()), (100, 5, &b"hello"[..]));
    }
}
