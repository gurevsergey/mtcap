//! A minimal RouterOS API client (plain TCP, login method of RouterOS 6.43+).

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

pub type Row = BTreeMap<String, String>;

pub struct Api {
    stream: TcpStream,
}

pub fn encode_len(n: usize) -> Vec<u8> {
    let n = n as u32;
    match n {
        0..=0x7F => vec![n as u8],
        0x80..=0x3FFF => (n | 0x8000).to_be_bytes()[2..].to_vec(),
        0x4000..=0x1F_FFFF => (n | 0xC0_0000).to_be_bytes()[1..].to_vec(),
        0x20_0000..=0x0FFF_FFFF => (n | 0xE000_0000).to_be_bytes().to_vec(),
        _ => [&[0xF0][..], &n.to_be_bytes()].concat(),
    }
}

pub fn read_len(r: &mut impl Read) -> std::io::Result<usize> {
    let mut first = [0u8; 1];
    r.read_exact(&mut first)?;
    let b = first[0];
    let (extra, head) = match b {
        _ if b & 0x80 == 0 => (0, u32::from(b)),
        _ if b & 0xC0 == 0x80 => (1, u32::from(b & 0x3F)),
        _ if b & 0xE0 == 0xC0 => (2, u32::from(b & 0x1F)),
        _ if b & 0xF0 == 0xE0 => (3, u32::from(b & 0x0F)),
        _ => (4, 0),
    };
    let mut rest = [0u8; 4];
    r.read_exact(&mut rest[..extra])?;
    Ok(rest[..extra].iter().fold(head, |acc, x| (acc << 8) | u32::from(*x)) as usize)
}

impl Api {
    pub fn connect(host: &str, port: u16) -> Result<Api, String> {
        let addr = (host, port)
            .to_socket_addrs()
            .map_err(|e| format!("cannot resolve {host}: {e}"))?
            .next()
            .ok_or_else(|| format!("cannot resolve {host}"))?;
        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
            .map_err(|e| format!("cannot connect to {addr}: {e}"))?;
        let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(15)));
        let _ = stream.set_nodelay(true);
        Ok(Api { stream })
    }

    /// Our address as the router sees it: the natural target for the stream.
    pub fn local_ip(&self) -> Option<IpAddr> {
        self.stream.local_addr().ok().map(|a| a.ip())
    }

    pub fn peer_ip(&self) -> Option<IpAddr> {
        self.stream.peer_addr().ok().map(|a| a.ip())
    }

    pub fn login(&mut self, user: &str, password: &str) -> Result<(), String> {
        let rows = self.run(&["/login", &format!("=name={user}"), &format!("=password={password}")])?;
        if rows.iter().any(|r| r.contains_key("ret")) {
            return Err("RouterOS older than 6.43 is not supported".into());
        }
        Ok(())
    }

    fn send(&mut self, words: &[&str]) -> std::io::Result<()> {
        let mut buf = Vec::new();
        for word in words {
            buf.extend(encode_len(word.len()));
            buf.extend(word.as_bytes());
        }
        buf.push(0);
        self.stream.write_all(&buf)
    }

    fn read_sentence(&mut self) -> std::io::Result<Vec<String>> {
        let mut words = Vec::new();
        loop {
            let len = read_len(&mut self.stream)?;
            if len == 0 {
                return Ok(words);
            }
            let mut word = vec![0u8; len];
            self.stream.read_exact(&mut word)?;
            words.push(String::from_utf8_lossy(&word).into_owned());
        }
    }

    /// Run a command; rows of `!re` replies (and attributes of `!done`, if any).
    pub fn run(&mut self, words: &[&str]) -> Result<Vec<Row>, String> {
        self.send(words).map_err(|e| format!("API write failed: {e}"))?;
        let mut rows = Vec::new();
        let mut trap: Option<String> = None;
        loop {
            let sentence = self.read_sentence().map_err(|e| format!("API read failed: {e}"))?;
            let Some((kind, attrs)) = sentence.split_first() else { continue };
            let row: Row = attrs
                .iter()
                .filter_map(|w| w.strip_prefix('=')?.split_once('='))
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            match kind.as_str() {
                "!re" => rows.push(row),
                "!trap" => trap = Some(row.get("message").cloned().unwrap_or_else(|| "command failed".into())),
                "!fatal" => return Err(attrs.first().cloned().unwrap_or_else(|| "connection closed by router".into())),
                "!done" => {
                    if let Some(message) = trap {
                        return Err(message);
                    }
                    if !row.is_empty() {
                        rows.push(row);
                    }
                    return Ok(rows);
                }
                _ => {} // !empty and anything newer
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn length_codec() {
        for n in [0usize, 1, 0x7F, 0x80, 0x3FFF, 0x4000, 0x1F_FFFF, 0x20_0000, 0x0FFF_FFFF, 0x1000_0000] {
            let bytes = encode_len(n);
            assert_eq!(read_len(&mut &bytes[..]).unwrap(), n, "{n:#x}");
        }
        assert_eq!(encode_len(0x80), [0x80, 0x80]);
        assert_eq!(encode_len(0x4000), [0xC0, 0x40, 0x00]);
    }

    fn sentence(words: &[&str]) -> Vec<u8> {
        let mut buf = Vec::new();
        for w in words {
            buf.extend(encode_len(w.len()));
            buf.extend(w.as_bytes());
        }
        buf.push(0);
        buf
    }

    #[test]
    fn talks_to_a_router() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut api = Api { stream };
            let login = api.read_sentence().unwrap();
            assert_eq!(login, ["/login", "=name=admin", "=password=secret"]);
            api.stream.write_all(&sentence(&["!done"])).unwrap();
            assert_eq!(api.read_sentence().unwrap(), ["/tool/sniffer/print"]);
            api.stream.write_all(&sentence(&["!re", "=running=false", "=filter-port=", "=streaming-server=0.0.0.0:37008"])).unwrap();
            api.stream.write_all(&sentence(&["!done"])).unwrap();
            assert_eq!(api.read_sentence().unwrap(), ["/tool/sniffer/set", "=filter-port=nonsense"]);
            api.stream.write_all(&sentence(&["!trap", "=category=1", "=message=bad port"])).unwrap();
            api.stream.write_all(&sentence(&["!done"])).unwrap();
        });
        let mut api = Api::connect("127.0.0.1", port).unwrap();
        api.login("admin", "secret").unwrap();
        let rows = api.run(&["/tool/sniffer/print"]).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["streaming-server"], "0.0.0.0:37008");
        assert_eq!(rows[0]["filter-port"], "");
        assert_eq!(api.run(&["/tool/sniffer/set", "=filter-port=nonsense"]).unwrap_err(), "bad port");
        server.join().unwrap();
    }
}
