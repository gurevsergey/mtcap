//! Devices and filter presets: ~/.config/mtcap/config.toml.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

#[derive(Deserialize, Default)]
pub struct Config {
    #[serde(default, rename = "device")]
    pub devices: Vec<Device>,
    #[serde(default, rename = "preset")]
    pub presets: Vec<Preset>,
}

#[derive(Deserialize, Clone)]
pub struct Device {
    pub name: String,
    pub host: String,
    pub user: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// Where the router should send the stream; defaults to our address on the API connection.
    pub stream_to: Option<String>,
    /// Source address of the stream, when it differs from `host`.
    pub source: Option<String>,
}

#[derive(Deserialize, Clone)]
pub struct Preset {
    pub name: String,
    #[serde(default)]
    pub about: String,
    /// Wireshark display filter.
    #[serde(default)]
    pub display: String,
    /// What the router should send: `/tool sniffer` properties, e.g. filter-port = "53,80".
    /// A list means "any of"; different properties narrow each other.
    #[serde(default)]
    pub router: BTreeMap<String, String>,
}

fn default_port() -> u16 {
    8728
}

const TEMPLATE: &str = r#"# mtcap: devices and filter presets.
#
# [[device]]
# name = "home"
# host = "192.168.88.1"
# user = "admin"
# port = 8728                  # optional, the plain API port
# stream_to = "192.168.88.10"  # optional: this computer's address as the router reaches it
# source = "192.168.88.1"      # optional: the address the stream comes from, if not `host`
#
# Your own presets go next to the built-in ones (`mtcap presets`); the same name replaces a built-in.
#
# [[preset]]
# name = "printer"
# about = "everything to and from the printer"
# display = "ip.addr == 192.168.88.50"
# router = { filter-ip-address = "192.168.88.50/32" }
"#;

/// The built-in presets capture a little more than their name says: the DNS lookup before a web
/// request, the ICMP error behind a stalled TCP connection. That is where the cause usually is.
/// RouterOS can only widen a filter within one property, which decides what can ride along.
fn builtin() -> Vec<Preset> {
    let preset = |name: &str, about: &str, display: &str, router: &[(&str, &str)]| Preset {
        name: name.into(),
        about: about.into(),
        display: display.into(),
        router: router.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
    };
    let unreachable = "icmp.type == 3 || icmp.type == 11";
    vec![
        preset("all", "everything the router forwards", "", &[]),
        preset("dns", "DNS queries and answers", "dns", &[("filter-port", "53")]),
        preset("dns-errors", "failed DNS lookups", "dns.flags.rcode != 0", &[("filter-port", "53")]),
        preset("dhcp", "DHCP leases", "dhcp", &[("filter-port", "67,68")]),
        preset("arp", "ARP", "arp", &[("filter-mac-protocol", "arp")]),
        preset("icmp", "ping and ICMP errors", "icmp || icmpv6", &[("filter-ip-protocol", "icmp,icmpv6")]),
        preset("web", "HTTP requests, TLS handshakes and the DNS before them",
               "http.request || tls.handshake.type == 1 || tls.alert_message || dns || tcp.flags.reset == 1",
               &[("filter-port", "80,443,8080,53")]),
        preset("tcp-problems", "retransmissions, resets, zero windows and ICMP errors",
               &format!("tcp.analysis.retransmission || tcp.analysis.fast_retransmission || tcp.analysis.zero_window || tcp.flags.reset == 1 || {unreachable}"),
               &[("filter-ip-protocol", "tcp,icmp")]),
        preset("syn", "new TCP connections and refusals",
               &format!("(tcp.flags.syn == 1 && tcp.flags.ack == 0) || tcp.flags.reset == 1 || {unreachable}"),
               &[("filter-ip-protocol", "tcp,icmp")]),
        preset("bgp", "BGP sessions", "bgp || tcp.flags.reset == 1", &[("filter-port", "179")]),
        preset("ospf", "OSPF", "ospf", &[("filter-ip-protocol", "ospf")]),
        preset("tunnels", "WireGuard and IPsec key exchange", "wg || isakmp || udpencap",
               &[("filter-port", "500,4500,51820,13231")]),
        preset("gre-esp", "GRE and IPsec ESP", "gre || esp", &[("filter-ip-protocol", "gre,ipsec-esp")]),
        preset("broadcast", "broadcast and multicast noise", "eth.dst.ig == 1", &[]),
    ]
}

pub fn dir() -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
    home.join(".config").join("mtcap")
}

pub fn path() -> PathBuf {
    dir().join("config.toml")
}

impl Config {
    /// Loads the config, creating a commented template on first run. Built-in presets are merged in.
    pub fn load() -> Result<Config, String> {
        let path = path();
        if !path.exists() {
            fs::create_dir_all(dir()).and_then(|_| fs::write(&path, TEMPLATE))
                .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
        }
        let text = fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let mut config: Config = toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut presets = builtin();
        for own in std::mem::take(&mut config.presets) {
            match presets.iter_mut().find(|p| p.name == own.name) {
                Some(slot) => *slot = own,
                None => presets.push(own),
            }
        }
        config.presets = presets;
        Ok(config)
    }

    pub fn device(&self, name: &str) -> Option<&Device> {
        self.devices.iter().find(|d| d.name == name)
    }

    pub fn preset(&self, name: &str) -> Option<&Preset> {
        self.presets.iter().find(|p| p.name == name)
    }
}

/// Appends a device to the config file.
pub fn add_device(name: &str, host: &str, user: &str, port: u16) -> Result<(), String> {
    let config = Config::load()?;
    if config.device(name).is_some() {
        return Err(format!("device {name} already exists in {}", path().display()));
    }
    let quoted = |s: &str| toml::Value::String(s.to_string()).to_string();
    let mut block = format!("\n[[device]]\nname = {}\nhost = {}\nuser = {}\n", quoted(name), quoted(host), quoted(user));
    if port != default_port() {
        block.push_str(&format!("port = {port}\n"));
    }
    let mut text = fs::read_to_string(path()).unwrap_or_default();
    text.push_str(&block);
    fs::write(path(), text).map_err(|e| format!("cannot write {}: {e}", path().display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_is_valid_and_empty() {
        let config: Config = toml::from_str(TEMPLATE).unwrap();
        assert!(config.devices.is_empty() && config.presets.is_empty());
    }

    #[test]
    fn parses_devices_and_presets() {
        let text = r#"
            [[device]]
            name = "home"
            host = "192.0.2.1"
            user = "admin"
            [[device]]
            name = "lab"
            host = "lab.example.net"
            user = "capture"
            port = 18728
            source = "192.0.2.9"
            [[preset]]
            name = "printer"
            display = "ip.addr == 192.0.2.50"
            router = { filter-ip-address = "192.0.2.50/32" }
        "#;
        let config: Config = toml::from_str(text).unwrap();
        assert_eq!(config.devices[0].port, 8728);
        assert_eq!(config.devices[1].port, 18728);
        assert_eq!(config.presets[0].router["filter-ip-address"], "192.0.2.50/32");
    }

    #[test]
    fn builtin_names_are_unique() {
        let mut names: Vec<String> = builtin().into_iter().map(|p| p.name).collect();
        let total = names.len();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), total);
    }
}
