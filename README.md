# mtcap

Live packet capture from MikroTik routers into Wireshark.

`mtcap` lets you pick a router and a filter, turns on the RouterOS packet sniffer in streaming mode
over the API, receives the TZSP stream on your computer, unwraps it and hands plain packets to
Wireshark (or `tshark` in the terminal). When you stop, the sniffer is stopped and its settings are put back.

```console
$ mtcap
device › home             admin@192.168.88.1
filter › dns              DNS queries and answers
interface › bridge        bridge
mtcap: home → 192.168.88.10, preset dns
       router sends: interface=bridge and port=53
mtcap: capturing from 192.168.88.1 on eth0; Ctrl-C to stop
    1   0.000000 192.168.88.23 → 192.168.88.1 DNS 83 Standard query 0x49d6 A example.com
```

## Requirements

- RouterOS 6.43+ with the `api` service enabled and reachable (`/ip service`), a user with
  `api`, `read`, `write`, `sniff` and `test` policies
- `dumpcap` (package `wireshark-cli`) and membership in the `wireshark` group
- `wireshark` for the graphical view, or `tshark` for the terminal
- optional: `fzf` for the menus, `secret-tool` and a keyring to remember passwords
- Rust 1.80+ to build

No firewall rule is needed on the computer: the stream is read from the interface with `dumpcap`,
before the host firewall sees it.

## Install

```sh
cargo build --release
install -Dm755 target/release/mtcap ~/.local/bin/mtcap
mtcap add home 192.168.88.1 admin
```

## Usage

```sh
mtcap                          # menus: device, filter, router interface
mtcap home dns                 # device and preset by name
mtcap home web -i bridge       # only one router interface
mtcap home all --ip 192.168.88.50          # everything one host does
mtcap home tcp-problems --ip 192.168.88.50 -t 60
mtcap home dns --tshark        # terminal view even if Wireshark is installed
mtcap report                   # summary of the capture just made
mtcap stop home                # after a crash: stop the sniffer, restore its settings
```

| Option | Meaning |
|---|---|
| `-i`, `--interface <name>` | only this router interface; `?` picks from a list |
| `--ip <addr[/mask]>` | only packets from or to this address |
| `--port <list>` | these TCP/UDP ports instead of the preset's |
| `--proto <list>` | these IP protocols instead of the preset's: `tcp`, `udp`, `icmp`, `ospf`, … |
| `--headers`, `--full` | headers only; whole packets |
| `-t`, `--time <seconds>` | stop after this long; default 600, `0` for no limit |
| `-w`, `--write <file>` | save here instead of `~/captures/` |
| `--no-save` | do not save |
| `--tshark`, `--no-view` | terminal view; no view at all |
| `--force` | take over a running sniffer; ignore the router's CPU load |

## How the filters work

There are two of them, and they are not interchangeable.

| | Router filter | View filter |
|---|---|---|
| Where | `/tool sniffer filter-*` on the router | Wireshark or `tshark` display filter |
| Decides | what is sent to you at all | what is shown of it |
| Can be changed later | no: what was not captured is gone | yes, at any time |

The saved file holds everything the router sent, not only what the view filter let through.

On the router, several values of one property mean "any of them", and different properties narrow
each other: ports `80,443,53` on interface `bridge` from address `192.168.88.50`. There is no way to
say "port 53 **or** ICMP". The preset and the command line simply add up, and `--port` or `--proto`
replace the preset's own.

## Presets

A preset is a router filter plus a view filter. The built-in ones capture a little more than their
name says, as far as RouterOS allows: the DNS lookup before a web request, the ICMP error behind a
stalled TCP connection. That is usually where the cause is.

| Preset | Router sends | View shows |
|---|---|---|
| `all` | everything, headers only | everything |
| `dns`, `dns-errors` | port 53 | DNS; failed lookups only |
| `dhcp` | ports 67, 68 | DHCP |
| `arp` | MAC protocol `arp` | ARP |
| `icmp` | ICMP, ICMPv6 | ping and ICMP errors |
| `web` | ports 80, 443, 8080, 53 | HTTP requests, TLS handshakes and alerts, DNS, resets |
| `tcp-problems` | TCP and ICMP | retransmissions, zero windows, resets, ICMP errors |
| `syn` | TCP and ICMP | new connections, resets, ICMP errors |
| `bgp` | port 179 | BGP, resets |
| `ospf` | protocol `ospf` | OSPF |
| `tunnels` | ports 500, 4500, 51820, 13231 | WireGuard, IKE |
| `gre-esp` | protocols `gre`, `ipsec-esp` | GRE, ESP |
| `broadcast` | everything, headers only | broadcast and multicast |

To investigate one device, prefer `all --ip <address>`: its whole traffic is small, and it keeps
the DNS and ICMP that explain a failure. Narrow by protocol in the view, not on the router.

Your own presets go into `~/.config/mtcap/config.toml`:

```toml
[[preset]]
name = "printer"
about = "everything to and from the printer"
display = "ip.addr == 192.168.88.50"
router = { filter-ip-address = "192.168.88.50/32" }
```

`router` takes any `/tool sniffer` property. In Wireshark the presets also appear as buttons on the
filter toolbar (profile `mtcap`).

## Saved captures and reports

Every capture is saved as `~/captures/<device>-<preset>-<time>.pcap`, with a `.json` next to it
that records the device, the router filter and the interface. Empty captures are not kept.

`mtcap report [file]` reads a capture top-down, the way an analysis should go:

- overview: packets, bytes on the wire, duration, rate
- protocols and the largest conversations
- TCP health: share of retransmissions, zero windows, who sends resets
- DNS: failures, median and slowest answers
- ICMP errors by kind, including "fragmentation needed"
- findings: what of the above is out of the ordinary, in words

It also notices when a capture is full of duplicates, which happens without `-i`, and says that
the TCP figures cannot be trusted then.

## Safeguards

- **Headers only** when nothing narrows the capture: less load on the router, no payload on disk.
- **Time limit** of ten minutes unless `-t` says otherwise.
- **CPU check.** A capture does not start when the router's CPU is above 80%, and stops when it
  stays above 90%.
- **Watchdog.** For the duration of the capture a scheduler entry `mtcap-watchdog` lives on the
  router. `mtcap` keeps it wound up; if the computer disappears, within about two minutes it stops
  the sniffer, switches streaming off and removes itself.
- **Restore.** The settings changed on the router are saved in `~/.local/state/mtcap/` first and
  put back afterwards; `mtcap stop <device>` or the next capture does it after a crash.

## Things to know

- **Fasttrack.** The sniffer does not see fasttracked connections beyond their first packets. To
  look at forwarded TCP/UDP flows in full, disable the fasttrack rule for the time of the capture.
- **Traffic between this computer and the router** itself may be missing: the sniffer is told to
  skip its own stream (`filter-stream`), and that hides more than the stream. Traffic this computer
  sends through the router is captured normally.
- **Duplicates.** Without `-i`, a packet crossing a bridge shows up once per interface it passes.
- **Timestamps** are the arrival time at this computer; RouterOS puts no capture time into the
  stream. Order and seconds are right, microsecond latencies are not.
- **Passwords** go over the plain API port unencrypted; use it on networks you trust.

## License

MIT
