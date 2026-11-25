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
mtcap: capturing from 192.168.88.1 on eth0 for up to 600 s; Ctrl-C to stop
time                   source   destination      proto   what
10:15:02.114           laptop → home             DNS       A     example.com → 93.184.215.14  17 ms
10:15:07.920           laptop → home             DNS     ✗ AAAA  printer.lan  NXDOMAIN  1 ms
10:15:09.301            phone → home             DNS     ? A     slow.example  no answer seen
10:15:11.530               tv → 192.168.88.255   UDP     52100 → 9999 Len=24  ×4
```

In the terminal a line is cut to the window width and coloured by protocol, with failures in red.
A DNS question and its answer make one line with the time the answer took; a question left
without an answer shows up after three seconds. A line that repeats the previous one is counted
(`×4`) instead of printed again. Addresses are replaced by names: the router's DHCP leases, and
`[hosts]` in the config for the rest.

## Requirements

- RouterOS 6.43+ with the `api` service enabled and reachable (`/ip service`), a user with
  `api`, `read`, `write`, `sniff` and `test` policies
- `dumpcap` (package `wireshark-cli`) and membership in the `wireshark` group
- `wireshark` for the graphical view, or `tshark` for the terminal
- optional: `fzf` for the menus; passwords are remembered in the desktop keyring (`secret-tool`)
  or, without one, in a file encrypted with `systemd-creds`
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
mtcap home web --ip laptop                 # the same by name: a DHCP lease or [hosts]
mtcap hosts home               # who is on the network: address, name, MAC, state
mtcap home tcp-problems --ip 192.168.88.50 -t 60
mtcap home dns --tshark        # terminal view even if Wireshark is installed
mtcap report                   # summary of the capture just made
mtcap stop home                # after a crash: stop the sniffer, restore its settings
```

| Option | Meaning |
|---|---|
| `-i`, `--interface <name>` | only this router interface; `?` picks from a list |
| `--ip <addr\|name>` | only packets from or to this address; a host name, or a unique part of it, works too |
| `--port <list>` | these TCP/UDP ports instead of the preset's |
| `--proto <list>` | these IP protocols instead of the preset's: `tcp`, `udp`, `icmp`, `ospf`, … |
| `--headers`, `--full` | headers only; whole packets |
| `-t`, `--time <seconds>` | stop after this long; default 600, `0` for no limit |
| `-w`, `--write <file>` | save here instead of `~/captures/` |
| `--no-save` | do not save |
| `--tshark`, `--no-view` | terminal view; no view at all |
| `-Y`, `--filter <filter>` | show only what this Wireshark display filter matches, on top of the preset's; works in `mtcap show` too |
| `--raw` | in the terminal, `tshark`'s own lines instead of the compact layout |
| `--wide` | in the terminal, do not cut lines to the window width |
| `--no-names` | in the terminal, addresses instead of host names |
| `--force` | take over a running sniffer; ignore the router's CPU load |

## Hosts

`mtcap hosts [device]` lists the hosts of the network as the router sees them. Nothing is scanned:
it is the router's ARP table and DHCP leases put together, with names from the leases and from
`[hosts]` in the config.

```console
$ mtcap hosts home
address          name                     mac                interface        state
192.168.88.1     home                     -                  -                this router
192.168.88.2     nas                      AA:BB:CC:00:00:02  bridge           online
192.168.88.23    laptop                   AA:BB:CC:00:00:17  bridge           online
192.168.88.40    -                        AA:BB:CC:00:00:28  bridge           seen
192.168.88.51    tv                       AA:BB:CC:00:00:33  -                offline
```

`online` answered the router lately, `seen` is still in its ARP table, `offline` is known only
from a lease or the config. Any name, or a unique part of it, works in `--ip`.

## Connections, marks and routing tables

The sniffer shows packets, not what the router decided about them. `mtcap conns <device>` asks
the connection tracker instead: every connection open right now, its connection mark, and the
routing table that mark leads to.

```console
$ mtcap conns home --ip laptop
proto                   source   destination            where                  mark             table          state             bytes
tcp               laptop:51020 → 140.82.112.4:443       US GitHub, Inc.        via-tunnel       to-tunnel      established     1.2 MiB
udp               laptop:40112 → 192.168.88.2:53        -                      -                -              -                 310 B
```

`--ip` and `--port` narrow the list. The table is taken from the mangle rules that set a routing
mark by connection mark; `-` means no such rule.

## Changing the router

The same connection can change things, so a finding does not need a second tool. Every change is
printed and confirmed first (`--yes` skips the question).

```sh
mtcap home dhcp make laptop                # keep the address the host has now (static lease)
mtcap home dhcp make laptop 192.168.88.50  # keep another one; the host moves at its next request
mtcap home dhcp free laptop                # back to the pool

mtcap home fw                              # filter rules, numbered, with packet counters
mtcap home fw forward                      # one chain; nat, mangle and raw work like fw
mtcap home fw add chain=forward src-address=tv dst-address=203.0.113.0/24 action=drop place-before=12
mtcap home fw off 14                       # also: on, del

mtcap home route                           # routes, numbered
mtcap home route check 8.8.8.8             # which route of every table carries the address
mtcap home route add 10.20.0.0/16 192.168.88.254 routing-table=main distance=2
mtcap home route del 31

mtcap home run ip address print            # any RouterOS API command
mtcap home run ip dns static add name=nas.lan address=192.168.88.5
```

Host names work in `src-address`, `dst-address` and `dhcp make`. Numbers come from the listing
and are looked up again at the moment of the change, when the rule itself is shown for
confirmation. What mtcap adds gets the comment `mtcap` unless `--comment` gives another.

A rule or a route can cut the router off from the computer that added it. So a new rule or route
is added disabled, a scheduler `mtcap-undo` that takes it back is put on the router, and only
then it is enabled; mtcap removes the scheduler after it has logged in again. If it cannot, the
router undoes the change within a minute. The same guards `fw on` and `fw off`. Removing an item
and `run` are not guarded: they are only confirmed.

## Countries and owners

`mtcap geoip` downloads two free databases (about 18 MB) into `~/.local/share/mtcap/geoip/`.
With them the terminal view gets a `where` column, and `mtcap report` and `mtcap conns` name
the far end: country code and the owner of the address block. Lookups are local; no address
leaves the computer. Run `mtcap geoip` again to refresh them, they are reissued monthly. The
country is where the block is registered, which for large networks is not where the server is.

IP geolocation by [DB-IP](https://db-ip.com), licensed under CC BY 4.0.

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

Names for hosts with static addresses go there too:

```toml
[hosts]
"192.168.88.2" = "nas"
```

`router` takes any `/tool sniffer` property. In Wireshark the presets also appear as buttons on the
filter toolbar (profile `mtcap`).

## Saved captures and reports

Every capture is saved as `~/captures/<device>-<preset>-<time>.pcap`, with a `.json` next to it
that records the device, the router filter and the interface. Empty captures are not kept.

A `.pcap` file is binary: do not `cat` it. `mtcap show [file] [preset]` prints a saved capture in
the terminal the way a live one looks, the latest one by default; a preset filters the view, and
`mtcap show | less -R` pages through a long one. Wireshark and `tshark -r` open the same files.

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
- **ICMP of this computer.** The sniffer is told to skip its own stream (`filter-stream`), and on
  RouterOS that also hides every ICMP packet of the computer receiving the stream: its pings do
  not show up, its TCP and UDP do. `mtcap` switches the setting off whenever the protocol filter
  leaves no room for UDP (`icmp`, `tcp-problems`, `syn`, `--proto icmp`), so pings are visible
  there; with `all` or a port filter they are not.
- **Duplicates.** Without `-i`, a packet crossing a bridge shows up once per interface it passes.
- **Bridges.** `-i <bridge>` shows what the router itself receives and sends on the bridge. Frames
  switched between two ports of the bridge are seen on those ports: use `-i <port>` for them.
- **Timestamps** are the arrival time at this computer; RouterOS puts no capture time into the
  stream. Order and seconds are right, microsecond latencies are not.
- **Passwords** go over the plain API port unencrypted; use it on networks you trust.

## License

MIT
