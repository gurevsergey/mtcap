//! Changes on the router: static DHCP leases, firewall rules, routes, and any API command.
//!
//! Everything that changes the router says what it is about to do and asks first. A change
//! that could cut this computer off (a new or re-enabled rule, a new route) is armed with a
//! rollback on the router: unless mtcap logs in again right after it, the router undoes it.

use crate::api::{Api, Row};
use crate::config::{Config, Device};
use crate::{address_fits, connect, interactive, open, pick_device, resolve_host, secret, Opts};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;

const UNDO: &str = "mtcap-undo";
/// The rollback fires after this many runs of a 15 s scheduler: 30–45 s.
const UNDO_LIVES: &str = "2";

fn get(row: &Row, key: &str) -> String {
    row.get(key).cloned().unwrap_or_default()
}

fn yes(row: &Row, key: &str) -> bool {
    row.get(key).is_some_and(|v| v == "true")
}

fn confirm(opts: &Opts, what: &str) -> Result<(), String> {
    eprintln!("{what}");
    if opts.yes {
        return Ok(());
    }
    if !interactive() {
        return Err("not a terminal: add --yes to change the router without being asked".into());
    }
    if secret::ask_yes("do it?") { Ok(()) } else { Err("left as it was".into()) }
}

/// The word that picks a firewall table.
pub fn table_path(word: &str) -> Option<&'static str> {
    Some(match word {
        "fw" => "/ip/firewall/filter",
        "nat" => "/ip/firewall/nat",
        "mangle" => "/ip/firewall/mangle",
        "raw" => "/ip/firewall/raw",
        _ => return None,
    })
}

/// Is `mtcap <device> <word> ...` one of the commands of this module?
pub fn handles(positional: &[String]) -> bool {
    match positional.get(1).map(String::as_str) {
        Some("route" | "run") => true,
        Some("dhcp") => positional.len() > 2, // `mtcap <device> dhcp` alone is the capture preset
        Some(word) => table_path(word).is_some(),
        None => false,
    }
}

/// `key=value` arguments, in order.
fn pairs(args: &[String]) -> Result<Vec<(String, String)>, String> {
    args.iter()
        .map(|a| a.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())).ok_or_else(|| format!("expected key=value, got {a}")))
        .collect()
}

/// Host names in address properties become addresses; "!name" keeps its negation.
fn addressed(pairs: &mut [(String, String)], names: &HashMap<String, String>) -> Result<(), String> {
    for (key, value) in pairs.iter_mut() {
        if !matches!(key.as_str(), "src-address" | "dst-address" | "address" | "to-addresses") {
            continue;
        }
        let (not, rest) = match value.strip_prefix('!') {
            Some(rest) => ("!", rest),
            None => ("", value.as_str()),
        };
        if rest.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) && !rest.contains(':') {
            *value = format!("{not}{}", resolve_host(rest, names)?);
        }
    }
    Ok(())
}

/// The scheduler script of a rollback: counts its comment down, then runs `action`.
fn undo_script(action: &str) -> String {
    format!(":local c [:tonum [/system scheduler get [find name=\"{UNDO}\"] comment]]; \
:if ($c > 0) do={{/system scheduler set [find name=\"{UNDO}\"] comment=($c - 1)}} \
else={{:do {{{action}}} on-error={{}}; /system scheduler remove [find name=\"{UNDO}\"]}}")
}

fn undo_ids(api: &mut Api) -> Vec<String> {
    api.run(&["/system/scheduler/print", "=.proplist=.id", &format!("?name={UNDO}")]).unwrap_or_default()
        .into_iter().filter_map(|r| r.get(".id").cloned()).collect()
}

fn undo_clear(api: &mut Api) -> Result<(), String> {
    for id in undo_ids(api) {
        api.run(&["/system/scheduler/remove", &format!("=.id={id}")])?;
    }
    Ok(())
}

/// Path of the API ("/ip/firewall/filter") as the console writes it.
fn console(path: &str) -> String {
    path.replace('/', " ").replacen(' ', "/", 1)
}

/// Runs `apply` with a rollback armed on the router; `undo` is the console command that takes
/// the change back. The rollback is disarmed only after a new login to the router succeeds.
fn guarded(api: &mut Api, device: &Device, password: &str, apply: &[&str], undo: &str) -> Result<(), String> {
    if !undo_ids(api).is_empty() {
        return Err("a rollback of an earlier change is still pending on the router; try again in a minute".into());
    }
    api.run(&["/system/scheduler/add", &format!("=name={UNDO}"), "=interval=15s", &format!("=comment={UNDO_LIVES}"),
              "=policy=read,write,test", &format!("=on-event={}", undo_script(undo))])
        .map_err(|e| format!("cannot arm the rollback, nothing changed: {e}"))?;
    if let Err(e) = api.run(apply) {
        let _ = undo_clear(api);
        return Err(e);
    }
    std::thread::sleep(Duration::from_secs(1));
    match connect(device, password).and_then(|mut fresh| fresh.run(&["/system/identity/print"]).map(|_| fresh)) {
        Ok(mut fresh) => undo_clear(&mut fresh).map_err(|e| format!("the change works, but its rollback could not be removed and will undo it: {e}")),
        Err(e) => Err(format!("the router stopped answering after the change ({e}); it takes the change back by itself within a minute")),
    }
}

/// Adds an item disabled, then enables it under a rollback. An item the user asked to be
/// disabled is simply added.
fn guarded_add(api: &mut Api, device: &Device, password: &str, path: &str, pairs: &[(String, String)]) -> Result<String, String> {
    let asked_disabled = pairs.iter().any(|(k, _)| k == "disabled");
    let mut words = vec![format!("{path}/add")];
    words.extend(pairs.iter().map(|(k, v)| format!("={k}={v}")));
    if !asked_disabled {
        words.push("=disabled=yes".into());
    }
    let refs: Vec<&str> = words.iter().map(String::as_str).collect();
    let id = api.run(&refs)?.iter().find_map(|r| r.get("ret").cloned()).ok_or("the router did not say what it added")?;
    if asked_disabled {
        return Ok(id);
    }
    let undo = format!("{} remove {id}", console(path));
    if let Err(e) = guarded(api, device, password, &[&format!("{path}/set"), &format!("=.id={id}"), "=disabled=no"], &undo) {
        let _ = api.run(&[&format!("{path}/remove"), &format!("=.id={id}")]);
        return Err(e);
    }
    Ok(id)
}

/// The row a number from a listing points at.
fn numbered<'a>(rows: &'a [Row], number: Option<&String>, usage: &str) -> Result<(usize, &'a Row), String> {
    let n: usize = number.and_then(|n| n.parse().ok()).ok_or_else(|| format!("usage: {usage}"))?;
    rows.get(n).map(|r| (n, r)).ok_or_else(|| format!("no item {n}: the list has {} (numbers start at 0)", rows.len()))
}

fn flags(row: &Row) -> String {
    [("disabled", 'X'), ("dynamic", 'D'), ("invalid", 'I'), ("active", 'A')].iter()
        .filter(|(key, _)| yes(row, key)).map(|(_, flag)| *flag).collect()
}

// ---------- firewall ----------

const RULE_SKIP: &[&str] = &[".id", ".nextid", "chain", "action", "comment", "bytes", "packets", "disabled", "dynamic", "invalid"];

fn rule_line(n: usize, row: &Row, names: &HashMap<String, String>) -> String {
    let what: Vec<String> = row.iter()
        .filter(|(k, v)| !RULE_SKIP.contains(&k.as_str()) && !v.is_empty() && !(k.as_str() == "log" && v.as_str() == "false"))
        .map(|(k, v)| match names.get(v.as_str()) {
            Some(name) if k.ends_with("address") => format!("{k}={v}({name})"),
            _ => format!("{k}={v}"),
        })
        .collect();
    let comment = get(row, "comment");
    format!("{n:>3} {:<2} {:<12} {:<14} {:>9}  {}{}", flags(row), get(row, "chain"), get(row, "action"), get(row, "packets"),
            what.join(" "), if comment.is_empty() { String::new() } else { format!("  ; {comment}") })
}

fn cmd_rules(opts: &Opts, api: &mut Api, device: &Device, password: &str, names: &HashMap<String, String>, word: &str) -> Result<(), String> {
    let path = table_path(word).unwrap_or("/ip/firewall/filter");
    let arg = |i: usize| opts.positional.get(i);
    let print = format!("{path}/print");
    let sub = arg(2).map_or("list", String::as_str);
    match sub {
        "add" => {
            let mut pairs = pairs(&opts.positional[3..])?;
            if pairs.is_empty() {
                return Err(format!("usage: mtcap <device> {word} add chain=forward src-address=<addr|name> action=drop [place-before=<number>]"));
            }
            addressed(&mut pairs, names)?;
            let rows = api.run(&[&print])?;
            let mut before = String::from("at the end of its chain");
            for (_, value) in pairs.iter_mut().filter(|(k, _)| k == "place-before") {
                let (n, row) = numbered(&rows, Some(&*value), "place-before=<number from the list>")?;
                before = format!("before rule {n}");
                *value = get(row, ".id");
            }
            if !pairs.iter().any(|(k, _)| k == "comment") {
                pairs.push(("comment".into(), opts.comment.clone().unwrap_or_else(|| "mtcap".into())));
            }
            let shown: Vec<String> = pairs.iter().filter(|(k, _)| k != "place-before").map(|(k, v)| format!("{k}={v}")).collect();
            confirm(opts, &format!("{}: add {} — {before}", device.name, shown.join(" ")))?;
            let id = guarded_add(api, device, password, path, &pairs)?;
            let rows = api.run(&[&print])?;
            match rows.iter().position(|r| get(r, ".id") == id) {
                Some(n) => println!("added:\n{}", rule_line(n, &rows[n], names)),
                None => println!("added"),
            }
            eprintln!("rules work top down: if an earlier rule of the chain already decides these packets, this one never sees them. \
                       `mtcap {} {word}` shows the order and the packet counters.", device.name);
        }
        "del" | "on" | "off" => {
            let rows = api.run(&[&print])?;
            let (n, row) = numbered(&rows, arg(3), &format!("mtcap <device> {word} {sub} <number from the list>"))?;
            if yes(row, "dynamic") {
                return Err(format!("rule {n} is dynamic: the router made it and manages it"));
            }
            let id = get(row, ".id");
            let verb = match sub { "del" => "remove", "on" => "enable", _ => "disable" };
            confirm(opts, &format!("{}: {verb}\n{}", device.name, rule_line(n, row, names)))?;
            let set = format!("{path}/set");
            let target = format!("=.id={id}");
            match sub {
                "del" => { api.run(&[&format!("{path}/remove"), &target])?; }
                "on" => guarded(api, device, password, &[&set, &target, "=disabled=no"], &format!("{} set {id} disabled=yes", console(path)))?,
                _ => guarded(api, device, password, &[&set, &target, "=disabled=yes"], &format!("{} set {id} disabled=no", console(path)))?,
            }
            println!("done");
        }
        _ => {
            // `fw`, `fw list`, `fw list forward`, `fw forward`
            let chain = if sub == "list" { arg(3) } else { arg(2) };
            let rows = api.run(&[&print])?;
            println!("{:>3} {:<2} {:<12} {:<14} {:>9}  {}", "#", "", "chain", "action", "packets", "what it matches");
            for (n, row) in rows.iter().enumerate().filter(|(_, r)| chain.is_none_or(|c| &get(r, "chain") == c)) {
                println!("{}", rule_line(n, row, names));
            }
            eprintln!("X disabled, D dynamic, I invalid. Numbers are for `{word} del|on|off <number>` and `{word} add ... place-before=<number>`.");
        }
    }
    Ok(())
}

// ---------- routes ----------

fn prefix(route: &Row) -> u32 {
    get(route, "dst-address").split_once('/').and_then(|(_, len)| len.parse().ok()).unwrap_or(32)
}

/// For every routing table, the active route that carries `address`: longest prefix first,
/// then the smallest distance. The main table comes first.
pub fn best_routes<'a>(routes: &'a [Row], address: &str) -> Vec<&'a Row> {
    let mut best: Vec<&Row> = Vec::new();
    for route in routes.iter().filter(|r| yes(r, "active") && address_fits(address, &get(r, "dst-address"))) {
        let distance = |r: &Row| get(r, "distance").parse::<u32>().unwrap_or(0);
        match best.iter_mut().find(|b| get(b, "routing-table") == get(route, "routing-table")) {
            Some(held) => {
                if (prefix(route), std::cmp::Reverse(distance(route))) > (prefix(held), std::cmp::Reverse(distance(held))) {
                    *held = route;
                }
            }
            None => best.push(route),
        }
    }
    best.sort_by_key(|r| (get(r, "routing-table") != "main", get(r, "routing-table")));
    best
}

fn via(route: &Row) -> String {
    let near = get(route, "immediate-gw");
    let gateway = get(route, "gateway");
    if near.is_empty() || near == gateway { gateway } else { format!("{gateway} ({near})") }
}

fn route_line(n: Option<usize>, route: &Row) -> String {
    format!("{:>3} {:<3} {:<20} {:<38} {:<16} {:>4}  {}", n.map_or(String::new(), |n| n.to_string()), flags(route),
            get(route, "dst-address"), via(route), get(route, "routing-table"), get(route, "distance"), get(route, "comment"))
}

fn cmd_route(opts: &Opts, api: &mut Api, device: &Device, password: &str, names: &HashMap<String, String>) -> Result<(), String> {
    let arg = |i: usize| opts.positional.get(i);
    let path = "/ip/route";
    let header = format!("{:>3} {:<3} {:<20} {:<38} {:<16} {:>4}  {}", "#", "", "destination", "gateway", "table", "dist", "comment");
    match arg(2).map_or("list", String::as_str) {
        "check" => {
            let target = resolve_host(arg(3).ok_or("usage: mtcap <device> route check <address|name>")?, names)?;
            let address = target.split('/').next().unwrap_or(&target).to_string();
            if address.parse::<Ipv4Addr>().is_err() {
                return Err(format!("{address} is not an IPv4 address"));
            }
            let routes = api.run(&["/ip/route/print"])?;
            let best = best_routes(&routes, &address);
            if best.is_empty() {
                println!("no active route to {address} in any table: such packets are dropped as unreachable");
                return Ok(());
            }
            println!("{address} goes:");
            println!("{:<16} {:<20} {:<38} {:>4}  {}", "table", "by route", "gateway", "dist", "comment");
            for route in &best {
                println!("{:<16} {:<20} {:<38} {:>4}  {}", get(route, "routing-table"), get(route, "dst-address"), via(route),
                         get(route, "distance"), get(route, "comment"));
            }
            eprintln!("The main table is used unless a mangle rule or a routing rule picks another one for the connection; \
                       `mtcap conns {} --ip <host>` shows which table live connections got.", device.name);
        }
        "add" => {
            let usage = "usage: mtcap <device> route add <destination> <gateway> [routing-table=<name>] [distance=<n>] [key=value ...]";
            let (Some(dst), Some(gateway)) = (arg(3), arg(4)) else { return Err(usage.into()) };
            if dst.contains('=') || gateway.contains('=') {
                return Err(usage.into());
            }
            let dst = if dst == "default" { "0.0.0.0/0".to_string() } else { dst.clone() };
            let mut pairs = vec![("dst-address".to_string(), dst.clone()), ("gateway".to_string(), gateway.clone())];
            pairs.extend(self::pairs(&opts.positional[5..])?);
            if !pairs.iter().any(|(k, _)| k == "comment") {
                pairs.push(("comment".into(), opts.comment.clone().unwrap_or_else(|| "mtcap".into())));
            }
            let shown: Vec<String> = pairs.iter().map(|(k, v)| format!("{k}={v}")).collect();
            confirm(opts, &format!("{}: add route {}", device.name, shown.join(" ")))?;
            let id = guarded_add(api, device, password, path, &pairs)?;
            let routes = api.run(&["/ip/route/print"])?;
            match routes.iter().position(|r| get(r, ".id") == id) {
                Some(n) => {
                    println!("added:\n{header}\n{}", route_line(Some(n), &routes[n]));
                    if !yes(&routes[n], "active") && !yes(&routes[n], "disabled") {
                        eprintln!("the route is not active: its gateway is unreachable, or another route to the same destination has a smaller distance");
                    }
                }
                None => println!("added"),
            }
        }
        "del" => {
            let routes = api.run(&["/ip/route/print"])?;
            let (n, route) = numbered(&routes, arg(3), "mtcap <device> route del <number from the list>")?;
            if yes(route, "dynamic") {
                return Err(format!("route {n} is dynamic (connected or learned): it goes away with what made it"));
            }
            confirm(opts, &format!("{}: remove route\n{}", device.name, route_line(Some(n), route)))?;
            api.run(&["/ip/route/remove", &format!("=.id={}", get(route, ".id"))])?;
            println!("done");
        }
        sub => {
            let table = if sub == "list" { arg(3) } else { arg(2) };
            let routes = api.run(&["/ip/route/print"])?;
            println!("{header}");
            for (n, route) in routes.iter().enumerate().filter(|(_, r)| table.is_none_or(|t| &get(r, "routing-table") == t)) {
                println!("{}", route_line(Some(n), route));
            }
            eprintln!("A active, D dynamic, X disabled, I invalid. `route check <address>` tells which of them carries an address.");
        }
    }
    Ok(())
}

// ---------- DHCP ----------

fn cmd_dhcp(opts: &Opts, api: &mut Api, device: &Device, names: &HashMap<String, String>) -> Result<(), String> {
    let arg = |i: usize| opts.positional.get(i);
    let usage = "usage: mtcap <device> dhcp make <address|name> [new address]   — keep the address for this host\n       \
                 mtcap <device> dhcp free <address|name>                 — let it go back to the pool";
    let sub = arg(2).map_or("", String::as_str);
    if !matches!(sub, "make" | "free") {
        return Err(usage.into());
    }
    let address = resolve_host(arg(3).ok_or(usage)?, names)?;
    let leases = api.run(&["/ip/dhcp-server/lease/print"])?;
    let lease = leases.iter().find(|l| get(l, "address") == address);
    let who = |l: &Row| format!("{} {} {}", get(l, "address"), get(l, "mac-address"), get(l, "host-name")).trim().to_string();
    if sub == "free" {
        let lease = lease.ok_or_else(|| format!("no lease for {address}"))?;
        if yes(lease, "dynamic") {
            return Err(format!("the lease of {address} is not static: nothing to free"));
        }
        confirm(opts, &format!("{}: remove the static lease {} — the host gets an address from the pool at its next request", device.name, who(lease)))?;
        api.run(&["/ip/dhcp-server/lease/remove", &format!("=.id={}", get(lease, ".id"))])?;
        println!("done");
        return Ok(());
    }
    let wanted = arg(4);
    if let Some(new) = wanted {
        if new.parse::<Ipv4Addr>().is_err() {
            return Err(format!("{new} is not an IPv4 address"));
        }
        if let Some(taken) = leases.iter().find(|l| &get(l, "address") == new && get(l, "address") != address) {
            return Err(format!("{new} already belongs to {}", who(taken)));
        }
    }
    let comment = opts.comment.clone();
    let id = match lease {
        Some(lease) if !yes(lease, "dynamic") && wanted.is_none() && comment.is_none() => {
            println!("{} is already static", who(lease));
            return Ok(());
        }
        Some(lease) => {
            let id = get(lease, ".id");
            let plan = match wanted {
                Some(new) => format!("keep {} for {} instead of {address}", new, who(lease)),
                None => format!("keep the address for {}", who(lease)),
            };
            confirm(opts, &format!("{}: {plan}", device.name))?;
            if yes(lease, "dynamic") {
                api.run(&["/ip/dhcp-server/lease/make-static", &format!("=.id={id}")])?;
            }
            id
        }
        None => {
            // no lease: the host has its address set by hand; bind it by the MAC the router sees
            let arp = api.run(&["/ip/arp/print", &format!("?address={address}")])?;
            let mac = arp.iter().map(|r| get(r, "mac-address")).find(|m| !m.is_empty())
                .ok_or_else(|| format!("{address} has no DHCP lease and the router does not see its MAC: nothing to bind"))?;
            let target = wanted.cloned().unwrap_or_else(|| address.clone());
            confirm(opts, &format!("{}: no lease for {address}; add a static one {target} for {mac}", device.name))?;
            let rows = api.run(&["/ip/dhcp-server/lease/add", &format!("=address={target}"), &format!("=mac-address={mac}")])?;
            let id = rows.iter().find_map(|r| r.get("ret").cloned()).ok_or("the router did not say what it added")?;
            if let Some(comment) = &comment {
                api.run(&["/ip/dhcp-server/lease/set", &format!("=.id={id}"), &format!("=comment={comment}")])?;
            }
            println!("done: {target} is kept for {mac}");
            return Ok(());
        }
    };
    let mut set = vec!["/ip/dhcp-server/lease/set".to_string(), format!("=.id={id}")];
    set.extend(wanted.map(|new| format!("=address={new}")));
    set.extend(comment.map(|c| format!("=comment={c}")));
    if set.len() > 2 {
        let refs: Vec<&str> = set.iter().map(String::as_str).collect();
        api.run(&refs)?;
    }
    match wanted {
        Some(new) => println!("done: the host moves to {new} when it next asks for an address (reconnect it to hurry)"),
        None => println!("done: {address} is kept for this host"),
    }
    Ok(())
}

// ---------- any command ----------

/// `ip route print`, `/ip/route/add dst-address=... gateway=...`, `?name=x` → an API sentence.
/// The flag says whether the command only reads.
pub fn sentence(args: &[String]) -> Result<(Vec<String>, bool), String> {
    let mut path: Vec<&str> = Vec::new();
    let mut rest = Vec::new();
    for arg in args {
        if arg.starts_with('?') {
            rest.push(arg.clone());
        } else if arg.contains('=') {
            rest.push(format!("={arg}"));
        } else if rest.is_empty() {
            path.extend(arg.split(['/', ' ']).filter(|w| !w.is_empty()));
        } else {
            return Err(format!("{arg}: after the first key=value everything must be key=value or ?query"));
        }
    }
    if path.len() < 2 {
        return Err("usage: mtcap <device> run <menu> <command> [key=value ...] [?key=value ...], e.g. run ip address print".into());
    }
    let reads = matches!(path[path.len() - 1], "print" | "getall");
    let mut words = vec![format!("/{}", path.join("/"))];
    words.extend(rest);
    Ok((words, reads))
}

fn cmd_run(opts: &Opts, api: &mut Api, device: &Device) -> Result<(), String> {
    let (words, reads) = sentence(&opts.positional[2..])?;
    if !reads {
        confirm(opts, &format!("{}: {}", device.name, words.join(" ")))?;
    }
    let refs: Vec<&str> = words.iter().map(String::as_str).collect();
    let rows = api.run(&refs)?;
    for row in &rows {
        println!("{}", row.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("  "));
    }
    if rows.is_empty() {
        eprintln!("{}", if reads { "nothing" } else { "done" });
    }
    Ok(())
}

pub fn run(opts: Opts) -> Result<(), String> {
    let config = Config::load()?;
    let device = pick_device(&config, opts.positional.first())?.clone();
    let (mut api, password) = open(&device)?;
    let names = if opts.no_names { HashMap::new() } else { crate::host_names(Some(&mut api), Some(&device), &config) };
    match opts.positional[1].as_str() {
        "dhcp" => cmd_dhcp(&opts, &mut api, &device, &names),
        "route" => cmd_route(&opts, &mut api, &device, &password, &names),
        "run" => cmd_run(&opts, &mut api, &device),
        word => cmd_rules(&opts, &mut api, &device, &password, &names, word),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(pairs: &[(&str, &str)]) -> Row {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn strings(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    #[test]
    fn picks_the_route_of_every_table() {
        let routes = [
            row(&[("dst-address", "0.0.0.0/0"), ("routing-table", "main"), ("gateway", "10.0.0.1"), ("active", "true"), ("distance", "1")]),
            row(&[("dst-address", "8.8.8.8/32"), ("routing-table", "main"), ("gateway", "10.1.0.1"), ("active", "true"), ("distance", "1")]),
            row(&[("dst-address", "8.8.8.0/24"), ("routing-table", "main"), ("gateway", "10.2.0.1"), ("active", "false"), ("distance", "1")]),
            row(&[("dst-address", "0.0.0.0/0"), ("routing-table", "away"), ("gateway", "10.3.0.1"), ("active", "true"), ("distance", "1")]),
            row(&[("dst-address", "192.168.0.0/16"), ("routing-table", "lan"), ("gateway", "bridge"), ("active", "true"), ("distance", "0")]),
        ];
        let best = best_routes(&routes, "8.8.8.8");
        let got: Vec<(String, String)> = best.iter().map(|r| (get(r, "routing-table"), get(r, "gateway"))).collect();
        assert_eq!(got, [("main".to_string(), "10.1.0.1".to_string()), ("away".to_string(), "10.3.0.1".to_string())]);
        assert_eq!(get(best_routes(&routes, "9.9.9.9")[0], "gateway"), "10.0.0.1");
    }

    #[test]
    fn builds_api_sentences() {
        let (words, reads) = sentence(&strings(&["ip", "route", "print", "?routing-table=main"])).unwrap();
        assert_eq!(words, ["/ip/route/print", "?routing-table=main"]);
        assert!(reads);
        let (words, reads) = sentence(&strings(&["/ip/route/add", "dst-address=10.0.0.0/8", "gateway=192.0.2.1"])).unwrap();
        assert_eq!(words, ["/ip/route/add", "=dst-address=10.0.0.0/8", "=gateway=192.0.2.1"]);
        assert!(!reads);
        assert!(sentence(&strings(&["print"])).is_err());
        assert!(sentence(&strings(&["ip", "route", "add", "a=b", "oops"])).is_err());
    }

    #[test]
    fn names_in_rules_become_addresses() {
        let names: HashMap<String, String> = [("192.168.0.10".to_string(), "tv".to_string())].into();
        let mut rule = pairs(&strings(&["chain=forward", "src-address=tv", "dst-address=!192.0.2.0/24", "action=drop"])).unwrap();
        addressed(&mut rule, &names).unwrap();
        assert_eq!(rule[1].1, "192.168.0.10");
        assert_eq!(rule[2].1, "!192.0.2.0/24");
        let mut unknown = pairs(&strings(&["src-address=fridge"])).unwrap();
        assert!(addressed(&mut unknown, &names).is_err());
        assert!(pairs(&strings(&["forward"])).is_err());
    }

    #[test]
    fn knows_its_commands() {
        assert!(handles(&strings(&["home", "dhcp", "make", "tv"])));
        assert!(!handles(&strings(&["home", "dhcp"])));
        assert!(handles(&strings(&["home", "fw"])));
        assert!(handles(&strings(&["home", "route", "check", "8.8.8.8"])));
        assert!(!handles(&strings(&["home", "web"])));
        assert_eq!(console("/ip/firewall/filter"), "/ip firewall filter");
        assert!(undo_script("/ip route remove *1").contains(":do {/ip route remove *1} on-error={}"));
    }
}
