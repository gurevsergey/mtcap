//! Country and owner of an address, from the free DB-IP Lite databases kept on this computer.
//! Nothing is asked from anyone at capture time: tshark and mmdbresolve read the local files.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const KINDS: [&str; 2] = ["country", "asn"];

pub fn dir() -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).filter(|p| p.is_absolute())
        .unwrap_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/share"));
    base.join("mtcap/geoip")
}

fn files() -> Vec<PathBuf> {
    KINDS.iter().map(|k| dir().join(format!("dbip-{k}-lite.mmdb")))
        .filter(|f| fs::metadata(f).is_ok_and(|m| m.len() > 0)).collect()
}

pub fn available() -> bool {
    !files().is_empty()
}

/// The preference that points tshark and Wireshark at the databases.
pub fn tshark_option() -> Option<String> {
    available().then(|| format!("uat:maxmind_db_paths:\"{}\"", dir().display()))
}

/// "US Example LLC" from a country code and an owner, either of which may be missing.
pub fn place(country: &str, owner: &str) -> String {
    [country, owner].iter().filter(|s| !s.is_empty()).copied().collect::<Vec<_>>().join(" ")
}

/// Downloads this month's databases (last month's until the new ones are out).
pub fn update() -> Result<(), String> {
    let month = |args: &[&str]| {
        let out = Command::new("date").args(args).output().ok()?;
        out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    let months: Vec<String> = [month(&["+%Y-%m"]), month(&["-d", "-1 month", "+%Y-%m"])].into_iter().flatten().collect();
    fs::create_dir_all(dir()).map_err(|e| format!("cannot create {}: {e}", dir().display()))?;
    for kind in KINDS {
        let packed = dir().join(format!("{kind}.gz"));
        let mut done = false;
        // the server stalls now and then: give up on a slow transfer quickly and try again
        'tries: for stamp in &months {
            for _ in 0..4 {
                let url = format!("https://download.db-ip.com/free/dbip-{kind}-lite-{stamp}.mmdb.gz");
                let fetched = Command::new("curl")
                    .args(["-sS", "-f", "-L", "--connect-timeout", "8", "--speed-limit", "30000", "--speed-time", "6", "-m", "120", "-o"])
                    .arg(&packed).arg(&url).stderr(Stdio::null()).status().is_ok_and(|s| s.success());
                if fetched && Command::new("gzip").arg("-t").arg(&packed).stderr(Stdio::null()).status().is_ok_and(|s| s.success()) {
                    done = true;
                    break 'tries;
                }
            }
        }
        if !done {
            let _ = fs::remove_file(&packed);
            return Err(format!("could not download the {kind} database from download.db-ip.com; try again later"));
        }
        let unpacked = Command::new("gzip").arg("-dc").arg(&packed).output().map_err(|e| format!("gzip: {e}"))?;
        let target = dir().join(format!("dbip-{kind}-lite.mmdb"));
        fs::write(&target, unpacked.stdout).map_err(|e| format!("cannot write {}: {e}", target.display()))?;
        let _ = fs::remove_file(&packed);
        println!("{}  {} bytes", target.display(), fs::metadata(&target).map(|m| m.len()).unwrap_or(0));
    }
    Ok(())
}

/// mmdbresolve's answer: sections "[address]" with "key: value" lines.
fn parse(text: &str) -> HashMap<String, String> {
    let mut found = HashMap::new();
    let (mut address, mut country, mut owner) = (String::new(), String::new(), String::new());
    for line in text.lines() {
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            address = name.to_string();
            country.clear();
            owner.clear();
        } else if let Some(value) = line.strip_prefix("country.iso_code: ") {
            country = value.to_string();
        } else if let Some(value) = line.strip_prefix("autonomous_system_organization: ") {
            owner = value.to_string();
        } else if line.starts_with("# End ") && address != "init" && !(country.is_empty() && owner.is_empty()) {
            found.insert(address.clone(), place(&country, &owner));
        }
    }
    found
}

/// Country and owner for each address the databases know.
pub fn lookup(addresses: &[String]) -> HashMap<String, String> {
    let files = files();
    if files.is_empty() || addresses.is_empty() {
        return HashMap::new();
    }
    let mut cmd = Command::new("mmdbresolve");
    for file in &files {
        cmd.arg("-f").arg(file);
    }
    let Ok(mut child) = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn() else {
        return HashMap::new();
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all((addresses.join("\n") + "\n").as_bytes());
    }
    child.wait_with_output().map(|out| parse(&String::from_utf8_lossy(&out.stdout))).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mmdbresolve_answers_are_read() {
        let text = "[init]\ndb.0.status: OK\n# End init\n[192.0.2.1]\n# DBIP-Country-Lite\ncountry.iso_code: AU\ncountry.names.en: Australia\n\
                    # DBIP-ASN-Lite\nautonomous_system_organization: Example, Inc.\nautonomous_system_number: 64500\n# End 192.0.2.1\n\
                    [192.168.1.1]\n# DBIP-Country-Lite\n# End 192.168.1.1\n[192.0.2.9]\ncountry.iso_code: NL\n# End 192.0.2.9\n";
        let found = parse(text);
        assert_eq!(found.len(), 2);
        assert_eq!(found["192.0.2.1"], "AU Example, Inc.");
        assert_eq!(found["192.0.2.9"], "NL");
        assert_eq!(place("", "Example"), "Example");
    }
}
