//! Passwords: environment, the desktop keyring (secret-tool), or a prompt.

use std::io::{BufRead, Write};
use std::process::{Command, Stdio};

fn keyring(args: &[&str], input: Option<&str>) -> Option<String> {
    let mut child = Command::new("secret-tool")
        .args(args)
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    if let (Some(text), Some(mut stdin)) = (input, child.stdin.take()) {
        let _ = stdin.write_all(text.as_bytes());
    }
    let out = child.wait_with_output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim_end_matches('\n').to_string())
}

pub fn lookup(device: &str) -> Option<String> {
    keyring(&["lookup", "service", "mtcap", "device", device], None).filter(|p| !p.is_empty())
}

pub fn store(device: &str, password: &str) -> bool {
    let label = format!("--label=mtcap: {device}");
    keyring(&["store", &label, "service", "mtcap", "device", device], Some(password)).is_some()
}

pub fn forget(device: &str) {
    let _ = keyring(&["clear", "service", "mtcap", "device", device], None);
}

fn tty_echo(on: bool) {
    let _ = Command::new("stty").arg(if on { "echo" } else { "-echo" }).stdin(Stdio::inherit()).status();
}

/// Reads a line from the terminal without echo.
pub fn prompt(question: &str) -> Result<String, String> {
    eprint!("{question}");
    let _ = std::io::stderr().flush();
    tty_echo(false);
    let mut line = String::new();
    let read = std::io::stdin().lock().read_line(&mut line);
    tty_echo(true);
    eprintln!();
    match read {
        Ok(n) if n > 0 => Ok(line.trim_end_matches(['\n', '\r']).to_string()),
        _ => Err("no password given".into()),
    }
}

pub fn ask_yes(question: &str) -> bool {
    eprint!("{question} [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    matches!(line.trim(), "y" | "Y" | "yes" | "д" | "да")
}
