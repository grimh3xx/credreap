//! Hash-cracking orchestration over hashcat.
//!
//! credreap does not implement cracking itself — it drives hashcat: it guesses
//! the hash mode, builds the command, runs it (optionally fanned out across
//! worker nodes by keyspace), and collects the recovered plaintexts. Workers
//! are reached with the system `ssh` binary, so no extra dependency is pulled
//! and the usual key-based auth applies.

use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use owo_colors::OwoColorize;

/// A hashcat mode guess with a human label.
#[derive(Debug, Clone, Copy)]
pub struct ModeGuess {
    pub mode: u32,
    pub label: &'static str,
    /// True when several modes share this format (e.g. MD5 vs NTLM at 32 hex).
    pub ambiguous: bool,
}

/// Guess the hashcat `-m` mode from a sample hash line.
pub fn guess_mode(sample: &str) -> Option<ModeGuess> {
    let s = sample.trim();
    let low = s.to_ascii_lowercase();

    // Prefixed formats are unambiguous.
    if low.starts_with("$2a$") || low.starts_with("$2b$") || low.starts_with("$2y$") {
        return Some(g(3200, "bcrypt", false));
    }
    if low.starts_with("$6$") {
        return Some(g(1800, "sha512crypt", false));
    }
    if low.starts_with("$5$") {
        return Some(g(7400, "sha256crypt", false));
    }
    if low.starts_with("$1$") {
        return Some(g(500, "md5crypt", false));
    }
    if low.starts_with("$argon2") {
        return Some(g(34000, "argon2", false));
    }
    if low.starts_with("{ssha}") {
        return Some(g(111, "ssha (ldap)", false));
    }
    if low.starts_with("$krb5tgs$") {
        return Some(g(13100, "kerberoast (TGS-REP)", false));
    }
    if low.starts_with("$krb5asrep$") {
        return Some(g(18200, "AS-REP roast", false));
    }
    // NetNTLMv2: user::domain:challenge:HMAC:blob
    if s.matches(':').count() >= 4 && s.contains("::") {
        return Some(g(5600, "NetNTLMv2", false));
    }

    // Bare hex digests, keyed by length.
    if is_hex(&low) {
        return match low.len() {
            32 => Some(g(1000, "NTLM / MD5 (ambiguous)", true)),
            40 => Some(g(100, "SHA1", true)),
            64 => Some(g(1400, "SHA-256", false)),
            128 => Some(g(1700, "SHA-512", false)),
            _ => None,
        };
    }
    None
}

fn g(mode: u32, label: &'static str, ambiguous: bool) -> ModeGuess {
    ModeGuess {
        mode,
        label,
        ambiguous,
    }
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Options for a cracking run.
pub struct CrackOpts {
    pub hashcat_bin: String,
    pub hashes_file: String,
    pub wordlist: String,
    pub mode: Option<u32>,
    pub rules: Option<String>,
    pub workers: Vec<String>,
    pub potfile: String,
    pub dry_run: bool,
}

/// Resolve the mode: explicit flag wins, otherwise guess from the first hash.
pub fn resolve_mode(opts: &CrackOpts) -> Result<u32> {
    if let Some(m) = opts.mode {
        return Ok(m);
    }
    let first = std::fs::read_to_string(&opts.hashes_file)
        .with_context(|| format!("reading {}", opts.hashes_file))?
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(str::to_string)
        .context("hash file is empty")?;
    match guess_mode(&first) {
        Some(gm) => {
            let note = if gm.ambiguous {
                " (ambiguous — pass --mode to override)"
                    .yellow()
                    .to_string()
            } else {
                String::new()
            };
            println!(
                "  {} guessed mode {} — {}{}",
                "·".dimmed(),
                gm.mode.to_string().bold(),
                gm.label,
                note
            );
            Ok(gm.mode)
        }
        None => bail!("could not guess hash mode; pass --mode <hashcat -m>"),
    }
}

/// Build the hashcat argument vector for a (sub)task.
fn hashcat_args(
    mode: u32,
    hashes: &str,
    wordlist: &str,
    rules: &Option<String>,
    potfile: &str,
    skip_limit: Option<(u64, u64)>,
) -> Vec<String> {
    let mut a = vec![
        "-m".into(),
        mode.to_string(),
        "-a".into(),
        "0".into(),
        "--quiet".into(),
        "--potfile-path".into(),
        potfile.into(),
        hashes.into(),
        wordlist.into(),
    ];
    if let Some(r) = rules {
        a.push("-r".into());
        a.push(r.clone());
    }
    if let Some((skip, limit)) = skip_limit {
        a.push("-s".into());
        a.push(skip.to_string());
        a.push("-l".into());
        a.push(limit.to_string());
    }
    a
}

/// Run a local crack and return the recovered `hash:plain` lines.
pub fn run_local(opts: &CrackOpts, mode: u32) -> Result<Vec<String>> {
    let args = hashcat_args(
        mode,
        &opts.hashes_file,
        &opts.wordlist,
        &opts.rules,
        &opts.potfile,
        None,
    );
    if opts.dry_run {
        println!(
            "  {} {} {}",
            "dry-run:".dimmed(),
            opts.hashcat_bin,
            args.join(" ")
        );
        return Ok(Vec::new());
    }
    println!("  {} running hashcat (mode {mode})…", "▸".bright_cyan());
    let status = Command::new(&opts.hashcat_bin)
        .args(&args)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("launching {}", opts.hashcat_bin))?;
    // hashcat exits 1 when it exhausts the keyspace without cracking all — not
    // a hard error for us, so we read the potfile regardless.
    let _ = status;
    read_cracked(opts, mode)
}

/// Query hashcat for the recovered plaintexts via `--show`.
pub fn read_cracked(opts: &CrackOpts, mode: u32) -> Result<Vec<String>> {
    let out = Command::new(&opts.hashcat_bin)
        .args([
            "-m",
            &mode.to_string(),
            "--show",
            "--potfile-path",
            &opts.potfile,
            &opts.hashes_file,
        ])
        .output()
        .with_context(|| format!("launching {}", opts.hashcat_bin))?;
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(str::to_string)
        .collect())
}

/// Distribute a crack across worker nodes by splitting the keyspace.
///
/// Each worker runs the same hashcat invocation over a `-s/-l` slice reached via
/// `ssh <worker> …`. This assumes the hash file, wordlist and hashcat exist at
/// the same paths on the workers (a shared mount or prior sync). Returns the
/// merged recovered lines.
pub fn run_distributed(opts: &CrackOpts, mode: u32) -> Result<Vec<String>> {
    let keyspace = hashcat_keyspace(opts, mode)?;
    let n = opts.workers.len() as u64;
    let chunk = keyspace.div_ceil(n);
    println!(
        "  {} keyspace {} split into {} chunk(s) of {}",
        "·".dimmed(),
        keyspace,
        n,
        chunk
    );

    for (i, worker) in opts.workers.iter().enumerate() {
        let skip = i as u64 * chunk;
        if skip >= keyspace {
            break;
        }
        let limit = chunk.min(keyspace - skip);
        let args = hashcat_args(
            mode,
            &opts.hashes_file,
            &opts.wordlist,
            &opts.rules,
            &opts.potfile,
            Some((skip, limit)),
        );
        let remote = format!("{} {}", opts.hashcat_bin, args.join(" "));
        if opts.dry_run {
            println!("  {} ssh {worker} '{remote}'", "dry-run:".dimmed());
            continue;
        }
        println!(
            "  {} dispatch → {worker} [s={skip} l={limit}]",
            "▸".bright_cyan()
        );
        let status = Command::new("ssh")
            .arg(worker)
            .arg(&remote)
            .status()
            .context("launching ssh")?;
        if !status.success() {
            println!("    {} worker {worker} returned non-zero", "!".yellow());
        }
    }
    if opts.dry_run {
        return Ok(Vec::new());
    }
    read_cracked(opts, mode)
}

/// Ask hashcat for the wordlist keyspace (`--keyspace`).
fn hashcat_keyspace(opts: &CrackOpts, mode: u32) -> Result<u64> {
    let mut args = vec![
        "-m".to_string(),
        mode.to_string(),
        "-a".into(),
        "0".into(),
        "--keyspace".into(),
        opts.wordlist.clone(),
    ];
    if let Some(r) = &opts.rules {
        args.push("-r".into());
        args.push(r.clone());
    }
    let out = Command::new(&opts.hashcat_bin)
        .args(&args)
        .output()
        .with_context(|| format!("launching {}", opts.hashcat_bin))?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .rev()
        .find_map(|l| l.trim().parse::<u64>().ok())
        .context("could not read keyspace from hashcat")
}

/// Verify the inputs exist before launching anything.
pub fn preflight(opts: &CrackOpts) -> Result<()> {
    if !Path::new(&opts.hashes_file).is_file() {
        bail!("hash file not found: {}", opts.hashes_file);
    }
    if !Path::new(&opts.wordlist).is_file() {
        bail!("wordlist not found: {}", opts.wordlist);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guesses_prefixed_formats() {
        assert_eq!(
            guess_mode("$2b$12$abcdefghijklmnopqrstuv").unwrap().mode,
            3200
        );
        assert_eq!(guess_mode("$6$salt$hash").unwrap().mode, 1800);
        assert_eq!(guess_mode("$krb5tgs$23$*user*...").unwrap().mode, 13100);
    }

    #[test]
    fn guesses_hex_by_length() {
        let md5 = guess_mode("5f4dcc3b5aa765d61d8327deb882cf99").unwrap();
        assert_eq!(md5.mode, 1000);
        assert!(md5.ambiguous);
        assert_eq!(guess_mode(&"a".repeat(64)).unwrap().mode, 1400);
        assert!(guess_mode("nothex!!").is_none());
    }

    #[test]
    fn args_include_rules_and_slice() {
        let a = hashcat_args(
            1000,
            "h.txt",
            "w.txt",
            &Some("best64.rule".into()),
            "p.pot",
            Some((10, 5)),
        );
        assert!(a.windows(2).any(|w| w == ["-r", "best64.rule"]));
        assert!(a.windows(2).any(|w| w == ["-s", "10"]));
        assert!(a.windows(2).any(|w| w == ["-l", "5"]));
    }
}
