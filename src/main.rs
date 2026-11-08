//! credreap — lockout-aware credential spraying + hash-cracking orchestrator.
//!
//! For AUTHORIZED security assessments only. credreap targets the hosts you
//! name, paces itself to avoid locking accounts out, and keeps recovered
//! credentials in one store. It does not scan the internet, discover targets,
//! or evade detection — it coordinates the credential-attack phase of an
//! engagement you are permitted to run.

mod cli;
mod crack;
mod creds;
mod http;
mod scheduler;

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use owo_colors::OwoColorize;
use regex::Regex;
use reqwest::Method;

use cli::{Cli, Command, CredsAction};
use creds::{Credential, Store};
use http::{HttpMode, HttpProtocol, SuccessRule};
use scheduler::{run_spray, Policy};

#[tokio::main]
async fn main() -> ExitCode {
    let args = Cli::parse();

    if args.no_color || std::env::var_os("NO_COLOR").is_some() {
        owo_colors::set_override(false);
    }
    if !args.json {
        banner();
    }

    let store_path = args.store.clone();
    let result = match args.command {
        Command::Spray(a) => run_spray_cmd(a, &store_path, args.json).await,
        Command::Crack(a) => run_crack_cmd(a, &store_path, args.json),
        Command::Creds(a) => run_creds_cmd(a, &store_path, args.json),
    };

    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("  {} {e:#}", "error:".red().bold());
            ExitCode::from(2)
        }
    }
}

async fn run_spray_cmd(
    a: cli::SprayArgs,
    store_path: &str,
    json: bool,
) -> anyhow::Result<ExitCode> {
    if !a.i_am_authorized {
        eprintln!(
            "  {} spraying is gated: re-run with {} to confirm you are authorized to test this target.",
            "refusing:".red().bold(),
            "--i-am-authorized".bold()
        );
        return Ok(ExitCode::from(2));
    }

    let users = read_lines(&a.users)?;
    let passwords = match (&a.passwords, &a.password) {
        (Some(file), _) => read_lines(file)?,
        (None, Some(p)) => vec![p.clone()],
        (None, None) => anyhow::bail!("provide --passwords <file> or --password <value>"),
    };
    if users.is_empty() || passwords.is_empty() {
        anyhow::bail!("empty user or password list");
    }

    let rule = SuccessRule {
        success_status: a.success_status.clone(),
        success_match: compile_opt(&a.success_match)?,
        fail_match: compile_opt(&a.fail_match)?,
        locked_status: a.locked_status.clone(),
    };
    let mode = if a.basic {
        HttpMode::Basic
    } else {
        HttpMode::Form {
            user_field: a.user_field.clone(),
            pass_field: a.pass_field.clone(),
            extra: parse_fields(&a.fields)?,
            method: if a.get { Method::GET } else { Method::POST },
        }
    };
    let proto: Arc<dyn scheduler::Protocol> = Arc::new(HttpProtocol::new(
        a.url.clone(),
        mode,
        rule,
        a.insecure,
        Duration::from_secs(a.timeout),
    )?);

    let policy = Policy {
        attempts_per_window: a.attempts_per_window,
        window: Duration::from_secs(a.window),
        round_delay: Duration::from_secs(a.round_delay),
        jitter: Duration::from_millis(a.jitter),
        concurrency: a.concurrency,
        stop_on_success: !a.keep_going,
    };

    println!(
        "  {} {}  ·  {} user(s) × {} password(s)  ·  ≤{}/account per {}s",
        "spray".bold(),
        proto.describe().bright_cyan(),
        users.len(),
        passwords.len(),
        policy.attempts_per_window,
        policy.window.as_secs(),
    );
    println!();

    let hits = run_spray(proto, users, passwords, policy).await;

    // Persist hits.
    let path = Path::new(store_path);
    let mut store = Store::load(path)?;
    for h in &hits {
        store.add(Credential {
            user: h.user.clone(),
            secret: h.pass.clone(),
            source: h.protocol.clone(),
            kind: "spray".into(),
        });
    }
    store.save(path)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&hits)?);
    } else {
        println!();
        if hits.is_empty() {
            println!("  {} no valid credentials found.", "·".dimmed());
        } else {
            println!(
                "  {} {} credential(s) recovered → {}",
                "✓".bright_green(),
                hits.len(),
                store_path.bold()
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn run_crack_cmd(a: cli::CrackArgs, store_path: &str, json: bool) -> anyhow::Result<ExitCode> {
    let opts = crack::CrackOpts {
        hashcat_bin: a.hashcat.clone(),
        hashes_file: a.hashes.clone(),
        wordlist: a.wordlist.clone(),
        mode: a.mode,
        rules: a.rules.clone(),
        workers: a.workers.clone(),
        potfile: a.potfile.clone(),
        dry_run: a.dry_run,
    };
    crack::preflight(&opts)?;
    let mode = crack::resolve_mode(&opts)?;

    let cracked = if opts.workers.is_empty() {
        crack::run_local(&opts, mode)?
    } else {
        crack::run_distributed(&opts, mode)?
    };

    // Store cracked "hash:plain" as credentials keyed by hash.
    let path = Path::new(store_path);
    let mut store = Store::load(path)?;
    for line in &cracked {
        if let Some((hash, plain)) = line.rsplit_once(':') {
            store.add(Credential {
                user: hash.to_string(),
                secret: plain.to_string(),
                source: format!("hashcat -m {mode}"),
                kind: "crack".into(),
            });
        }
    }
    store.save(path)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&cracked)?);
    } else {
        println!();
        if cracked.is_empty() {
            println!("  {} nothing recovered (yet).", "·".dimmed());
        } else {
            println!(
                "  {} {} hash(es) cracked → {}",
                "✓".bright_green(),
                cracked.len(),
                store_path.bold()
            );
            for line in cracked.iter().take(20) {
                if let Some((h, p)) = line.rsplit_once(':') {
                    let hp = if h.len() > 24 { &h[..24] } else { h };
                    println!("    {} … : {}", hp.dimmed(), p.green());
                }
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn run_creds_cmd(a: cli::CredsArgs, store_path: &str, json: bool) -> anyhow::Result<ExitCode> {
    let path = Path::new(store_path);
    let mut store = Store::load(path)?;
    match a.action {
        CredsAction::List => {
            if json {
                println!("{}", serde_json::to_string_pretty(&store.credentials)?);
            } else if store.credentials.is_empty() {
                println!("  {} store is empty.", "·".dimmed());
            } else {
                for c in &store.credentials {
                    println!(
                        "    {}  {}  {}  {}",
                        c.user.bold(),
                        scheduler::mask(&c.secret).green(),
                        format!("[{}]", c.kind).dimmed(),
                        c.source.dimmed(),
                    );
                }
            }
        }
        CredsAction::Reuse => {
            let report = store.reuse_report();
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                for (user, secrets) in &report {
                    let tag = if secrets.len() > 1 {
                        format!("{} distinct", secrets.len()).yellow().to_string()
                    } else {
                        "1".dimmed().to_string()
                    };
                    println!("    {}  {} secret(s)", user.bold(), tag);
                }
            }
        }
        CredsAction::Add {
            user,
            secret,
            source,
        } => {
            let added = store.add(Credential {
                user,
                secret,
                source,
                kind: "manual".into(),
            });
            store.save(path)?;
            println!(
                "  {} {}",
                "✓".bright_green(),
                if added { "added" } else { "already present" }
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn read_lines(path: &str) -> anyhow::Result<Vec<String>> {
    let text = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("reading {path}: {e}"))?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect())
}

fn compile_opt(pat: &Option<String>) -> anyhow::Result<Option<Regex>> {
    match pat {
        Some(p) => Ok(Some(Regex::new(p)?)),
        None => Ok(None),
    }
}

fn parse_fields(fields: &[String]) -> anyhow::Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for f in fields {
        let (k, v) = f
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("--field expects NAME=VALUE, got '{f}'"))?;
        out.push((k.to_string(), v.to_string()));
    }
    Ok(out)
}

fn banner() {
    let art = r#"
   ___ ___ ___ ___  ___ ___ ___ _ __
  / __|  _/ -_) _ \| _/ -_) _` | '_ \
  \__|_| \___\___/|_| \___\__,_| .__/   lockout-aware credential ops
                               |_|      authorized engagements only
"#;
    println!("{}", art.bright_cyan());
}
