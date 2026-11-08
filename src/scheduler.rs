//! Lockout-aware spray scheduler.
//!
//! Password spraying is dangerous to the *target* if done carelessly: too many
//! attempts per account trips the lockout policy and can take users offline — a
//! denial of service, not an assessment. credreap's scheduler is built around
//! **not** doing that. It sprays one password across all accounts per round,
//! caps attempts per account per time window, and paces rounds so the window is
//! respected, with jitter and bounded concurrency.
//!
//! This file is protocol-agnostic: it drives any [`Protocol`] implementation.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use owo_colors::OwoColorize;
use tokio::time::{sleep, Instant};

/// Result of a single authentication attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Valid credentials.
    Success,
    /// Reached the service but the credentials were rejected.
    Failure,
    /// The account appears locked / throttled by the target.
    Locked,
    /// Transport or protocol error (not a credential signal).
    Error,
}

/// An authentication mechanism credreap can spray.
#[async_trait::async_trait]
pub trait Protocol: Send + Sync {
    /// Try one username/password pair.
    async fn attempt(&self, user: &str, pass: &str) -> Outcome;
    /// One-line description for the banner.
    fn describe(&self) -> String;
}

/// Pacing policy. Defaults are deliberately conservative.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Max attempts per account within `window`.
    pub attempts_per_window: u32,
    /// Lockout observation window.
    pub window: Duration,
    /// Fixed delay between spray rounds (one password each).
    pub round_delay: Duration,
    /// Random extra delay (0..=jitter) before each attempt.
    pub jitter: Duration,
    /// Maximum concurrent attempts.
    pub concurrency: usize,
    /// Stop testing an account once it yields a hit.
    pub stop_on_success: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            attempts_per_window: 1,
            window: Duration::from_secs(1800), // 30 min — safe under most policies
            round_delay: Duration::from_secs(0),
            jitter: Duration::from_millis(0),
            concurrency: 8,
            stop_on_success: true,
        }
    }
}

/// A valid credential discovered during the spray.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Hit {
    pub user: String,
    pub pass: String,
    pub protocol: String,
}

/// Run a password spray. `passwords` are tried one round at a time across all
/// not-yet-cracked `users`, honouring the lockout policy between rounds.
pub async fn run_spray(
    proto: Arc<dyn Protocol>,
    users: Vec<String>,
    passwords: Vec<String>,
    policy: Policy,
) -> Vec<Hit> {
    let proto_name = proto.describe();
    let mut succeeded: HashSet<String> = HashSet::new();
    let mut hits: Vec<Hit> = Vec::new();

    let mut window_start = Instant::now();
    let mut attempts_this_window: u32 = 0;

    for (round, pass) in passwords.iter().enumerate() {
        // Respect the lockout window: if this round would exceed the per-account
        // allowance, wait out the remainder of the window first.
        if attempts_this_window >= policy.attempts_per_window {
            let elapsed = window_start.elapsed();
            if elapsed < policy.window {
                let wait = policy.window - elapsed;
                println!(
                    "  {} lockout window reached ({} attempts/account) — waiting {}",
                    "⏸".yellow(),
                    policy.attempts_per_window,
                    humantime(wait),
                );
                sleep(wait).await;
            }
            window_start = Instant::now();
            attempts_this_window = 0;
        }

        let targets: Vec<String> = users
            .iter()
            .filter(|u| !succeeded.contains(*u))
            .cloned()
            .collect();
        if targets.is_empty() {
            break;
        }

        println!(
            "  {} round {}/{}  password {}  →  {} account(s)",
            "▸".bright_cyan(),
            round + 1,
            passwords.len(),
            mask(pass).dimmed(),
            targets.len(),
        );

        // Bounded-concurrency sweep of this password across all live accounts.
        let proto = Arc::clone(&proto);
        let jitter = policy.jitter;
        let results: Vec<(String, Outcome)> = stream::iter(targets)
            .map(|user| {
                let proto = Arc::clone(&proto);
                let pass = pass.clone();
                async move {
                    if !jitter.is_zero() {
                        let extra = rand::random::<f64>() * jitter.as_millis() as f64;
                        sleep(Duration::from_millis(extra as u64)).await;
                    }
                    let outcome = proto.attempt(&user, &pass).await;
                    (user, outcome)
                }
            })
            .buffer_unordered(policy.concurrency.max(1))
            .collect()
            .await;

        for (user, outcome) in results {
            match outcome {
                Outcome::Success => {
                    println!(
                        "    {} {} : {}",
                        "✓ HIT".bright_green().bold(),
                        user.bold(),
                        mask(pass).green(),
                    );
                    hits.push(Hit {
                        user: user.clone(),
                        pass: pass.clone(),
                        protocol: proto_name.clone(),
                    });
                    if policy.stop_on_success {
                        succeeded.insert(user);
                    }
                }
                Outcome::Locked => {
                    println!("    {} {} appears locked/throttled", "!".yellow(), user);
                }
                Outcome::Error => {
                    println!("    {} {} transport error", "·".dimmed(), user.dimmed());
                }
                Outcome::Failure => {}
            }
        }

        attempts_this_window += 1;
        if !policy.round_delay.is_zero() && round + 1 < passwords.len() {
            sleep(policy.round_delay).await;
        }
    }

    hits
}

/// Mask a secret for console output (show first/last char only).
pub fn mask(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    match chars.len() {
        0 => "''".to_string(),
        1 | 2 => "*".repeat(chars.len()),
        n => format!("{}{}{}", chars[0], "*".repeat(n - 2), chars[n - 1]),
    }
}

fn humantime(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 60 {
        format!("{}m{:02}s", s / 60, s % 60)
    } else {
        format!("{s}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct Mock {
        calls: AtomicU32,
        hit_user: String,
        hit_pass: String,
    }

    #[async_trait::async_trait]
    impl Protocol for Mock {
        async fn attempt(&self, user: &str, pass: &str) -> Outcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if user == self.hit_user && pass == self.hit_pass {
                Outcome::Success
            } else {
                Outcome::Failure
            }
        }
        fn describe(&self) -> String {
            "mock".into()
        }
    }

    #[tokio::test]
    async fn finds_hit_and_stops_account() {
        let proto = Arc::new(Mock {
            calls: AtomicU32::new(0),
            hit_user: "alice".into(),
            hit_pass: "Winter2025".into(),
        });
        let policy = Policy {
            attempts_per_window: 100,
            window: Duration::from_secs(1),
            round_delay: Duration::ZERO,
            jitter: Duration::ZERO,
            concurrency: 4,
            stop_on_success: true,
        };
        let hits = run_spray(
            proto.clone(),
            vec!["alice".into(), "bob".into()],
            vec!["Spring2025".into(), "Winter2025".into()],
            policy,
        )
        .await;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].user, "alice");
        // alice: 2 attempts (miss, hit); bob: 2 (miss, miss) = 4 total.
        assert_eq!(proto.calls.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn masks_secrets() {
        assert_eq!(mask("Winter2025"), "W********5");
        assert_eq!(mask("ab"), "**");
        assert_eq!(mask(""), "''");
    }
}
