//! Command-line interface.

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "credreap",
    version,
    about = "Lockout-aware credential spraying + hash-cracking orchestrator",
    long_about = "credreap orchestrates the credential-attack phase of an AUTHORIZED engagement: \
lockout-aware password spraying and hashcat-driven cracking, with a shared credential store. \
It targets only the hosts you specify and paces itself to avoid locking accounts out. \
Use it solely against systems you are explicitly permitted to assess."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Path to the credential store.
    #[arg(long, global = true, default_value = "credreap-creds.json")]
    pub store: String,

    /// Disable colored output.
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Emit machine-readable JSON where applicable.
    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Password-spray an authentication service.
    Spray(SprayArgs),
    /// Orchestrate hash cracking with hashcat.
    Crack(CrackArgs),
    /// Inspect the credential store.
    Creds(CredsArgs),
}

#[derive(clap::ValueEnum, Clone, Debug, Default)]
pub enum Proto {
    /// HTTP Basic or form login.
    #[default]
    Http,
}

#[derive(Parser, Debug)]
pub struct SprayArgs {
    /// Protocol to spray (more to come; HTTP for now).
    #[arg(long, value_enum, default_value_t = Proto::Http)]
    pub proto: Proto,

    /// File with one username per line.
    #[arg(short, long)]
    pub users: String,

    /// File with one password per line (tried one round at a time).
    #[arg(short, long, conflicts_with = "password")]
    pub passwords: Option<String>,

    /// A single password to spray (e.g. a seasonal guess).
    #[arg(long, conflicts_with = "passwords")]
    pub password: Option<String>,

    /// Max attempts per account within the lockout window.
    #[arg(long, default_value_t = 1)]
    pub attempts_per_window: u32,

    /// Lockout window in seconds (defaults to a safe 30 minutes).
    #[arg(long, default_value_t = 1800)]
    pub window: u64,

    /// Fixed delay between spray rounds, in seconds.
    #[arg(long, default_value_t = 0)]
    pub round_delay: u64,

    /// Random extra delay before each attempt, in milliseconds.
    #[arg(long, default_value_t = 0)]
    pub jitter: u64,

    /// Maximum concurrent attempts.
    #[arg(long, default_value_t = 8)]
    pub concurrency: usize,

    /// Keep trying an account after it yields a hit.
    #[arg(long)]
    pub keep_going: bool,

    /// I confirm I am authorized to test this target.
    #[arg(long)]
    pub i_am_authorized: bool,

    // --- HTTP options ---
    /// Target URL.
    #[arg(long)]
    pub url: String,

    /// Use HTTP Basic auth (default is form).
    #[arg(long)]
    pub basic: bool,

    /// Form username field name.
    #[arg(long, default_value = "username")]
    pub user_field: String,

    /// Form password field name.
    #[arg(long, default_value = "password")]
    pub pass_field: String,

    /// Extra static form field, repeatable: --field name=value.
    #[arg(long = "field", value_name = "NAME=VALUE")]
    pub fields: Vec<String>,

    /// Use GET instead of POST for the form.
    #[arg(long)]
    pub get: bool,

    /// Status code(s) that mean success (repeatable).
    #[arg(long = "success-status")]
    pub success_status: Vec<u16>,

    /// Regex on the body that means success.
    #[arg(long)]
    pub success_match: Option<String>,

    /// Regex on the body that means failure (e.g. "Invalid").
    #[arg(long)]
    pub fail_match: Option<String>,

    /// Status code(s) that mean the account is locked (repeatable).
    #[arg(long = "locked-status")]
    pub locked_status: Vec<u16>,

    /// Accept invalid TLS certificates (lab targets).
    #[arg(long)]
    pub insecure: bool,

    /// Per-request timeout in seconds.
    #[arg(long, default_value_t = 15)]
    pub timeout: u64,
}

#[derive(Parser, Debug)]
pub struct CrackArgs {
    /// File of hashes, one per line.
    #[arg(short = 'H', long)]
    pub hashes: String,

    /// Wordlist path.
    #[arg(short, long)]
    pub wordlist: String,

    /// hashcat -m mode (otherwise guessed from the first hash).
    #[arg(short, long)]
    pub mode: Option<u32>,

    /// hashcat rules file.
    #[arg(short, long)]
    pub rules: Option<String>,

    /// Worker hosts to distribute across (repeatable): --worker user@host.
    #[arg(long = "worker")]
    pub workers: Vec<String>,

    /// hashcat binary.
    #[arg(long, default_value = "hashcat")]
    pub hashcat: String,

    /// Potfile path.
    #[arg(long, default_value = "credreap.pot")]
    pub potfile: String,

    /// Print the commands without running them.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Parser, Debug)]
pub struct CredsArgs {
    #[command(subcommand)]
    pub action: CredsAction,
}

#[derive(Subcommand, Debug)]
pub enum CredsAction {
    /// List stored credentials.
    List,
    /// Show password reuse grouped by user.
    Reuse,
    /// Add a credential manually: --user U --secret S [--source X].
    Add {
        #[arg(long)]
        user: String,
        #[arg(long)]
        secret: String,
        #[arg(long, default_value = "manual")]
        source: String,
    },
}
