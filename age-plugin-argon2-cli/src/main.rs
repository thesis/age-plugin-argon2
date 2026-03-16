use std::io;
use std::path::PathBuf;
use std::process;

use age_plugin::run_state_machine;
use clap::Parser;

mod commands;
mod encoding;
mod plugin;

use plugin::Argon2PluginHandler;

#[derive(Debug, Parser)]
#[command(name = "age-plugin-argon2", about = "age plugin for Argon2id password-based encryption")]
struct Args {
    /// Run the given age plugin state machine (internal use by age clients).
    #[arg(long, value_name = "STATE-MACHINE")]
    age_plugin: Option<String>,

    /// Generate a new identity.
    #[arg(long)]
    generate: bool,

    /// Write the generated identity to FILE instead of stdout.
    #[arg(short = 'o', long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Memory cost for Argon2id (KiB, default 65536).
    #[arg(long, value_name = "N", default_value_t = 65536)]
    m_cost: u32,

    /// Time cost for Argon2id (iterations, default 3).
    #[arg(long, value_name = "N", default_value_t = 3)]
    t_cost: u32,

    /// Parallelism for Argon2id (lanes, default 4).
    #[arg(long, value_name = "N", default_value_t = 4)]
    p_cost: u32,

    /// List recipients from an identity file.
    #[arg(long)]
    list: bool,

    /// Identity file to read (required with --list).
    #[arg(short = 'i', long, value_name = "FILE")]
    identity: Option<PathBuf>,
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    if let Some(state_machine) = args.age_plugin {
        return run_state_machine(&state_machine, Argon2PluginHandler);
    }

    if args.generate {
        if let Err(e) = commands::generate::run(
            args.m_cost,
            args.t_cost,
            args.p_cost,
            args.output.as_deref(),
        ) {
            eprintln!("error: {e}");
            process::exit(1);
        }
        return Ok(());
    }

    if args.list {
        let identity_file = match args.identity {
            Some(ref f) => f.as_path(),
            None => {
                eprintln!("error: --list requires -i <identity-file>");
                process::exit(1);
            }
        };
        if let Err(e) = commands::list::run(identity_file) {
            eprintln!("error: {e}");
            process::exit(1);
        }
        return Ok(());
    }

    eprintln!("Usage: age-plugin-argon2 --generate [-o FILE] [--m-cost N] [--t-cost N] [--p-cost N]");
    eprintln!("       age-plugin-argon2 --list -i FILE");
    process::exit(1);
}
