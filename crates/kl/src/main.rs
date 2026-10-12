// SPDX-License-Identifier: Apache-2.0 OR MIT
//! `kl` — Kernel Layer Primitives CLI.

use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

use kl::{probe_kernel, IsolationPlan};

fn print_usage() {
    println!("kl — Kernel Layer Primitives (Landlock LSM, seccomp-BPF, namespaces)");
    println!();
    println!("USAGE:");
    println!("    kl probe              Probe host kernel Landlock and seccomp capabilities");
    println!("    kl verify [PLAN.json] Verify isolation plan invariants");
    println!("    kl --version, -v      Print version information");
    println!("    kl --help, -h         Print this help message");
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        return ExitCode::SUCCESS;
    }

    match args[1].as_str() {
        "--version" | "-v" => {
            println!("kl {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        "--help" | "-h" => {
            print_usage();
            ExitCode::SUCCESS
        }
        "probe" => {
            let report = probe_kernel();
            match serde_json::to_string_pretty(&report) {
                Ok(json) => {
                    println!("{json}");
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("kl: serialization error: {err}");
                    ExitCode::FAILURE
                }
            }
        }
        "verify" => {
            let plan: IsolationPlan = if let Some(path_str) = args.get(2) {
                let path = Path::new(path_str);
                let content = match fs::read_to_string(path) {
                    Ok(c) => c,
                    Err(err) => {
                        eprintln!("kl: failed to read plan file '{}': {err}", path.display());
                        return ExitCode::FAILURE;
                    }
                };
                match serde_json::from_str(&content) {
                    Ok(p) => p,
                    Err(err) => {
                        eprintln!("kl: failed to parse plan JSON: {err}");
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                IsolationPlan::default()
            };

            let violations = plan.validate_invariants();
            if violations.is_empty() {
                println!("kl: isolation plan verified cleanly with zero invariant violations");
                ExitCode::SUCCESS
            } else {
                eprintln!("kl: isolation plan failed validation:");
                for v in violations {
                    eprintln!("  - {v}");
                }
                ExitCode::FAILURE
            }
        }
        unknown => {
            eprintln!("kl: unrecognized command '{unknown}'");
            print_usage();
            ExitCode::FAILURE
        }
    }
}
