use std::{fs, io};
use std::io::Read;
use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use colored::Colorize;

use network::network::statistics::FinalizedManagerStats;

#[derive(Parser)]
#[clap(version)]
struct Cli {
    #[clap(short, long, parse(from_os_str), value_name = "FILE")]
    file: Option<PathBuf>,

    #[clap(short, long, parse(from_os_str), value_name = "DIR")]
    dir: Option<PathBuf>,
}

fn read_to_string(path: &Option<PathBuf>) -> Result<String> {
    // Bit dirty but it's only for configs so doesn't really matter
    Ok(match path {
        None => {
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf)?;
            buf
        },
        Some(f) => fs::read_to_string(f)?
    })
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let json = read_to_string(&cli.file)?;
    let stats: FinalizedManagerStats = serde_json::from_str(&json)?;
    println!("{}", "Communication:".bold().green());
    println!("\tBytes sent:    {} B", stats.sent_bytes());
    println!("\tMessages sent: {}", stats.sent_count());
    println!();
    println!("{}", "Time:".bold().green());
    for handle_stats in stats.handle_stats() {
        if let Some(duration) = handle_stats.duration() {
            println!("\t{}: {} ms", handle_stats.get_label().as_ref().unwrap().bold(), duration);
            for (label, time) in handle_stats.get_events() {
                println!("\t\t{} after {} ms", label, *time - handle_stats.get_start().unwrap())
            }
        }
    }
    Ok(())
}
