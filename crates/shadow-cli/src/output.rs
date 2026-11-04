#![allow(dead_code)]

use colored::*;

pub fn print_banner() {
    println!(
        "{}",
        "ShadowCLI — Zero-Trust Execution Layer for AI Agents".bold()
    );
}

pub fn print_success(msg: &str) {
    println!("{} {}", "✔".green().bold(), msg);
}

pub fn print_warning(msg: &str) {
    println!("{} {}", "⚠".yellow().bold(), msg);
}

pub fn print_error(msg: &str) {
    eprintln!("{} {}", "✖".red().bold(), msg);
}

pub fn print_info(msg: &str) {
    println!("{} {}", "ℹ".cyan(), msg);
}
