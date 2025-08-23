use anyhow::Result;
use nmap_core::{NmapOptions, RMAP_NAME, RMAP_VERSION, RMAP_URL};
use std::collections::HashMap;

pub struct Cli {
    pub options: NmapOptions,
}

impl Cli {
    pub fn parse(args: &[String]) -> Result<Self> {
        let mut options = NmapOptions::new();
        
        // Simple argument parsing - in a real implementation, use clap
        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                "-V" | "--version" => {
                    print_version();
                    std::process::exit(0);
                }
                "-v" => {
                    options.verbosity += 1;
                }
                "-vv" => {
                    options.verbosity += 2;
                }
                "-d" => {
                    options.debug_level += 1;
                }
                "-dd" => {
                    options.debug_level += 2;
                }
                "-sS" => {
                    options.scan_types = vec![nmap_net::ScanType::Syn];
                }
                "-sT" => {
                    options.scan_types = vec![nmap_net::ScanType::Connect];
                }
                "-sU" => {
                    options.scan_types = vec![nmap_net::ScanType::Udp];
                }
                "-O" => {
                    options.os_detection = true;
                }
                "-sV" => {
                    options.version_detection = true;
                }
                "-sC" => {
                    options.script_scan = true;
                }
                "-A" => {
                    options.os_detection = true;
                    options.version_detection = true;
                    options.script_scan = true;
                    options.traceroute = true;
                }
                "-Pn" => {
                    options.ping_types.clear();
                }
                "-n" => {
                    options.never_resolve = true;
                }
                "-R" => {
                    options.resolve_all = true;
                }
                "--traceroute" => {
                    options.traceroute = true;
                }
                "--packet-trace" => {
                    options.packet_trace = true;
                }
                "--reason" => {
                    options.reason = true;
                }
                "--open" => {
                    options.open_only = true;
                }
                arg if arg.starts_with("-p") => {
                    let port_spec = if arg.len() > 2 {
                        &arg[2..]
                    } else if i + 1 < args.len() {
                        i += 1;
                        &args[i]
                    } else {
                        anyhow::bail!("Port specification required for -p");
                    };
                    // TODO: Parse port specification
                    options.port_specs.push(nmap_net::PortSpec::parse(port_spec)?);
                }
                arg if arg.starts_with("-T") => {
                    let timing = if arg.len() > 2 {
                        &arg[2..]
                    } else if i + 1 < args.len() {
                        i += 1;
                        &args[i]
                    } else {
                        anyhow::bail!("Timing template required for -T");
                    };
                    options.timing_template = parse_timing_template(timing)?;
                }
                arg if !arg.starts_with('-') => {
                    // This is a target
                    options.targets.push(arg.to_string());
                }
                _ => {
                    // Unknown option, add to targets for now
                    if !args[i].starts_with('-') {
                        options.targets.push(args[i].clone());
                    }
                }
            }
            i += 1;
        }
        
        Ok(Self { options })
    }
}

fn parse_timing_template(timing: &str) -> Result<nmap_timing::TimingTemplate> {
    match timing {
        "0" => Ok(nmap_timing::TimingTemplate::Paranoid),
        "1" => Ok(nmap_timing::TimingTemplate::Sneaky),
        "2" => Ok(nmap_timing::TimingTemplate::Polite),
        "3" => Ok(nmap_timing::TimingTemplate::Normal),
        "4" => Ok(nmap_timing::TimingTemplate::Aggressive),
        "5" => Ok(nmap_timing::TimingTemplate::Insane),
        _ => anyhow::bail!("Invalid timing template: {}", timing),
    }
}

fn print_version() {
    println!("{} {} ( {} )", RMAP_NAME, RMAP_VERSION, RMAP_URL);
}

fn print_usage() {
    println!("{} {} ( {} )", RMAP_NAME, RMAP_VERSION, RMAP_URL);
    println!("Usage: rmap [Scan Type(s)] [Options] {{target specification}}");
    println!();
    println!("TARGET SPECIFICATION:");
    println!("  Can pass hostnames, IP addresses, networks, etc.");
    println!("  Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254");
    println!();
    println!("SCAN TECHNIQUES:");
    println!("  -sS: TCP SYN scan");
    println!("  -sT: TCP connect() scan");
    println!("  -sU: UDP scan");
    println!();
    println!("HOST DISCOVERY:");
    println!("  -Pn: Treat all hosts as online -- skip host discovery");
    println!();
    println!("PORT SPECIFICATION:");
    println!("  -p <port ranges>: Only scan specified ports");
    println!("    Ex: -p22; -p1-65535; -p U:53,111,137,T:21-25,80,139,8080");
    println!();
    println!("SERVICE/VERSION DETECTION:");
    println!("  -sV: Probe open ports to determine service/version info");
    println!();
    println!("SCRIPT SCAN:");
    println!("  -sC: equivalent to --script=default");
    println!();
    println!("OS DETECTION:");
    println!("  -O: Enable OS detection");
    println!();
    println!("TIMING AND PERFORMANCE:");
    println!("  -T<0-5>: Set timing template (higher is faster)");
    println!();
    println!("OUTPUT:");
    println!("  -v: Increase verbosity level");
    println!("  -d: Increase debugging level");
    println!("  --reason: Display the reason a port is in a particular state");
    println!("  --open: Only show open (or possibly open) ports");
    println!("  --packet-trace: Show all packets sent and received");
    println!();
    println!("MISC:");
    println!("  -A: Enable OS detection, version detection, script scanning, and traceroute");
    println!("  --traceroute: Trace hop path to each host");
    println!("  -n: Never do DNS resolution");
    println!("  -R: Always resolve [default: sometimes]");
    println!("  -V: Print version number");
    println!("  -h: Print this help summary page");
    println!();
    println!("EXAMPLES:");
    println!("  nmap -v -A scanme.nmap.org");
    println!("  nmap -v -sn 192.168.0.0/16 10.0.0.0/8");
    println!("  nmap -v -iR 10000 -Pn -p 80");
}