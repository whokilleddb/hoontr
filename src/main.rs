mod cli;
mod findfiles;
mod stomp;
mod userenums;
mod opcode;
mod consts;
mod export;

use std::{process::exit, thread};
use std::fs;

use std::path::Path;
use num_cpus;
use std::sync::{Arc, Mutex};
use clap::ArgMatches;

fn banner() {
    println!(
    r"
     __  __                          __            
    /\ \/\ \                        /\ \__         
    \ \ \_\ \    ___     ___     ___\ \ ,_\  _ __  
     \ \  _  \  / __`\  / __`\ /' _ `\ \ \/ /\`'__\
      \ \ \ \ \/\ \L\ \/\ \L\ \/\ \/\ \ \ \_\ \ \/ 
       \ \_\ \_\ \____/\ \____/\ \_\ \_\ \__\\ \_\ 
        \/_/\/_/\/___/  \/___/  \/_/\/_/\/__/ \/_/ 
                                               
        A hoontr must hoont - Eileen the crow

    ");
    
}

fn is_path_valid<'a>(matches: &'a ArgMatches) ->&'a Path {
    match matches.subcommand() {
        Some((_name, submatch)) => {
            let path_str: &String = submatch.get_one::<String>("path").unwrap();
            let path = Path::new(path_str);

            if !path.exists() {
                eprintln!("[-] Path {} does not exist!", path_str);
                exit(-1);
            }

            path
        },
        None => unreachable!()
    }
}

fn main() {
    let matches: ArgMatches = cli::gen_cli().get_matches();                         // Get command line arguments
    let mut file_bytes: Vec<u8> = Vec::new();                                       // Save file bytes here
    let disable_banner: bool;                                                       // Do not show banner
    let recurse: bool;                                                              // Recursively search a dir
    let all_pes: bool;                                                               // Search for artefacts in all sorts of PEs
    let th_count = num_cpus::get();                                           // Number of threads
    let print_lock = Arc::new(Mutex::new(()));                 // Create a mutex for synchronized console output
    let mut export_str: String = String::default();                                                         // Exported string to look out for

    // Get value of --arch, --nobanner, --recurse
    let arch = match matches.subcommand() {
        Some((name, submatch)) => {

            // While we are at this, use the --banner
            disable_banner = submatch.get_flag("nobanner");
            recurse = submatch.get_flag("recurse");
            all_pes = submatch.get_flag("all_pes");

            if name.eq_ignore_ascii_case("bytehoont") {
                let bytefile: &String = submatch.get_one::<String>("bytefile").unwrap();
                file_bytes = fs::read(bytefile).unwrap();
            }

            if name.eq_ignore_ascii_case("exporthoont") {
                export_str = submatch.get_one::<String>("func_name").unwrap().clone();
            }

            submatch.get_one::<String>("arch").unwrap().parse::<userenums::ARCH>().unwrap()
        },
        None => unreachable!()
    };

    if !disable_banner {
        banner();
    }

    // Get value of --path
    let path: &Path = is_path_valid(&matches);
    if path.is_file() && recurse {
        println!("[!] The `recurse` flag will be ignored as provided path does not point to a directory");
    }

    let targets: Vec<String> = findfiles::scan_path(path, recurse, all_pes);
    println!("[+] Selected {} targets for hoonting using {} threads", targets.len(), th_count);
    println!("[+] Target path: {}", path.to_str().unwrap());

    // Calculate chunk size for dividing targets
    let chunk_size = (targets.len() + th_count - 1) / th_count; // Ceiling division
    
    // Create thread handles
    let mut handles = Vec::new();

    let subcommand = matches.subcommand().map(|(name, sub)| (name.to_string(), sub.clone()));

    // Divide targets into chunks and create threads
    match &subcommand {
        Some((name, sub_matches)) if name == "stomphoont" => {
            println!("[+] Searching for artefacts with a `.text` section with a virtual size of {} bytes or more\n", sub_matches.get_one::<u32>("shellcode_size").unwrap());
            println!("\t| ARCHITECTURE\t| IS MANAGED?\t| CFG STATUS\t| DLL (VIRTUAL SIZE)");
        },

        Some((name, _sub_matches)) if name == "bytehoont" => {
            print!("[+] Searching for artefacts with a `.text` section with the following bytecode: ");
            for byte in &file_bytes {
                print!("{:02x} ", byte);
            }
        },

        Some((name, _sub_matches)) if name == "exporthoont" => {
            println!("[+] Searching for artefacts which exports the function with the following string: {}", export_str);
        },

        _ => unreachable!()
    }

    for i in 0..th_count {
        let start = i * chunk_size;
        let end = std::cmp::min(start + chunk_size, targets.len());
        
        // Skip if no elements for this thread
        if start >= targets.len() {
            break;
        }
        
        // Clone the chunk for this thread
        let chunk: Vec<String> = targets[start..end].to_vec();
        let print_lock_clone = Arc::clone(&print_lock);

        // Create thread
        match &subcommand {
            Some((name, _sub_matches)) if name == "bytehoont" => { 
                let handle = thread::spawn({
                    let pattern = file_bytes.clone();
                    move || {
                        opcode::find_opcode(chunk, pattern, arch, print_lock_clone);
                    }
                });
                handles.push(handle);  
            },

            Some((name, sub_matches)) if name == "stomphoont" => {
                let shellcode_size = sub_matches.get_one::<u32>("shellcode_size").unwrap();
                let no_cfg = sub_matches.get_flag("no_cfg");

                let handle = thread::spawn({
                    let shellcode_size = *shellcode_size;
                    move || {
                        stomp::check_stompable(chunk, shellcode_size, no_cfg, arch, print_lock_clone);
                    }
                });
                handles.push(handle);
            }

            Some((name, _sub_matches)) if name == "exporthoont" => { 
                let match_case = _sub_matches.get_flag("match_case");
                let handle = thread::spawn({
                    let exp_str = export_str.clone();
                    move || {
                       export::find_exports(chunk, exp_str, arch, match_case, print_lock_clone);
                    }
                });
                handles.push(handle);  
            },

            _ => unreachable!(),
        };
        
    }
    
    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }

}