use std::sync::{Arc, Mutex};
use std::path::Path;
use std::fs::File;
use std::io::Read;
use goblin::pe::{header, PE};
use std;
use crate::userenums::ARCH;
use crate::consts::IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR;

pub fn find_exports(
    targets: Vec<String>, 
    pattern: String, 
    arch: ARCH,
    match_case: bool,
    print_lock: Arc<Mutex<()>>
) {

    for target in targets {
        let path = Path::new(&target);
        let mut file = match File::open(&path) {
            Ok(v) => v,
            Err(_e) => continue
        };
        
        let mut buffer = Vec::new();
        match file.read_to_end(&mut buffer) {
            Ok(v) => v,
            Err(_e) => continue
        };
        match PE::parse(&buffer) {
            Ok(pe) => {
                let arch = if arch == ARCH::All {
                    if pe.header.coff_header.machine == header::COFF_MACHINE_X86_64 {
                        "x64"
                    } else if pe.header.coff_header.machine == header::COFF_MACHINE_X86 {
                        "x86"
                    } else {
                        "Unknown"
                    }
                } else if   arch == ARCH::X86 {
                    if pe.header.coff_header.machine != header::COFF_MACHINE_X86 {
                        continue
                    } else {
                        "x86"
                    }
                } else  {
                    if pe.header.coff_header.machine != header::COFF_MACHINE_X86_64 {
                        continue
                    } else {"x64"}
                };

                let is_managed_dll = match pe.header.optional_header {
                    Some(v) => {
                        let data_dir = v.data_directories.data_directories;
                        if data_dir[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].is_some() {"YES"} else {"NO"}
                    },
                    None => continue
                };
                
                let mut msg = format!("\n[+] Matches found in: {} (ARCH: {} | Is Managed DLL: {})\n\n\t", target, arch, is_managed_dll);
                let mut count = 0;


                for exports in  pe.exports {


                    match exports.name {
                        Some(v) => {
                            if match_case {
                                if v.contains(&pattern) {
                                    count = count + 1;
                                    msg = format!("{}{}, ", msg, v);
                                    if count%5 == 0 {msg = format!("{}\n\t", msg);}
                                }
                            } else {
                                if v.to_lowercase().contains(&pattern.to_lowercase()) {
                                    count = count + 1;
                                    msg = format!("{}{}, ", msg, v);
                                    if count%5 == 0 {msg = format!("{}\n\t", msg);}
                                }
                            }

                            // if count%8 == 0 && count != 0 {
                            //     msg = format!("{}\n\t", msg);
                            // }
                        },
                        None => {}
                    }
                }
            
                if count > 0 {
                    let _guard  = print_lock.lock().unwrap();
                    if count < 5 { println!("{}\n\n\tTotal matches found: {}", msg, count);}
                    else {println!("{}\n\tTotal matches found: {}", msg, count);}
                }
            },
            Err(_err) => {}
        }
    }
}