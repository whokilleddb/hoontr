use std::sync::{Arc, Mutex};
use crate::userenums::ARCH;
use std::path::Path;
use std::fs::File;
use std::io::Read;
use goblin::pe::{header, PE};
use crate::consts::IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR;

pub fn find_opcode(
    targets: Vec<String>, 
    pattern: Vec<u8>,
    arch: ARCH,
    print_lock: Arc<Mutex<()>>) {

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
                for section in pe.sections {
                    let section_name = match str::from_utf8(&section.name) {
                        Ok(v) => v,
                        Err(_e) => continue
                    };

                    if section_name.eq_ignore_ascii_case(".text\0\0\0") { 
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

                        let start = section.pointer_to_raw_data as usize;
                        let size = section.size_of_raw_data as usize;

                        if start + size > buffer.len() {
                            // ".text section extends beyond file size",
                            continue;
                        }
                        let text_data = &buffer[start..start + size];
                        
                        
                        // Search for pattern in .text
                        let mut prnt_hdr = true;
                        let mut j = 0;
                       
                        let mut prnt_msg = String::default();

                        for i in 0..=text_data.len().saturating_sub(pattern.len()) {
                            if &text_data[i..i + pattern.len()] == pattern.as_slice() {
                                j = j+1;
                               
                                if prnt_hdr {
                                    prnt_msg = format!("\n\n[+] Opcode matches found in {} (Arch: {} | Managed DLL: {}) at the following offsets:\n\n\t", target, arch, is_managed_dll);
                                }
                                prnt_hdr = false;
                                
                                prnt_msg = format!("{}0x{:04X}, ", prnt_msg, i);
                                if j%8 == 0 {prnt_msg = format!("{}\n\t", prnt_msg);}
                            }
                        }

                        if !prnt_hdr {
                            let _guard  = print_lock.lock().unwrap();
                            print!("{}\n\n\tTotal matches found: {}", prnt_msg, j);
                        }
                    }
                }
            },
            Err(_) => {
                
            }
        }
    }

    println!();
}
