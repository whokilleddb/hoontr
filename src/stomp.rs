use std::sync::{Arc, Mutex};
use std::path::Path;
use std::fs::File;
use std::io::Read;
use goblin::pe::{header, PE};
use std::str;
use std;
use crate::userenums::ARCH;
use crate::consts::{IMAGE_DLLCHARACTERISTICS_GUARD_CF, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR};

pub fn check_stompable(
    targets: Vec<String>, 
    threshold_size: u32, 
    show_no_cfg_only: bool,
    arch: ARCH,
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
                for section in pe.sections {
                    let section_name = match str::from_utf8(&section.name) {
                        Ok(v) => v,
                        Err(_e) => continue
                    };
                    
                    if section_name.eq_ignore_ascii_case(".text\0\0\0") { 
                        if section.virtual_size >= threshold_size {
                            
                            let is_managed_dll = match pe.header.optional_header {
                                Some(v) => {
                                    let data_dir = v.data_directories.data_directories;
                                    data_dir[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].is_some()
                                },
                                None => continue
                            };

                            let cfg_status: &str = match pe.header.coff_header.machine {
                                header::COFF_MACHINE_X86 | header::COFF_MACHINE_X86_64=> {
                                    match pe.header.optional_header{
                                        Some(opt_hdr) => {
                                            if opt_hdr.windows_fields.dll_characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF != 0 {
                                               if show_no_cfg_only {
                                                continue;
                                               } else {
                                                "ENABLED"
                                               }
                                            } else {
                                                "DISABLED"
                                            }
                                            
                                        },
                                        None => "UNKNOWN"
                                    }
                                },
                                _ => "UNKNOWN"
                            };
                            
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

                            let _guard = print_lock.lock().unwrap();
                            println!("\t| {}\t\t| {}\t\t| {}\t| {} ({})",
                                arch,
                                if is_managed_dll { "YES"} else {"NO"},
                                cfg_status,
                                target,
                                section.virtual_size, 
                            );
                            // let is_cfg_enabled: bool = pe.header.optional_header.map(
                                
                            
                        }
                    }
                }
            },
            Err(_err) => {

            }
        }
    }
}
