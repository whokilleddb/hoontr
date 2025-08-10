use std::thread;
use std::sync::{Arc, Mutex};
use std::path::Path;
use std::fs::File;
use std::io::Read;
use goblin::pe::{header, PE};
use std::str;

const IMAGE_DLLCHARACTERISTICS_GUARD_CF: u16 = 0x4000;
const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;

pub fn hoont_stomps(
    targets: Vec<String>,       // List of targets 
    th_count: usize,            // thread count
    threshold_size: u32         // minimum size of .text section
) {
    println!("\n\tVIRTUAL SIZE\t| ARCHITECTURE\t| IS MANAGED?\t| CFG STATUS\t|DLL");

    // Create a mutex for synchronized console output
    let print_lock = Arc::new(Mutex::new(()));
    
    // Calculate chunk size for dividing targets
    let chunk_size = (targets.len() + th_count - 1) / th_count; // Ceiling division
    
    // Create thread handles
    let mut handles = Vec::new();

    // Divide targets into chunks and create threads
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
        let handle = thread::spawn(move || {
            check_stompable(chunk, threshold_size, print_lock_clone);
        });
        
        handles.push(handle);
    }
    
    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }
}

fn check_stompable(
    targets: Vec<String>, 
    threshold_size: u32, 
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
                                                "ENABLED"
                                            } else {
                                                "DISABLED"
                                            }
                                            
                                        },
                                        None => "UNKNOWN"
                                    }
                                },
                                _ => "UNKNOWN"
                            };
                            
                            let _guard = print_lock.lock().unwrap();
                            println!("\t{}\t\t| {}\t\t| {}\t\t| {}\t| {}",
                                section.virtual_size, 
                                if pe.header.coff_header.machine == header::COFF_MACHINE_X86_64 {"x64"} else if pe.header.coff_header.machine == header::COFF_MACHINE_X86 {"x86"} else {"Unknown"},
                                if is_managed_dll { "YES"} else {"NO"},
                                cfg_status,
                                target,
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
