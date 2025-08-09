use clap::{Parser, ValueEnum};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Parser)]
#[command(author, version, about = "PE Hunter - Hunt for artifacts in PE files", long_about = None)]
struct Args {
    /// Base directory to search for artifacts in
    #[arg(long)]
    dir: PathBuf,

    /// Recursively search subdirectories
    #[arg(long)]
    recurse: bool,

    /// Do not print banner
    #[arg(long)]
    quiet: bool,

    /// Hunting mode
    #[arg(long, value_enum)]
    mode: Mode,

    /// File containing bytes to search for (bytehoont mode)
    #[arg(long)]
    file: Option<PathBuf>,

    /// Minimum size for .text section (sizehoont mode)
    #[arg(long)]
    size: Option<u64>,

    /// Function name to search for (namehoont mode)
    #[arg(long)]
    name: Option<String>,
}

#[derive(Clone, ValueEnum)]
enum Mode {
    Bytehoont,
    Sizehoont,
    Namehoont,
}

// PE structures
#[repr(C)]
struct ImageDosHeader {
    e_magic: u16,
    _unused: [u8; 58],
    e_lfanew: u32,
}

#[repr(C)]
struct ImageNtHeaders32 {
    signature: u32,
    file_header: ImageFileHeader,
    optional_header: ImageOptionalHeader32,
}

#[repr(C)]
struct ImageNtHeaders64 {
    signature: u32,
    file_header: ImageFileHeader,
    optional_header: ImageOptionalHeader64,
}

#[repr(C)]
struct ImageFileHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[repr(C)]
struct ImageOptionalHeader32 {
    magic: u16,
    _unused1: [u8; 94],
    number_of_rva_and_sizes: u32,
    data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
struct ImageOptionalHeader64 {
    magic: u16,
    _unused1: [u8; 110],
    number_of_rva_and_sizes: u32,
    data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
struct ImageDataDirectory {
    virtual_address: u32,
    size: u32,
}

#[derive(Copy, Clone)]
#[repr(C)]
struct ImageSectionHeader {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_line_numbers: u32,
    number_of_relocations: u16,
    number_of_line_numbers: u16,
    characteristics: u32,
}

#[repr(C)]
struct ImageExportDirectory {
    characteristics: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    name: u32,
    base: u32,
    number_of_functions: u32,
    number_of_names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_name_ordinals: u32,
}

struct TextSection {
    data: Vec<u8>,
    virtual_address: u32,
    size: u32,
}

fn print_banner() {
    println!(r#"
 ____  _____   _   _             _            
|  _ \| ____| | | | |_   _ _ __ | |_ ___ _ __ 
| |_) |  _|   | |_| | | | | '_ \| __/ _ \ '__|
|  __/| |___  |  _  | |_| | | | | ||  __/ |   
|_|   |_____| |_| |_|\__,_|_| |_|\__\___|_|   
                                             
PE Hunter v1.0 - Hunt for artifacts in PE files
"#);
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    if !args.quiet {
        print_banner();
    }

    // Validate arguments based on mode
    match args.mode {
        Mode::Bytehoont => {
            if args.file.is_none() {
                eprintln!("Error: --file is required for bytehoont mode");
                std::process::exit(1);
            }
        }
        Mode::Sizehoont => {
            if args.size.is_none() {
                eprintln!("Error: --size is required for sizehoont mode");
                std::process::exit(1);
            }
        }
        Mode::Namehoont => {
            if args.name.is_none() {
                eprintln!("Error: --name is required for namehoont mode");
                std::process::exit(1);
            }
        }
    }

    let files = collect_pe_files(&args.dir, args.recurse)?;
    
    match args.mode {
        Mode::Bytehoont => {
            let search_bytes = fs::read(args.file.unwrap())?;
            bytehoont_mode(&files, &search_bytes)?;
        }
        Mode::Sizehoont => {
            sizehoont_mode(&files, args.size.unwrap())?;
        }
        Mode::Namehoont => {
            namehoont_mode(&files, &args.name.unwrap())?;
        }
    }

    Ok(())
}

fn collect_pe_files(dir: &Path, recurse: bool) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    
    if recurse {
        for entry in WalkDir::new(dir).follow_links(false) {
            let entry = entry.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            let path = entry.path();
            
            if is_pe_file(path) {
                files.push(path.to_path_buf());
            }
        }
    } else {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_file() && is_pe_file(&path) {
                files.push(path);
            }
        }
    }
    
    Ok(files)
}

fn is_pe_file(path: &Path) -> bool {
    if let Some(ext) = path.extension() {
        let ext = ext.to_string_lossy().to_lowercase();
        ext == "exe" || ext == "dll"
    } else {
        false
    }
}

fn bytehoont_mode(files: &[PathBuf], search_bytes: &[u8]) -> io::Result<()> {
    println!("Running bytehoont mode - searching for byte sequence in .text sections");
    println!("Search pattern length: {} bytes\n", search_bytes.len());
    
    for file in files {
        match extract_text_section(file) {
            Ok(Some(text_section)) => {
                let matches = find_byte_pattern(&text_section.data, search_bytes);
                if !matches.is_empty() {
                    println!("File: {}", file.display());
                    println!("  .text section size: {} bytes", text_section.size);
                    println!("  Found {} matches:", matches.len());
                    for offset in matches {
                        println!("    Offset: 0x{:08X} (RVA: 0x{:08X})", 
                                offset, text_section.virtual_address + offset as u32);
                    }
                    println!();
                }
            }
            Ok(None) => {
                println!("Warning: No .text section found in {}", file.display());
            }
            Err(e) => {
                println!("Error analyzing {}: {}", file.display(), e);
            }
        }
    }
    
    Ok(())
}

fn sizehoont_mode(files: &[PathBuf], min_size: u64) -> io::Result<()> {
    println!("Running sizehoont mode - searching for .text sections >= {} bytes\n", min_size);
    
    let mut matches = Vec::new();
    
    for file in files {
        match extract_text_section(file) {
            Ok(Some(text_section)) => {
                if text_section.size as u64 >= min_size {
                    matches.push((file.clone(), text_section.size));
                }
            }
            Ok(None) => {
                println!("Warning: No .text section found in {}", file.display());
            }
            Err(e) => {
                println!("Error analyzing {}: {}", file.display(), e);
            }
        }
    }
    
    if matches.is_empty() {
        println!("No files found with .text section >= {} bytes", min_size);
    } else {
        println!("Found {} files with .text section >= {} bytes:", matches.len(), min_size);
        matches.sort_by(|a, b| b.1.cmp(&a.1)); // Sort by size descending
        
        for (file, size) in matches {
            println!("  {} - {} bytes", file.display(), size);
        }
    }
    
    Ok(())
}

fn namehoont_mode(files: &[PathBuf], search_name: &str) -> io::Result<()> {
    println!("Running namehoont mode - searching for exported functions containing '{}'\n", search_name);
    
    let search_name_lower = search_name.to_lowercase();
    let mut total_matches = 0;
    
    for file in files {
        match get_exported_functions(file) {
            Ok(exports) => {
                let mut file_matches = Vec::new();
                
                for export in exports {
                    if export.to_lowercase().contains(&search_name_lower) {
                        file_matches.push(export);
                    }
                }
                
                if !file_matches.is_empty() {
                    println!("File: {}", file.display());
                    println!("  Found {} matching exports:", file_matches.len());
                    for export in file_matches {
                        println!("    {}", export);
                    }
                    println!();
                    total_matches += 1;
                }
            }
            Err(e) => {
                if !e.to_string().contains("No export table") {
                    println!("Error analyzing {}: {}", file.display(), e);
                }
            }
        }
    }
    
    if total_matches == 0 {
        println!("No exported functions found containing '{}'", search_name);
    }
    
    Ok(())
}

fn extract_text_section(path: &Path) -> io::Result<Option<TextSection>> {
    let mut file = fs::File::open(path)?;
    let mut buffer = [0u8; 1024];
    
    // Read DOS header
    file.read_exact(&mut buffer[..64])?;
    let dos_header = unsafe { &*(buffer.as_ptr() as *const ImageDosHeader) };
    
    if dos_header.e_magic != 0x5A4D {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid DOS signature"));
    }
    
    // Seek to NT headers
    file.seek(SeekFrom::Start(dos_header.e_lfanew as u64))?;
    file.read_exact(&mut buffer[..4])?;
    let nt_signature = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    
    if nt_signature != 0x00004550 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid NT signature"));
    }
    
    // Read file header
    file.read_exact(&mut buffer[..20])?;
    let file_header = unsafe { &*(buffer.as_ptr() as *const ImageFileHeader) };
    
    // Skip optional header
    file.seek(SeekFrom::Current(file_header.size_of_optional_header as i64))?;
    
    // Read section headers
    let section_size = std::mem::size_of::<ImageSectionHeader>();
    for _ in 0..file_header.number_of_sections {
        file.read_exact(&mut buffer[..section_size])?;
        let section = unsafe { &*(buffer.as_ptr() as *const ImageSectionHeader) };
        
        let section_name = std::str::from_utf8(&section.name)
            .unwrap_or("")
            .trim_end_matches('\0');
            
        if section_name == ".text" {
            // Read the .text section data
            let current_pos = file.stream_position()?;
            file.seek(SeekFrom::Start(section.pointer_to_raw_data as u64))?;
            
            let mut text_data = vec![0u8; section.size_of_raw_data as usize];
            file.read_exact(&mut text_data)?;
            
            file.seek(SeekFrom::Start(current_pos))?;
            
            return Ok(Some(TextSection {
                data: text_data,
                virtual_address: section.virtual_address,
                size: section.size_of_raw_data,
            }));
        }
    }
    
    Ok(None)
}

fn find_byte_pattern(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut matches = Vec::new();
    
    if needle.is_empty() || haystack.len() < needle.len() {
        return matches;
    }
    
    for i in 0..=haystack.len() - needle.len() {
        if &haystack[i..i + needle.len()] == needle {
            matches.push(i);
        }
    }
    
    matches
}

fn get_exported_functions(path: &Path) -> io::Result<Vec<String>> {
    let mut file = fs::File::open(path)?;
    let mut buffer = [0u8; 1024];
    
    // Read DOS header
    file.read_exact(&mut buffer[..64])?;
    let dos_header = unsafe { &*(buffer.as_ptr() as *const ImageDosHeader) };
    
    if dos_header.e_magic != 0x5A4D {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid DOS signature"));
    }
    
    // Seek to NT headers
    file.seek(SeekFrom::Start(dos_header.e_lfanew as u64))?;
    file.read_exact(&mut buffer[..4])?;
    let nt_signature = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    
    if nt_signature != 0x00004550 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid NT signature"));
    }
    
    // Read file header
    file.read_exact(&mut buffer[..20])?;
    let file_header = unsafe { &*(buffer.as_ptr() as *const ImageFileHeader) };
    
    // Read optional header to get export table RVA
    let optional_header_pos = file.stream_position()?;
    let export_table_rva = if file_header.size_of_optional_header == 224 {
        // 32-bit
        file.read_exact(&mut buffer[..224])?;
        let opt_header = unsafe { &*(buffer.as_ptr() as *const ImageOptionalHeader32) };
        opt_header.data_directory[0].virtual_address
    } else {
        // 64-bit
        file.read_exact(&mut buffer[..240])?;
        let opt_header = unsafe { &*(buffer.as_ptr() as *const ImageOptionalHeader64) };
        opt_header.data_directory[0].virtual_address
    };
    
    if export_table_rva == 0 {
        return Err(io::Error::new(io::ErrorKind::NotFound, "No export table"));
    }
    
    // Find the section containing the export table
    file.seek(SeekFrom::Start(optional_header_pos + file_header.size_of_optional_header as u64))?;
    
    let mut sections = HashMap::new();
    let section_size = std::mem::size_of::<ImageSectionHeader>();
    
    for _ in 0..file_header.number_of_sections {
        file.read_exact(&mut buffer[..section_size])?;
        let section = unsafe { &*(buffer.as_ptr() as *const ImageSectionHeader) };
        sections.insert(section.virtual_address, *section);
    }
    
    // Find which section contains the export table
    let export_section = sections.values()
        .find(|s| export_table_rva >= s.virtual_address && 
                  export_table_rva < s.virtual_address + s.virtual_size)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Export table section not found"))?;
    
    // Calculate file offset
    let export_file_offset = export_section.pointer_to_raw_data + 
                            (export_table_rva - export_section.virtual_address);
    
    // Read export directory
    file.seek(SeekFrom::Start(export_file_offset as u64))?;
    file.read_exact(&mut buffer[..40])?;
    let export_dir = unsafe { &*(buffer.as_ptr() as *const ImageExportDirectory) };
    
    // Read export names
    let names_rva = export_dir.address_of_names;
    let names_section = sections.values()
        .find(|s| names_rva >= s.virtual_address && 
                  names_rva < s.virtual_address + s.virtual_size)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Names section not found"))?;
    
    let names_file_offset = names_section.pointer_to_raw_data + 
                           (names_rva - names_section.virtual_address);
    
    // Read name pointers
    file.seek(SeekFrom::Start(names_file_offset as u64))?;
    let mut name_pointers = vec![0u32; export_dir.number_of_names as usize];
    for i in 0..export_dir.number_of_names as usize {
        file.read_exact(&mut buffer[..4])?;
        name_pointers[i] = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    }
    
    // Read actual names
    let mut export_names = Vec::new();
    for name_rva in name_pointers {
        let name_section = sections.values()
            .find(|s| name_rva >= s.virtual_address && 
                      name_rva < s.virtual_address + s.virtual_size)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Name string section not found"))?;
        
        let name_file_offset = name_section.pointer_to_raw_data + 
                              (name_rva - name_section.virtual_address);
        
        file.seek(SeekFrom::Start(name_file_offset as u64))?;
        let mut name_bytes = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            file.read_exact(&mut byte)?;
            if byte[0] == 0 {
                break;
            }
            name_bytes.push(byte[0]);
        }
        
        if let Ok(name) = String::from_utf8(name_bytes) {
            export_names.push(name);
        }
    }
    
    Ok(export_names)
}
