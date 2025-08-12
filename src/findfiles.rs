use std::fs;
use std::path::Path;

pub fn scan_path(path: &Path, recurse: bool, all_pe: bool) -> Vec<String> {
    let mut results = Vec::new();
    
    // If path is a file, return just that file's path
    if path.is_file() {
        results.push(path.to_string_lossy().to_string());
        return results;
    }
    
    // If path is a directory
    if path.is_dir() {
        if recurse {
            // Recursive search
            collect_files_recursive(path, &mut results, all_pe);
        } else {
            // Non-recursive search - only immediate directory
            collect_files_in_directory(path, &mut results, all_pe);
        }
    }
    
    results
}

fn collect_files_recursive(dir: &Path, results: &mut Vec<String>, all_pe: bool) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            
            if path.is_file() {
                if has_target_extension(&path, all_pe) {
                    results.push(path.to_string_lossy().to_string());
                }
            } else if path.is_dir() {
                // Recursively search subdirectories
                collect_files_recursive(&path, results, all_pe);
            }
        }
    }
}

fn collect_files_in_directory(dir: &Path, results: &mut Vec<String>, all_pe: bool) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            
            if path.is_file() && has_target_extension(&path, all_pe) {
                results.push(path.to_string_lossy().to_string());
            }
        }
    }
}

fn has_target_extension(path: &Path, all_pe: bool) -> bool {
    if let Some(extension) = path.extension() {
        if let Some(ext_str) = extension.to_str() {
            let ext_lower = ext_str.to_lowercase();
            if all_pe {
                return ext_lower == "dll" || ext_lower == "exe" || ext_lower == "cpl";
            }
            return ext_lower == "dll"
        }
    }
    false
}