use std::fs;
use std::path::Path;

pub fn scan_path(path: &Path, recurse: bool) -> Vec<String> {
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
            collect_files_recursive(path, &mut results);
        } else {
            // Non-recursive search - only immediate directory
            collect_files_in_directory(path, &mut results);
        }
    }
    
    results
}

fn collect_files_recursive(dir: &Path, results: &mut Vec<String>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            
            if path.is_file() {
                if has_target_extension(&path) {
                    results.push(path.to_string_lossy().to_string());
                }
            } else if path.is_dir() {
                // Recursively search subdirectories
                collect_files_recursive(&path, results);
            }
        }
    }
}

fn collect_files_in_directory(dir: &Path, results: &mut Vec<String>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            
            if path.is_file() && has_target_extension(&path) {
                results.push(path.to_string_lossy().to_string());
            }
        }
    }
}

fn has_target_extension(path: &Path) -> bool {
    if let Some(extension) = path.extension() {
        if let Some(ext_str) = extension.to_str() {
            let ext_lower = ext_str.to_lowercase();
            return ext_lower == "dll" || ext_lower == "exe" || ext_lower == "cpl";
        }
    }
    false
}