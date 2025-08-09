mod cli;
mod findfiles;

use std::path::Path;

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

fn main() {
    let matches = cli::gen_cli().get_matches();
   
    if !matches.get_flag("nobanner") {
        banner();
    }

    // Get value provided by --path
    let path_str: &String = matches.get_one::<String>("path").unwrap();
    let path: &Path = Path::new(path_str);

    if !path.exists() {
        eprintln!("[-] Path {} does not exist!", path_str);
        return;
    }

    println!("[+] Enumerating artefacts in: {}", path_str);

    // Check if the recurse flag is set
    let recurse = matches.get_flag("recurse");
    if path.is_file() && recurse {
        println!("[!] The `recurse` flag will be ignored as provided path does not point to a directory");
    }

    
    let targets: Vec<String> = findfiles::scan_path(path, recurse);
    println!("[+] Selected {} targets for hoonting", targets.len());


}