use clap::{Arg, ArgAction, Command, crate_name, crate_authors, crate_description, crate_version};

// Helper function to create common arguments that will be shared across subcommands
fn common_args() -> Vec<Arg> {
    vec![
        Arg::new("path")
            .short('p')
            .long("path")
            .value_name("PATH")
            .help("Path to file or folder to enumerate")
            .default_value(r"C:\Windows\System32")
            .value_parser(clap::value_parser!(String)),
        
        Arg::new("nobanner")
            .long("nobanner")
            .value_name("NOBANNER")
            .help("Do not print intro banner")
            .action(ArgAction::SetTrue),
        
        Arg::new("recurse")
            .short('r')
            .long("recurse")
            .value_name("RECURSE")
            .help("If the value specified by --path is a directory, recursively enumerate all subdirectories")
            .action(ArgAction::SetTrue),
        
        Arg::new("all_pes")
            .long("pe")
            .value_name("ALL_PES")
            .help("Include other PE files like EXEs and CPLs in scope as well")
            .action(ArgAction::SetTrue),
        
        Arg::new("arch")
            .long("arch")
            .value_name("ARCH")
            .help("Target architecture")
            .default_value("all")
            .value_parser(["all", "x86", "x64"])
    ]
}

pub fn gen_cli() -> Command {
    let matches = Command::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .subcommand(
            Command::new("bytehoont")
                .about("Enumerate for a particular byte sequence")
                .arg(
                    Arg::new("bytefile")
                        .short('f')
                        .long("file")
                        .value_name("BYTE_FILE")
                        .help("Path to a file containing the byte sequence to find")
                        .required(true)
                        .value_parser(clap::value_parser!(String))
                )
                .args(common_args()) // Add common args to this subcommand
        )
        .subcommand(
            Command::new("stomphoont")
                .about("Enumerate for dlls to stomp")
                .arg(
                    Arg::new("shellcode_size")
                        .short('s')
                        .long("size")
                        .value_name("SHELLCODE_SIZE")
                        .help("Minimum size of .text size section to look for")
                        .required(true)
                        .value_parser(clap::value_parser!(u32))
                )
                .arg(
                    Arg::new("no_cfg")
                        .long("no-cfg")
                        .value_name("NO_CFG")
                        .help("Only include DLLs with CFG disabled")
                        .action(ArgAction::SetTrue)
                )
                .args(common_args()) // Add common args to this subcommand
        )
        .subcommand(
            Command::new("exporthoont")
                .about("Enumerate DLLs for exported functions")
                .arg(
                    Arg::new("func_name")
                        .short('n')
                        .long("name")
                        .value_name("FUNC_NAME")
                        .help("String to look for in function names in a case insensitive manner")
                        .required(true)
                        .value_parser(clap::value_parser!(String))
                )
                .args(common_args()) // Add common args to this subcommand
        )
        .subcommand_required(true);
    
    return matches;
}