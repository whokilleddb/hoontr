use clap::{Arg, ArgAction, Command, crate_name, crate_authors, crate_description, crate_version};


/*
Command line flags to have something like:

Usage: hoontr.exe [OPTIONS] --path <PATH> <COMMAND>

Commands:
  bytehoont    Enumerate for a particular byte sequence
  stomphoont   Enumerate for dlls to stomp
  exporthoont  Enumerate DLLs for exported functions
  help         Print this message or the help of the given subcommand(s)

Options:
  -p, --path <PATH>  Path to file or folder to enumerate
      --nobanner     Do not print intro banner
  -r, --recurse      If the value specified by --path is a directory, recursively enumerate all subdirectories
  -h, --help         Print help

----------------------------------------------------------------------------------------------------------------------

Developer Notes: Why does life have to be all suffering with only moments of reprieve? 

*/
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
    ))
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
    )
    .subcommand_required(true)
    .arg(
        Arg::new("path")
        .short('p')
        .long("path")
        .value_name("PATH")
        .help("Path to file or folder to enumerate")
        .default_value(r"C:\Windows\System32")
        .value_parser(clap::value_parser!(String))
    )
    .arg(
        Arg::new("nobanner")
        .long("nobanner")
        .value_name("NOBANNER")
        .help("Do not print intro banner")
        .action(ArgAction::SetTrue)
    )
    .arg(
        Arg::new("recurse")
        .short('r')
        .long("recurse")
        .value_name("RECURSE")
        .help("If the value specified by --path is a directory, recursively enumerate all subdirectories")
        .action(ArgAction::SetTrue)
    )
    .arg(
        Arg::new("all_pe")
        .long("pe")
        .value_name("ALL_PE")
        .help("Include other PE files like EXEs and CPLs in scope as well")
        .action(ArgAction::SetTrue)
    )
    .arg(
        Arg::new("arch")
        .long("arch")
        .value_name("ARCH")
        .help("Target architecture")
        .default_value("all")
        .value_parser(["all", "x86", "x64"])
    );
    return matches;

}