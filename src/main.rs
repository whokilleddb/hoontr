mod cli;

fn main() {
    let matches = cli::gen_cli();
    matches.get_matches();

}