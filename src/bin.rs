#![deny(warnings)]

mod tests;

use std::path::Path;

use tests::action_script::action_script_test;
use tests::basic::basic_test;
use tests::version::version_test;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        println!("Need exactly one parameter: path to a criu binary");
        std::process::exit(1);
    }

    let criu_bin_path = args[1].clone();
    if !Path::new(&criu_bin_path).is_file() {
        println!("Invalid path to a criu binary");
        std::process::exit(1);
    }

    version_test(&criu_bin_path);
    basic_test(&criu_bin_path);
    action_script_test(&criu_bin_path);
}
