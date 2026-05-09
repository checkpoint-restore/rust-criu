#![deny(warnings)]

mod tests;

use std::path::Path;

use tests::action_script::action_script_test;
use tests::basic::basic_test;
use tests::external_netns::external_netns_test;
use tests::lazy_pages::lazy_pages_test;
use tests::orphan_pts::orphan_pts_master_test;
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
    external_netns_test(&criu_bin_path);
    orphan_pts_master_test(&criu_bin_path);
    lazy_pages_test(&criu_bin_path);
}
