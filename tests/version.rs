/// Version check: print CRIU version from $PATH and from the given binary path.
fn version_test(criu_bin_path: &str) {
    let mut criu = rust_criu::Criu::new().unwrap();
    match criu.get_criu_version() {
        Ok(version) => println!("Version from CRIU found in $PATH: {}", version),
        Err(e) => println!("{:#?}", e),
    };

    criu = rust_criu::Criu::new_with_criu_path(criu_bin_path.to_string()).unwrap();
    match criu.get_criu_version() {
        Ok(version) => println!("Version from {}: {}", criu_bin_path, version),
        Err(e) => println!("{:#?}", e),
    };
}

#[test]
fn version() {
    let criu_bin_path =
        std::env::var("CRIU_BINARY").expect("CRIU_BINARY must be set to run integration tests");
    version_test(&criu_bin_path);
}
