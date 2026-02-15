use std::os::unix::io::AsRawFd;

/// Basic dump/restore test using piggie (original test)
pub fn basic_test(criu_bin_path: &str) {
    println!("Running basic test");
    let pid = match std::process::Command::new("test/piggie").output() {
        Ok(p) => String::from_utf8_lossy(&p.stdout).parse().unwrap_or(0),
        Err(e) => panic!("Starting test process failed ({:#?})", e),
    };

    let mut criu = rust_criu::Criu::new_with_criu_path(criu_bin_path.to_string()).unwrap();
    criu.set_pid(pid);

    if let Err(e) = std::fs::create_dir("test/images") {
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            panic!(
                "Creating image directory 'test/images' failed with {:#?}",
                e
            );
        }
    }

    let directory = std::fs::File::open("test/images").unwrap();
    criu.set_images_dir_fd(directory.as_raw_fd());
    criu.set_log_file("dumppp.log".to_string());
    criu.set_log_level(4);

    println!("Dumping PID {}", pid);
    if let Err(e) = criu.dump() {
        panic!("Dumping process failed with {:#?}", e);
    }

    if !std::path::Path::new("test/images/dumppp.log").exists() {
        panic!("Error: Expected log file 'test/images/dumppp.log' missing.");
    }

    criu.set_images_dir_fd(directory.as_raw_fd());
    criu.set_log_level(4);
    criu.set_log_file("restoreee.log".to_string());

    println!("Restoring PID {}", pid);
    if let Err(e) = criu.restore() {
        panic!("Restoring process failed with {:#?}", e);
    }

    if !std::path::Path::new("test/images/restoreee.log").exists() {
        panic!("Error: Expected log file 'test/images/restoreee.log' missing.");
    }

    println!("Cleaning up");
    if let Err(e) = std::fs::remove_dir_all("test/images") {
        panic!(
            "Removing image directory 'test/images' failed with {:#?}",
            e
        );
    }
}
