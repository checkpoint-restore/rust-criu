#![deny(warnings)]

use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Counter for notify actions (similar to test_notify.c's actions_called)
static ACTIONS_CALLED: AtomicUsize = AtomicUsize::new(0);

/// CRIU notification callback (similar to test_notify.c's notify function)
fn notify_callback(
    action: &str,
    _notify: &rust_criu::rust_criu_protobuf::rpc::Criu_notify,
    _fds: &[RawFd],
) -> i32 {
    println!("ACTION: {}", action);
    ACTIONS_CALLED.fetch_add(1, Ordering::SeqCst);
    0
}

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

    // Run tests
    println!("--- Version Test ---");
    version_test(&criu_bin_path);

    println!("\n--- Basic Test (piggie) ---");
    basic_test(&criu_bin_path);

    println!("\n--- Notify Test (loop) ---");
    notify_test(&criu_bin_path);

    println!("\n=== All tests passed! ===");
}

/// Version check test
fn version_test(criu_bin_path: &str) {
    // Test Criu::new() (uses PATH)
    let mut criu = rust_criu::Criu::new().unwrap();
    match criu.get_criu_version() {
        Ok(version) => println!("Version from $PATH: {}", version),
        Err(e) => println!("$PATH lookup failed: {:#?}", e),
    };

    // Test Criu::new_with_criu_path()
    let mut criu = rust_criu::Criu::new_with_criu_path(criu_bin_path.to_string()).unwrap();
    match criu.get_criu_version() {
        Ok(version) => println!("Version from {}: {}", criu_bin_path, version),
        Err(e) => panic!("Version check failed: {:#?}", e),
    };

    println!("Version test: PASS");
}

/// Basic dump/restore test using piggie (original test)
fn basic_test(criu_bin_path: &str) {
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

    println!("Basic test: PASS");
}

/// Notify callback test using loop binary
/// Based on CRIU's test/others/libcriu/test_notify.c
fn notify_test(criu_bin_path: &str) {
    // Reset action counter
    ACTIONS_CALLED.store(0, Ordering::SeqCst);

    // Start loop process
    println!("--- Start loop ---");
    let mut child = match std::process::Command::new("test/loop")
        .stdout(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => panic!("Starting loop process failed: {:#?}", e),
    };

    // Read PID from child
    let pid: i32 = {
        use std::io::BufRead;
        let stdout = child.stdout.take().unwrap();
        let mut reader = std::io::BufReader::new(stdout);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        line.trim().parse().unwrap_or(0)
    };

    if pid == 0 {
        panic!("Failed to get PID from loop process");
    }
    println!("   `- loop: PID {}", pid);

    // Create images directory
    if let Err(e) = std::fs::create_dir("test/notify_images") {
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            panic!("Creating notify_images failed: {:#?}", e);
        }
    }

    let directory = std::fs::File::open("test/notify_images").unwrap();

    // Dump with notify callback
    println!("--- Dump loop ---");
    let mut criu = rust_criu::Criu::new_with_criu_path(criu_bin_path.to_string()).unwrap();
    criu.set_pid(pid);
    criu.set_log_file("dump.log".to_string());
    criu.set_log_level(4);
    criu.set_notify_cb(notify_callback);
    criu.set_notify_scripts(true);
    criu.set_images_dir_fd(directory.as_raw_fd());

    match criu.dump() {
        Ok(_) => println!("   `- Dump succeeded"),
        Err(e) => {
            // Kill child on failure
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
            let _ = child.wait();
            let _ = std::fs::remove_dir_all("test/notify_images");
            panic!("Dump failed: {:#?}", e);
        }
    }

    // Wait for child (CRIU kills it by default)
    let _ = child.wait();

    // Check results
    let actions = ACTIONS_CALLED.load(Ordering::SeqCst);
    if actions == 0 {
        let _ = std::fs::remove_dir_all("test/notify_images");
        panic!("FAIL (no actions called)");
    }

    println!("   `- Success ({} actions)", actions);

    // Cleanup
    if let Err(e) = std::fs::remove_dir_all("test/notify_images") {
        eprintln!("Warning: cleanup failed: {:#?}", e);
    }

    println!("Notify test: PASS");
}
