use std::os::unix::io::AsRawFd;
use std::sync::{Mutex, OnceLock};

/// Recorded script names for action_script_test (corresponds to CRIU test/others/action-script).
static RECORDED_ACTIONS: OnceLock<Mutex<Vec<String>>> = OnceLock::new();

/// Callback that records script names for action_script_test (check_actions.py semantics).
const RECORD_ACTIONS_CALLBACK: rust_criu::NotifyCallback = record_actions_callback_impl;
fn record_actions_callback_impl(
    script: &str,
    _notify: &rust_criu::rust_criu_protobuf::rpc::Criu_notify,
) -> i32 {
    if let Some(m) = RECORDED_ACTIONS.get() {
        m.lock().unwrap().push(script.to_string());
    }
    0
}

/// Expected action script order for dump + restore.
const EXPECTED_ACTIONS_DUMP_RESTORE: &[&str] = &[
    "pre-dump",
    "query-ext-files",
    "post-dump",
    "pre-restore",
    "post-restore",
    "pre-resume",
    "post-resume",
];

/// Action script order test: record script names and verify sequence.
pub fn action_script_test(criu_bin_path: &str) {
    println!("Running action script test");
    RECORDED_ACTIONS.get_or_init(|| Mutex::new(Vec::new()));
    RECORDED_ACTIONS.get().unwrap().lock().unwrap().clear();

    let mut child = match std::process::Command::new("test/loop")
        .stdout(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => panic!("Starting loop process failed: {:#?}", e),
    };

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

    if let Err(e) = std::fs::create_dir("test/action_script_images") {
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            panic!("Creating action_script_images failed: {:#?}", e);
        }
    }

    let directory = std::fs::File::open("test/action_script_images").unwrap();

    let mut criu = rust_criu::Criu::new_with_criu_path(criu_bin_path.to_string()).unwrap();
    criu.set_pid(pid);
    criu.set_log_file("dump.log".to_string());
    criu.set_log_level(4);
    criu.set_notify_cb(RECORD_ACTIONS_CALLBACK);
    criu.set_notify_scripts(true);
    criu.set_images_dir_fd(directory.as_raw_fd());

    println!("Dumping PID {}", pid);
    if let Err(e) = criu.dump() {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        let _ = child.wait();
        panic!("Dumping process failed with {:#?}", e);
    }

    let _ = child.wait();

    criu.set_images_dir_fd(directory.as_raw_fd());
    criu.set_log_file("restore.log".to_string());
    criu.set_notify_cb(RECORD_ACTIONS_CALLBACK);
    criu.set_notify_scripts(true);

    println!("Restoring PID {}", pid);
    if let Err(e) = criu.restore() {
        panic!("Restoring process failed with {:#?}", e);
    }

    let recorded = RECORDED_ACTIONS.get().unwrap().lock().unwrap().clone();
    if recorded != EXPECTED_ACTIONS_DUMP_RESTORE {
        let _ = std::fs::remove_dir_all("test/action_script_images");
        panic!(
            "Action script order mismatch: got {:?}, expected {:?}",
            recorded, EXPECTED_ACTIONS_DUMP_RESTORE
        );
    }

    println!("Cleaning up");
    if let Err(e) = std::fs::remove_dir_all("test/action_script_images") {
        panic!("Removing test/action_script_images failed with {:#?}", e);
    }
}
