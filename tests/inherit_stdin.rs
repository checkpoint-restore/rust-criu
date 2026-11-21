use std::io::{BufRead, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};

/// Inherit stdin test: dump a process whose stdin is a pipe, then restore it
/// with a new pipe registered as inherit_fd on fd 0, and check that data
/// written to the new pipe reaches the restored process.
///
/// CRIU resolves inherit_fd numbers in its own fd table, so this only works
/// if criu swrk inherits the caller's stdin. Container runtimes rely on this
/// to reconnect a container's stdin pipe on restore.
/// Skipped unless root.
fn inherit_stdin_test(criu_bin_path: &str) {
    if unsafe { libc::geteuid() } != 0 {
        println!("inherit_stdin_test: skip (not root)");
        return;
    }

    println!("Running inherit_stdin_test");

    let img_dir = "test/inherit_stdin_images";
    if let Err(e) = std::fs::create_dir(img_dir) {
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            panic!("create_dir {} failed: {:#?}", img_dir, e);
        }
    }
    let output = std::fs::canonicalize(img_dir).unwrap().join("stdin.out");
    let _ = std::fs::remove_file(&output);

    let mut child = std::process::Command::new("test/loop_stdin")
        .arg(&output)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn loop_stdin failed: {:#?}", e));

    let pid: i32 = {
        let stdout = child.stdout.take().unwrap();
        let mut line = String::new();
        std::io::BufReader::new(stdout)
            .read_line(&mut line)
            .unwrap();
        line.trim().parse().unwrap_or(0)
    };
    if pid == 0 {
        panic!("failed to get PID from loop_stdin process");
    }

    // The key must match the pipe recorded in the image, e.g. "pipe:[12345]".
    let key = std::fs::read_link(format!("/proc/{}/fd/0", pid))
        .unwrap()
        .to_string_lossy()
        .into_owned();
    if !key.starts_with("pipe:") {
        panic!("loop_stdin stdin is not a pipe: {}", key);
    }

    let directory = std::fs::File::open(img_dir).unwrap();
    let mut criu = rust_criu::Criu::new_with_criu_path(criu_bin_path.to_string()).unwrap();
    criu.set_pid(pid);
    criu.set_images_dir_fd(directory.as_raw_fd());
    criu.set_log_file("dump.log".to_string());
    criu.set_log_level(4);

    println!("Dumping PID {} (stdin {})", pid, key);
    if let Err(e) = criu.dump() {
        unsafe { libc::kill(pid, libc::SIGKILL) };
        let _ = child.wait();
        panic!("inherit_stdin dump failed: {:#?}", e);
    }
    let _ = child.wait();
    drop(child);

    // Make a new pipe our own stdin for the duration of the restore, so that
    // criu swrk inherits it as fd 0. The tests run with --test-threads=1.
    let mut fds = [0; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        panic!("pipe2 failed: {}", std::io::Error::last_os_error());
    }
    let (read_end, write_end) =
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    let saved_stdin = unsafe { libc::dup(0) };
    if saved_stdin < 0 || unsafe { libc::dup2(read_end.as_raw_fd(), 0) } < 0 {
        panic!(
            "redirecting stdin failed: {}",
            std::io::Error::last_os_error()
        );
    }
    drop(read_end);

    criu.set_images_dir_fd(directory.as_raw_fd());
    criu.set_log_file("restore.log".to_string());
    criu.set_log_level(4);
    criu.set_rst_sibling(true);
    criu.add_inherit_fd(0, key.clone())
        .unwrap_or_else(|e| panic!("add_inherit_fd failed: {:#?}", e));

    println!("Restoring (inherit_fd 0 key {})", key);
    let result = criu.restore();

    unsafe {
        libc::dup2(saved_stdin, 0);
        libc::close(saved_stdin);
    }
    if let Err(e) = result {
        panic!("inherit_stdin restore failed: {:#?}", e);
    }

    // The restored process holds the only read end of the new pipe, so the
    // write fails with EPIPE if its stdin was not connected to the pipe.
    let mut writer = std::fs::File::from(write_end);
    if let Err(e) = writer.write_all(b"hello\n") {
        unsafe { libc::kill(pid, libc::SIGKILL) };
        unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
        panic!(
            "restored process is not connected to the inherited stdin pipe: {:#?}",
            e
        );
    }

    let mut received = String::new();
    for _ in 0..50 {
        received = std::fs::read_to_string(&output).unwrap_or_default();
        if !received.is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    println!("Cleaning up");
    unsafe { libc::kill(pid, libc::SIGKILL) };
    unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };

    assert_eq!(
        received, "hello\n",
        "restored process did not read from the inherited stdin pipe"
    );
    println!("Verified: restored process reads from the inherited stdin pipe");

    if let Err(e) = std::fs::remove_dir_all(img_dir) {
        panic!("remove_dir_all {} failed: {:#?}", img_dir, e);
    }
}

#[test]
fn inherit_stdin() {
    let criu_bin_path =
        std::env::var("CRIU_BINARY").expect("CRIU_BINARY must be set to run integration tests");
    inherit_stdin_test(&criu_bin_path);
}
