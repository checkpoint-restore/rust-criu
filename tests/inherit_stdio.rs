use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;

/// Create a pipe with O_CLOEXEC set on both ends.
fn pipe() -> (OwnedFd, OwnedFd) {
    let mut fds = [0; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        panic!("pipe2 failed: {}", std::io::Error::last_os_error());
    }
    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
}

/// Read from `file` until `expected_len` bytes arrive, EOF, or about 5 seconds pass.
fn read_with_timeout(file: &mut std::fs::File, expected_len: usize) -> String {
    let mut buf = Vec::new();
    for _ in 0..50 {
        let mut pfd = libc::pollfd {
            fd: file.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut pfd, 1, 100) } <= 0 {
            continue;
        }
        let mut chunk = [0u8; 256];
        match file.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
        if buf.len() >= expected_len {
            break;
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// Inherit stdio test: dump a process whose stdin, stdout and stderr are
/// pipes, then restore it with new pipes registered as inherit_fd on fds 0,
/// 1 and 2, and check that the restored process reads from and writes to the
/// new pipes.
///
/// CRIU resolves inherit_fd numbers in its own fd table, so this only works
/// if criu swrk inherits the caller's stdio. Container runtimes rely on this
/// to reconnect a container's stdio pipes on restore.
/// Skipped unless root.
fn inherit_stdio_test(criu_bin_path: &str) {
    if unsafe { libc::geteuid() } != 0 {
        println!("inherit_stdio_test: skip (not root)");
        return;
    }

    println!("Running inherit_stdio_test");

    let img_dir = "test/inherit_stdio_images";
    if let Err(e) = std::fs::create_dir(img_dir) {
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            panic!("create_dir {} failed: {:#?}", img_dir, e);
        }
    }

    // The shell echoes each line read from stdin to stdout and stderr. Run it
    // in a new session so that CRIU can dump it without --shell-job.
    let mut child = unsafe {
        std::process::Command::new("sh")
            .args([
                "-c",
                "while read -r line; do echo \"out:$line\"; echo \"err:$line\" >&2; done",
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            })
            .spawn()
    }
    .unwrap_or_else(|e| panic!("spawn sh failed: {:#?}", e));
    let pid = child.id() as i32;

    // The keys must match the pipes recorded in the image, e.g. "pipe:[12345]".
    let keys: Vec<String> = (0..3)
        .map(|fd| {
            let key = std::fs::read_link(format!("/proc/{}/fd/{}", pid, fd))
                .unwrap()
                .to_string_lossy()
                .into_owned();
            if !key.starts_with("pipe:") {
                panic!("sh fd {} is not a pipe: {}", fd, key);
            }
            key
        })
        .collect();

    let directory = std::fs::File::open(img_dir).unwrap();
    let mut criu = rust_criu::Criu::new_with_criu_path(criu_bin_path.to_string()).unwrap();
    criu.set_pid(pid);
    criu.set_images_dir_fd(directory.as_raw_fd());
    criu.set_log_file("dump.log".to_string());
    criu.set_log_level(4);

    println!("Dumping PID {} (stdio {:?})", pid, keys);
    if let Err(e) = criu.dump() {
        unsafe { libc::kill(pid, libc::SIGKILL) };
        let _ = child.wait();
        panic!("inherit_stdio dump failed: {:#?}", e);
    }
    let _ = child.wait();
    drop(child);

    criu.set_images_dir_fd(directory.as_raw_fd());
    criu.set_log_file("restore.log".to_string());
    criu.set_log_level(4);
    criu.set_rst_sibling(true);
    for (fd, key) in keys.iter().enumerate() {
        criu.add_inherit_fd(fd as i32, key.clone())
            .unwrap_or_else(|e| panic!("add_inherit_fd {} failed: {:#?}", fd, e));
    }
    println!("Restoring (inherit_fd 0-2 keys {:?})", keys);

    // Make new pipes our own stdio for the duration of the restore, so that
    // criu swrk inherits them as fds 0, 1 and 2. This is safe because this
    // file builds its own test binary with this single test. Nothing may be
    // printed until our stdio is put back.
    let (stdin_read, stdin_write) = pipe();
    let (stdout_read, stdout_write) = pipe();
    let (stderr_read, stderr_write) = pipe();
    let mut saved = [0; 3];
    for (fd, new) in [&stdin_read, &stdout_write, &stderr_write]
        .into_iter()
        .enumerate()
    {
        // Keep the saved stdio out of criu swrk.
        saved[fd] = unsafe { libc::fcntl(fd as i32, libc::F_DUPFD_CLOEXEC, 0) };
        if saved[fd] < 0 || unsafe { libc::dup2(new.as_raw_fd(), fd as i32) } < 0 {
            panic!(
                "redirecting fd {} failed: {}",
                fd,
                std::io::Error::last_os_error()
            );
        }
    }
    drop((stdin_read, stdout_write, stderr_write));

    let result = criu.restore();

    for (fd, saved_fd) in saved.into_iter().enumerate() {
        unsafe {
            libc::dup2(saved_fd, fd as i32);
            libc::close(saved_fd);
        }
    }
    if let Err(e) = result {
        panic!("inherit_stdio restore failed: {:#?}", e);
    }

    // The restored process holds the only read end of the new stdin pipe, so
    // the write fails with EPIPE if its stdin was not connected to the pipe.
    let mut stdin = std::fs::File::from(stdin_write);
    if let Err(e) = stdin.write_all(b"hello\n") {
        unsafe { libc::kill(pid, libc::SIGKILL) };
        unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
        panic!(
            "restored process is not connected to the inherited stdin pipe: {:#?}",
            e
        );
    }

    let stdout = read_with_timeout(&mut std::fs::File::from(stdout_read), 10);
    let stderr = read_with_timeout(&mut std::fs::File::from(stderr_read), 10);

    println!("Cleaning up");
    unsafe { libc::kill(pid, libc::SIGKILL) };
    unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };

    assert_eq!(
        stdout, "out:hello\n",
        "restored process did not write to the inherited stdout pipe"
    );
    assert_eq!(
        stderr, "err:hello\n",
        "restored process did not write to the inherited stderr pipe"
    );
    println!("Verified: restored process uses the inherited stdio pipes");

    if let Err(e) = std::fs::remove_dir_all(img_dir) {
        panic!("remove_dir_all {} failed: {:#?}", img_dir, e);
    }
}

#[test]
fn inherit_stdio() {
    let criu_bin_path =
        std::env::var("CRIU_BINARY").expect("CRIU_BINARY must be set to run integration tests");
    inherit_stdio_test(&criu_bin_path);
}
