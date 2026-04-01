use std::os::unix::io::{AsRawFd, OwnedFd, RawFd};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

const IMAGES_DIR: &str = "test/images";
const READY_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(100);

// Create a pipe and make the read end non-blocking
fn create_state_pipe() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let (r, w) = nix::unistd::pipe().map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
    let fd = r.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((r, w))
}

// Create a checkpoint with lazy-pages enabled, then restore it.
pub fn lazy_pages_test(criu_bin_path: &str) {
    println!("Running lazy_pages_test");

    let pid: i32 = match Command::new("test/piggie").output() {
        Ok(p) => String::from_utf8_lossy(&p.stdout).parse().unwrap_or(0),
        Err(e) => panic!("Starting test process failed ({:#?})", e),
    };
    if pid <= 0 {
        panic!("Failed to obtain PID from test/piggie");
    }

    if let Err(e) = std::fs::create_dir(IMAGES_DIR) {
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            unsafe { libc::kill(pid, libc::SIGKILL) };
            panic!(
                "Creating image directory '{}' failed with {:#?}",
                IMAGES_DIR, e
            );
        }
    }

    let directory = std::fs::File::open(IMAGES_DIR).unwrap();
    let images_dir_fd = directory.as_raw_fd();

    // Wait via status_fd until dump's page-server is listening on TCP; otherwise
    // the lazy-pages daemon's connect() races the page-server's bind()/listen().
    let (pipe_r, pipe_w) = match create_state_pipe() {
        Ok(p) => p,
        Err(e) => {
            unsafe { libc::kill(pid, libc::SIGKILL) };
            panic!("Creating pipe failed: {:#?}", e);
        }
    };
    let pipe_r_fd = pipe_r.as_raw_fd();
    let pipe_w_fd = pipe_w.as_raw_fd();

    // Dynamically choose a free ephemeral port so a leaked page-server
    // from an earlier run does not hang this test with EADDRINUSE.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port() as i32;
    drop(listener);

    // Run dump on a background thread: with --lazy-pages, dump() returns only
    // after restore has fetched all pages through the daemon.
    let criu_bin_for_dump = criu_bin_path.to_string();
    let dump_handle = thread::spawn(move || -> Result<(), String> {
        let mut criu = rust_criu::Criu::new_with_criu_path(criu_bin_for_dump)
            .map_err(|e| format!("Criu::new failed: {:#?}", e))?;
        criu.set_pid(pid);
        criu.set_images_dir_fd(images_dir_fd);
        criu.set_lazy_pages(true);
        criu.set_page_server("0.0.0.0".to_string(), port);
        criu.set_status_fd(pipe_w_fd);
        criu.dump().map_err(|e| format!("{:#?}", e))
    });

    // Wait until CRIU reports readiness before starting the daemon.
    let ready = wait_for_ready(pipe_r_fd, READY_TIMEOUT);
    drop(pipe_w);
    drop(pipe_r);

    if !ready {
        unsafe { libc::kill(pid, libc::SIGKILL) };
        let _ = dump_handle.join();
        panic!(
            "CRIU lazy-pages page-server did not become ready within {:?}",
            READY_TIMEOUT
        );
    }

    // Launch the lazy-pages daemon and wait via --status-fd until it is listening
    // on lazy-pages.socket
    let (daemon_pipe_r, daemon_pipe_w) = match create_state_pipe() {
        Ok(p) => p,
        Err(e) => {
            unsafe { libc::kill(pid, libc::SIGKILL) };
            let _ = dump_handle.join();
            panic!("Creating daemon status pipe failed: {:#?}", e);
        }
    };
    let daemon_pipe_r_fd = daemon_pipe_r.as_raw_fd();
    let daemon_pipe_w_fd = daemon_pipe_w.as_raw_fd();

    // nix::unistd::pipe() sets O_CLOEXEC, so the write end must be made
    // inheritable before spawning the daemon.
    if unsafe { libc::fcntl(daemon_pipe_w_fd, libc::F_SETFD, 0) } < 0 {
        unsafe { libc::kill(pid, libc::SIGKILL) };
        let _ = dump_handle.join();
        panic!(
            "Clearing FD_CLOEXEC on daemon pipe failed: {}",
            std::io::Error::last_os_error()
        );
    }

    println!("Spawning lazy-pages daemon");
    let port_str = port.to_string();
    let daemon_status_fd_str = daemon_pipe_w_fd.to_string();
    let mut lazy_daemon = match Command::new(criu_bin_path)
        .args([
            "lazy-pages",
            "--page-server",
            "--address",
            "127.0.0.1",
            "--port",
            &port_str,
            "-D",
            IMAGES_DIR,
            "--status-fd",
            &daemon_status_fd_str,
        ])
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            unsafe { libc::kill(pid, libc::SIGKILL) };
            let _ = dump_handle.join();
            panic!("Spawning `criu lazy-pages` daemon failed: {:#?}", e);
        }
    };

    // Close the parent's copy of the write end so we see EOF if the daemon
    // exits before signalling readiness.
    drop(daemon_pipe_w);

    let daemon_ready = wait_for_ready(daemon_pipe_r_fd, READY_TIMEOUT);
    drop(daemon_pipe_r);

    if !daemon_ready {
        let _ = lazy_daemon.kill();
        let _ = lazy_daemon.wait();
        unsafe { libc::kill(pid, libc::SIGKILL) };
        let _ = dump_handle.join();
        panic!(
            "CRIU lazy-pages daemon did not become ready within {:?}",
            READY_TIMEOUT
        );
    }

    println!("Running restore");
    let restore_result = (|| -> Result<(), String> {
        let mut criu = rust_criu::Criu::new_with_criu_path(criu_bin_path.to_string())
            .map_err(|e| format!("Criu::new failed: {:#?}", e))?;
        criu.set_images_dir_fd(images_dir_fd);
        criu.set_lazy_pages(true);
        criu.restore().map_err(|e| format!("{:#?}", e))
    })();

    // Tear down background tasks: the daemon may linger if restore failed,
    // and dump() unblocks only after the daemon is gone.
    let _ = lazy_daemon.kill();
    let _ = lazy_daemon.wait();
    let dump_result = dump_handle.join();

    if let Err(e) = restore_result {
        unsafe { libc::kill(pid, libc::SIGKILL) };
        panic!("criu restore failed: {:#?}", e);
    }

    if let Ok(Err(e)) = dump_result {
        unsafe { libc::kill(pid, libc::SIGKILL) };
        panic!("criu dump (lazy-pages page-server) failed: {}", e);
    }

    unsafe {
        libc::kill(pid, libc::SIGKILL);
        libc::waitpid(pid, std::ptr::null_mut(), 0);
    }

    println!("Cleaning up");
    let _ = std::fs::remove_dir_all(IMAGES_DIR);
}

fn wait_for_ready(fd: RawFd, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 1];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n == 1 {
            return true;
        }
        // EOF means CRIU closed its end without sending readiness.
        if n == 0 {
            return false;
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EAGAIN) | Some(libc::EINTR) => {}
            _ => return false,
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}
