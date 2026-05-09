use nix::errno::Errno;
use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::waitpid;
use nix::unistd::Pid;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::io::{AsRawFd, OwnedFd};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

const IMAGES_DIR: &str = "test/images";
const READY_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(100);

fn create_state_pipe() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let (r, w) = nix::unistd::pipe().map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
    let flags = FdFlag::from_bits_truncate(
        fcntl(w.as_fd(), FcntlArg::F_GETFD)
            .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?,
    );
    fcntl(w.as_fd(), FcntlArg::F_SETFD(flags & !FdFlag::FD_CLOEXEC))
        .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
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
            let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
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
            let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
            panic!("Creating pipe failed: {:#?}", e);
        }
    };

    // Dynamically choose a free ephemeral port so a leaked page-server
    // from an earlier run does not hang this test with EADDRINUSE.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port() as i32;
    drop(listener);
    let status_fd = pipe_w.as_raw_fd();

    let criu_bin_for_dump = criu_bin_path.to_string();
    let dump_handle = thread::spawn(move || -> Result<(), String> {
        // Keep pipe_w alive until criu.dump() spawns CRIU swrk so the writer fd is inherited.
        let _pipe_w = pipe_w;
        let mut criu = rust_criu::Criu::new_with_criu_path(criu_bin_for_dump)
            .map_err(|e| format!("Criu::new failed: {:#?}", e))?;
        criu.set_pid(pid);
        criu.set_images_dir_fd(images_dir_fd);
        criu.set_lazy_pages(true);
        criu.set_page_server("0.0.0.0".to_string(), port);
        criu.set_status_fd(status_fd);
        criu.dump().map_err(|e| format!("{:#?}", e))
    });

    let ready = wait_for_ready(pipe_r.as_fd(), READY_TIMEOUT);
    drop(pipe_r);

    if !ready {
        let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
        let _ = dump_handle.join();
        panic!(
            "CRIU lazy-pages page-server did not become ready within {:?}",
            READY_TIMEOUT
        );
    }

    // CRIU writes inventory.img once the dump-side state is established;
    // its absence here means the page-server signalled readiness without
    // producing a usable image set, so there is nothing for the daemon to serve.
    if !std::path::Path::new(IMAGES_DIR)
        .join("inventory.img")
        .exists()
    {
        let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
        let _ = dump_handle.join();
        panic!("inventory.img was not written to {}", IMAGES_DIR);
    }

    // Launch the lazy-pages daemon and wait via --status-fd until it is listening
    // on lazy-pages.socket
    let (daemon_pipe_r, daemon_pipe_w) = match create_state_pipe() {
        Ok(p) => p,
        Err(e) => {
            let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
            let _ = dump_handle.join();
            panic!("Creating daemon status pipe failed: {:#?}", e);
        }
    };
    let daemon_pipe_w_fd = daemon_pipe_w.as_raw_fd();

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
            let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
            let _ = dump_handle.join();
            panic!("Spawning `criu lazy-pages` daemon failed: {:#?}", e);
        }
    };
    drop(daemon_pipe_w);

    let daemon_ready = wait_for_ready(daemon_pipe_r.as_fd(), READY_TIMEOUT);
    drop(daemon_pipe_r);

    if !daemon_ready {
        let _ = lazy_daemon.kill();
        let _ = lazy_daemon.wait();
        let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
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
        // Restore as a sibling so the task outlives the short-lived CRIU swrk for the post-restore liveness check.
        criu.set_rst_sibling(true);
        criu.restore().map_err(|e| format!("{:#?}", e))
    })();

    if let Err(e) = restore_result {
        // Tear down background tasks: the daemon may linger if restore failed,
        // and dump() unblocks only after the daemon is gone.
        let _ = lazy_daemon.kill();
        let _ = lazy_daemon.wait();
        let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
        let _ = dump_handle.join();
        panic!("criu restore failed: {:#?}", e);
    }

    // Check liveness while the lazy-pages daemon is still serving page faults;
    // once the daemon exits, the restored task will follow it.
    if let Err(err) = kill(Pid::from_raw(pid), None) {
        let _ = lazy_daemon.kill();
        let _ = lazy_daemon.wait();
        let _ = dump_handle.join();
        panic!("restored process is not running: kill(pid={pid}, 0) failed: {err}");
    }

    let _ = lazy_daemon.wait();
    let dump_result = dump_handle.join();

    if let Ok(Err(e)) = dump_result {
        panic!("criu dump (lazy-pages page-server) failed: {}", e);
    }

    let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
    let _ = waitpid(Pid::from_raw(pid), None);

    println!("Cleaning up");
    let _ = std::fs::remove_dir_all(IMAGES_DIR);
}

fn wait_for_ready(fd: BorrowedFd<'_>, timeout: Duration) -> bool {
    // Set read pipe to non-blocking so the timeout loop isn't blocked forever if no data arrives
    let flags = nix::fcntl::OFlag::from_bits_truncate(
        nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFL).expect("F_GETFL failed"),
    );
    nix::fcntl::fcntl(
        fd,
        nix::fcntl::FcntlArg::F_SETFL(flags | nix::fcntl::OFlag::O_NONBLOCK),
    )
    .expect("F_SETFL failed");

    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 1];
    loop {
        match nix::unistd::read(fd, &mut buf) {
            Ok(1) => return true,
            // EOF means CRIU closed its end without sending readiness.
            Ok(_) => return false,
            Err(Errno::EAGAIN) | Err(Errno::EINTR) => {}
            Err(_) => return false,
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}
