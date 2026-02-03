#![deny(warnings)]

use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Counter for notify actions (similar to test_notify.c's actions_called)
static ACTIONS_CALLED: AtomicUsize = AtomicUsize::new(0);

/// CRIU notification callback (similar to test_notify.c's notify function)
fn notify_callback(
    _action: &str,
    _notify: &rust_criu::rust_criu_protobuf::rpc::Criu_notify,
    _fds: &[RawFd],
) -> i32 {
    ACTIONS_CALLED.fetch_add(1, Ordering::SeqCst);
    0
}

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

    // Basic dump/restore test (original test)
    basic_test(&criu_bin_path);

    // Notify callback test
    notify_test(&criu_bin_path);

    // PTY test with orphan-pts-master support
    pty_test(&criu_bin_path);
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
}

/// Notify callback test using loop binary
/// Based on CRIU's test/others/libcriu/test_notify.c
fn notify_test(criu_bin_path: &str) {
    // Reset action counter
    ACTIONS_CALLED.store(0, Ordering::SeqCst);

    // Start loop process
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

    // Create images directory
    if let Err(e) = std::fs::create_dir("test/notify_images") {
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            panic!("Creating notify_images failed: {:#?}", e);
        }
    }

    let directory = std::fs::File::open("test/notify_images").unwrap();

    // Dump with notify callback
    let mut criu = rust_criu::Criu::new_with_criu_path(criu_bin_path.to_string()).unwrap();
    criu.set_pid(pid);
    criu.set_log_file("dump.log".to_string());
    criu.set_log_level(4);
    criu.set_notify_cb(notify_callback);
    criu.set_notify_scripts(true);
    criu.set_images_dir_fd(directory.as_raw_fd());

    println!("Dumping PID {} (with notify callback)", pid);
    if let Err(e) = criu.dump() {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        let _ = child.wait();
        panic!("Dumping process failed with {:#?}", e);
    }

    if !std::path::Path::new("test/notify_images/dump.log").exists() {
        let _ = child.wait();
        panic!("Error: Expected log file 'test/notify_images/dump.log' missing.");
    }

    // Wait for child (CRIU kills it by default)
    let _ = child.wait();

    let actions = ACTIONS_CALLED.load(Ordering::SeqCst);
    if actions == 0 {
        panic!("Notify test failed: no actions called");
    }

    // Restore with notify callback
    criu.set_images_dir_fd(directory.as_raw_fd());
    criu.set_log_level(4);
    criu.set_log_file("restore.log".to_string());

    println!("Restoring PID {} (with notify callback)", pid);
    if let Err(e) = criu.restore() {
        panic!("Restoring process failed with {:#?}", e);
    }

    if !std::path::Path::new("test/notify_images/restore.log").exists() {
        panic!("Error: Expected log file 'test/notify_images/restore.log' missing.");
    }

    // Cleanup
    println!("Cleaning up");
    if let Err(e) = std::fs::remove_dir_all("test/notify_images") {
        panic!(
            "Removing image directory 'test/notify_images' failed with {:#?}",
            e
        );
    }
}

/// Test for orphan-pts-master support (similar to crun's criu_notify at criu.c#L210).
///
/// PTY/orphan-pts-master behavior is the same as in the container case (crun):
/// - Dump: process has PTY slave as stdio; master lives in the parent (runtime).
///   CRIU checkpoints only the process → master is "orphaned" (not in image).
/// - Restore: client provides a new PTY master via inherit_fd(key tty[rdev:dev]).
///   Optional: orphan-pts-master notify callback can send that FD to a console socket
///   (we have no console socket here; crun does when e.g. re-attaching).
///
/// This test uses no namespaces/cgroups/rootfs; only the PTY path is exercised.
///
/// PTY and the two processes (test binary + test/loop):
///
///   DUMP PHASE:
///     [test binary] ----master---- [ PTY ] ----slave---- [ test/loop ]
///          |                           |                     |
///          |  (holds master,           |  (stdio = 0,1,2)    |  ← CRIU dumps this
///          |   not checkpointed)       |                     |
///          |                           |  Master is "orphaned" (stays in parent)
///
///   RESTORE PHASE:
///     [test binary] ----new master---- [ new PTY ] ----slave---- [ restored test/loop ]
///          |                                  |                         |
///          |  add_inherit_fd(master,          |  CRIU connects          |  stdio = 0,1,2
///          |    tty[rdev:dev])                |  restored process       |
///          |       → CRIU uses this FD        |  to this slave          |
fn pty_test(criu_bin_path: &str) {
    use std::io::BufRead;

    // Start loop process with PTY slave as stdio
    let mut cmd = std::process::Command::new("test/loop");
    let (mut child, pty) = match spawn_with_pty_slave(&mut cmd) {
        Ok((c, p)) => (c, p),
        Err(e) => panic!("Starting loop process with PTY failed ({:#?})", e),
    };

    // Read PID from PTY master
    let pid: i32 = {
        let master = &pty.master;
        let mut reader = std::io::BufReader::new(master);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        line.trim().parse().unwrap_or(0)
    };

    if pid == 0 {
        panic!("Failed to get PID from loop process");
    }

    // Create images directory
    if let Err(e) = std::fs::create_dir("test/pty_images") {
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            panic!(
                "Creating image directory 'test/pty_images' failed with {:#?}",
                e
            );
        }
    }

    let directory = std::fs::File::open("test/pty_images").unwrap();

    // Dump with PTY (crun style)
    let mut criu = rust_criu::Criu::new_with_criu_path(criu_bin_path.to_string()).unwrap();
    criu.set_pid(pid);
    criu.set_log_file("pty_dump.log".to_string());
    criu.set_log_level(4);
    criu.set_images_dir_fd(directory.as_raw_fd());
    criu.set_shell_job(true); // Required for PTY (crun sets this)

    println!("Dumping PID {} (with PTY)", pid);
    if let Err(e) = criu.dump() {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        let _ = child.wait();
        panic!("Dumping process failed with {:#?}", e);
    }

    if !std::path::Path::new("test/pty_images/pty_dump.log").exists() {
        let _ = child.wait();
        panic!("Error: Expected log file 'test/pty_images/pty_dump.log' missing.");
    }

    // Wait for child (CRIU kills it by default)
    let _ = child.wait();

    // Restore with PTY (crun style)
    // Create new PTY for restore
    let restore_pty = match PtyPair::new() {
        Ok(p) => p,
        Err(e) => panic!("Creating PTY for restore failed ({:#?})", e),
    };

    // Store PTY master fd for use in notification callback
    let restore_pty_master_fd = restore_pty.master_fd();

    // Get rdev and dev from restore PTY master using fstat
    // CRIU uses tty[rdev:dev] format for inherit_fd key (tty.c:1217)
    // Reference: snprintf(buf, s, "tty[%x:%x]", info->tie->rdev, info->tie->dev);
    // In open_fd(), inherit_fd_lookup_id() is called with the id from d->ops->name()
    // which returns tty[rdev:dev] format for PTY devices
    let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(restore_pty_master_fd, &mut stat_buf) } != 0 {
        panic!(
            "fstat failed on restore PTY master fd: {}",
            std::io::Error::last_os_error()
        );
    }
    let rdev = stat_buf.st_rdev;
    let dev = stat_buf.st_dev;
    // Format as hex (lowercase) to match CRIU's tty_d_name format
    let tty_key = format!("tty[{:x}:{:x}]", rdev, dev);

    // Notification callback for orphan-pts-master (crun style)
    // Reference: crun's criu_notify function
    let pty_notify_callback = |action: &str,
                               _notify: &rust_criu::rust_criu_protobuf::rpc::Criu_notify,
                               fds: &[RawFd]|
     -> i32 {
        if action == "orphan-pts-master" {
            /* CRIU sends us the master FD via the 'orphan-pts-master'
             * callback and we are passing it on to the '--console-socket'
             * if it exists. */
            // In crun: master_fd = libcriu_wrapper->criu_get_orphan_pts_master_fd();
            // In our case, the master FD is received via SCM_RIGHTS in the fds parameter
            let _master_fd = fds[0]; // Get the first FD from received_fds

            // In crun, if console_socket exists, the master FD is sent to it
            // For our test, we don't have a console_socket, so we just acknowledge (same as crun)
            // Reference: crun's criu_notify function
            //   if (! console_socket)
            //     return 0;  // No console_socket, just acknowledge

            return 0;
        }
        0
    };

    // Setup CRIU restore options (crun style)
    // Reference: crun's restore_container function
    let mut criu = rust_criu::Criu::new_with_criu_path(criu_bin_path.to_string()).unwrap();
    criu.set_log_file("pty_restore.log".to_string());
    criu.set_log_level(4); // DEBUG level (crun uses 4)
    criu.set_images_dir_fd(directory.as_raw_fd());
    criu.set_shell_job(true); // Required for PTY (crun sets this)
    criu.set_orphan_pts_master(true); // Enable orphan-pts-master support (crun sets this)
    criu.set_notify_cb(pty_notify_callback);
    criu.set_notify_scripts(true); // Enable notify scripts
    criu.set_rst_sibling(true); // Required for swrk mode

    // Add PTY master as inherit fd (crun style)
    // The key must be in tty[rdev:dev] format (tty.c:1217)
    // Reference: snprintf(buf, s, "tty[%x:%x]", info->tie->rdev, info->tie->dev);
    // CRIU uses this format to lookup inherit_fd via inherit_fd_lookup_id()
    criu.add_inherit_fd(restore_pty_master_fd, &tty_key);

    // Keep PTY alive during restore
    let _pty_guard = restore_pty;

    println!("Restoring PID {} (with PTY)", pid);
    if let Err(e) = criu.restore() {
        panic!("Restoring process failed with {:#?}", e);
    }

    if !std::path::Path::new("test/pty_images/pty_restore.log").exists() {
        panic!("Error: Expected log file 'test/pty_images/pty_restore.log' missing.");
    }

    // Cleanup
    println!("Cleaning up");
    if let Err(e) = std::fs::remove_dir_all("test/pty_images") {
        panic!(
            "Removing image directory 'test/pty_images' failed with {:#?}",
            e
        );
    }
}

/// PTY master/slave pair
pub struct PtyPair {
    pub master: std::fs::File,
    pub slave: std::fs::File,
    pub master_fd: RawFd,
    pub slave_fd: RawFd,
}

impl PtyPair {
    /// Create a new PTY pair using posix_openpt
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Open PTY master
        let master_fd = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
        if master_fd < 0 {
            return Err(format!("posix_openpt failed: {}", std::io::Error::last_os_error()).into());
        }

        // Grant access to slave
        if unsafe { libc::grantpt(master_fd) } != 0 {
            unsafe {
                libc::close(master_fd);
            }
            return Err(format!("grantpt failed: {}", std::io::Error::last_os_error()).into());
        }

        // Unlock slave
        if unsafe { libc::unlockpt(master_fd) } != 0 {
            unsafe {
                libc::close(master_fd);
            }
            return Err(format!("unlockpt failed: {}", std::io::Error::last_os_error()).into());
        }

        // Get slave name
        let slave_name = unsafe {
            let name_ptr = libc::ptsname(master_fd);
            if name_ptr.is_null() {
                libc::close(master_fd);
                return Err(format!("ptsname failed: {}", std::io::Error::last_os_error()).into());
            }
            std::ffi::CStr::from_ptr(name_ptr)
                .to_string_lossy()
                .into_owned()
        };

        // Open slave
        let slave_fd = unsafe {
            let slave_cstr = std::ffi::CString::new(slave_name)?;
            libc::open(slave_cstr.as_ptr(), libc::O_RDWR | libc::O_NOCTTY, 0)
        };

        if slave_fd < 0 {
            unsafe {
                libc::close(master_fd);
            }
            return Err(format!("open slave failed: {}", std::io::Error::last_os_error()).into());
        }

        let master = unsafe { std::fs::File::from_raw_fd(master_fd) };
        let slave = unsafe { std::fs::File::from_raw_fd(slave_fd) };

        Ok(PtyPair {
            master,
            slave,
            master_fd,
            slave_fd,
        })
    }

    /// Get the slave file descriptor (for passing to child process)
    pub fn slave_fd(&self) -> RawFd {
        self.slave_fd
    }

    /// Get the master file descriptor (for parent process)
    pub fn master_fd(&self) -> RawFd {
        self.master_fd
    }
}

/// Spawn a command with PTY slave as stdio (see pty_test DUMP PHASE diagram).
/// Returns the child process and the PTY pair; parent keeps master, child gets slave as stdin/stdout/stderr.
pub fn spawn_with_pty_slave(
    cmd: &mut std::process::Command,
) -> Result<(std::process::Child, PtyPair), Box<dyn std::error::Error>> {
    let pty = PtyPair::new()?;
    let slave_fd = pty.slave_fd();

    // Set up stdio to use PTY slave via pre_exec
    // pre_exec runs after fork but before exec, so we can dup2 the slave fd
    unsafe {
        cmd.pre_exec(move || {
            // Set slave as stdin, stdout, stderr
            if libc::dup2(slave_fd, libc::STDIN_FILENO) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::dup2(slave_fd, libc::STDOUT_FILENO) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::dup2(slave_fd, libc::STDERR_FILENO) < 0 {
                return Err(std::io::Error::last_os_error());
            }

            // Close slave_fd if it's not one of stdio (shouldn't happen, but be safe)
            if slave_fd != libc::STDIN_FILENO
                && slave_fd != libc::STDOUT_FILENO
                && slave_fd != libc::STDERR_FILENO
            {
                libc::close(slave_fd);
            }

            Ok(())
        });
    }

    // Set stdio to inherit - pre_exec will override with PTY slave
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let child = cmd.spawn()?;

    Ok((child, pty))
}
