use std::os::unix::io::AsRawFd;
use std::os::unix::process::CommandExt;
use std::time::Duration;

/// Integration test: verify orphan-pts-master fd delivery via take_orphan_pts_master_fd().
///
/// Spawns loop_pts with an inherited slave PTY fd. loop_pts calls setsid()+TIOCSCTTY
/// internally. Parent dumps the child (slave only, master stays in parent). On restore,
/// CRIU sends "orphan-pts-master" notify with the new master fd; the library stores it
/// and we retrieve it with take_orphan_pts_master_fd() after restore().
pub fn orphan_pts_master_test(criu_bin_path: &str) {
    if unsafe { libc::geteuid() } != 0 {
        println!("Running orphan_pts_master_test: skip (not root)");
        return;
    }

    println!("Running orphan_pts_master_test");

    // Open PTY master and slave.
    let master_fd = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    if master_fd < 0 {
        println!("Running orphan_pts_master_test: skip (posix_openpt failed)");
        return;
    }
    if unsafe { libc::grantpt(master_fd) } != 0 || unsafe { libc::unlockpt(master_fd) } != 0 {
        unsafe { libc::close(master_fd) };
        println!("Running orphan_pts_master_test: skip (grantpt/unlockpt failed)");
        return;
    }
    let pts_name_ptr = unsafe { libc::ptsname(master_fd) };
    if pts_name_ptr.is_null() {
        unsafe { libc::close(master_fd) };
        println!("Running orphan_pts_master_test: skip (ptsname failed)");
        return;
    }
    let slave_path = unsafe { std::ffi::CStr::from_ptr(pts_name_ptr) }
        .to_string_lossy()
        .into_owned();
    let slave_fd = unsafe {
        libc::open(
            std::ffi::CString::new(slave_path).unwrap().as_ptr(),
            libc::O_RDWR,
        )
    };
    if slave_fd < 0 {
        unsafe { libc::close(master_fd) };
        println!("Running orphan_pts_master_test: skip (open slave failed)");
        return;
    }

    // Spawn loop_pts: inherits slave_fd, calls setsid()+TIOCSCTTY internally.
    let mut child = unsafe {
        std::process::Command::new("test/loop_pts")
            .arg(slave_fd.to_string())
            .pre_exec(move || {
                // Clear FD_CLOEXEC so slave_fd is inherited across exec.
                libc::fcntl(slave_fd, libc::F_SETFD, 0);
                Ok(())
            })
            .spawn()
            .expect("failed to spawn loop_pts")
    };
    let child_pid = child.id() as libc::pid_t;

    // Parent closes slave (child has it), keeps master open during dump.
    unsafe { libc::close(slave_fd) };
    std::thread::sleep(Duration::from_secs(1));

    let img_dir = "test/orphan_pts_images";
    if let Err(e) = std::fs::create_dir(img_dir) {
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            unsafe {
                libc::kill(child_pid, libc::SIGKILL);
                libc::close(master_fd);
            }
            let _ = child.wait();
            return;
        }
    }
    let directory = std::fs::File::open(img_dir).unwrap();

    let mut criu = rust_criu::Criu::new_with_criu_path(criu_bin_path.to_string()).unwrap();
    criu.set_pid(child_pid);
    criu.set_images_dir_fd(directory.as_raw_fd());
    criu.set_log_file("dump.log".to_string());
    criu.set_log_level(4);
    criu.set_shell_job(true);

    println!("Dumping PID {}", child_pid);
    if let Err(e) = criu.dump() {
        unsafe {
            libc::kill(child_pid, libc::SIGKILL);
            libc::close(master_fd);
        }
        let _ = child.wait();
        panic!("Dumping process failed with {:#?}", e);
    }
    unsafe { libc::close(master_fd) };
    let _ = child.wait();

    println!("Restoring PID {}", child_pid);
    let directory = std::fs::File::open(img_dir).unwrap();
    let mut criu = rust_criu::Criu::new_with_criu_path(criu_bin_path.to_string()).unwrap();
    let dir_fd = directory.as_raw_fd();
    criu.set_images_dir_fd(dir_fd);
    criu.set_work_dir_fd(dir_fd);
    criu.set_log_file("restore.log".to_string());
    criu.set_log_level(4);
    criu.set_notify_scripts(true);
    criu.set_shell_job(true);
    criu.set_orphan_pts_master(true);

    if let Err(e) = criu.restore() {
        unsafe {
            libc::kill(child_pid, libc::SIGKILL);
            libc::waitpid(child_pid, std::ptr::null_mut(), 0);
        }
        panic!(
            "Restoring process failed with {:#?}\nsee {}/restore.log for details",
            e, img_dir
        );
    }

    let master_fd = criu
        .take_orphan_pts_master_fd()
        .expect("orphan-pts-master fd not received after restore");
    assert!(
        unsafe { libc::isatty(master_fd) } != 0,
        "received fd is not a TTY (master)"
    );
    unsafe { libc::close(master_fd) };

    // Kill the restored process to avoid leaving orphan processes.
    unsafe {
        libc::kill(child_pid, libc::SIGKILL);
        libc::waitpid(child_pid, std::ptr::null_mut(), 0);
    }

    println!("Cleaning up");
    let _ = std::fs::remove_dir_all(img_dir);
}
