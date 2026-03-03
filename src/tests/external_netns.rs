use std::os::unix::io::AsRawFd;
use std::os::unix::process::CommandExt;

const EXTERNAL_NETNS_NAME: &str = "rust_criu_netns_test";

/// RAII guard that always deletes the test netns on drop.
/// Ensures cleanup on both success and panic paths.
struct NetnsGuard;

impl Drop for NetnsGuard {
    fn drop(&mut self) {
        let _ = std::process::Command::new("ip")
            .args(["netns", "del", EXTERNAL_NETNS_NAME])
            .status();
    }
}

/// External network namespace test: dump a process in a netns, restore into that same netns
/// using --external net[inode]:path so CRIU restores into the existing namespace.
/// Skipped unless root and `ip netns` is available.
pub fn external_netns_test(criu_bin_path: &str) {
    if unsafe { libc::geteuid() } != 0 {
        println!("external_netns_test: skip (not root)");
        return;
    }

    // Create netns (requires ip from iproute2)
    match std::process::Command::new("ip")
        .args(["netns", "add", EXTERNAL_NETNS_NAME])
        .output()
    {
        Ok(o) if o.status.success() => {}
        Ok(o) => {
            println!(
                "external_netns_test: skip (ip netns add failed: {:?})",
                String::from_utf8_lossy(&o.stderr)
            );
            return;
        }
        Err(e) => {
            println!(
                "external_netns_test: skip (ip not found or error: {:#?})",
                e
            );
            return;
        }
    }

    println!("Running external_netns_test");
    let _guard = NetnsGuard;

    let netns_path = format!("/var/run/netns/{}", EXTERNAL_NETNS_NAME);
    // Open netns once: for setns in child and for dump inode/restore inherit_fd.
    let ns_file = std::fs::File::open(&netns_path)
        .unwrap_or_else(|e| panic!("failed to open namespace: {:#?}", e));
    let netns_fd = ns_file.as_raw_fd();

    // Run loop in the netns via setns(CLONE_NEWNET) so we keep the same mount namespace as the parent.
    let mut child = match unsafe {
        std::process::Command::new("test/loop")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .pre_exec(move || {
                if libc::setns(netns_fd, libc::CLONE_NEWNET) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            })
            .spawn()
    } {
        Ok(c) => c,
        Err(e) => panic!("spawn loop in netns failed: {:#?}", e),
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
        panic!("failed to get PID from loop process");
    }
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(ns_file.as_raw_fd(), &mut stat) } != 0 {
        let _ = child.wait();
        panic!("failed to stat namespace");
    }
    let inode = stat.st_ino;
    let external = format!("{}[{}]:{}", "net", inode, rust_criu::criu_ns_to_key("net"));

    let img_dir = "test/external_netns_images";
    if let Err(e) = std::fs::create_dir(img_dir) {
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            let _ = child.wait();
            panic!("create_dir {} failed: {:#?}", img_dir, e);
        }
    }
    let directory = std::fs::File::open(img_dir).unwrap();

    let mut criu = rust_criu::Criu::new_with_criu_path(criu_bin_path.to_string()).unwrap();
    criu.set_pid(pid);
    criu.set_images_dir_fd(directory.as_raw_fd());
    criu.set_log_file("dump.log".to_string());
    criu.set_log_level(4);
    criu.set_ext_unix_sk(true);
    criu.set_shell_job(true);
    println!("Dumping PID {} (external {})", pid, external);
    criu.add_external(external);
    if let Err(e) = criu.dump() {
        unsafe { libc::kill(pid, libc::SIGKILL) };
        let _ = child.wait();
        panic!("external_netns dump failed: {:#?}", e);
    }
    let _ = child.wait();

    // Restore into existing netns via inherit_fd. Key must be the external id from dump (extRootNetNS).
    // Open netns and clear CLOEXEC so the child (criu swrk) inherits the fd (crun-style).
    let netns_file = std::fs::File::open(&netns_path).unwrap();
    let netns_fd = netns_file.as_raw_fd();
    unsafe { libc::fcntl(netns_fd, libc::F_SETFD, 0) }; // clear CLOEXEC so child inherits
    criu.set_images_dir_fd(directory.as_raw_fd());
    criu.set_log_file("restore.log".to_string());
    criu.set_log_level(4);
    let key = rust_criu::criu_ns_to_key("net");
    criu.add_inherit_fd(netns_fd, key.clone())
        .unwrap_or_else(|e| panic!("add_inherit_fd failed: {:#?}", e));

    println!("Restoring (inherit_fd key {})", key);
    if let Err(e) = criu.restore() {
        panic!("external_netns restore failed: {:#?}", e);
    }

    // Verify the restored process is in the expected network namespace by
    // comparing the inode of /proc/<pid>/ns/net with the one we recorded
    // before dump.
    let proc_netns = std::ffi::CString::new(format!("/proc/{}/ns/net", pid)).unwrap();
    let mut restored_stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(proc_netns.as_ptr(), &mut restored_stat) } != 0 {
        panic!("failed to stat /proc/{}/ns/net after restore", pid);
    }
    if restored_stat.st_ino != inode {
        panic!(
            "restored process is in wrong netns: got inode {} expected {}",
            restored_stat.st_ino, inode
        );
    }
    println!("Verified: restored process is in netns inode {}", inode);

    println!("Cleaning up");
    unsafe { libc::kill(pid, libc::SIGKILL) };
    unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };

    if let Err(e) = std::fs::remove_dir_all(img_dir) {
        panic!("remove_dir_all {} failed: {:#?}", img_dir, e);
    }
}
