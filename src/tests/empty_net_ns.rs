use nix::sched::{unshare, CloneFlags};
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::waitpid;
use nix::unistd::{geteuid, Pid};
use std::io::{BufRead, BufReader};
use std::os::unix::io::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;

fn netns_contains_iface(pid: i32, iface: &str) -> std::io::Result<bool> {
    let content = std::fs::read_to_string(format!("/proc/{}/net/dev", pid))?;
    Ok(content.lines().any(|line| {
        line.trim_start()
            .strip_prefix(iface)
            .is_some_and(|s| s.starts_with(':'))
    }))
}

/// Verifies empty_net_ns option: network interfaces created before dump
/// are absent after restore, confirming CRIU skips restoring network
/// interfaces when --empty-ns net is specified.
pub fn empty_net_ns_test(criu_bin_path: &str) {
    if !geteuid().is_root() {
        println!("empty_net_ns_test: skip (not root)");
        return;
    }

    println!("Running empty_net_ns_test");

    let mut child = match unsafe {
        Command::new("test/loop")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .pre_exec(|| {
                unshare(CloneFlags::CLONE_NEWNET)?;
                Ok(())
            })
            .spawn()
    } {
        Ok(c) => c,
        Err(e) => panic!("spawn loop with unshared netns failed: {:#?}", e),
    };

    let pid_raw: i32 = {
        let mut line = String::new();
        BufReader::new(child.stdout.take().expect("stdout should be piped"))
            .read_line(&mut line)
            .expect("failed to read from loop process");
        line.trim()
            .parse()
            .expect("loop process did not print a valid PID")
    };
    let pid = Pid::from_raw(pid_raw);

    let netns_path = format!("/proc/{}/ns/net", pid_raw);
    let netns_option = format!("--net={}", &netns_path);

    // Use tun device (not lo with extra IP) because lo state is always restored
    // by CRIU regardless of empty_ns. Dummy is unsupported by CRIU.
    let setup_steps: &[(&str, &[&str])] = &[
        (
            "nsenter",
            &[&netns_option, "ip", "tuntap", "add", "tun0", "mode", "tun"],
        ),
        (
            "nsenter",
            &[
                &netns_option,
                "ip",
                "addr",
                "add",
                "10.99.99.1/24",
                "dev",
                "tun0",
            ],
        ),
        (
            "nsenter",
            &[&netns_option, "ip", "link", "set", "tun0", "up"],
        ),
    ];

    for (cmd, args) in setup_steps {
        let status = match Command::new(cmd).args(*args).status() {
            Ok(s) => s,
            Err(e) => {
                let _ = kill(pid, Signal::SIGKILL);
                let _ = child.wait();
                panic!("netns setup step `{} {:?}` failed: {:#?}", cmd, args, e);
            }
        };
        if !status.success() {
            let _ = kill(pid, Signal::SIGKILL);
            let _ = child.wait();
            panic!(
                "netns setup step `{} {:?}` exited with {:?}",
                cmd, args, status
            );
        }
    }

    match netns_contains_iface(pid_raw, "tun0") {
        Ok(true) => {}
        Ok(false) => {
            let _ = kill(pid, Signal::SIGKILL);
            let _ = child.wait();
            panic!(
                "test network interface(tun0) was not visible in netns before dump (setup failed?)"
            );
        }
        Err(e) => {
            let _ = kill(pid, Signal::SIGKILL);
            let _ = child.wait();
            panic!(
                "failed to read /proc/{}/net/dev before dump: {:#?}",
                pid_raw, e
            );
        }
    }

    let img_dir = "test/empty_net_ns_images";
    if let Err(e) = std::fs::create_dir(img_dir) {
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            let _ = kill(pid, Signal::SIGKILL);
            let _ = child.wait();
            panic!("create_dir {} failed: {:#?}", img_dir, e);
        }
    }
    let directory = std::fs::File::open(img_dir).unwrap();

    let mut criu = rust_criu::Criu::new_with_criu_path(criu_bin_path.to_string()).unwrap();
    criu.set_pid(pid_raw);
    criu.set_images_dir_fd(directory.as_raw_fd());
    criu.set_log_file("dump.log".to_string());
    criu.set_log_level(4);
    criu.set_empty_net_ns(true);

    println!("Dumping PID {}", pid_raw);
    if let Err(e) = criu.dump() {
        let _ = kill(pid, Signal::SIGKILL);
        let _ = child.wait();
        panic!("empty_net_ns dump failed: {:#?}", e);
    }
    let _ = child.wait();

    criu.set_images_dir_fd(directory.as_raw_fd());
    criu.set_log_file("restore.log".to_string());
    criu.set_log_level(4);
    criu.set_empty_net_ns(true);

    println!("Restoring empty_net_ns_test");
    if let Err(e) = criu.restore() {
        panic!("empty_net_ns restore failed: {:#?}", e);
    }

    match netns_contains_iface(pid_raw, "tun0") {
        Ok(false) => {}
        Ok(true) => {
            let _ = kill(pid, Signal::SIGKILL);
            let _ = waitpid(pid, None);
            panic!(
                "empty_net_ns did not produce an empty netns: test interface still present in PID {}",
                pid_raw
            );
        }
        Err(e) => {
            let _ = kill(pid, Signal::SIGKILL);
            let _ = waitpid(pid, None);
            panic!(
                "failed to read /proc/{}/net/dev after restore: {:#?}",
                pid_raw, e
            );
        }
    }

    println!("Cleaning up");
    let _ = kill(pid, Signal::SIGKILL);
    let _ = waitpid(pid, None);

    if let Err(e) = std::fs::remove_dir_all(img_dir) {
        panic!("remove_dir_all {} failed: {:#?}", img_dir, e);
    }
}
