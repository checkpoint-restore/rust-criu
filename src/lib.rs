pub mod rust_criu_protobuf;

use anyhow::{Context, Result};
use protobuf::Message;
use rust_criu_protobuf::rpc;
use rust_criu_protobuf::rpc::Criu_notify;
use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::process::{Child, Command, Stdio};

/// CRIU notification callback type (libcriu style).
pub type NotifyCallback = fn(script: &str, notify: &Criu_notify, fd: Option<RawFd>) -> i32;

#[derive(Clone)]
pub enum CgMode {
    IGNORE = 0,
    NONE = 1,
    PROPS = 2,
    SOFT = 3,
    FULL = 4,
    STRICT = 5,
    DEFAULT = 6,
}

impl CgMode {
    pub fn from(value: i32) -> CgMode {
        match value {
            0 => Self::IGNORE,
            1 => Self::NONE,
            2 => Self::PROPS,
            3 => Self::SOFT,
            4 => Self::FULL,
            5 => Self::STRICT,
            6 => Self::DEFAULT,
            _ => Self::DEFAULT,
        }
    }
}

#[derive(Clone)]
pub struct Criu {
    criu_path: String,
    sv: [i32; 2],
    pid: i32,
    images_dir_fd: i32,
    log_level: i32,
    log_file: Option<String>,
    external_mounts: Vec<(String, String)>,
    /// Generic --external strings, e.g. "net[<inode>]:<path>" for external network namespace.
    externals: Vec<String>,
    /// Inherit FDs for restore: (fd, key). Only effective with swrk (binary) mode. The fd must be opened
    /// without CLOEXEC (e.g. crun's `O_RDONLY`) so the child (criu swrk) inherits it; we use that fd number in the RPC.
    inherit_fds: Vec<(RawFd, String)>,
    orphan_pts_master: Option<bool>,
    /// PTY master fd received via SCM_RIGHTS on "orphan-pts-master" notify.
    /// Retrieve with take_orphan_pts_master_fd() after restore(). -1 if not received.
    orphan_pts_master_fd: i32,
    root: Option<String>,
    leave_running: Option<bool>,
    ext_unix_sk: Option<bool>,
    shell_job: Option<bool>,
    tcp_established: Option<bool>,
    file_locks: Option<bool>,
    manage_cgroups: Option<bool>,
    work_dir_fd: i32,
    freeze_cgroup: Option<String>,
    cgroups_mode: Option<CgMode>,
    cgroup_props: Option<String>,
    notify_scripts: Option<bool>,
    notify_cb: Option<NotifyCallback>,
}

impl Criu {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        Criu::new_with_criu_path(String::from("criu"))
    }

    pub fn new_with_criu_path(path_to_criu: String) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            criu_path: path_to_criu,
            sv: [-1, -1],
            pid: -1,
            images_dir_fd: -1,
            log_level: -1,
            log_file: None,
            external_mounts: Vec::new(),
            externals: Vec::new(),
            inherit_fds: Vec::new(),
            orphan_pts_master: None,
            orphan_pts_master_fd: -1,
            root: None,
            leave_running: None,
            ext_unix_sk: None,
            shell_job: None,
            tcp_established: None,
            file_locks: None,
            manage_cgroups: None,
            work_dir_fd: -1,
            freeze_cgroup: None,
            cgroups_mode: None,
            cgroup_props: None,
            notify_scripts: None,
            notify_cb: None,
        })
    }

    pub fn get_criu_version(&mut self) -> Result<u32, Box<dyn Error>> {
        let response = self.do_swrk_with_response(rpc::Criu_req_type::VERSION, None)?;

        let mut version: u32 = (response.version.major_number() * 10000)
            .try_into()
            .context("parsing criu version failed")?;
        version += (response.version.minor_number() * 100) as u32;
        version += response.version.sublevel() as u32;

        if response.version.has_gitid() {
            // taken from runc: if it is a git release -> increase minor by 1
            version -= version % 100;
            version += 100;
        }

        Ok(version)
    }

    fn do_swrk_with_response(
        &mut self,
        request_type: rpc::Criu_req_type,
        criu_opts: Option<rpc::Criu_opts>,
    ) -> Result<rpc::Criu_resp, Box<dyn Error>> {
        if unsafe {
            libc::socketpair(
                libc::AF_LOCAL,
                libc::SOCK_SEQPACKET,
                0,
                self.sv.as_mut_ptr(),
            ) != 0
        } {
            return Err("libc::socketpair failed".into());
        }

        let mut cmd = Command::new(self.criu_path.clone());
        cmd.arg("swrk").arg(format!("{}", self.sv[1]));
        cmd.stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        // Caller passes fds opened without CLOEXEC; the child (criu swrk) inherits them. We use those fd numbers in the RPC (crun-style).
        let mut criu = cmd.spawn().with_context(|| {
            format!(
                "executing criu binary for swrk using path {:?} failed",
                self.criu_path
            )
        })?;

        // Close sv[1] in the parent now that criu swrk has inherited it.
        // Matches libcriu's close(sks[1]) after fork().
        unsafe { libc::close(self.sv[1]) };
        self.sv[1] = -1;

        let mut req = rpc::Criu_req::new();
        req.set_type(request_type);

        if let Some(co) = criu_opts {
            req.opts = protobuf::MessageField::some(co);
        }

        let fd = self.sv[0];

        let req_bytes = req
            .write_to_bytes()
            .context("writing protobuf request to byte vec failed")?;

        self.send_request(fd, &req_bytes)
            .with_context(|| "sending protobuf request failed".to_string())?;

        let mut f = unsafe { File::from_raw_fd(fd) };
        self.sv[0] = -1;

        // Handle responses in a loop (like runc's criuSwrk)
        // Reference: https://github.com/opencontainers/runc/blob/main/libcontainer/criu_linux.go
        let response = self.handle_criu_response_loop(&mut f, &mut criu, request_type)?;

        let _ = criu.wait();
        Result::Ok(response)
    }

    fn send_request(&self, fd: RawFd, data: &[u8]) -> std::io::Result<()> {
        let ret = unsafe {
            libc::write(
                fd,
                data.as_ptr() as *const libc::c_void,
                data.len().min(libc::ssize_t::MAX as usize),
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if ret as usize != data.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "incomplete write to CRIU socket",
            ));
        }
        Ok(())
    }

    /// Receive CRIU response, returning the raw bytes and an optional SCM_RIGHTS fd.
    /// Mirrors libcriu's recv_resp: MSG_PEEK to size the buffer, MSG_TRUNC on recvmsg,
    /// EINVAL if cmsg_type != SCM_RIGHTS, ENFILE if MSG_CTRUNC.
    fn recv_criu_response(fd: RawFd) -> Result<(Vec<u8>, Option<RawFd>), Box<dyn Error>> {
        // Probe the datagram length without consuming it.
        // MSG_PEEK: leaves the message in the queue for the actual read below.
        // MSG_TRUNC: makes the kernel return the true on-wire length even with a 0-byte buffer.
        let len = unsafe {
            let ret = libc::recv(
                fd,
                std::ptr::null_mut(),
                0,
                libc::MSG_TRUNC | libc::MSG_PEEK,
            );
            if ret == -1 {
                let e = std::io::Error::last_os_error();
                return Err(format!("can't read response: {}", e).into());
            }
            ret as usize
        };

        let mut data_buf = vec![0u8; len];
        // Reserve space for exactly one fd in ancillary data (mirrors C's CMSG_LEN(sizeof(int))).
        let cmsg_len =
            unsafe { libc::CMSG_LEN(std::mem::size_of::<RawFd>() as libc::c_uint) as usize };
        let mut cmsg_buf = vec![0u8; cmsg_len];

        let mut iov = libc::iovec {
            iov_base: data_buf.as_mut_ptr().cast::<libc::c_void>(),
            iov_len: len,
        };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr().cast::<libc::c_void>();
        msg.msg_controllen = cmsg_len;

        let n = unsafe {
            let ret = libc::recvmsg(fd, &mut msg, libc::MSG_TRUNC);
            if ret == -1 {
                let e = std::io::Error::last_os_error();
                return Err(format!("can't read response: {}", e).into());
            }
            if ret == 0 {
                return Err("unexpected EOF from CRIU".into());
            }
            ret as usize
        };

        // NULL if no FD is present in the ancillary data.
        // Currently only the 'orphan-pts-master' notify callback sends an FD
        // (the master side of the pts) via SCM_RIGHTS.
        let mut orphan_fd: Option<RawFd> = None;
        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        if !cmsg.is_null() {
            // We probably got an FD from CRIU.
            if unsafe { (*cmsg).cmsg_type } != libc::SCM_RIGHTS {
                return Err(std::io::Error::from_raw_os_error(libc::EINVAL).into());
            }
            // MSG_CTRUNC is set if msg_controllen was too small to hold all ancillary data.
            if msg.msg_flags & libc::MSG_CTRUNC != 0 {
                return Err(std::io::Error::from_raw_os_error(libc::ENFILE).into());
            }
            // read_unaligned handles the case where CMSG_DATA's *u8 pointer does not
            // satisfy RawFd's alignment requirement, avoiding type-punning UB.
            let fd_val = unsafe { std::ptr::read_unaligned(libc::CMSG_DATA(cmsg) as *const RawFd) };
            orphan_fd = Some(fd_val);
        }

        Ok((data_buf[..n].to_vec(), orphan_fd))
    }

    /// Handle CRIU responses in a loop, processing NOTIFY messages.
    fn handle_criu_response_loop(
        &mut self,
        f: &mut File,
        criu: &mut Child,
        request_type: rpc::Criu_req_type,
    ) -> Result<rpc::Criu_resp, Box<dyn Error>> {
        let fd = f.as_raw_fd();

        loop {
            let (data, scm_fd) = Self::recv_criu_response(fd)?;

            let response: rpc::Criu_resp =
                Message::parse_from_bytes(&data).context("parsing criu response failed")?;

            let resp_type = response.type_();

            if !response.success() {
                criu.kill()
                    .context("killing criu process (due to failed request) failed")?;
                return Err(format!(
                    "criu failed: type {:?} errno {}",
                    resp_type,
                    response.cr_errno()
                )
                .into());
            }

            match resp_type {
                rpc::Criu_req_type::NOTIFY => {
                    // Handle notification like libcriu's send_req_and_recv_resp_sk
                    let notify_msg = &response.notify;
                    let script = notify_msg.script();

                    // Store any SCM_RIGHTS fd (orphan-pts-master delivers master fd this way).
                    if let Some(received_fd) = scm_fd {
                        self.orphan_pts_master_fd = received_fd;
                    }

                    let notify_ret = if let Some(cb) = self.notify_cb {
                        cb(script, notify_msg, scm_fd)
                    } else {
                        0
                    };

                    // Send notify ack (like libcriu's send_notify_ack).
                    // Mirrors C: ret = send_notify_ack(fd, ret).
                    // notify_success carries the callback result; ack send success drives loop/exit.
                    let mut notify_req = rpc::Criu_req::new();
                    notify_req.set_type(rpc::Criu_req_type::NOTIFY);
                    notify_req.set_notify_success(notify_ret == 0);

                    // Like C: if send_notify_ack fails → exit; if succeeds → goto again.
                    // If callback failed, CRIU will respond with success=false which is caught below.
                    f.write_all(
                        &notify_req
                            .write_to_bytes()
                            .context("writing notify ack to byte vec failed")?,
                    )
                    .context("writing notify ack response failed")?;
                    continue;
                }
                rpc::Criu_req_type::DUMP
                | rpc::Criu_req_type::RESTORE
                | rpc::Criu_req_type::PRE_DUMP
                | rpc::Criu_req_type::FEATURE_CHECK
                | rpc::Criu_req_type::VERSION => {
                    // Expected response types - break the loop
                    if resp_type != request_type {
                        criu.kill()
                            .context("killing criu process (due to incorrect response) failed")?;
                        return Err(
                            format!("Unexpected CRIU RPC response ({:?})", resp_type).into()
                        );
                    }
                    return Ok(response);
                }
                _ => {
                    return Err(format!("unable to parse the response {:?}", resp_type).into());
                }
            }
        }
    }

    pub fn set_pid(&mut self, pid: i32) {
        self.pid = pid;
    }

    pub fn set_images_dir_fd(&mut self, fd: i32) {
        self.images_dir_fd = fd;
    }

    pub fn set_log_level(&mut self, log_level: i32) {
        self.log_level = log_level;
    }

    pub fn set_log_file(&mut self, log_file: String) {
        self.log_file = Some(log_file);
    }

    pub fn set_external_mount(&mut self, key: String, value: String) {
        self.external_mounts.push((key, value));
    }

    /// Add a generic external resource (--external). Format is type-dependent, e.g. `tty[rdev:dev]` for TTY.
    pub fn add_external(&mut self, external: String) {
        self.externals.push(external);
    }

    /// Add an inherited file descriptor for CRIU restore. Inheriting is only supported with swrk (binary) mode.
    /// The fd must be opened **without CLOEXEC** (e.g. `O_RDONLY` like crun; or clear with `fcntl(fd, F_SETFD, 0)`)
    /// so the child (criu swrk) inherits it; we use that fd number in the RPC.
    pub fn add_inherit_fd(&mut self, fd: RawFd, key: String) -> Result<(), Box<dyn Error>> {
        if fd < 0 {
            return Err(format!("invalid fd {}: must be >= 0", fd).into());
        }
        self.inherit_fds.push((fd, key));
        Ok(())
    }

    /// If set to true, CRIU sends the "orphan-pts-master" notify during restore when the process
    /// has a controlling TTY; the PTY master fd is stored internally and retrievable via
    /// `take_orphan_pts_master_fd()` after `restore()` returns.
    pub fn set_orphan_pts_master(&mut self, orphan_pts_master: bool) {
        self.orphan_pts_master = Some(orphan_pts_master);
    }

    /// Returns the PTY master fd received during the last restore, consuming it.
    /// Returns None if not received. Caller is responsible for closing the fd.
    pub fn take_orphan_pts_master_fd(&mut self) -> Option<RawFd> {
        if self.orphan_pts_master_fd >= 0 {
            let fd = self.orphan_pts_master_fd;
            self.orphan_pts_master_fd = -1;
            Some(fd)
        } else {
            None
        }
    }

    pub fn set_root(&mut self, root: String) {
        self.root = Some(root);
    }

    pub fn set_leave_running(&mut self, leave_running: bool) {
        self.leave_running = Some(leave_running);
    }

    pub fn set_ext_unix_sk(&mut self, ext_unix_sk: bool) {
        self.ext_unix_sk = Some(ext_unix_sk);
    }

    pub fn set_shell_job(&mut self, shell_job: bool) {
        self.shell_job = Some(shell_job);
    }

    pub fn set_tcp_established(&mut self, tcp_established: bool) {
        self.tcp_established = Some(tcp_established);
    }

    pub fn set_file_locks(&mut self, file_locks: bool) {
        self.file_locks = Some(file_locks);
    }

    pub fn set_manage_cgroups(&mut self, manage_cgroups: bool) {
        self.manage_cgroups = Some(manage_cgroups);
    }

    pub fn set_work_dir_fd(&mut self, fd: i32) {
        self.work_dir_fd = fd;
    }

    pub fn set_freeze_cgroup(&mut self, freeze_cgroup: String) {
        self.freeze_cgroup = Some(freeze_cgroup);
    }

    pub fn cgroups_mode(&mut self, mode: CgMode) {
        self.cgroups_mode = Some(mode);
    }

    pub fn set_cgroup_props(&mut self, props: String) {
        self.cgroup_props = Some(props);
    }

    pub fn set_notify_scripts(&mut self, notify_scripts: bool) {
        self.notify_scripts = Some(notify_scripts);
    }

    /// Set the notification callback. Based on libcriu's criu_set_notify_cb.
    pub fn set_notify_cb(&mut self, cb: NotifyCallback) {
        self.notify_cb = Some(cb);
    }

    fn fill_criu_opts(&mut self, criu_opts: &mut rpc::Criu_opts) {
        if self.pid != -1 {
            criu_opts.set_pid(self.pid);
        }

        if self.images_dir_fd != -1 {
            criu_opts.set_images_dir_fd(self.images_dir_fd);
        }

        if self.log_level != -1 {
            criu_opts.set_log_level(self.log_level);
        }

        if let Some(ref log_file) = self.log_file {
            criu_opts.set_log_file(log_file.clone());
        }

        if !self.external_mounts.is_empty() {
            criu_opts.ext_mnt = std::mem::take(&mut self.external_mounts)
                .into_iter()
                .map(|(key, val)| {
                    let mut m = rpc::Ext_mount_map::new();
                    m.set_key(key);
                    m.set_val(val);
                    m
                })
                .collect();
        }

        if !self.externals.is_empty() {
            criu_opts.external = std::mem::take(&mut self.externals);
        }

        // inherit_fd: only supported with swrk. Use the caller's fd numbers (caller must open without CLOEXEC so child inherits).
        if !self.inherit_fds.is_empty() {
            criu_opts.inherit_fd = std::mem::take(&mut self.inherit_fds)
                .into_iter()
                .map(|(fd, key)| {
                    let mut m = rpc::Inherit_fd::new();
                    m.set_key(key);
                    m.set_fd(fd);
                    m
                })
                .collect();
        }

        if let Some(orphan_pts_master) = self.orphan_pts_master {
            criu_opts.set_orphan_pts_master(orphan_pts_master);
        }

        if let Some(ref root) = self.root {
            criu_opts.set_root(root.clone());
        }

        if let Some(leave_running) = self.leave_running {
            criu_opts.set_leave_running(leave_running);
        }

        if let Some(ext_unix_sk) = self.ext_unix_sk {
            criu_opts.set_ext_unix_sk(ext_unix_sk);
        }

        if let Some(shell_job) = self.shell_job {
            criu_opts.set_shell_job(shell_job);
        }

        if let Some(tcp_established) = self.tcp_established {
            criu_opts.set_tcp_established(tcp_established);
        }

        if let Some(file_locks) = self.file_locks {
            criu_opts.set_file_locks(file_locks);
        }

        if let Some(manage_cgroups) = self.manage_cgroups {
            criu_opts.set_manage_cgroups(manage_cgroups);
        }

        if self.work_dir_fd != -1 {
            criu_opts.set_work_dir_fd(self.work_dir_fd);
        }

        if let Some(ref freeze_cgroup) = self.freeze_cgroup {
            criu_opts.set_freeze_cgroup(freeze_cgroup.clone());
        }

        if let Some(ref cgroups_mode) = self.cgroups_mode {
            let mode = match cgroups_mode {
                CgMode::IGNORE => rpc::Criu_cg_mode::IGNORE,
                CgMode::NONE => rpc::Criu_cg_mode::CG_NONE,
                CgMode::PROPS => rpc::Criu_cg_mode::PROPS,
                CgMode::SOFT => rpc::Criu_cg_mode::SOFT,
                CgMode::FULL => rpc::Criu_cg_mode::FULL,
                CgMode::STRICT => rpc::Criu_cg_mode::STRICT,
                CgMode::DEFAULT => rpc::Criu_cg_mode::DEFAULT,
            };
            criu_opts.set_manage_cgroups_mode(mode);
        }

        if let Some(ref cgroup_props) = self.cgroup_props {
            criu_opts.set_cgroup_props(cgroup_props.clone());
        }

        if let Some(notify_scripts) = self.notify_scripts {
            criu_opts.set_notify_scripts(notify_scripts);
        }
    }

    fn clear(&mut self) {
        self.pid = -1;
        self.images_dir_fd = -1;
        self.log_level = -1;
        self.log_file = None;
        self.external_mounts = Vec::new();
        self.externals = Vec::new();
        self.inherit_fds = Vec::new();
        self.orphan_pts_master = None;
        self.root = None;
        self.leave_running = None;
        self.ext_unix_sk = None;
        self.shell_job = None;
        self.tcp_established = None;
        self.file_locks = None;
        self.manage_cgroups = None;
        self.work_dir_fd = -1;
        self.freeze_cgroup = None;
        self.cgroups_mode = None;
        self.cgroup_props = None;
        self.notify_scripts = None;
        self.notify_cb = None;
    }

    /// Dump (checkpoint) a process.
    /// Uses the callback set by set_notify_cb if any.
    pub fn dump(&mut self) -> Result<(), Box<dyn Error>> {
        let mut criu_opts = rpc::Criu_opts::default();
        self.fill_criu_opts(&mut criu_opts);
        self.do_swrk_with_response(rpc::Criu_req_type::DUMP, Some(criu_opts))?;
        self.clear();
        Ok(())
    }

    /// Restore a process.
    /// Uses the callback set by set_notify_cb if any.
    pub fn restore(&mut self) -> Result<(), Box<dyn Error>> {
        let mut criu_opts = rpc::Criu_opts::default();
        self.fill_criu_opts(&mut criu_opts);
        self.do_swrk_with_response(rpc::Criu_req_type::RESTORE, Some(criu_opts))?;
        self.clear();
        Ok(())
    }
}

/// Build the CRIU external key for a namespace type.
/// Follows runc's criuNsToKey: "extRoot" + capitalize(nsName) + "NS".
/// Ref: https://github.com/opencontainers/runc/blob/v1.4.0/libcontainer/criu_linux.go
pub fn criu_ns_to_key(name: &str) -> String {
    let mut chars = name.chars();
    let capitalized = match chars.next() {
        Some(c) => c.to_uppercase().chain(chars).collect::<String>(),
        None => String::new(),
    };
    format!("extRoot{}NS", capitalized)
}

impl Drop for Criu {
    fn drop(&mut self) {
        if self.sv[0] >= 0 {
            unsafe { libc::close(self.sv[0]) };
        }
        if self.sv[1] >= 0 {
            unsafe { libc::close(self.sv[1]) };
        }
        if self.orphan_pts_master_fd >= 0 {
            unsafe { libc::close(self.orphan_pts_master_fd) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recv_criu_response() {
        let mut fds = [-1i32; 2];
        unsafe { libc::socketpair(libc::AF_LOCAL, libc::SOCK_SEQPACKET, 0, fds.as_mut_ptr()) };

        // Data only (no SCM_RIGHTS): plain send suffices
        let data1 = [1u8; 10];
        unsafe { libc::send(fds[0], data1.as_ptr().cast(), data1.len(), 0) };
        let (data_out, scm_fd) = Criu::recv_criu_response(fds[1]).expect("recv failed");
        assert_eq!(data_out.len(), 10);
        assert!(scm_fd.is_none());

        // Data + one fd (SCM_RIGHTS)
        let open_fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        assert!(open_fd >= 0);
        let data2 = [2u8; 8];
        let mut iov = libc::iovec {
            iov_base: data2.as_ptr().cast_mut().cast::<libc::c_void>(),
            iov_len: data2.len(),
        };
        let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as _) as usize };
        let mut cmsg_buf = vec![0u8; cmsg_space];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr().cast::<libc::c_void>();
        msg.msg_controllen = cmsg_space;
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as _) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(cmsg) as *mut RawFd, open_fd);
            libc::sendmsg(fds[0], &msg, 0);
            libc::close(open_fd);
        }
        let (data_out, scm_fd) = Criu::recv_criu_response(fds[1]).expect("recv failed");
        assert_eq!(data_out.len(), 8);
        let received_fd = scm_fd.expect("expected SCM_RIGHTS fd");
        assert!(received_fd >= 0);
        unsafe {
            libc::close(received_fd);
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }
}
