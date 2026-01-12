mod notify;
mod rust_criu_protobuf;

// Re-export Notify trait and NoopNotify (following go-criu design)
pub use notify::{NoopNotify, Notify};

use anyhow::{Context, Result};
use protobuf::Message;
use rust_criu_protobuf::rpc;
use std::error::Error;
use std::fs::File;
use std::io::{IoSliceMut, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};

/// Options for restoring a process with CRIU.
#[derive(Default)]
pub struct RestoreOpts<'a> {
    /// Extra files to pass to the CRIU subprocess at fd 4, 5, 6, etc.
    pub extra_files: &'a [RawFd],
}

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

pub struct Criu {
    criu_path: String,
    sv: [i32; 2],
    pid: i32,
    images_dir_fd: i32,
    log_level: i32,
    log_file: Option<String>,
    external_mounts: Vec<(String, String)>,
    externals: Vec<String>,
    inherit_fds: Vec<(String, i32)>,
    orphan_pts_master: Option<bool>,
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
    rst_sibling: Option<bool>,
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
            rst_sibling: None,
        })
    }

    pub fn get_criu_version(&mut self) -> Result<u32, Box<dyn Error>> {
        let response =
            self.do_swrk_with_response::<NoopNotify>(rpc::Criu_req_type::VERSION, None, None, &[])?;

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

    fn do_swrk_with_response<N: Notify>(
        &mut self,
        request_type: rpc::Criu_req_type,
        criu_opts: Option<rpc::Criu_opts>,
        notify: Option<&mut N>,
        extra_files: &[RawFd],
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

        // Clone extra_files for use in pre_exec closure
        let extra_files = extra_files.to_vec();

        let mut cmd = Command::new(self.criu_path.clone());
        cmd.arg("swrk").arg(format!("{}", self.sv[1]));
        cmd.stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        // Pass extra files to the child process at fd 4, 5, 6, etc.
        // (fd 3 is used by criu swrk socket)
        // This mirrors Go's cmd.ExtraFiles functionality.
        //
        // Based on Go's syscall/exec_unix.go forkAndExecInChild implementation:
        // 1. Calculate nextfd - the first fd that's safe for temporary use
        // 2. Move any source fds that conflict with destination range to nextfd
        // 3. Dup2 all fds to their final destinations
        if !extra_files.is_empty() {
            unsafe {
                cmd.pre_exec(move || {
                    let n = extra_files.len();
                    // Destination fds are 4, 5, 6, ..., 4+n-1
                    // nextfd is the first fd we can use for temporary storage
                    let mut nextfd = 4 + n as i32;

                    // Step 1: Move source fds that are in the destination range [4, 4+n)
                    // to higher fd numbers to avoid conflicts
                    let mut pipe: Vec<i32> = extra_files.clone();
                    for (i, fd_slot) in pipe.iter_mut().enumerate() {
                        let fd = *fd_slot;
                        // If this fd is in the destination range but not at its final position
                        if fd >= 4 && fd < 4 + n as i32 && fd != 4 + i as i32 {
                            // Check if it will be overwritten by another fd
                            if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                                // fd is already closed or invalid, skip
                                continue;
                            }
                            // Dup to a safe fd number
                            let new_fd = libc::fcntl(fd, libc::F_DUPFD, nextfd);
                            if new_fd < 0 {
                                return Err(std::io::Error::last_os_error());
                            }
                            *fd_slot = new_fd;
                            nextfd = new_fd + 1;
                        }
                    }

                    // Step 2: Dup2 all fds to their final destinations
                    for (i, &src_fd) in pipe.iter().enumerate() {
                        let dst_fd = 4 + i as i32;
                        if src_fd == dst_fd {
                            // Already at the right position, just clear close-on-exec
                            libc::fcntl(dst_fd, libc::F_SETFD, 0);
                        } else {
                            if libc::dup2(src_fd, dst_fd) < 0 {
                                return Err(std::io::Error::last_os_error());
                            }
                            libc::close(src_fd);
                        }
                    }

                    Ok(())
                });
            }
        }

        let mut criu = cmd.spawn().with_context(|| {
            format!(
                "executing criu binary for swrk using path {:?} failed",
                self.criu_path
            )
        })?;

        let mut req = rpc::Criu_req::new();
        req.set_type(request_type);

        if let Some(co) = criu_opts {
            req.opts = protobuf::MessageField::some(co);
        }

        let mut f = unsafe { File::from_raw_fd(self.sv[0]) };

        f.write_all(
            &req.write_to_bytes()
                .context("writing protobuf request to byte vec failed")?,
        )
        .with_context(|| {
            format!(
                "writing protobuf request to file (fd : {}) failed",
                self.sv[0]
            )
        })?;

        // Handle responses in a loop (like runc's criuSwrk)
        // Reference: https://github.com/opencontainers/runc/blob/main/libcontainer/criu_linux.go
        let response = self.handle_criu_response_loop(&mut f, &mut criu, request_type, notify)?;

        let _ = criu.wait();
        Result::Ok(response)
    }

    /// Handle CRIU responses in a loop, processing NOTIFY messages.
    /// This is similar to runc's criuSwrk loop.
    /// Uses recvmsg to receive both data and ancillary data (SCM_RIGHTS for fd passing).
    fn handle_criu_response_loop<N: Notify>(
        &self,
        f: &mut File,
        criu: &mut Child,
        request_type: rpc::Criu_req_type,
        mut notify: Option<&mut N>,
    ) -> Result<rpc::Criu_resp, Box<dyn Error>> {
        // 10*4096 taken from runc (larger than go-criu's 2*4096)
        let mut buffer = [0u8; 10 * 4096];
        // oob is the abbreviation of out of band data (for SCM_RIGHTS)
        let mut oob = [0u8; 4096];

        let fd = f.as_raw_fd();

        loop {
            // Use recvmsg to receive both data and ancillary data
            let mut iov = [IoSliceMut::new(&mut buffer)];

            let (n, received_fds) = unsafe {
                let mut msg: libc::msghdr = std::mem::zeroed();
                msg.msg_iov = iov.as_mut_ptr() as *mut libc::iovec;
                msg.msg_iovlen = 1;
                msg.msg_control = oob.as_mut_ptr() as *mut libc::c_void;
                msg.msg_controllen = oob.len();

                let n = libc::recvmsg(fd, &mut msg, 0);
                if n < 0 {
                    return Err(
                        format!("recvmsg failed: {}", std::io::Error::last_os_error()).into(),
                    );
                }
                if n == 0 {
                    return Err("unexpected EOF from CRIU".into());
                }

                // Parse any received file descriptors from ancillary data
                let fds = parse_scm_rights(&oob[..msg.msg_controllen]);
                (n as usize, fds)
            };

            // Check if buffer was too small
            if n == buffer.len() {
                return Err("buffer is too small for CRIU response".into());
            }

            let response: rpc::Criu_resp =
                Message::parse_from_bytes(&buffer[..n]).context("parsing criu response failed")?;

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
                    // Handle notification like runc's criuNotifications
                    if let Some(ref mut nfy) = notify {
                        self.dispatch_notify_with_fds(*nfy, &response, &received_fds)?;
                    }

                    // Send NotifySuccess response (like runc)
                    let mut notify_req = rpc::Criu_req::new();
                    notify_req.set_type(rpc::Criu_req_type::NOTIFY);
                    notify_req.set_notify_success(true);

                    f.write_all(
                        &notify_req
                            .write_to_bytes()
                            .context("writing notify success to byte vec failed")?,
                    )
                    .context("writing notify success response failed")?;

                    continue; // Continue loop to get next response
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

    /// Dispatch CRIU notification to appropriate callback with received fds.
    fn dispatch_notify_with_fds<N: Notify>(
        &self,
        notify: &mut N,
        response: &rpc::Criu_resp,
        received_fds: &[RawFd],
    ) -> Result<(), Box<dyn Error>> {
        let notify_msg = &response.notify;
        let script = notify_msg.script();
        let pid = notify_msg.pid();

        eprintln!(
            "[rust-criu] received notification: script={}, pid={}, fds={:?}",
            script, pid, received_fds
        );

        match script {
            "pre-dump" => notify.pre_dump(),
            "post-dump" => notify.post_dump(),
            "pre-restore" => notify.pre_restore(),
            "post-restore" => notify.post_restore(pid),
            "setup-namespaces" => notify.setup_namespaces(pid),
            "post-setup-namespaces" => notify.post_setup_namespaces(),
            "post-resume" => notify.post_resume(),
            "network-lock" => notify.network_lock(),
            "network-unlock" => notify.network_unlock(),
            "orphan-pts-master" => {
                // CRIU sends the PTY master fd via SCM_RIGHTS
                eprintln!(
                    "[rust-criu] orphan-pts-master received with {} fds",
                    received_fds.len()
                );
                if let Some(&master_fd) = received_fds.first() {
                    notify.orphan_pts_master(master_fd)
                } else {
                    Err("orphan-pts-master notification without fd".into())
                }
            }
            _ => {
                eprintln!("[rust-criu] unknown notification: {}", script);
                Ok(())
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

    /// Set an external resource for CRIU.
    /// This is used for resources like network namespaces that should be
    /// inherited rather than restored.
    pub fn set_external(&mut self, value: String) {
        self.externals.push(value);
    }

    /// Set an inherited file descriptor for CRIU restore.
    /// This is used to pass file descriptors from the parent process to the
    /// restored process.
    pub fn set_inherit_fd(&mut self, key: String, fd: i32) {
        self.inherit_fds.push((key, fd));
    }

    pub fn set_orphan_pts_master(&mut self, orphan_pts_master: bool) {
        self.orphan_pts_master = Some(orphan_pts_master);
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

    /// Set rst_sibling option.
    /// When true, the restored process becomes a sibling of the CRIU process
    /// rather than a child. This is required for proper process management
    /// when using swrk mode.
    pub fn set_rst_sibling(&mut self, rst_sibling: bool) {
        self.rst_sibling = Some(rst_sibling);
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

        if self.log_file.is_some() {
            criu_opts.set_log_file(self.log_file.clone().unwrap());
        }

        if !self.external_mounts.is_empty() {
            let mut external_mounts = Vec::new();
            for e in &self.external_mounts {
                let mut external_mount = rpc::Ext_mount_map::new();
                external_mount.set_key(e.0.clone());
                external_mount.set_val(e.1.clone());
                external_mounts.push(external_mount);
            }
            self.external_mounts.clear();
            criu_opts.ext_mnt = external_mounts;
        }

        if !self.externals.is_empty() {
            criu_opts.external = self.externals.clone();
            self.externals.clear();
        }

        if !self.inherit_fds.is_empty() {
            let mut inherit_fds = Vec::new();
            for (key, fd) in &self.inherit_fds {
                let mut inherit_fd = rpc::Inherit_fd::new();
                inherit_fd.set_key(key.clone());
                inherit_fd.set_fd(*fd);
                inherit_fds.push(inherit_fd);
            }
            self.inherit_fds.clear();
            criu_opts.inherit_fd = inherit_fds;
        }

        if self.orphan_pts_master.is_some() {
            criu_opts.set_orphan_pts_master(self.orphan_pts_master.unwrap());
        }

        if self.root.is_some() {
            criu_opts.set_root(self.root.clone().unwrap());
        }

        if self.leave_running.is_some() {
            criu_opts.set_leave_running(self.leave_running.unwrap());
        }

        if self.ext_unix_sk.is_some() {
            criu_opts.set_ext_unix_sk(self.ext_unix_sk.unwrap());
        }

        if self.shell_job.is_some() {
            criu_opts.set_shell_job(self.shell_job.unwrap());
        }

        if self.tcp_established.is_some() {
            criu_opts.set_tcp_established(self.tcp_established.unwrap());
        }

        if self.file_locks.is_some() {
            criu_opts.set_file_locks(self.file_locks.unwrap());
        }

        if self.manage_cgroups.is_some() {
            criu_opts.set_manage_cgroups(self.manage_cgroups.unwrap());
        }

        if self.work_dir_fd != -1 {
            criu_opts.set_work_dir_fd(self.work_dir_fd);
        }

        if self.freeze_cgroup.is_some() {
            criu_opts.set_freeze_cgroup(self.freeze_cgroup.clone().unwrap());
        }

        if self.cgroups_mode.is_some() {
            let mode = match self.cgroups_mode.as_ref().unwrap() {
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

        if self.cgroup_props.is_some() {
            criu_opts.set_cgroup_props(self.cgroup_props.clone().unwrap());
        }

        if self.notify_scripts.is_some() {
            criu_opts.set_notify_scripts(self.notify_scripts.unwrap());
        }

        if self.rst_sibling.is_some() {
            criu_opts.set_rst_sibling(self.rst_sibling.unwrap());
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
        self.rst_sibling = None;
    }

    /// Dump (checkpoint) a process without notification callbacks.
    pub fn dump(&mut self) -> Result<(), Box<dyn Error>> {
        self.dump_notify::<NoopNotify>(None)
    }

    /// Dump (checkpoint) a process with notification callbacks.
    pub fn dump_notify<N: Notify>(&mut self, notify: Option<&mut N>) -> Result<(), Box<dyn Error>> {
        let mut criu_opts = rpc::Criu_opts::default();
        self.fill_criu_opts(&mut criu_opts);
        self.do_swrk_with_response(rpc::Criu_req_type::DUMP, Some(criu_opts), notify, &[])?;
        self.clear();

        Ok(())
    }

    /// Restore a process without notification callbacks.
    pub fn restore(&mut self, opts: RestoreOpts) -> Result<(), Box<dyn Error>> {
        self.restore_notify::<NoopNotify>(None, opts)
    }

    /// Restore a process with notification callbacks.
    pub fn restore_notify<N: Notify>(
        &mut self,
        notify: Option<&mut N>,
        opts: RestoreOpts,
    ) -> Result<(), Box<dyn Error>> {
        let mut criu_opts = rpc::Criu_opts::default();
        self.fill_criu_opts(&mut criu_opts);
        self.do_swrk_with_response(
            rpc::Criu_req_type::RESTORE,
            Some(criu_opts),
            notify,
            opts.extra_files,
        )?;
        self.clear();
        Ok(())
    }
}

impl Drop for Criu {
    fn drop(&mut self) {
        unsafe { libc::close(self.sv[0]) };
        unsafe { libc::close(self.sv[1]) };
    }
}

/// Parse SCM_RIGHTS control messages to extract file descriptors.
/// Returns a vector of received file descriptors.
fn parse_scm_rights(cmsg_buffer: &[u8]) -> Vec<RawFd> {
    let mut fds = Vec::new();

    if cmsg_buffer.is_empty() {
        return fds;
    }

    // SAFETY: We're parsing the control message buffer that was filled by recvmsg
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: std::ptr::null_mut(),
            msg_iovlen: 0,
            msg_control: cmsg_buffer.as_ptr() as *mut libc::c_void,
            msg_controllen: cmsg_buffer.len(),
            msg_flags: 0,
        });

        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let data_ptr = libc::CMSG_DATA(cmsg);
                let data_len = (*cmsg).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                let num_fds = data_len / std::mem::size_of::<RawFd>();

                for i in 0..num_fds {
                    let fd = *(data_ptr as *const RawFd).add(i);
                    fds.push(fd);
                }
            }

            cmsg = libc::CMSG_NXTHDR(
                &libc::msghdr {
                    msg_name: std::ptr::null_mut(),
                    msg_namelen: 0,
                    msg_iov: std::ptr::null_mut(),
                    msg_iovlen: 0,
                    msg_control: cmsg_buffer.as_ptr() as *mut libc::c_void,
                    msg_controllen: cmsg_buffer.len(),
                    msg_flags: 0,
                },
                cmsg,
            );
        }
    }

    fds
}
