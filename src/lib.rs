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
pub type NotifyCallback = fn(script: &str, notify: &Criu_notify) -> i32;

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

        let fd = self.sv[0];

        let req_bytes = req
            .write_to_bytes()
            .context("writing protobuf request to byte vec failed")?;

        self.send_request(fd, &req_bytes)
            .with_context(|| "sending protobuf request failed".to_string())?;

        let mut f = unsafe { File::from_raw_fd(fd) };

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

    /// Handle CRIU responses in a loop, processing NOTIFY messages.
    fn handle_criu_response_loop(
        &self,
        f: &mut File,
        criu: &mut Child,
        request_type: rpc::Criu_req_type,
    ) -> Result<rpc::Criu_resp, Box<dyn Error>> {
        // 10*4096 taken from runc (larger than go-criu's 2*4096)
        let mut buffer = [0u8; 10 * 4096];
        let fd = f.as_raw_fd();

        loop {
            let n = unsafe {
                let ret = libc::read(fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len());
                if ret < 0 {
                    return Err(format!("read failed: {}", std::io::Error::last_os_error()).into());
                }
                if ret == 0 {
                    return Err("unexpected EOF from CRIU".into());
                }
                ret as usize
            };

            // Fixed buffer: unlike libcriu we don't use MSG_TRUNC|MSG_PEEK to get
            // exact message size. If we read a full buffer, we conservatively assume
            // the message may be larger (more data still in socket) and fail to avoid
            // parsing truncated protobuf.
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
                    // Handle notification like libcriu's send_req_and_recv_resp_sk
                    let ret = if let Some(cb) = self.notify_cb {
                        let notify_msg = &response.notify;
                        cb(notify_msg.script(), notify_msg)
                    } else {
                        0
                    };

                    // Send notify ack (like libcriu's send_notify_ack)
                    let mut notify_req = rpc::Criu_req::new();
                    notify_req.set_type(rpc::Criu_req_type::NOTIFY);
                    notify_req.set_notify_success(ret == 0);

                    f.write_all(
                        &notify_req
                            .write_to_bytes()
                            .context("writing notify ack to byte vec failed")?,
                    )
                    .context("writing notify ack response failed")?;

                    if ret != 0 {
                        return Err(format!("notify callback failed with {}", ret).into());
                    }

                    continue; // goto again
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

    /// Set the notification callback.
    /// Based on libcriu's criu_set_notify_cb.
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

impl Drop for Criu {
    fn drop(&mut self) {
        unsafe { libc::close(self.sv[0]) };
        unsafe { libc::close(self.sv[1]) };
    }
}
