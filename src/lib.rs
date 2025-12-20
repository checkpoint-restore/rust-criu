mod notify;
mod rust_criu_protobuf;

// Re-export Notify trait and NoopNotify (following go-criu design)
pub use notify::{NoopNotify, Notify};

use anyhow::{Context, Result};
use protobuf::Message;
use rust_criu_protobuf::rpc;
use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::io::FromRawFd;
use std::process::{Child, Command};

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
        let response = self.do_swrk_with_response::<NoopNotify>(
            rpc::Criu_req_type::VERSION,
            None,
            None,
        )?;

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

        let mut criu = Command::new(self.criu_path.clone())
            .arg("swrk")
            .arg(format!("{}", self.sv[1]))
            .spawn()
            .with_context(|| {
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
    fn handle_criu_response_loop<N: Notify>(
        &self,
        f: &mut File,
        criu: &mut Child,
        request_type: rpc::Criu_req_type,
        mut notify: Option<&mut N>,
    ) -> Result<rpc::Criu_resp, Box<dyn Error>> {
        // 2*4096 taken from go-criu
        let mut buffer = [0u8; 2 * 4096];

        loop {
            let n = f.read(&mut buffer[..]).with_context(|| {
                format!(
                    "reading criu response from file (fd :{}) failed",
                    self.sv[0]
                )
            })?;

            if n == 0 {
                return Err("unexpected EOF from CRIU".into());
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
                ).into());
            }

            match resp_type {
                rpc::Criu_req_type::NOTIFY => {
                    // Handle notification like runc's criuNotifications
                    if let Some(ref mut nfy) = notify {
                        self.dispatch_notify(*nfy, &response)?;
                    }

                    // Send NotifySuccess response (like runc)
                    let mut notify_req = rpc::Criu_req::new();
                    notify_req.set_type(rpc::Criu_req_type::NOTIFY);
                    notify_req.set_notify_success(true);

                    f.write_all(
                        &notify_req.write_to_bytes()
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

    /// Dispatch CRIU notification to appropriate callback.
    fn dispatch_notify<N: Notify>(
        &self,
        notify: &mut N,
        response: &rpc::Criu_resp,
    ) -> Result<(), Box<dyn Error>> {
        let notify_msg = &response.notify;
        let script = notify_msg.script();
        let pid = notify_msg.pid();

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
            _ => Ok(()), // Ignore unknown notifications
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
        self.do_swrk_with_response(rpc::Criu_req_type::DUMP, Some(criu_opts), notify)?;
        self.clear();

        Ok(())
    }

    /// Restore a process without notification callbacks.
    pub fn restore(&mut self) -> Result<(), Box<dyn Error>> {
        self.restore_notify::<NoopNotify>(None)
    }

    /// Restore a process with notification callbacks.
    pub fn restore_notify<N: Notify>(&mut self, notify: Option<&mut N>) -> Result<(), Box<dyn Error>> {
        let mut criu_opts = rpc::Criu_opts::default();
        self.fill_criu_opts(&mut criu_opts);
        self.do_swrk_with_response(rpc::Criu_req_type::RESTORE, Some(criu_opts), notify)?;
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
