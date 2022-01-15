mod proto;

use proto::rpc;
use protobuf::Message;
use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::io::FromRawFd;
use std::process::Command;

#[derive(Clone)]
pub struct Criu {
    criu_path: String,
    sv: [i32; 2],
    pid: i32,
    images_dir_fd: i32,
    log_level: i32,
    log_file: Option<String>,
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
        })
    }

    pub fn get_criu_version(&mut self) -> Result<u32, Box<dyn Error>> {
        let response = self.do_swrk_with_response(rpc::criu_req_type::VERSION, None)?;

        let mut version: u32 = (response.get_version().get_major_number() * 10000).try_into()?;
        version += (response.get_version().get_minor_number() * 100) as u32;
        version += response.get_version().get_sublevel() as u32;

        if response.get_version().has_gitid() {
            // taken from runc: if it is a git release -> increase minor by 1
            version -= version % 100;
            version += 100;
        }

        Ok(version)
    }

    fn do_swrk_with_response(
        &mut self,
        request_type: rpc::criu_req_type,
        criu_opts: Option<rpc::criu_opts>,
    ) -> Result<rpc::criu_resp, Box<dyn Error>> {
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

        let criu = Some(
            Command::new(self.criu_path.clone())
                .arg("swrk")
                .arg(format!("{}", self.sv[1]))
                .spawn()?,
        );

        let mut req = rpc::criu_req::new();
        req.set_field_type(request_type);

        if let Some(co) = criu_opts {
            req.set_opts(co);
        }

        let mut f = unsafe { File::from_raw_fd(self.sv[0]) };

        f.write_all(&req.write_to_bytes()?)?;

        // 2*4096 taken from go-criu
        let mut buffer = [0; 2 * 4096];

        let read = f.read(&mut buffer[..])?;
        let response: rpc::criu_resp = Message::parse_from_bytes(&buffer[..read as usize])?;
        if !response.get_success() {
            criu.unwrap().kill()?;
            return Err(format!(
                "CRIU RPC request failed with (message:{} error:{}",
                response.get_cr_errmsg(),
                response.get_cr_errno()
            )
            .into());
        }

        if response.get_field_type() != request_type {
            criu.unwrap().kill()?;
            return Err(format!(
                "Unexpected CRIU RPC response ({:?})",
                response.get_field_type()
            )
            .into());
        }

        criu.unwrap().kill()?;
        Ok(response)
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

    fn fill_criu_opts(&mut self, criu_opts: &mut rpc::criu_opts) {
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
    }

    pub fn dump(&mut self) -> Result<(), Box<dyn Error>> {
        let mut criu_opts = rpc::criu_opts::default();
        self.fill_criu_opts(&mut criu_opts);
        self.do_swrk_with_response(rpc::criu_req_type::DUMP, Some(criu_opts))?;

        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), Box<dyn Error>> {
        let mut criu_opts = rpc::criu_opts::default();
        self.fill_criu_opts(&mut criu_opts);
        self.do_swrk_with_response(rpc::criu_req_type::RESTORE, Some(criu_opts))?;

        Ok(())
    }
}

impl Drop for Criu {
    fn drop(&mut self) {
        unsafe { libc::close(self.sv[0]) };
        unsafe { libc::close(self.sv[1]) };
    }
}
