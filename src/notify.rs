//! CRIU notification callback trait.
//!
//! This implementation follows the go-criu library design:
//! <https://github.com/checkpoint-restore/go-criu/blob/master/notify.go>

use std::error::Error;
use std::os::unix::io::RawFd;

/// CRIU notification callback trait.
///
/// Based on go-criu's Notify interface:
/// <https://github.com/checkpoint-restore/go-criu/blob/master/notify.go>
pub trait Notify {
    /// Called before dump starts.
    fn pre_dump(&mut self) -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    /// Called after dump completes.
    fn post_dump(&mut self) -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    /// Called before restore starts.
    fn pre_restore(&mut self) -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    /// Called after restore completes with the restored PID.
    fn post_restore(&mut self, pid: i32) -> Result<(), Box<dyn Error>> {
        let _ = pid;
        Ok(())
    }

    /// Called during namespace setup. Critical for PTY restore.
    fn setup_namespaces(&mut self, pid: i32) -> Result<(), Box<dyn Error>> {
        let _ = pid;
        Ok(())
    }

    /// Called after namespace setup.
    fn post_setup_namespaces(&mut self) -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    /// Called after process resumes.
    fn post_resume(&mut self) -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    /// Called when network should be locked.
    fn network_lock(&mut self) -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    /// Called when network can be unlocked.
    fn network_unlock(&mut self) -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    /// Called when CRIU sends the orphan PTY master fd.
    /// This is used during restore when orphan_pts_master option is set.
    /// The fd is the PTY master that should be sent to the console socket.
    fn orphan_pts_master(&mut self, master_fd: RawFd) -> Result<(), Box<dyn Error>> {
        let _ = master_fd;
        Ok(())
    }
}

/// Default no-op implementation of Notify.
#[derive(Default, Clone, Copy, Debug)]
pub struct NoopNotify;

impl Notify for NoopNotify {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noop_notify() {
        let mut notify = NoopNotify;
        assert!(notify.pre_dump().is_ok());
        assert!(notify.post_dump().is_ok());
        assert!(notify.setup_namespaces(123).is_ok());
    }
}
