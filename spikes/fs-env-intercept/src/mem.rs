//! Access to the target's memory from the supervisor.
//!
//! Always goes through `process_vm_readv`/`process_vm_writev` so a bad pointer in the target turns
//! into `EFAULT` for the target instead of a fault in the supervisor. In thread mode the target
//! shares our address space and the pid is our own, which the kernel accepts.

use std::ffi::CString;
use std::io;

#[derive(Debug, Clone, Copy)]
pub struct TargetMem {
    pid: libc::pid_t,
}

pub const PATH_MAX: usize = 4096;

impl TargetMem {
    pub fn new(pid: libc::pid_t) -> Self {
        Self { pid }
    }

    pub fn pid(&self) -> libc::pid_t {
        self.pid
    }

    pub fn read(&self, addr: u64, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let local = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let remote = libc::iovec {
            iov_base: addr as usize as *mut libc::c_void,
            iov_len: buf.len(),
        };
        // SAFETY: both iovecs describe live memory of the given lengths.
        let n = unsafe { libc::process_vm_readv(self.pid, &local, 1, &remote, 1, 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    pub fn read_exact(&self, addr: u64, buf: &mut [u8]) -> io::Result<()> {
        let n = self.read(addr, buf)?;
        if n != buf.len() {
            return Err(io::Error::from_raw_os_error(libc::EFAULT));
        }
        Ok(())
    }

    pub fn write(&self, addr: u64, buf: &[u8]) -> io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let local = libc::iovec {
            iov_base: buf.as_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let remote = libc::iovec {
            iov_base: addr as usize as *mut libc::c_void,
            iov_len: buf.len(),
        };
        // SAFETY: both iovecs describe live memory of the given lengths.
        let n = unsafe { libc::process_vm_writev(self.pid, &local, 1, &remote, 1, 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n as usize != buf.len() {
            return Err(io::Error::from_raw_os_error(libc::EFAULT));
        }
        Ok(())
    }

    /// Read a NUL-terminated path (at most `PATH_MAX` bytes).
    pub fn read_cstr(&self, addr: u64) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut chunk = [0u8; 256];
        let mut cursor = addr;
        while out.len() < PATH_MAX {
            // Never cross a page boundary in one read so a string ending just before an unmapped
            // page still succeeds.
            let page_left = 4096 - (cursor as usize % 4096);
            let want = chunk.len().min(page_left);
            let n = self.read(cursor, &mut chunk[..want])?;
            if n == 0 {
                return Err(io::Error::from_raw_os_error(libc::EFAULT));
            }
            if let Some(nul) = chunk[..n].iter().position(|b| *b == 0) {
                out.extend_from_slice(&chunk[..nul]);
                return Ok(out);
            }
            out.extend_from_slice(&chunk[..n]);
            cursor += n as u64;
        }
        Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG))
    }

    pub fn read_path(&self, addr: u64) -> io::Result<CString> {
        let bytes = self.read_cstr(addr)?;
        CString::new(bytes).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
    }
}
