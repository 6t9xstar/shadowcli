use crate::error::{Result, SandboxError};

pub fn run_pid1_init<F>(target_exec: F) -> Result<i32>
where
    F: FnOnce() -> Result<()>,
{
    // Fork the target child
    let child_pid = unsafe { libc::fork() };
    if child_pid < 0 {
        return Err(SandboxError::Process(
            "Failed to fork target process from init".to_string(),
        ));
    }

    if child_pid == 0 {
        // Target child executes payload
        if let Err(e) = target_exec() {
            eprintln!("ShadowCLI sandbox child error: {e}");
            unsafe { libc::_exit(125) };
        }
        unsafe { libc::_exit(0) };
    }

    // PID 1 supervisor loop
    let mut target_exit_code = 1;
    let mut target_exited = false;

    loop {
        let mut status: libc::c_int = 0;
        let reaped_pid = unsafe { libc::waitpid(-1, &mut status, 0) };

        if reaped_pid < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ECHILD) {
                // No more children left in PID namespace
                break;
            }
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }

        if reaped_pid == child_pid {
            target_exited = true;
            if libc::WIFEXITED(status) {
                target_exit_code = libc::WEXITSTATUS(status);
            } else if libc::WIFSIGNALED(status) {
                target_exit_code = 128 + libc::WTERMSIG(status);
            }
        }

        // If target exited, reap remaining orphans non-blocking and finish
        if target_exited {
            while unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) } > 0 {}
            break;
        }
    }

    Ok(target_exit_code)
}
