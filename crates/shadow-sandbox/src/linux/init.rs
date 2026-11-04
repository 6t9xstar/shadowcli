use crate::error::{Result, SandboxError};
use std::sync::atomic::{AtomicI32, Ordering};

static TARGET_CHILD_PID: AtomicI32 = AtomicI32::new(0);

extern "C" fn sig_forward_handler(sig: libc::c_int) {
    let pid = TARGET_CHILD_PID.load(Ordering::Relaxed);
    if pid > 0 {
        unsafe {
            libc::kill(pid, sig);
        }
    }
}

unsafe fn setup_signal_forwarding() {
    let handler = sig_forward_handler as *const () as usize;
    libc::signal(libc::SIGINT, handler);
    libc::signal(libc::SIGTERM, handler);
    libc::signal(libc::SIGHUP, handler);
}

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
        // Reset default signal handlers for target child
        unsafe {
            libc::signal(libc::SIGINT, libc::SIG_DFL);
            libc::signal(libc::SIGTERM, libc::SIG_DFL);
            libc::signal(libc::SIGHUP, libc::SIG_DFL);
        }
        // Target child executes payload
        if let Err(e) = target_exec() {
            eprintln!("ShadowCLI sandbox child error: {e}");
            unsafe { libc::_exit(125) };
        }
        unsafe { libc::_exit(0) };
    }

    // Register child PID and setup signal forwarding in PID 1 supervisor
    TARGET_CHILD_PID.store(child_pid, Ordering::SeqCst);
    unsafe {
        setup_signal_forwarding();
    }

    // PID 1 supervisor loop
    let mut target_exit_code = 1;

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
            if libc::WIFEXITED(status) {
                target_exit_code = libc::WEXITSTATUS(status);
            } else if libc::WIFSIGNALED(status) {
                target_exit_code = 128 + libc::WTERMSIG(status);
            }
            break;
        }
    }

    // Target child has terminated. Clean up all remaining orphaned processes in the PID namespace
    unsafe {
        // 1. Send SIGTERM to all processes in namespace (except PID 1)
        libc::kill(-1, libc::SIGTERM);

        // 2. Allow brief 50ms grace period for graceful cleanup
        let start = std::time::Instant::now();
        while start.elapsed() < std::time::Duration::from_millis(50) {
            let mut status: libc::c_int = 0;
            let r = libc::waitpid(-1, &mut status, libc::WNOHANG);
            if r < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ECHILD) {
                    return Ok(target_exit_code);
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        // 3. Force-terminate any lingering processes with SIGKILL
        libc::kill(-1, libc::SIGKILL);

        // 4. Reap all descendants until ECHILD
        loop {
            let mut status: libc::c_int = 0;
            let r = libc::waitpid(-1, &mut status, 0);
            if r < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ECHILD) {
                    break;
                }
            }
        }
    }

    Ok(target_exit_code)
}
