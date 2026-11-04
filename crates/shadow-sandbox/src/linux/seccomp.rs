use crate::error::{Result, SandboxError};

// List of denied syscall names on x86_64 & aarch64
pub const DENIED_SYSCALLS: &[&str] = &[
    "kexec_load",
    "kexec_file_load",
    "init_module",
    "finit_module",
    "delete_module",
    "bpf",
    "perf_event_open",
    "ptrace",
    "mount",
    "umount2",
    "pivot_root",
    "setns",
    "unshare",
    "chroot",
    "keyctl",
    "add_key",
    "request_key",
    "userfaultfd",
    "open_by_handle_at",
    "iopl",
    "ioperm",
    "swapon",
    "swapoff",
    "reboot",
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    "personality",
    "process_vm_readv",
    "process_vm_writev",
    "syslog",
    "lookup_dcookie",
    "acct",
    "kcmp",
    "fanotify_init",
    "fanotify_mark",
    "clock_settime",
    "settimeofday",
    "adjtimex",
    "vmsplice",
];

pub fn apply_seccomp_policy() -> Result<()> {
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        return Err(SandboxError::Seccomp(
            "Seccomp BPF filter currently only supports x86_64 and aarch64 architectures"
                .to_string(),
        ));
    }

    // 1. Ensure PR_SET_NO_NEW_PRIVS is set (mandatory before unprivileged seccomp filter)
    unsafe {
        let ret = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            return Err(SandboxError::Seccomp(format!(
                "Failed to set PR_SET_NO_NEW_PRIVS: {err}"
            )));
        }
    }

    // 2. Build BPF filter denying dangerous syscalls with EPERM, allowing all others
    let mut filter = Vec::new();

    // BPF_LD | BPF_W | BPF_ABS: Load arch from seccomp_data.arch (offset 4)
    filter.push(libc::sock_filter {
        code: 0x20, // BPF_LD | BPF_W | BPF_ABS
        jt: 0,
        jf: 0,
        k: 4, // offsetof(struct seccomp_data, arch)
    });

    #[cfg(target_arch = "x86_64")]
    let expected_arch = 0xc000003eu32; // AUDIT_ARCH_X86_64
    #[cfg(target_arch = "aarch64")]
    let expected_arch = 0xc00000b7u32; // AUDIT_ARCH_AARCH64

    filter.push(libc::sock_filter {
        code: 0x15, // BPF_JMP | BPF_JEQ | BPF_K
        jt: 1,      // Jump to next instruction if equal
        jf: 0,      // Jump to kill if false
        k: expected_arch,
    });

    // Return SECCOMP_RET_KILL_PROCESS (0x80000000) if architecture doesn't match
    filter.push(libc::sock_filter {
        code: 0x06, // BPF_RET | BPF_K
        jt: 0,
        jf: 0,
        k: 0x80000000, // SECCOMP_RET_KILL_PROCESS
    });

    // Load syscall nr from seccomp_data.nr (offset 0)
    filter.push(libc::sock_filter {
        code: 0x20, // BPF_LD | BPF_W | BPF_ABS
        jt: 0,
        jf: 0,
        k: 0, // offsetof(struct seccomp_data, nr)
    });

    #[cfg(target_arch = "x86_64")]
    {
        // Mitigate x32 ABI bypass: reject any syscall with nr >= 0x40000000 (__X32_SYSCALL_BIT)
        filter.push(libc::sock_filter {
            code: 0x25, // BPF_JMP | BPF_JGE | BPF_K
            jt: 0,      // if nr >= 0x40000000, jump to return EPERM
            jf: 1,      // else skip return EPERM
            k: 0x40000000,
        });
        filter.push(libc::sock_filter {
            code: 0x06, // BPF_RET | BPF_K
            jt: 0,
            jf: 0,
            k: 0x00050001, // SECCOMP_RET_ERRNO | (EPERM = 1)
        });
    }

    // Syscall numbers to deny on x86_64
    #[cfg(target_arch = "x86_64")]
    let denied_nrs = [
        libc::SYS_kexec_load,
        320, // SYS_kexec_file_load
        libc::SYS_init_module,
        313, // SYS_finit_module
        libc::SYS_delete_module,
        321, // SYS_bpf
        298, // SYS_perf_event_open
        libc::SYS_ptrace,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        308, // SYS_setns
        libc::SYS_unshare,
        libc::SYS_chroot,
        250, // SYS_keyctl
        248, // SYS_add_key
        249, // SYS_request_key
        323, // SYS_userfaultfd
        304, // SYS_open_by_handle_at
        libc::SYS_iopl,
        libc::SYS_ioperm,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_reboot,
        425, // SYS_io_uring_setup
        426, // SYS_io_uring_enter
        427, // SYS_io_uring_register
        135, // SYS_personality
        310, // SYS_process_vm_readv
        311, // SYS_process_vm_writev
        103, // SYS_syslog
        212, // SYS_lookup_dcookie
        libc::SYS_acct,
        312, // SYS_kcmp
        300, // SYS_fanotify_init
        301, // SYS_fanotify_mark
        libc::SYS_clock_settime,
        libc::SYS_settimeofday,
        libc::SYS_adjtimex,
        libc::SYS_vmsplice,
    ];

    #[cfg(target_arch = "aarch64")]
    let denied_nrs = [
        104, // SYS_kexec_load
        294, // SYS_kexec_file_load
        105, // SYS_init_module
        273, // SYS_finit_module
        106, // SYS_delete_module
        280, // SYS_bpf
        241, // SYS_perf_event_open
        libc::SYS_ptrace,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        268, // SYS_setns
        97,  // SYS_unshare
        51,  // SYS_chroot
        219, // SYS_keyctl
        217, // SYS_add_key
        218, // SYS_request_key
        282, // SYS_userfaultfd
        264, // SYS_open_by_handle_at
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_reboot,
        425, // SYS_io_uring_setup
        426, // SYS_io_uring_enter
        427, // SYS_io_uring_register
        92,  // SYS_personality
        270, // SYS_process_vm_readv
        271, // SYS_process_vm_writev
        116, // SYS_syslog
        18,  // SYS_lookup_dcookie
        89,  // SYS_acct
        272, // SYS_kcmp
        262, // SYS_fanotify_init
        263, // SYS_fanotify_mark
        112, // SYS_clock_settime
        170, // SYS_settimeofday
        171, // SYS_adjtimex
        75,  // SYS_vmsplice
    ];

    // For each denied syscall, if equal, return SECCOMP_RET_ERRNO(EPERM = 1)
    for &nr in &denied_nrs {
        filter.push(libc::sock_filter {
            code: 0x15, // BPF_JMP | BPF_JEQ | BPF_K
            jt: 0,      // Jump to next instruction if equal
            jf: 1,      // Jump over the return if not equal
            k: nr as u32,
        });
        filter.push(libc::sock_filter {
            code: 0x06, // BPF_RET | BPF_K
            jt: 0,
            jf: 0,
            k: 0x00050001, // SECCOMP_RET_ERRNO | (EPERM = 1)
        });
    }

    // Default allow: SECCOMP_RET_ALLOW (0x7fff0000)
    filter.push(libc::sock_filter {
        code: 0x06, // BPF_RET | BPF_K
        jt: 0,
        jf: 0,
        k: 0x7fff0000, // SECCOMP_RET_ALLOW
    });

    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };

    unsafe {
        let ret = libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &prog);
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            return Err(SandboxError::Seccomp(format!(
                "Failed to apply seccomp filter: {err}"
            )));
        }
    }

    Ok(())
}
