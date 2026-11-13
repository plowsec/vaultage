//! Process hardening. Call `harden()` first thing in `main`.
//!
//! What keeps other processes out of our memory on macOS is the *hardened runtime* code signature
//! (no `get-task-allow`): with SIP on, the kernel then refuses task ports, debugger attach and
//! dylib injection, even to root. The calls here add defence in depth and report the real state.

use serde::Serialize;
use std::sync::OnceLock;

#[derive(Serialize, Clone, Debug, Default)]
pub struct Posture {
    /// No core files (they would contain keys).
    pub core_dumps_off: bool,
    /// ptrace(PT_DENY_ATTACH) / PR_SET_DUMPABLE=0 applied.
    pub attach_denied: bool,
    /// Signed with the hardened runtime (macOS). None = unknown / not applicable.
    pub hardened_runtime: Option<bool>,
    /// Signature allows debuggers (`get-task-allow`). Must be false in a release build.
    pub debuggable: Option<bool>,
    /// System Integrity Protection is on (macOS).
    pub sip: Option<bool>,
    /// Key memory is locked against swap.
    pub memory_locked: bool,
}

static POSTURE: OnceLock<Posture> = OnceLock::new();

pub fn harden() -> Posture {
    POSTURE.get_or_init(apply).clone()
}

#[cfg(target_os = "macos")]
fn apply() -> Posture {
    extern "C" {
        fn csops(pid: libc::pid_t, ops: libc::c_uint, useraddr: *mut libc::c_void, usersize: libc::size_t) -> libc::c_int;
        fn csr_get_active_config(config: *mut u32) -> libc::c_int;
        fn ptrace(request: libc::c_int, pid: libc::pid_t, addr: *mut libc::c_char, data: libc::c_int) -> libc::c_int;
    }
    const PT_DENY_ATTACH: libc::c_int = 31;
    const CS_GET_TASK_ALLOW: u32 = 0x4;
    const CS_RUNTIME: u32 = 0x10000;

    let mut p = Posture::default();
    unsafe {
        let lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        p.core_dumps_off = libc::setrlimit(libc::RLIMIT_CORE, &lim) == 0;
        // Debug builds stay debuggable on purpose.
        if !cfg!(debug_assertions) {
            p.attach_denied = ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) == 0;
        }
        let mut flags: u32 = 0;
        if csops(libc::getpid(), 0, &mut flags as *mut u32 as *mut libc::c_void, 4) == 0 {
            p.hardened_runtime = Some(flags & CS_RUNTIME != 0);
            p.debuggable = Some(flags & CS_GET_TASK_ALLOW != 0);
        }
        let mut cfg: u32 = 0;
        if csr_get_active_config(&mut cfg) == 0 {
            p.sip = Some(cfg == 0);
        }
        let probe = [0u8; 32];
        p.memory_locked = libc::mlock(probe.as_ptr() as *const libc::c_void, 32) == 0;
        libc::munlock(probe.as_ptr() as *const libc::c_void, 32);
    }
    p
}

/// iOS: the sandbox and code signing keep other apps out. What is left is a debugger on a
/// development-signed build (`get-task-allow`), so report that and refuse attach on device.
#[cfg(target_os = "ios")]
fn apply() -> Posture {
    extern "C" {
        fn csops(pid: libc::pid_t, ops: libc::c_uint, useraddr: *mut libc::c_void, usersize: libc::size_t) -> libc::c_int;
        fn ptrace(request: libc::c_int, pid: libc::pid_t, addr: *mut libc::c_char, data: libc::c_int) -> libc::c_int;
    }
    const PT_DENY_ATTACH: libc::c_int = 31;
    const CS_GET_TASK_ALLOW: u32 = 0x4;

    let mut p = Posture::default();
    unsafe {
        let lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        p.core_dumps_off = libc::setrlimit(libc::RLIMIT_CORE, &lim) == 0;
        // Debug builds and the simulator stay debuggable on purpose.
        if !cfg!(debug_assertions) && !cfg!(target_abi = "sim") {
            p.attach_denied = ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) == 0;
        }
        let mut flags: u32 = 0;
        if csops(libc::getpid(), 0, &mut flags as *mut u32 as *mut libc::c_void, 4) == 0 {
            p.debuggable = Some(flags & CS_GET_TASK_ALLOW != 0);
        }
        let probe = [0u8; 32];
        p.memory_locked = libc::mlock(probe.as_ptr() as *const libc::c_void, 32) == 0;
        libc::munlock(probe.as_ptr() as *const libc::c_void, 32);
    }
    p
}

#[cfg(all(unix, not(target_os = "macos"), not(target_os = "ios")))]
fn apply() -> Posture {
    let mut p = Posture::default();
    unsafe {
        let lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        p.core_dumps_off = libc::setrlimit(libc::RLIMIT_CORE, &lim) == 0;
        #[cfg(target_os = "linux")]
        {
            // Also blocks ptrace and /proc/<pid>/mem from same-uid processes.
            p.attach_denied = libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0;
        }
        let probe = [0u8; 32];
        p.memory_locked = libc::mlock(probe.as_ptr() as *const libc::c_void, 32) == 0;
        libc::munlock(probe.as_ptr() as *const libc::c_void, 32);
    }
    p
}

#[cfg(not(unix))]
fn apply() -> Posture {
    Posture::default()
}
