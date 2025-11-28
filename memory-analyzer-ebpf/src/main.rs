#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{kprobe, map},
    maps::RingBuf,
    programs::ProbeContext,
    helpers::bpf_get_current_pid_tgid,
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PageFaultEvent {
    pub pid: u32,
    pub addr: u64,
    pub flags: u32,
}

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 256, 0);

#[kprobe]
pub fn memory_analyzer(ctx: ProbeContext) -> u32 {
    match try_memory_analyzer(ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_memory_analyzer(ctx: ProbeContext) -> Result<(), u32> {
    let pid = ({ bpf_get_current_pid_tgid() } >> 32) as u32;
    // arg(0) = struct vm_area_struct *vma
    // arg(1) = unsigned long address  <- THE FAULTING ADDRESS
    // arg(2) = unsigned int flags     <- THE FLAGS
    let addr: u64 = { ctx.arg(1).ok_or(1u32)? };
    let flags: u32 = { ctx.arg(2).ok_or(1u32)? };

    let event = PageFaultEvent {
        pid,
        addr,
        flags,
    };

    unsafe {
        if let Some(mut buf) = EVENTS.reserve::<PageFaultEvent>(0) {
            buf.as_mut_ptr().write(event);
            buf.submit(0);
        }
    }

    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[cfg(not(test))]
#[unsafe(no_mangle)]
pub static _license: [u8; 4] = *b"GPL\0";