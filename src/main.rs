#![no_std]
#![no_main]
mod vga_buffer;
use core::panic::PanicInfo;

/// 这个函数将在 panic 时被调用
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("{}", info);
    loop {}
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    println!("Hello! This is bcOS{}", "!");
    loop {}
}
