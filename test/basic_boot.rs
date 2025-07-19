#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(bcOS::test_runner)]

use bcOS::println;
use core::panic::PanicInfo;

#[no_mangle] // don't mangle the name of this function
pub extern "C" fn _start() -> ! {
    // 手动运行测试
    println!("Running test");
    println!("test_println output");
    
    println!("Tests completed successfully");
    bcOS::exit_qemu(bcOS::QemuExitCode::Success);
    loop {}
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    bcOS::test_panic_handler(info)
}
