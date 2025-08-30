# 基于 Rust 语言的 bcOS 开发技术报告

## 一、项目背景与目标

本项目严格遵循 Philipp Oppermann 的"Writing an OS in Rust"博客系列教程，使用 Rust 语言开发了一个小型操作系统。项目核心目标是在裸机环境下验证 Rust 语言的内存安全特性与高性能优势，同时系统掌握操作系统底层原理。开发过程完全开源，源代码托管于 GitHub 仓库，可通过分步实现从基础执行程序到多任务内核的完整演进。

## 二、BARE BONES 模块

### 2.1 独立式可执行程序

#### 2.1.1 核心设计目标

该模块的核心目标是创建一个完全脱离标准库依赖的 Rust 可执行文件，实现真正意义上的裸机（bare metal）运行能力。这意味着需要摆脱对任何底层操作系统的依赖，直接在硬件上执行代码，为后续构建内核奠定基础。

#### 2.1.2 关键技术实现

-   **标准库禁用配置**：通过在代码中添加`#![no_std]`属性，彻底禁用 Rust 标准库。标准库包含大量依赖操作系统的功能，如文件操作、线程管理等，这些在裸机环境下无法使用。同时使用`#![no_main]`属性禁用 Rust 默认的`main`函数入口，因为默认入口会依赖标准库的启动代码。
-   **自定义入口函数**：定义`_start`函数作为程序入口点，并用`#[no_mangle]`属性确保函数名不被编译器修饰，以便链接器能够正确识别。该函数采用`extern "C"`调用约定，符合硬件引导程序的调用规范，函数返回类型为`!`（永不返回），通过`loop {}`死循环防止程序执行到未定义状态。

```rust
// main.rs
#![no_std]          // 禁用标准库
#![no_main]         // 禁用默认main入口

use core::panic::PanicInfo;

// 定义内核入口函数（由引导程序调用）
#[no_mangle]        // 禁止名字修饰，确保链接器能找到该符号
pub extern "C" fn _start() -> ! {
    // 内核初始化逻辑
    loop {}         // 死循环防止程序退出
}
```

-   **异常处理配置**：在`no_std`环境下必须自定义`panic`处理函数，通过`#[panic_handler]`属性指定，确保程序发生错误时能进入可控制的处理流程。

```rust
// 定义 panic 处理函数（no_std环境必需）
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
```

-   **链接脚本配置**：编写专用的链接脚本（如`linker.ld`），明确指定程序的内存布局。设置程序入口点为`_start`，定义代码段（.text）、只读数据段（.rodata）、数据段（.data）和未初始化数据段（.bss）的排列顺序和起始地址，对于 x86_64 架构通常将内核加载到`0xffff_8000_0000_0000`起始的高半内存区域。

```ld
ENTRY(_start)  // 程序入口点

SECTIONS {
    . = 0xffff_8000_0000_0000;  // x86_64内核起始地址（高半内核）

    .text : {
        *(.text.boot)           // 引导相关代码
        *(.text*)               // 其他代码段
    }

    .rodata : { *(.rodata*) }   // 只读数据段

    .data : { *(.data*) }       // 数据段

    .bss : { *(.bss*) }         // 未初始化数据段
}
```

#### 2.1.3 验证与测试

通过`objdump`等工具检查生成的 ELF 文件，确认其中不包含标准库相关的符号和依赖，确保可执行程序的独立性。使用 QEMU 模拟器加载程序，验证其能否在无操作系统支持的环境下正常启动并执行入口函数中的逻辑。

### 2.2 最小内核

#### 2.2.1 核心设计目标

基于独立式可执行程序，构建一个能在 x86 架构上运行的 64 位最小内核，实现向显示器打印字符串的功能，并能被打包为可引导启动的磁盘映像（disk image）。

#### 2.2.2 关键技术实现

-   **引导流程设计**：采用`bootloader` crate 替代传统的 GRUB 引导程序，实现从 BIOS/UEFI 到内核的直接跳转。引导程序负责完成硬件初始化、内存映射信息收集等工作，并将这些信息传递给内核。
-   **内存初始化**：内核启动时接收引导程序提供的内存映射信息，识别系统中的可用物理内存区域，为后续的内存管理奠定基础。
-   **显示功能实现**：直接操作硬件实现字符串打印功能，初期通过向 VGA 文本缓冲区（0xB8000 起始地址）写入数据来实现简单的字符显示，为内核提供基本的输出能力。
-   **磁盘映像打包**：使用`bootimage`工具将内核与引导程序打包为可引导的 ISO 镜像，该镜像可直接在 QEMU 等模拟器或实际硬件上启动。

#### 2.2.3 验证与测试

将生成的磁盘映像加载到 QEMU 模拟器中，验证内核能否成功引导启动，并观察显示器上是否正确打印出预设的字符串，以此确认最小内核的功能完整性。

### 2.3 VGA 字符模式

#### 2.3.1 核心设计目标

将 VGA 字符模式（VGA text mode）封装为安全、简单的接口，支持 Rust 的格式化宏（如`println!`），为内核提供便捷、可靠的屏幕输出功能。

#### 2.3.2 关键技术实现

-   **VGA 缓冲区封装**：VGA 文本模式通过 0xB8000 起始的内存映射 IO 区域控制显示，该区域包含一个 80 列 ×25 行的字符数组。将该区域封装为`Buffer`结构体，每个字符由`ScreenChar`结构体表示，包含 ASCII 字符值和颜色代码（`ColorCode`）。`ColorCode`由前景色和背景色组成，通过 4 位分别表示。

```rust
// 颜色枚举
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Color {
    Black = 0,
    Blue = 1,
    Green = 2,
    Cyan = 3,
    Red = 4,
    Magenta = 5,
    Brown = 6,
    LightGray = 7,
    DarkGray = 8,
    LightBlue = 9,
    LightGreen = 10,
    LightCyan = 11,
    LightRed = 12,
    Pink = 13,
    Yellow = 14,
    White = 15,
}

// 颜色组合（前景色+背景色）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
struct ColorCode(u8);

impl ColorCode {
    fn new(foreground: Color, background: Color) -> Self {
        ColorCode((background as u8) << 4 | (foreground as u8))
    }
}

// VGA字符单元（ASCII字符+颜色）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
struct ScreenChar {
    ascii_character: u8,
    color_code: ColorCode,
}

// VGA缓冲区
#[repr(transparent)]
struct Buffer {
    chars: [[ScreenChar; BUFFER_WIDTH]; BUFFER_HEIGHT],
}
```

-   **安全接口设计**：创建`Writer`结构体作为操作 VGA 缓冲区的接口，包含当前列位置、颜色代码和指向 VGA 缓冲区的静态引用。`Writer`提供`write_byte`和`write_str`方法，分别用于写入单个字节和字符串，并处理换行等特殊字符。
-   **格式化输出支持**：为`Writer`实现`core::fmt::Write` trait，使`println!`等格式化宏能够直接使用`Writer`进行输出。通过自定义`println!`和`print!`宏，将输出内容转发到`Writer`的实例。

```rust
// 实现fmt::Write trait以支持格式化输出
impl fmt::Write for Writer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_str(s);
        Ok(())
    }
}

// 提供println!宏
#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($arg)));
}
```

-   **线程安全处理**：使用`lazy_static!`宏和`spin::Mutex`创建全局的`WRITER`实例，确保在多任务环境下对 VGA 缓冲区的操作是线程安全的。

```rust
// 全局终端实例（使用lazy_static和spin::Mutex实现线程安全）
lazy_static! {
    pub static ref WRITER: Mutex<Writer> = Mutex::new(Writer {
        column_position: 0,
        color_code: ColorCode::new(Color::LightGray, Color::Black),
        // 不安全代码：获取VGA缓冲区的静态可变引用
        buffer: unsafe { &mut *(0xb8000 as *mut Buffer) },
    });
}
```

#### 2.3.3 优化与扩展

-   **性能优化**：维护当前光标位置状态，避免每次打印都重新计算偏移量，减少对 VGA 缓冲区的不必要操作。
-   **功能扩展**：实现屏幕滚动功能，当一行写满或遇到换行符时，将所有行向上滚动一行，并清空最后一行，确保显示内容始终在可见区域内。

```rust
// 换行处理
fn new_line(&mut self) {
    // 向上滚动一行
    for row in 1..BUFFER_HEIGHT {
        for col in 0..BUFFER_WIDTH {
            self.buffer.chars[row - 1][col] = self.buffer.chars[row][col];
        }
    }
    // 清空最后一行
    self.clear_row(BUFFER_HEIGHT - 1);
    self.column_position = 0;
}
```

### 2.4 内核测试

#### 2.4.1 核心设计目标

在`no_std`环境下构建完整的测试体系，实现内核的单元测试和集成测试，通过 QEMU 等工具反馈测试结果，确保内核功能的正确性和稳定性。

#### 2.4.2 关键技术实现

-   **自定义测试框架**：在`no_std`环境下，无法使用 Rust 标准库的测试框架，因此需要自定义测试框架。通过`#[test_case]`等属性标记测试函数，实现对测试用例的识别和管理。
-   **测试结果输出**：利用 QEMU 的`-serial`参数将测试结果重定向到主机终端，使开发者能够查看测试的执行情况和结果。通过在测试函数中输出特定的格式信息（如测试通过、失败等），实现对测试结果的清晰展示。
-   **自动化测试流程**：集成`bootimage test`命令，实现从编译内核、打包磁盘映像、在 QEMU 中运行测试到收集并展示测试结果的全自动化流程，提高测试效率。
-   **多样化测试类型**：
    -   **单元测试**：针对内核中的独立模块（如内存分配算法、字符串处理函数等）进行测试，验证单个功能的正确性。
    -   **集成测试**：测试多个模块之间的交互和协作（如中断处理流程与内存管理的协同工作），确保系统整体功能的完整性。
    -   **硬件交互测试**：测试内核与硬件设备的交互（如 VGA 显示、键盘输入等），验证硬件驱动的正确性。

#### 2.4.3 测试用例设计原则

-   **覆盖关键功能**：确保测试用例覆盖内核的核心功能模块，如中断处理、内存管理、任务调度等。
-   **边界条件测试**：设计针对边界条件的测试用例，如内存分配的极限情况、中断的嵌套触发等，验证内核在极端情况下的稳定性。
-   **可重复性**：测试用例应具有可重复性，确保每次运行都能得到一致的结果，便于问题的定位和修复。

## 三、Interrupts 模块

### 3.1 CPU 异常处理

#### 3.1.1 核心设计目标

处理 CPU 在运行过程中可能出现的各种异常情况，如访问无效内存地址、除法运算中除以 0 等，通过设置中断描述符表提供相应的异常处理函数，使内核能够捕获异常并在处理后恢复正常执行。

#### 3.1.2 关键技术实现

-   **中断描述符表（IDT）设置**：IDT 是 x86 架构中用于指定异常和中断处理函数的关键数据结构。通过创建`InterruptDescriptorTable`结构体，并为每种 CPU 异常注册对应的处理函数。

```rust
lazy_static! {
    static ref IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        // 为其他异常设置处理函数
        idt
    };
}

// 初始化IDT
pub fn init_idt() {
    IDT.load();
}
```

-   **异常处理函数实现**：异常处理函数需要使用特定的调用约定（如`extern "x86-interrupt"`），以确保在异常发生时正确保存和恢复 CPU 状态。处理函数会接收一个`InterruptStackFrame`参数，包含异常发生时的栈状态信息。

```rust
extern "x86-interrupt" fn breakpoint_handler(stack_frame: &InterruptStackFrame) {
    println!("\nEXCEPTION: BREAKPOINT\n{:#?}", stack_frame);
}
```

-   **断点异常处理**：断点异常是一种常见的调试异常，内核可以通过捕获断点异常实现调试功能。在处理断点异常后，内核能够恢复正常执行流程。

#### 3.1.3 验证与测试

通过编写专门的测试用例，故意触发各种 CPU 异常（如访问空指针、执行除法除以 0 操作等），验证内核能否正确捕获异常并执行相应的处理函数，同时检查处理后系统是否能正常运行或进行适当的错误处理。

### 3.2 Double Faults

#### 3.2.1 核心设计目标

处理 double fault 异常，该异常在异常处理函数本身出错时触发。通过捕获 double fault 异常，防止致命的 triple faults 异常导致系统重启，提高系统的稳定性和可靠性。

#### 3.2.2 关键技术实现

-   **double fault 异常处理函数**：为 double fault 异常注册专门的处理函数，该函数需要使用独立的内核栈，以避免原栈损坏导致的问题。通过设置中断栈表（IST）为 double fault 异常分配独立的栈空间。

```rust
extern "x86-interrupt" fn double_fault_handler(
    stack_frame: &InterruptStackFrame,
    _error_code: u64,
) -> ! {
    panic!("\nEXCEPTION: DOUBLE FAULT\n{:#?}", stack_frame);
}

// 在IDT中配置double fault处理函数
lazy_static! {
    static ref IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();
        // 其他异常处理配置
        unsafe {
            idt.double_fault.set_handler_fn(double_fault_handler)
                .set_stack_index(crate::gdt::DOUBLE_FAULT_IST_INDEX);
        }
        idt
    };
}
```

-   **中断栈表（IST）配置**：IST 是 x86_64 架构中的一种机制，允许为特定的中断和异常指定独立的栈。在全局描述符表（GDT）中配置专门的段用于 double fault 异常的栈，确保在处理 double fault 时使用干净的栈空间。

#### 3.2.3 验证与测试

设计测试用例故意触发 double fault 异常，例如在一个异常处理函数中再次触发异常，验证内核能否正确捕获 double fault 异常并执行处理函数，同时检查系统是否避免了 triple faults 导致的重启。

### 3.3 硬件中断

#### 3.3.1 核心设计目标

配置可编程中断控制器，使硬件设备的中断能够被转发到 CPU，实现对硬件事件（如周期计时器中断、键盘输入等）的响应和处理。

#### 3.3.2 关键技术实现

-   **可编程中断控制器（PIC）配置**：对 8259A PIC 进行编程，设置中断向量偏移，避免与 CPU 异常向量冲突，并配置中断优先级链。通过`pic8259` crate 简化 PIC 的初始化和操作。

```rust
use pic8259::ChainedPics;
use spin;

pub const PIC_1_OFFSET: u8 = 32;
pub const PIC_2_OFFSET: u8 = PIC_1_OFFSET + 8;

pub static PICS: spin::Mutex<ChainedPics> = spin::Mutex::new(unsafe {
    ChainedPics::new(PIC_1_OFFSET, PIC_2_OFFSET)
});

// 初始化PIC
pub fn init_pics() {
    unsafe { PICS.lock().initialize() };
}
```

-   **硬件中断处理函数注册**：在 IDT 中为硬件中断注册处理函数，

### 3.3.3 硬件中断处理示例

硬件中断处理是操作系统与硬件设备交互的核心机制，以下通过**周期计时器中断**和**键盘输入中断**两个示例，展示 x86 架构下的中断处理实现。

#### 周期计时器中断

配置 PIT（可编程间隔定时器）产生固定频率的中断，用于实现系统时钟。在中断处理函数中更新系统时间，并可触发任务调度等操作。

```rust
extern "x86-interrupt" fn timer_interrupt_handler(_stack_frame: &InterruptStackFrame) {
    // 更新系统时间或触发任务调度
    print!(".");

    // 发送**EOI（中断结束）信号**，通知中断控制器中断处理完成
    unsafe {
        PICS.lock().notify_end_of_interrupt(PIC_1_OFFSET);
    }
}
```

#### 键盘输入中断

处理键盘设备产生的中断，读取扫描码并转换为对应字符。通过`pc_keyboard` crate 解析扫描码，支持不同键盘布局（示例中为 US 104 键布局）。

```rust
extern "x86-interrupt" fn keyboard_interrupt_handler(_stack_frame: &InterruptStackFrame) {
    use pc_keyboard::{layouts, DecodedKey, HandleControl, Keyboard, ScancodeSet1};
    use spin::Mutex;
    use x86_64::instructions::port::Port;

    // 懒加载键盘实例，使用互斥锁（Mutex）保证多线程安全
    lazy_static! {
        static ref KEYBOARD: Mutex<Keyboard<layouts::Us104Key, ScancodeSet1>> =
            Mutex::new(Keyboard::new(
                layouts::Us104Key,    // US 104键键盘布局
                ScancodeSet1,         // PS/2键盘扫描码集1
                HandleControl::Ignore // 忽略控制键（如Ctrl）
            ));
    }

    let mut keyboard = KEYBOARD.lock();
    let mut port = Port::new(0x60);  // PS/2键盘数据端口（固定地址0x60）

    // 从端口读取键盘扫描码（unsafe：直接端口访问，需确保安全性）
    let scancode: u8 = unsafe { port.read() };
    // 解析扫描码为键盘事件，再转换为字符
    if let Ok(Some(key_event)) = keyboard.add_byte(scancode) {
        if let Some(key) = keyboard.process_keyevent(key_event) {
            match key {
                DecodedKey::Unicode(c) => print!("{}", c),       // 打印Unicode字符（如字母、数字）
                DecodedKey::RawKey(key) => print!("<{:?}>", key), // 打印原始键（如功能键、方向键）
            }
        }
    }

    // 发送EOI信号，中断号为PIC_1_OFFSET + 1（键盘中断对应IRQ1）
    unsafe {
        PICS.lock().notify_end_of_interrupt(PIC_1_OFFSET + 1);
    }
}
```

### 3.3.4 验证与测试

通过以下方式验证硬件中断处理的正确性：

1. **计时器中断验证**：观察控制台是否周期性输出`.`（示例中`print!(".")`），确认中断被稳定捕获。
2. **键盘中断验证**：按下键盘按键（如字母、数字、功能键），检查控制台是否正确输出对应字符或原始键标识（如`<F1>`）。
3. **中断连续性验证**：确保中断结束信号（EOI）正常发送，避免后续中断被阻塞（如连续按键盘无响应）。

## 四、内存管理模块

内存管理是操作系统的核心功能之一，负责物理内存分配、虚拟地址映射、堆管理等，确保内存安全隔离与高效利用。本节围绕 x86_64 架构，从分页机制到分配器设计展开实现。

### 4.1 内存分页初探

#### 4.1.1 核心设计目标

理解内存分页的底层逻辑与价值，具体目标包括：

-   掌握**内存隔离**的必要性（保障内核与用户态、进程间的内存安全）。
-   区分**分段机制**与**分页机制**的差异及各自问题（如分段的内存碎片问题）。
-   理解**虚拟内存**的概念与作用（进程独立地址空间、按需分配）。
-   探索 x86_64 架构的**多级页表布局**（4 级页表），掌握地址转换原理。

#### 4.1.2 关键技术概念

| 概念                | 核心解释                                                                                                               |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| **内存隔离**        | 通过页表项的权限位（可读、可写、可执行）限制内存访问，防止未授权操作（如用户态修改内核内存）。                         |
| **分段与分页**      | 分段按逻辑功能（代码段、数据段）划分内存，易产生碎片；分页按固定大小（如 4KB）划分，通过页表映射虚拟地址，灵活性更高。 |
| **虚拟内存**        | 为每个进程提供独立的虚拟地址空间，进程访问虚拟地址后通过页表转换为物理地址，屏蔽物理内存布局细节。                     |
| **x86_64 多级页表** | 采用 4 级页表（PML4 → PDPT → PD → PT），每级页表项指向更低一级页表或物理页帧，高效管理 64 位大地址空间。               |

#### 4.1.3 页表布局探索

x86_64 的虚拟地址（64 位，实际使用 48 位）由 5 部分组成，每部分对应一级页表的索引，最终定位到物理页帧：

1. **PML4 索引**（9 位）：定位 PML4 页表中的页表项。
2. **PDPT 索引**（9 位）：定位 PDPT（页目录指针表）中的页表项。
3. **PD 索引**（9 位）：定位 PD（页目录）中的页表项。
4. **PT 索引**（9 位）：定位 PT（页表）中的页表项，指向物理页帧。
5. **页内偏移**（12 位）：定位物理页帧内的具体字节（4KB 页大小 → 2¹² = 4096）。

通过多级索引逐层查找，最终将虚拟地址转换为物理地址。

### 4.2 分页实现

#### 4.2.1 核心设计目标

在操作系统内核中落地分页机制，具体实现：

-   使内核能够访问物理页帧的技术（直接映射/动态映射）。
-   虚拟地址到物理地址的转换功能。
-   动态创建虚拟地址与物理地址的映射关系。

#### 4.2.2 关键技术实现

##### 1. 物理页帧访问技术

-   **直接映射（Identity Mapping）**：将物理地址直接映射到虚拟地址的相同位置（如物理地址`0x1000` → 虚拟地址`0x1000`），内核可直接访问所有物理内存，实现简单但浪费虚拟地址空间。
-   **动态映射**：按需将物理页帧映射到虚拟地址空间的任意位置，灵活性高，但实现复杂（需动态维护页表）。

##### 2. 页表初始化

获取当前活跃的 4 级页表（通过**Cr3 寄存器**读取），并创建`OffsetPageTable`实例管理页表（`physical_memory_offset`为物理内存到虚拟内存的偏移量）。

```rust
use x86_64::{
    structures::paging::{
        FrameAllocator, OffsetPageTable, PageTable, PhysFrame, Size4KiB,
    },
    PhysAddr, VirtAddr,
};

// 初始化页表，返回OffsetPageTable实例（用于管理页表）
pub unsafe fn init(physical_memory_offset: VirtAddr) -> OffsetPageTable<'static> {
    let level_4_table = active_level_4_table(physical_memory_offset);
    OffsetPageTable::new(level_4_table, physical_memory_offset)
}

// 读取Cr3寄存器，获取当前活跃的PML4（4级页表）地址
unsafe fn active_level_4_table(physical_memory_offset: VirtAddr) -> &'static mut PageTable {
    use x86_64::registers::control::Cr3;

    // 从Cr3读取PML4页表的物理帧地址（Cr3存储PML4页表的物理基址）
    let (level_4_table_frame, _) = Cr3::read();
    let phys_addr = level_4_table_frame.start_address();
    // 将物理地址转换为虚拟地址（内核通过虚拟地址访问物理内存）
    let virt_addr = physical_memory_offset + phys_addr.as_u64();
    let page_table_ptr: *mut PageTable = virt_addr.as_mut_ptr();

    &mut *page_table_ptr // 返回PML4页表的可变引用
}
```

##### 3. 地址转换功能

实现虚拟地址到物理地址的转换，通过遍历 4 级页表查找对应的物理页帧，再结合页内偏移计算最终物理地址。

```rust
// 虚拟地址转物理地址（返回Option<PhysAddr>，None表示映射不存在）
fn translate_addr(addr: VirtAddr, page_table: &OffsetPageTable) -> Option<PhysAddr> {
    use x86_64::structures::paging::PageTableFlags as Flags;
    // 找到虚拟地址所在的页（4KB页）
    let page = Page::containing_address(addr);
    // 从页表中查找该页对应的物理帧
    let frame = page_table.translate_page(page)?;
    // 物理地址 = 物理页帧起始地址 + 页内偏移
    Some(frame.start_address() + u64::from(addr.offset_in_page()))
}
```

##### 4. 创建新映射

在页表中建立虚拟页到物理帧的映射，并设置页表项的权限（如可读、可写），最后刷新 TLB（ Translation Lookaside Buffer，地址转换缓存）确保映射生效。

```rust
use x86_64::structures::paging::Mapper;
use x86_64::structures::paging::MapToError;
use x86_64::structures::paging::PageTableFlags;

// 创建虚拟页（page）到物理帧（frame）的映射
pub fn create_mapping(
    page: Page,                      // 虚拟页
    frame: PhysFrame<Size4KiB>,      // 物理帧
    flags: PageTableFlags,           // 页表项权限（如PRESENT、WRITABLE）
    mapper: &mut OffsetPageTable,    // 页表管理器
    frame_allocator: &mut impl FrameAllocator<Size4KiB>, // 物理帧分配器
) -> Result<(), MapToError<Size4KiB>> {
    // 建立映射（若中间级页表不存在，使用frame_allocator分配页表帧）
    let map_to_result = mapper.map_to(page, frame, flags, frame_allocator);
    // 刷新TLB，确保新映射立即生效
    map_to_result?.flush();
    Ok(())
}
```

#### 4.2.3 验证与测试

1. **映射正确性验证**：创建虚拟页与物理帧的映射，调用`translate_addr`检查虚拟地址是否能正确转换为物理地址。
2. **权限验证**：测试不同权限的映射（如只读、可执行），尝试越权操作（如修改只读页），确认是否触发内存保护（如页错误中断）。

### 4.3 堆分配

#### 4.3.1 核心设计目标

为内核添加动态堆支持，实现 Rust 标准库的`alloc`接口，使`Vec`、`String`等动态数据结构可在内核中使用。

#### 4.3.2 关键技术实现

##### 1. 动态内存介绍

动态内存允许程序在运行时分配/释放内存（如创建可变大小的数组），Rust 的借用检查器可防止悬垂指针、重复释放等错误，但内核需手动实现内存分配逻辑。

##### 2. 堆内存区域创建

内核启动时，划定一块连续的物理内存作为堆，并将其映射到虚拟地址空间（通过分页机制），为堆分配提供基础。

```rust
use x86_64::structures::paging::Page;
use x86_64::structures::paging::MapToError;
use x86_64::structures::paging::PageTableFlags;

// 堆初始化错误类型（示例）
#[derive(Debug)]
pub enum HeapInitError {
    FrameAllocationFailed,
    MappingFailed(MapToError<Size4KiB>),
}

// 初始化内核堆
pub fn init_heap(
    physical_memory_offset: VirtAddr,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>
) -> Result<(), HeapInitError> {
    // 堆的虚拟地址范围（示例：起始地址0x4444_4444_0000，大小100KB）
    let heap_start = 0x4444_4444_0000;
    let heap_size = 100 * 1024; // 100KB
    let heap_end = heap_start + heap_size;

    // 计算堆对应的虚拟页范围（4KB页）
    let page_range = {
        let start_page = Page::containing_address(VirtAddr::new(heap_start));
        let end_page = Page::containing_address(VirtAddr::new(heap_end - 1));
        Page::range_inclusive(start_page, end_page)
    };

    // 初始化页表管理器
    let mut mapper = unsafe {
        OffsetPageTable::new(active_level_4_table(physical_memory_offset), physical_memory_offset)
    };

    // 为每个虚拟页分配物理帧并建立映射（权限：PRESENT + WRITABLE）
    for page in page_range {
        // 分配物理帧（若分配失败，返回错误）
        let frame = frame_allocator.allocate_frame()
            .ok_or(HeapInitError::FrameAllocationFailed)?;
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        // 建立映射（若失败，返回错误）
        unsafe {
            mapper.map_to(page, frame, flags, frame_allocator)
                .map_err(HeapInitError::MappingFailed)?
                .flush();
        }
    }

    // 初始化全局堆分配器（链接到后续实现的Allocator）
    unsafe {
        ALLOCATOR.lock().init(heap_start, heap_size);
    }

    Ok(())
}
```

##### 3. Rust 分配接口实现

实现 Rust 标准库的`GlobalAlloc` trait，为内核提供全局内存分配器（`alloc`分配内存，`dealloc`释放内存），使用`spin::Mutex`保证多线程安全。

```rust
use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use spin::Mutex;
// 假设LinkedListAllocator已实现（见4.4.2）
use super::linked_list_allocator::LinkedListAllocator;

// 内核堆分配器（包装LinkedListAllocator，添加互斥锁）
pub struct HeapAllocator(Mutex<LinkedListAllocator>);

impl HeapAllocator {
    // 创建空的堆分配器
    pub const fn new() -> Self {
        HeapAllocator(Mutex::new(LinkedListAllocator::new()))
    }
}

// 实现GlobalAlloc trait（Rust全局分配器接口）
unsafe impl GlobalAlloc for HeapAllocator {
    // 分配内存：根据Layout（大小+对齐）分配内存，返回内存指针（null_mut表示失败）
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.0.lock().alloc(layout)
    }

    // 释放内存：根据指针和Layout释放内存
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.0.lock().dealloc(ptr, layout)
    }
}

// 声明全局分配器（Rust会自动使用该分配器处理`alloc` crate的内存请求）
#[global_allocator]
static ALLOCATOR: HeapAllocator = HeapAllocator::new();
```

#### 4.3.3 验证与测试

1. **基础功能测试**：使用`alloc::vec::Vec`或`alloc::string::String`创建动态数据，检查是否能正常初始化、添加元素、释放内存。
2. **压力测试**：频繁分配/释放不同大小的内存块，检查是否出现内存泄漏、双重释放或内存访问错误。

### 4.4 分配器设计

#### 4.4.1 核心设计目标

从零实现三种经典堆分配器，分析其优缺点与适用场景，满足不同内核需求：

-   **Bump 分配器**：适合简单场景（单任务、无频繁释放）。
-   **链表分配器**：支持碎片化释放，适合多任务场景。
-   **固定大小块分配器**：适合频繁分配相同大小内存的场景（如线程栈）。

#### 4.4.2 关键技术实现

##### 1. Bump 分配器（线性分配器）

###### 原理

维护一个指向堆当前空闲起始位置的指针（`next`），分配内存时将指针按“大小+对齐”向前移动；释放内存时仅支持**整体重置**（无法单独释放某块内存）。

###### 实现代码

```rust
use core::alloc::Layout;
use core::ptr;

pub struct BumpAllocator {
    heap_start: usize, // 堆起始地址（虚拟地址）
    heap_end: usize,   // 堆结束地址（虚拟地址）
    next: usize,       // 下一个空闲内存的起始地址
}

impl BumpAllocator {
    // 创建Bump分配器：指定堆起始地址和大小
    pub fn new(heap_start: usize, heap_size: usize) -> Self {
        BumpAllocator {
            heap_start,
            heap_end: heap_start + heap_size,
            next: heap_start,
        }
    }

    // 分配内存：根据Layout计算对齐后的地址，移动next指针
    pub fn alloc(&mut self, layout: Layout) -> *mut u8 {
        let align = layout.align();
        let size = layout.size();

        // 计算对齐后的起始地址（确保内存地址符合Layout的对齐要求）
        let start = self.next.align_up(align);
        let end = start + size;

        // 检查内存是否充足（若end超过heap_end，返回空指针表示分配失败）
        if end > self.heap_end {
            return ptr::null_mut();
        }

        // 更新next指针，指向本次分配后的下一个空闲地址
        self.next = end;
        start as *mut u8 // 返回分配的内存指针
    }

    // 重置分配器：将next指针恢复到heap_start，相当于释放所有内存
    pub fn reset(&mut self) {
        self.next = self.heap_start;
    }
}

// 辅助函数：计算地址的上取整对齐
fn align_up(addr: usize, align: usize) -> usize {
    (addr + align - 1) & !(align - 1)
}
```

###### 优缺点

-   **优点**：实现简单，分配速度快（时间复杂度 O(1)），无额外内存开销。
-   **缺点**：不支持单独释放内存，易产生内存碎片，仅适合单任务或“分配后不释放”的场景（如内核初始化阶段）。

##### 2. 链表分配器（空闲块链表分配器）

###### 原理

维护一个**空闲块链表**，每个空闲块包含“块大小”和“下一个空闲块指针”。分配时采用“首次适配”策略查找第一个足够大的空闲块，分割为“分配块”和“剩余空闲块”；释放时将块插入链表，并尝试与前后空闲块合并（减少内存碎片）。

###### 实现代码

```rust
use core::alloc::Layout;
use core::ptr;

// 空闲块链表节点：存储空闲块大小和下一个节点指针
struct ListNode {
    size: usize,                // 空闲块大小（不包含节点自身大小）
    next: Option<&'static mut ListNode>, // 下一个空闲块节点
}

impl ListNode {
    // 计算空闲块的总大小（包含节点自身大小）
    fn size_including_self(&self) -> usize {
        self.size + core::mem::size_of::<ListNode>()
    }
}

pub struct LinkedListAllocator {
    head: ListNode, // 链表头节点（哨兵节点，不存储实际空闲块）
}

impl LinkedListAllocator {
    // 创建空的链表分配器（头节点的next初始为None）
    pub const fn new() -> Self {
        LinkedListAllocator {
            head: ListNode { size: 0, next: None },
        }
    }

    // 初始化分配器：指定堆的起始地址和大小，创建初始空闲块
    pub unsafe fn init(&mut self, heap_start: *mut u8, heap_size: usize) {
        self.add_free_region(heap_start, heap_size);
    }

    // 向链表添加空闲块：确保空闲块地址对齐，且大小足够容纳ListNode
    unsafe fn add_free_region(&mut self, addr: *mut u8, size: usize) {
        // 检查空闲块地址是否符合ListNode的对齐要求
        assert_eq!(
            align_up(addr as usize, core::mem::align_of::<ListNode>()),
            addr as usize
        );
        // 检查空闲块大小是否至少能容纳一个ListNode（否则无法加入链表）
        assert!(size >= core::mem::size_of::<ListNode>());

        // 创建新的空闲块节点（大小 = 传入大小 - 节点自身大小）
        let mut node = ListNode {
            size: size - core::mem::size_of::<ListNode>(),
            next: self.head.next.take(), // 插入到链表头部（头插法）
        };
        let node_ptr = addr as *mut ListNode;
        node_ptr.write(node); // 将节点数据写入空闲块地址

        // 更新头节点的next，指向新插入的空闲块
        self.head.next = Some(&mut *node_ptr);
    }

    // 分配内存：查找第一个足够大的空闲块，分割并返回分配地址
    pub fn alloc(&mut self, layout: Layout) -> *mut u8 {
        let (size, align) = (layout.size(), layout.align());
        let mut current = &mut self.head;

        // 遍历空闲块链表，查找首个满足条件的空闲块（首次适配）
        while let Some(ref mut region) = current.next {
            // 尝试从当前空闲块分配内存
            if let Ok(alloc_start) = self.alloc_from_region(region, size, align) {
                // 从链表中移除当前空闲块（将current的next指向region的next）
                let region = current.next.take().unwrap();
                current.next = region.next.take();

                return alloc_start as *mut u8; // 返回分配的内存指针
            } else {
                // 当前块不满足条件，继续遍历下一个块
                current = current.next.as_mut().unwrap();
            }
        }

        ptr::null_mut() // 未找到合适的空闲块，分配失败
    }

    // 从单个空闲块分配内存：检查块大小和对齐是否满足要求
    fn alloc_from_region(&self, region: &ListNode, size: usize, align: usize) -> Result<usize, ()> {
        // 计算分配块的起始地址：
        // 空闲块地址 + 节点大小（跳过ListNode） → 对齐后的地址
        let alloc_start = align_up(
            region as *const ListNode as usize + core::mem::size_of::<ListNode>(),
            align
        );
        let alloc_end = alloc_start + size; // 分配块的结束地址
        let region_end = region as *const ListNode as usize + region.size_including_self(); // 空闲块的结束地址

        // 检查分配块是否超出空闲块范围
        if alloc_end > region_end {
            return Err(());
        }

        // 计算剩余空闲块大小（若剩余大小不足以容纳ListNode，无法形成新空闲块，分配失败）
        let remaining_size = region_end - alloc_end;
        if remaining_size > 0 && remaining_size < core::mem::size_of::<ListNode>() {
            return Err(());
        }

        Ok(alloc_start) // 分配成功，返回分配块的起始地址
    }

    // 释放内存：将分配块插入空闲链表，并尝试合并相邻空闲块
    pub unsafe fn dealloc(&mut self, ptr: *mut u8, layout: Layout) {
        let (size, _) = (layout.size(), layout.align());
        // 计算释放块的总大小（包含ListNode大小）
        let block_size = size + core::mem::size_of::<ListNode>();
        // 计算释放块的起始地址（分配块指针 - ListNode大小 → 节点起始地址）
        let block_start = ptr as usize - core::mem::size_of::<ListNode>();
        let block_end = block_start + block_size; // 释放块的结束地址

        // 创建释放块的ListNode（大小 = 分配块大小）
        let mut node = ListNode {
            size: size,
            next: None,
        };
        let node_ptr = block_start as *mut ListNode;
        node_ptr.write(node); // 将节点写入释放块地址

        // 遍历链表，找到释放块的插入位置（确保链表按地址有序，便于合并）
        let mut current = &mut self.head;
        while let Some(ref mut region) = current.next {
            let region_start = region as *const ListNode as usize;
            // 若当前空闲块的地址 > 释放块的结束地址，说明插入位置在current和region之间
            if region_start > block_end {
                break;
            }
            // 继续遍历下一个块
            current = current.next.as_mut().unwrap();
        }

        // 尝试合并释放块与下一个空闲块（若下一个块的起始地址 = 释放块的结束地址）
        if let Some(next_region) = current.next.as_mut() {
            let next_region_start = next_region as *const ListNode as usize;
            if block_end == next_region_start {
                // 合并：释放块的大小 += 下一个块的总大小，next指向next_region的next
                node.size += next_region.size_including_self();
                node.next = next_region.next.take();
            }
        }

        // 尝试合并释放块与前一个空闲块（current的next）
        if let Some(prev_region) = current.next.as_mut() {
            let prev_region_end = prev_region as *const ListNode as usize + prev_region.size_including_self();
            if prev_region_end == block_start {
                // 合并：前一个块的大小 += 释放块的总大小，next指向释放块的next
                prev_region.size += node.size_including_self();
                prev_region.next = node.next.take();
            } else {
                // 无法合并，直接插入到current和next_region之间
                current.next = Some(&mut *node_ptr);
            }
        } else {
            // 链表末尾，直接插入
            current.next = Some(&mut *node_ptr);
        }
    }
}

// 辅助函数：地址上取整对齐
fn align_up(addr: usize, align: usize) -> usize {
    (addr + align - 1) & !(align - 1)
}
```

###### 优缺点

-   **优点**：支持单独释放内存，通过块合并减少内存碎片，适用多任务场景。
-   **缺点**：分配速度较慢（遍历链表，时间复杂度 O(n)），每个空闲块需额外存储链表节点（内存开销），“首次适配”策略可能导致小块碎片残留。
