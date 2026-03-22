---
title: "Minimal PE: A no_std Rust Setup for Windows"
published: 2026-03-22
description: "A practical guide to building minimal Windows binaries in Rust using no_std and no_main, with custom entry points and WinAPI bindings."
image: ""
tags: ["rust", "windows", "no_std", "pe", "winapi"]
category: "Malware Development"
draft: false
lang: "en-US"
---

In this article, I'll show how I implemented a minimal binary with `#![no_std]` and `#![no_main]`. By default, a Rust binary ships with the standard library, a heap allocator, runtime initialization code, and a set of well-known imports. This adds size and, more importantly, creates a fingerprint that static analysis tools and EDRs recognize immediately. 

:::note[Size Comparison]
A standard "Hello World" weighs around 126KB, while a minimal binary showing a MessageBox occupies only 2KB.
:::

#### Edit Cargo.toml:

```toml title="Cargo.toml"
[package]
name = "message_box"
version = "0.1.0"
edition = "2024"

[profile.dev]
panic = "abort"

[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
panic = "abort"
strip = true
```

- `opt-level = "z"` optimizes for size rather than speed, the **z** flag aggressively eliminates anything that adds bytes.
- `lto = true` enables **Link Time Optimization**, allowing the linker to remove unused code across crates and produce a leaner final binary.
- `codegen-units = 1` forces the compiler to treat the entire crate as a single unit, enabling better dead code elimination at the cost of longer compile times.
- `panic = "abort"` replaces the default panic handler with a simple abort, removing a significant chunk of runtime code. Applied to both dev and release profiles to keep behavior consistent.
- `strip = true` strips debug symbols from the final binary.

#### Create .cargo/config.toml:

```toml title=".cargo/config.toml"
[build]
target = "x86_64-pc-windows-msvc"

rustflags = [
  "-C", "link-arg=/ENTRY:mainCRTStartup",
  "-C", "link-arg=/SUBSYSTEM:WINDOWS",
  "-C", "link-arg=/NODEFAULTLIB",
  "-C", "link-arg=/MERGE:.rdata=.text",
  "-C", "link-arg=/MERGE:.pdata=.text",
]
```

- `target = "x86_64-pc-windows-msvc"` sets the default compilation target, so you don't need to pass **--target** on every cargo build.
- `/ENTRY:mainCRTStartup` tells the linker which function serves as the binary's entry point.
- `/SUBSYSTEM:WINDOWS` defines the PE subsystem. Using **WINDOWS** instead of **CONSOLE** tells Windows this is a GUI application.
- `/NODEFAULTLIB` instructs the linker to not automatically link any default libraries, only what you explicitly declare gets linked.
- `/MERGE:.rdata=.text` merges the **.rdata** section into **.text**, reducing the total number of PE sections and trimming binary size.
- `/MERGE:.pdata=.text` does the same for **.pdata**, which holds exception handling data for stack unwinding. Since we use panic = "abort", this section is unused and can be safely merged away.

#### Edit src/main.rs 

```rust title="src/main.rs"
#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::ptr;
use core::ffi::c_void;

#[link(name = "user32")]
unsafe extern "system" {
    fn MessageBoxA(
        hwnd: *mut c_void,
        text: *const u8,
        title: *const u8,
        flags: u32,
    ) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn ExitProcess(uExitCode: u32) -> !;
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    unsafe {
        ExitProcess(1);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn mainCRTStartup() -> ! {
    static TITLE: &[u8] = b"Title\0";
    static BODY: &[u8] = b"Hello, world!\0";

    unsafe {
        MessageBoxA(
            ptr::null_mut(),
            BODY.as_ptr(),
            TITLE.as_ptr(),
            0x00000030,
        );
        ExitProcess(0);
    }
}
```

- `#![no_std]` disables the Rust standard library entirely, no heap allocator, no runtime, no OS abstractions.
- `#![no_main]` tells the compiler you are not using the standard main entry point, allowing you to define your own.
- `#[link(name = "...")]` instructs the linker to include a specific Windows library.
- `#[panic_handler]` is mandatory in **no_std**, without the standard library, you must define what happens on a panic yourself.
- `#[unsafe(no_mangle)]` prevents Rust from mangling the function name, ensuring the linker can find mainCRTStartup as the entry point we declared in config.toml.

#### Build and Run
```ps
cargo build --release
.\target\x86_64-pc-windows-msvc\release\message_box.exe
```

If everything is set up correctly, a MessageBox should appear. And the final binary will weigh around 2KB!
