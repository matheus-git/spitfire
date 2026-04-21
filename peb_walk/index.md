---
title: "PEB Walking in Rust: Manual API Resolution Without WinAPI"
published: 2026-04-20
description: "A step-by-step guide to resolving Windows API functions manually in Rust by walking the PEB and parsing loaded modules, without relying on the WinAPI."
image: ""
tags: ["rust", "windows", "peb", "no_std", "windows internals"]
category: "Malware Development"
draft: true
lang: "en-US"
---

In this article, I will show how to walk the Process Environment Block (PEB) to resolve API functions dynamically, avoiding static imports that can be analyzed to identify the functions used by the PE. I will use Rust, and I recommend using `#![no_std]` and `#![no_main]` to produce a cleaner binary. For more details, check my tutorial: <a href="https://cyberspitfire.com/posts/minimal_binary/" target="_blank">How to Build Minimal Windows PE Files in Rust</a>.

:::note
The Process Environment Block (PEB) is a data structure allocated for each process by the Windows kernel to provide user-mode access to various process attributes, such as BeingDebugged, ImageBaseAddress, and the list of loaded modules. [[1]](https://learn.microsoft.com/en-us/shows/inside/peb)
:::

# PEB 

The <a href="https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb" target="_blank">official documentation</a> does not tell much about the data present in the PEB, so I used WinDbg to parse the structure with more details. Open WinDbg and attach to or execute any process, then execute the command `dt _PEB` to show the complete structure fields. To view the data, you need to pass the virtual address of the start of the PEB, which can be found in the first line of the output when executing `!peb`. After that, run `dt _PEB <addr>`, like below:

![peb_windbg](peb_windbg.png)

`Ldr` is what we looking for, it have a pointer to struct `_PEB_LDR_DATA` that have `InMemoryOrderModuleList` a linked-list to loaded modules [[2]](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data). Now, define the PEB structure in code, define padding to skip unimportant fields, and retrieve the Ldr pointer:

```rust
#[repr(C)]
struct PEB {
    _pad: [u8; 0x18],
    ldr: *mut PEB_LDR_DATA,
}
```

# PEB_LDR_DATA 

When debugging PEB_LDR_DATA, we can find the offset of InMemoryOrderModuleList, as shown below:

![peb_ldr_data_windbg](peb_ldr_data_windbg.png)

:::note[InMemoryOrderModuleList]
The head of a doubly-linked list that contains the loaded modules for the process. Each item in the list is a pointer to an LDR_DATA_TABLE_ENTRY structure.
:::

Now, define the structure:

```rust
#[repr(C)]
struct PEB_LDR_DATA {
    _pad: [u8; 0x20],
    in_memory_order_module_list: LIST_ENTRY,
}
```

# LIST_ENTRY

![list_entry_windbg](list_entry_windbg.png)

In practice, in this context, Flink and Blink are pointers inside the `LIST_ENTRY` structure used as `InMemoryOrderLinks` in `LDR_DATA_TABLE_ENTRY`. They point to the next and previous `LIST_ENTRY` entries in the circular doubly linked list of loaded modules.[[3]](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-list_entry) This will make more sense when we look at `LDR_DATA_TABLE_ENTRY` next.

Now, define the structure:

```rust
#[repr(C)]
struct LIST_ENTRY {
    flink: *mut LIST_ENTRY,
    blink: *mut LIST_ENTRY,
}
```

# LDR_DATA_TABLE_ENTRY

# fn get_kernel32()

# IMAGE_DOS_HEADER

# IMAGE_NT_HEADERS64

# IMAGE_OPTIONAL_HEADER64

# IMAGE_OPTIONAL_HEADER64

# IMAGE_EXPORT_DIRECTORY

# fn get_func_address()

***

#### Article source:

::github{repo="matheus-git/spitfire"}
