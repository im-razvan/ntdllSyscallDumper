# ntdllSyscallDumper

A minimal C++ tool to extract syscall IDs from `ntdll.dll` on Windows x64 systems.

## How does it work

![ntdll preview](https://github.com/im-razvan/ntdllSyscallDumper/blob/main/ntdll_preview.png?raw=true)

This tool extracts Windows x64 system call IDs by parsing `ntdll.dll`, detecting Nt-prefixed functions with a specific pattern (`4C 8B D1 B8`), and then outputs the names and IDs to `syscalls.csv`.

---

Tested on Windows 11 23H2 and 24H2.