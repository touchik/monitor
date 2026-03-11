# ProcessMonitor v2.0

A lightweight, cross-platform activity logger for executable files.
Run any binary under ProcessMonitor and it will record every meaningful
thing that process (and its children) does on the system.

Supports **Windows** (XP and later) and **Linux** (kernel 2.6.36 and later).
The correct platform backend is selected automatically at compile time.

---

## Features

| Category    | What is logged                                          | Windows API                     | Linux source                  |
|-------------|--------------------------------------------------------|---------------------------------|-------------------------------|
| `PROCESS`   | Child process spawns and exits                         | `CreateToolhelp32Snapshot`      | `/proc/<pid>/status`          |
| `THREAD`    | New threads created inside tracked processes           | `TH32CS_SNAPTHREAD`             | `/proc/<pid>/task/`           |
| `DLL/SOLIB` | Loaded libraries (DLLs / .so files)                    | `TH32CS_SNAPMODULE`             | `/proc/<pid>/maps`            |
| `NETWORK`   | TCP and UDP connections                                | `GetExtendedTcpTable/UdpTable`  | `/proc/net/tcp`, `/proc/net/udp` |
| `FILE`      | Files opened by tracked processes                      | NtQuerySystemInformation        | `/proc/<pid>/fd/`             |
| `FILESYS`   | File and directory changes in a watched directory      | `ReadDirectoryChangesW`         | `inotify`                     |
| `REGISTRY`  | Windows registry key modifications                     | `RegQueryInfoKey` polling       | *(Windows only)*              |

A built-in **noise filter** suppresses OS runtime artefacts — standard
C/C++ runtime libraries, TLS stacks, glibc NSS modules, kernel pseudo-files,
and similar entries that appear in every process — so only application-specific
events are shown.

---

## Building

### Linux — GCC

```bash
g++ -o process_monitor process_monitor.cpp \
    -std=c++17 -O2 -pthread -lstdc++fs
```

### Windows — MinGW / MSYS2

```bash
g++ -o process_monitor.exe process_monitor.cpp \
    -lpsapi -liphlpapi -lws2_32 -std=c++17 -O2 -pthread
```

### Windows — MSVC (Developer Command Prompt)

```cmd
cl /std:c++17 /O2 process_monitor.cpp ^
   /link psapi.lib iphlpapi.lib ws2_32.lib
```

---

## Usage

> **Linux** — run as `root` or with `sudo` for full `/proc` access.  
> **Windows** — run as **Administrator** for handle enumeration and registry access.

```
$ sudo ./process_monitor

╔══════════════════════════════════════════════════════╗
║       ProcessMonitor v2.0  —  Cross-Platform        ║
║  Detected OS : Linux                                 ║
║  Run as root for full /proc access                   ║
╚══════════════════════════════════════════════════════╝

Path to executable: /usr/bin/curl
Arguments (blank = none): https://example.com
Log file (blank = monitor_log.txt):
Directory to watch (blank = /home):
```

All events are printed to stdout and appended to the log file simultaneously.

---

## Sample output

```
[2026-03-11 21:48:14.695] [INIT]     OS Platform : Linux
[2026-03-11 21:48:14.696] [PROCESS]  Launched: curl PID=270151
[2026-03-11 21:48:15.203] [THREAD]   New TID=270164 in PID=270151
[2026-03-11 21:48:15.705] [SOLIB]    PID=270151 Loaded: /usr/lib/libcurl.so.4.8.0
[2026-03-11 21:48:17.717] [NETWORK]  PID=270151 TCP 192.168.0.106:47702 -> 34.223.124.45:80
[2026-03-11 21:48:22.746] [PROCESS]  Spawned: PID=270273 Name=ping ParentPID=270151
[2026-03-11 21:48:24.757] [PROCESS]  Exited:  PID=270273 Name=ping
[2026-03-11 21:48:36.819] [FILESYS]  CREATED: /home/user/.cache/curl/response.json
[2026-03-11 21:48:40.102] [PROCESS]  Target process exited (PID=270151)
[2026-03-11 21:48:42.847] [INIT]     Monitoring complete. Log saved to: monitor_log.txt
```

---

## Noise filter

The filter runs before every log write and silently drops entries that match
known OS/runtime patterns. The rules are:

| Category      | What is suppressed                                                 |
|---------------|--------------------------------------------------------------------|
| `MONITOR`     | Internal startup messages from monitor threads                     |
| `SOLIB / DLL` | Standard C/C++ runtime, TLS stacks, Kerberos, HTTP/2-3 internals, glibc NSS modules, Windows core DLLs |
| `FILE`        | `/dev/pts/*`, `/dev/null`, `/dev/tty`, `/proc/self/*`, the monitor's own log file, Windows named-pipe noise |

Everything outside these patterns is always logged. To see the raw unfiltered
output, comment out the `if (isNoise(...)) return;` line in `log()`.

---

## Test targets

Two companion programs are included for testing:

| File                       | Platform | Description                                                     |
|----------------------------|----------|-----------------------------------------------------------------|
| `test_target_linux.cpp`    | Linux    | Spawns ping/curl/wget, opens TCP sockets, creates files, loads .so libs, creates threads |
| `test_target_windows.cpp`  | Windows  | Spawns ping/cmd/ipconfig, connects via TCP, writes registry keys, loads DLLs, creates files |

### Build and run (Linux)

```bash
g++ -o test_target test_target_linux.cpp -std=c++17 -pthread -ldl
sudo ./process_monitor
# Path to executable: ./test_target
```

### Build and run (Windows)

```cmd
g++ -o test_target.exe test_target_windows.cpp -lws2_32 -std=c++17
process_monitor.exe
# Path to executable: test_target.exe
```

---

## Project structure

```
process_monitor.cpp        — Main source (Windows + Linux in one file)
test_target_linux.cpp      — Linux test workload
test_target_windows.cpp    — Windows test workload
README.md                  — This file
monitor_log.txt            — Generated at runtime (default log name)
```

---

## Requirements

| Platform | Requirement                              |
|----------|------------------------------------------|
| Linux    | GCC 8+ or Clang 7+, C++17, root access   |
| Windows  | MinGW-w64 or MSVC 2017+, C++17, Admin   |

---

## Limitations

- Network monitoring covers **IPv4** only (IPv6 support can be added using
  `AF_INET6` variants of the same APIs).
- The inotify watch on Linux is **non-recursive** by default — only the top
  level of the specified directory is watched directly.
- On Windows, handle enumeration (`NtQuerySystemInformation`) can be slow
  when the system has a very large number of open handles.
- Some protected system processes may reject `DuplicateHandle` on Windows
  even when running as Administrator.
