/*
 * ============================================================================
 *  ProcessMonitor v2.0  —  Cross-Platform Activity Logger
 *  Supported OS: Windows (XP+) and Linux (kernel 2.6.36+)
 * ============================================================================
 *
 *  Tracks the following activity of a target executable and all its children:
 *    - Child process spawns and exits
 *    - Thread creation
 *    - Loaded DLLs / shared libraries (.so)
 *    - File system changes in a watched directory
 *    - Open file handles / file descriptors
 *    - TCP and UDP network connections
 *    - Windows registry key modifications
 *
 *  All output is written to stdout and to a log file simultaneously.
 *  A built-in noise filter suppresses well-known OS runtime artefacts so
 *  that only meaningful, application-specific events are shown.
 *
 * ----------------------------------------------------------------------------
 *  Build — Windows (MinGW / MSYS2)
 *    g++ -o process_monitor.exe process_monitor.cpp \
 *        -lpsapi -liphlpapi -lws2_32 -std=c++17 -O2 -pthread
 *
 *  Build — Windows (MSVC Developer Prompt)
 *    cl /std:c++17 /O2 process_monitor.cpp \
 *       /link psapi.lib iphlpapi.lib ws2_32.lib
 *
 *  Build — Linux (GCC / Clang)
 *    g++ -o process_monitor process_monitor.cpp \
 *        -std=c++17 -O2 -pthread -lstdc++fs
 *
 * ----------------------------------------------------------------------------
 *  Runtime requirements
 *    Windows : must be run as Administrator
 *    Linux   : must be run as root (for full /proc access)
 * ============================================================================
 */

// ============================================================================
//  Platform detection
//  Exactly one of PLATFORM_WINDOWS or PLATFORM_LINUX will be defined.
// ============================================================================
#if defined(_WIN32) || defined(_WIN64)
    #define PLATFORM_WINDOWS
#elif defined(__linux__)
    #define PLATFORM_LINUX
#else
    #error "Unsupported platform. Only Windows and Linux are supported."
#endif

// ============================================================================
//  Common standard-library includes (used on both platforms)
// ============================================================================
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <iomanip>
#include <algorithm>
#include <filesystem>

// ============================================================================
//  Windows-specific headers and type aliases
// ============================================================================
#ifdef PLATFORM_WINDOWS
    #define WIN32_LEAN_AND_MEAN   // exclude rarely-used Win32 headers
    #define NOMINMAX              // prevent Windows.h from defining min/max macros
    #include <windows.h>
    #include <psapi.h>            // GetModuleFileNameEx, EnumProcessModules
    #include <tlhelp32.h>         // CreateToolhelp32Snapshot, Process32First/Next
    #include <winternl.h>         // NtQueryInformationProcess (undocumented)
    #include <iphlpapi.h>         // GetExtendedTcpTable, GetExtendedUdpTable
    #include <ws2tcpip.h>         // inet_ntop
    #pragma comment(lib, "psapi.lib")
    #pragma comment(lib, "iphlpapi.lib")
    #pragma comment(lib, "ws2_32.lib")
    using PID_T = DWORD;
    #define SLEEP_MS(ms) Sleep(ms)
#endif

// ============================================================================
//  Linux-specific headers and type aliases
// ============================================================================
#ifdef PLATFORM_LINUX
    #include <unistd.h>           // fork, execv, readlink, getpid
    #include <signal.h>
    #include <sys/types.h>
    #include <sys/wait.h>         // waitpid
    #include <sys/inotify.h>      // inotify_init1, inotify_add_watch
    #include <dirent.h>
    #include <fcntl.h>            // open, O_WRONLY
    #include <cstring>            // strerror
    #include <cerrno>
    #include <arpa/inet.h>        // inet_ntoa, inet_ntop
    #include <netinet/in.h>
    using PID_T = pid_t;
    #define SLEEP_MS(ms) usleep((ms) * 1000)
#endif

// ============================================================================
//  Global state
// ============================================================================
static std::ofstream             g_logFile;    // output log file stream
static std::mutex                g_logMutex;   // serialises all log writes
static std::atomic<bool>         g_running(true); // set to false when target exits

static std::set<PID_T>           g_trackedPIDs;   // PIDs being monitored
static std::mutex                g_pidMutex;

// Delta-detection maps — store the last known state so we can report changes
static std::map<PID_T, std::string>       g_knownProcesses; // PID  -> name
static std::set<std::string>              g_knownModules;   // "PID:path"
static std::map<PID_T, std::set<PID_T>>  g_knownThreads;   // PID  -> {TIDs}

// Absolute path of the log file; used by the noise filter to suppress
// events that the monitor itself causes (e.g. its own writes to the log).
static std::string g_logPath;

// ============================================================================
//  Noise filter
//  Returns true when a log entry should be SUPPRESSED because it represents
//  well-known OS runtime behaviour rather than target-specific activity.
// ============================================================================

// Returns true if 'str' contains at least one substring from 'patterns'.
static bool containsAny(const std::string& str,
                         const std::initializer_list<const char*>& patterns) {
    for (auto* p : patterns)
        if (str.find(p) != std::string::npos) return true;
    return false;
}

static bool isNoise(const std::string& category, const std::string& msg) {

    // Internal monitor startup messages — never interesting to the user.
    if (category == "MONITOR") return true;

    // Shared libraries / DLLs ------------------------------------------------
    // Suppress entries that match well-known OS / runtime libraries.
    // Any library NOT on this list will still be reported.
    if (category == "SOLIB" || category == "DLL") {
        static const std::initializer_list<const char*> sysLibs = {
            // Linux C / C++ runtime
            "libc.so", "libm.so", "libdl.so", "libpthread.so",
            "libgcc_s.so", "libstdc++.so", "ld-linux",
            "libz.so", "libzstd.so",
            // glibc name-service switch (loaded automatically)
            "libnss_", "libresolv.so",
            // TLS / crypto stacks — present in every HTTPS-capable tool
            "libssl.so", "libcrypto.so", "libgnutls.so", "libnettle.so",
            "libhogweed.so", "libtasn1.so", "libgmp.so", "libffi.so",
            "libp11-kit.so", "libleancrypto.so",
            // Kerberos — pulled in transitively by curl / wget
            "libkrb5", "libk5crypto", "libkeyutils", "libcom_err",
            "libgssapi_krb5",
            // Unicode / IDN support
            "libunistring.so", "libidn2.so",
            // HTTP/2 and HTTP/3 internals (curl dependencies)
            "libnghttp2.so", "libnghttp3.so", "libngtcp2",
            "libbrotli", "libpsl.so", "libssh2.so",
            "libcurl.so",
            // wget / glib dependencies
            "libpcre2", "libuuid.so",
            // Windows core runtime DLLs
            "ntdll.dll", "kernel32.dll", "kernelbase.dll",
            "msvcrt.dll", "vcruntime", "api-ms-win",
            "ucrtbase.dll",
        };
        if (containsAny(msg, sysLibs)) return true;
        return false; // non-system library — keep the entry
    }

    // Open file handles / descriptors ----------------------------------------
    // Suppress the monitor's own log file and kernel pseudo-files that are
    // always present in every process's file-descriptor table.
    if (category == "FILE") {
        if (!g_logPath.empty() && msg.find(g_logPath) != std::string::npos)
            return true; // hide accesses to our own log file

        static const std::initializer_list<const char*> fileNoise = {
            // Terminal and pseudo-TTY devices
            "/dev/pts/", "/dev/tty", "/dev/null", "/dev/zero",
            // Linux kernel virtual files (always open in every process)
            "/proc/self/", "/proc/stat", "/proc/meminfo",
            // Shared-memory arena
            "/dev/shm",
            // Windows named-pipe / device noise
            "\\Device\\ConDrv", "\\Device\\Afd",
            "\\??\\pipe\\",
        };
        if (containsAny(msg, fileNoise)) return true;
        return false;
    }

    // All other categories (PROCESS, THREAD, NETWORK, FILESYS, REGISTRY, INIT)
    // are passed through without filtering.
    return false;
}

// ============================================================================
//  Logging helpers (shared between both platform implementations)
// ============================================================================

// Returns the current wall-clock time as "YYYY-MM-DD HH:MM:SS.mmm".
static std::string currentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto t   = std::chrono::system_clock::to_time_t(now);
    auto ms  = std::chrono::duration_cast<std::chrono::milliseconds>(
                   now.time_since_epoch()) % 1000;
    std::tm tm_buf{};
#ifdef PLATFORM_WINDOWS
    localtime_s(&tm_buf, &t);
#else
    localtime_r(&t, &tm_buf);
#endif
    std::ostringstream ss;
    ss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S")
       << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return ss.str();
}

// Thread-safe log function.  Writes "[timestamp] [category] msg" to both
// stdout and the log file.  Filtered entries are silently dropped.
static void log(const std::string& category, const std::string& msg) {
    if (isNoise(category, msg)) return;
    std::lock_guard<std::mutex> lk(g_logMutex);
    std::string line = "[" + currentTimestamp() + "] [" + category + "] " + msg;
    std::cout << line << "\n";
    if (g_logFile.is_open()) { g_logFile << line << "\n"; g_logFile.flush(); }
}

// ============================================================================
//
//   W I N D O W S   I M P L E M E N T A T I O N
//
// ============================================================================
#ifdef PLATFORM_WINDOWS

// Converts a UTF-16 wide string to a UTF-8 std::string.
static std::string wstrToStr(const std::wstring& ws) {
    if (ws.empty()) return {};
    int sz = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1,
                                  nullptr, 0, nullptr, nullptr);
    std::string s(sz - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, s.data(), sz, nullptr, nullptr);
    return s;
}

// Returns the parent PID of a given process using the undocumented
// NtQueryInformationProcess API (available on all NT versions).
static DWORD getParentPID(DWORD pid) {
    typedef NTSTATUS(WINAPI* pfn)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    static auto fn = (pfn)GetProcAddress(GetModuleHandleA("ntdll"),
                                          "NtQueryInformationProcess");
    if (!fn) return 0;
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!h) return 0;
    PROCESS_BASIC_INFORMATION pbi{}; DWORD ppid = 0;
    if (fn(h, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr) == 0)
        ppid = (DWORD)(uintptr_t)pbi.Reserved3; // InheritedFromUniqueProcessId
    CloseHandle(h);
    return ppid;
}

// ----------------------------------------------------------------------------
//  Monitor: processes
//  Polls the system process list every 500 ms.  Reports new child processes
//  whose parent is already in g_trackedPIDs, and reports process exits.
// ----------------------------------------------------------------------------
static void monitorProcesses() {
    log("MONITOR", "Process monitor started [Windows]");
    while (g_running) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) { SLEEP_MS(500); continue; }

        std::map<DWORD, std::string> current;
        PROCESSENTRY32 pe{}; pe.dwSize = sizeof(pe);
        if (Process32First(snap, &pe))
            do { current[pe.th32ProcessID] = pe.szExeFile; }
            while (Process32Next(snap, &pe));
        CloseHandle(snap);

        std::lock_guard<std::mutex> lk(g_pidMutex);

        // Detect newly spawned processes whose parent is tracked
        for (auto& [pid, name] : current) {
            if (!g_knownProcesses.count(pid)) {
                DWORD ppid = getParentPID(pid);
                if (g_trackedPIDs.count(ppid)) {
                    g_trackedPIDs.insert(pid);
                    log("PROCESS", "Spawned: PID=" + std::to_string(pid) +
                        " Name=" + name + " ParentPID=" + std::to_string(ppid));
                }
            }
        }

        // Detect processes that have exited
        for (auto it = g_knownProcesses.begin(); it != g_knownProcesses.end(); ) {
            if (!current.count(it->first) && g_trackedPIDs.count(it->first)) {
                log("PROCESS", "Exited: PID=" + std::to_string(it->first) +
                    " Name=" + it->second);
                g_trackedPIDs.erase(it->first);
                it = g_knownProcesses.erase(it);
            } else ++it;
        }

        g_knownProcesses = current;
        SLEEP_MS(500);
    }
}

// ----------------------------------------------------------------------------
//  Monitor: threads
//  Polls TH32CS_SNAPTHREAD every 500 ms and reports any new thread ID that
//  belongs to a tracked process.
// ----------------------------------------------------------------------------
static void monitorThreads() {
    log("MONITOR", "Thread monitor started [Windows]");
    while (g_running) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) { SLEEP_MS(500); continue; }

        std::set<DWORD> tracked;
        { std::lock_guard<std::mutex> lk(g_pidMutex); tracked = g_trackedPIDs; }

        THREADENTRY32 te{}; te.dwSize = sizeof(te);
        if (Thread32First(snap, &te)) {
            do {
                if (!tracked.count(te.th32OwnerProcessID)) continue;
                if (!g_knownThreads[te.th32OwnerProcessID].count(te.th32ThreadID)) {
                    g_knownThreads[te.th32OwnerProcessID].insert(te.th32ThreadID);
                    log("THREAD", "New TID=" + std::to_string(te.th32ThreadID) +
                        " in PID=" + std::to_string(te.th32OwnerProcessID));
                }
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
        SLEEP_MS(500);
    }
}

// ----------------------------------------------------------------------------
//  Monitor: loaded modules (DLLs)
//  Polls TH32CS_SNAPMODULE for each tracked process every second and logs
//  any module that has not been seen before.
// ----------------------------------------------------------------------------
static void monitorModules() {
    log("MONITOR", "Module monitor started [Windows]");
    while (g_running) {
        std::set<DWORD> snapshot;
        { std::lock_guard<std::mutex> lk(g_pidMutex); snapshot = g_trackedPIDs; }

        for (DWORD pid : snapshot) {
            HANDLE snap = CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
            if (snap == INVALID_HANDLE_VALUE) continue;

            MODULEENTRY32 me{}; me.dwSize = sizeof(me);
            if (Module32First(snap, &me))
                do {
                    std::string key = std::to_string(pid) + ":" + me.szExePath;
                    if (!g_knownModules.count(key)) {
                        g_knownModules.insert(key);
                        log("DLL", "PID=" + std::to_string(pid) +
                            " Loaded=" + me.szModule + " Path=" + me.szExePath);
                    }
                } while (Module32Next(snap, &me));
            CloseHandle(snap);
        }
        SLEEP_MS(1000);
    }
}

// ----------------------------------------------------------------------------
//  Monitor: network connections (TCP/UDP via iphlpapi)
//  Queries the extended TCP and UDP owner-PID tables every second.
//  Each unique (pid, local, remote) tuple is reported once.
// ----------------------------------------------------------------------------
static void monitorNetwork() {
    log("MONITOR", "Network monitor started [Windows]");
    std::set<std::string> seen; // deduplication set

    while (g_running) {
        std::set<DWORD> tracked;
        { std::lock_guard<std::mutex> lk(g_pidMutex); tracked = g_trackedPIDs; }

        // --- TCP IPv4 --------------------------------------------------------
        ULONG sz = 0;
        GetExtendedTcpTable(nullptr, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        std::vector<BYTE> buf(sz);
        if (GetExtendedTcpTable(buf.data(), &sz, FALSE, AF_INET,
                                TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            auto* t = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
            static const char* states[] = {
                "","CLOSED","LISTEN","SYN_SENT","SYN_RCVD",
                "ESTAB","FIN_WAIT1","FIN_WAIT2","CLOSE_WAIT",
                "CLOSING","LAST_ACK","TIME_WAIT","DEL"
            };
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                auto& r = t->table[i];
                if (!tracked.count(r.dwOwningPid)) continue;
                char la[INET_ADDRSTRLEN], ra[INET_ADDRSTRLEN];
                IN_ADDR a{};
                a.S_un.S_addr = r.dwLocalAddr;  inet_ntop(AF_INET, &a, la, sizeof(la));
                a.S_un.S_addr = r.dwRemoteAddr; inet_ntop(AF_INET, &a, ra, sizeof(ra));
                int lp = ntohs((WORD)r.dwLocalPort), rp = ntohs((WORD)r.dwRemotePort);
                std::string key = "tcp:" + std::to_string(r.dwOwningPid) +
                                  ":" + la + ":" + std::to_string(lp) +
                                  "->" + ra + ":" + std::to_string(rp);
                if (!seen.count(key)) {
                    seen.insert(key);
                    log("NETWORK", "PID=" + std::to_string(r.dwOwningPid) +
                        " TCP " + la + ":" + std::to_string(lp) +
                        " -> " + ra + ":" + std::to_string(rp) +
                        " [" + (r.dwState < 13 ? states[r.dwState] : "?") + "]");
                }
            }
        }

        // --- UDP IPv4 --------------------------------------------------------
        ULONG usz = 0;
        GetExtendedUdpTable(nullptr, &usz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
        std::vector<BYTE> ubuf(usz);
        if (GetExtendedUdpTable(ubuf.data(), &usz, FALSE, AF_INET,
                                UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
            auto* t = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(ubuf.data());
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                auto& r = t->table[i];
                if (!tracked.count(r.dwOwningPid)) continue;
                char la[INET_ADDRSTRLEN]; IN_ADDR a{};
                a.S_un.S_addr = r.dwLocalAddr; inet_ntop(AF_INET, &a, la, sizeof(la));
                int lp = ntohs((WORD)r.dwLocalPort);
                std::string key = "udp:" + std::to_string(r.dwOwningPid) +
                                  ":" + la + ":" + std::to_string(lp);
                if (!seen.count(key)) {
                    seen.insert(key);
                    log("NETWORK", "PID=" + std::to_string(r.dwOwningPid) +
                        " UDP " + la + ":" + std::to_string(lp));
                }
            }
        }
        SLEEP_MS(1000);
    }
}

// ----------------------------------------------------------------------------
//  Monitor: Windows registry
//  Polls last-write timestamps of high-value keys every 1.5 s and logs
//  any key whose timestamp has changed since the previous poll.
// ----------------------------------------------------------------------------
static void monitorRegistry() {
    log("MONITOR", "Registry monitor started [Windows]");

    // Keys that are commonly targeted by malware or installers
    static const std::vector<std::string> watchedKeys = {
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        "SYSTEM\\CurrentControlSet\\Services",
        "SOFTWARE",
        "SYSTEM"
    };

    std::map<std::string, FILETIME> lastWriteTime;

    // Helper lambda: query the last-write time of a registry key
    auto queryLastWrite = [](HKEY root, const std::string& sub, FILETIME& ft) {
        HKEY hk;
        if (RegOpenKeyExA(root, sub.c_str(), 0, KEY_READ, &hk) != ERROR_SUCCESS)
            return false;
        DWORD subCount, valueCount;
        bool ok = RegQueryInfoKeyA(hk, nullptr, nullptr, nullptr,
                                    &subCount, nullptr, nullptr,
                                    &valueCount, nullptr, nullptr, nullptr, &ft)
                  == ERROR_SUCCESS;
        RegCloseKey(hk);
        return ok;
    };

    while (g_running) {
        for (auto& subKey : watchedKeys) {
            for (auto [rootHandle, rootName] :
                 std::initializer_list<std::pair<HKEY, const char*>>{
                     {HKEY_LOCAL_MACHINE, "HKLM"}, {HKEY_CURRENT_USER, "HKCU"}}) {
                FILETIME ft{};
                std::string fullKey = rootName + std::string("\\") + subKey;
                if (queryLastWrite(rootHandle, subKey, ft)) {
                    auto it = lastWriteTime.find(fullKey);
                    if (it != lastWriteTime.end()) {
                        if (CompareFileTime(&it->second, &ft) != 0) {
                            log("REGISTRY", "Modified: " + fullKey);
                            it->second = ft;
                        }
                    } else {
                        lastWriteTime[fullKey] = ft; // first observation — baseline
                    }
                }
            }
        }
        SLEEP_MS(1500);
    }
}

// ----------------------------------------------------------------------------
//  Monitor: file system (ReadDirectoryChangesW)
//  Watches a directory tree recursively using an overlapped I/O read.
//  Reports CREATE, DELETE, MODIFY, and RENAME events as they occur.
// ----------------------------------------------------------------------------
static void monitorFileSystem(const std::string& watchDir) {
    log("MONITOR", "FileSystem monitor on: " + watchDir + " [Windows]");

    HANDLE hDir = CreateFileA(watchDir.c_str(), FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr);

    if (hDir == INVALID_HANDLE_VALUE) {
        log("FILESYS", "Cannot watch directory: " + watchDir); return;
    }

    std::vector<BYTE> buf(65536);
    OVERLAPPED ov{};
    ov.hEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);

    while (g_running) {
        ResetEvent(ov.hEvent);
        DWORD ret = 0;
        if (!ReadDirectoryChangesW(hDir, buf.data(), (DWORD)buf.size(), TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME  |
            FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_CREATION |
            FILE_NOTIFY_CHANGE_SIZE, &ret, &ov, nullptr)) {
            SLEEP_MS(1000); continue;
        }

        if (WaitForSingleObject(ov.hEvent, 2000) != WAIT_OBJECT_0) continue;
        GetOverlappedResult(hDir, &ov, &ret, FALSE);

        static const char* actionNames[] = {
            "?", "CREATED", "DELETED", "MODIFIED", "RENAMED_FROM", "RENAMED_TO"
        };

        auto* fni = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buf.data());
        for (;;) {
            std::wstring fileName(fni->FileName, fni->FileNameLength / sizeof(wchar_t));
            log("FILESYS",
                std::string(fni->Action <= 5 ? actionNames[fni->Action] : "?") +
                ": " + watchDir + "\\" + wstrToStr(fileName));

            if (!fni->NextEntryOffset) break;
            fni = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(
                reinterpret_cast<BYTE*>(fni) + fni->NextEntryOffset);
        }
    }

    CloseHandle(ov.hEvent);
    CloseHandle(hDir);
}

// ----------------------------------------------------------------------------
//  Waits for the target process to exit, then signals all monitors to stop.
// ----------------------------------------------------------------------------
static void waitForTarget(HANDLE hProcess) {
    WaitForSingleObject(hProcess, INFINITE);
    log("PROCESS", "Target process exited");
    SLEEP_MS(2000); // let monitors flush any final events
    g_running = false;
}

// ----------------------------------------------------------------------------
//  Windows entry point: launch the target, start all monitor threads,
//  wait for them to finish, then return.
// ----------------------------------------------------------------------------
static int platformRun(const std::string& exePath, const std::string& args,
                        const std::string& watchDir) {
    std::string cmd = "\"" + exePath + "\"";
    if (!args.empty()) cmd += " " + args;

    STARTUPINFOA si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);

    if (!CreateProcessA(nullptr, const_cast<char*>(cmd.c_str()), nullptr, nullptr,
                        FALSE, 0, nullptr, nullptr, &si, &pi)) {
        std::cerr << "ERROR: CreateProcess failed (err=" << GetLastError() << ")\n";
        return 1;
    }
    CloseHandle(pi.hThread); // we don't need the main-thread handle

    log("PROCESS", "Launched: " + exePath + " PID=" + std::to_string(pi.dwProcessId));
    { std::lock_guard<std::mutex> lk(g_pidMutex); g_trackedPIDs.insert(pi.dwProcessId); }
    g_knownProcesses[pi.dwProcessId] =
        std::filesystem::path(exePath).filename().string();

    std::thread tP(monitorProcesses),
                tT(monitorThreads),
                tM(monitorModules),
                tN(monitorNetwork),
                tR(monitorRegistry),
                tFS(monitorFileSystem, watchDir),
                tW(waitForTarget, pi.hProcess);

    tP.join(); tT.join(); tM.join(); tN.join(); tR.join(); tFS.join(); tW.join();
    CloseHandle(pi.hProcess);
    return 0;
}

#endif // PLATFORM_WINDOWS

// ============================================================================
//
//   L I N U X   I M P L E M E N T A T I O N
//
// ============================================================================
#ifdef PLATFORM_LINUX

// Reads the entire content of a file under /proc into a string.
static std::string readProcFile(const std::string& path) {
    std::ifstream f(path);
    if (!f) return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// Resolves a symbolic link and returns its target as a string.
static std::string readLink(const std::string& path) {
    char buf[4096] = {};
    ssize_t n = readlink(path.c_str(), buf, sizeof(buf) - 1);
    return (n > 0) ? std::string(buf, n) : "";
}

// Returns the executable name of a process by reading /proc/<pid>/comm.
static std::string getProcName(pid_t pid) {
    std::string comm = readProcFile("/proc/" + std::to_string(pid) + "/comm");
    if (!comm.empty() && comm.back() == '\n') comm.pop_back();
    return comm.empty() ? "<unknown>" : comm;
}

// Returns the parent PID by parsing the PPid field in /proc/<pid>/status.
static pid_t getParentPID(pid_t pid) {
    std::ifstream f("/proc/" + std::to_string(pid) + "/status");
    std::string line;
    while (std::getline(f, line))
        if (line.rfind("PPid:", 0) == 0)
            return std::stoi(line.substr(5));
    return 0;
}

// ----------------------------------------------------------------------------
//  Monitor: processes
//  Scans /proc for numeric directory names (each is a PID) every 500 ms.
//  Reports new children of tracked PIDs and reports process exits.
// ----------------------------------------------------------------------------
static void monitorProcesses() {
    log("MONITOR", "Process monitor started [Linux]");
    while (g_running) {
        std::map<pid_t, std::string> current;

        for (auto& entry : std::filesystem::directory_iterator("/proc")) {
            std::string n = entry.path().filename().string();
            if (!std::all_of(n.begin(), n.end(), ::isdigit)) continue;
            pid_t pid = std::stoi(n);
            current[pid] = getProcName(pid);
        }

        std::lock_guard<std::mutex> lk(g_pidMutex);

        // Detect newly spawned children of tracked processes
        for (auto& [pid, pname] : current) {
            if (!g_knownProcesses.count(pid)) {
                pid_t ppid = getParentPID(pid);
                if (g_trackedPIDs.count(ppid)) {
                    g_trackedPIDs.insert(pid);
                    log("PROCESS", "Spawned: PID=" + std::to_string(pid) +
                        " Name=" + pname + " ParentPID=" + std::to_string(ppid));
                }
            }
        }

        // Detect processes that have exited (no longer present in /proc)
        for (auto it = g_knownProcesses.begin(); it != g_knownProcesses.end(); ) {
            if (!current.count(it->first) && g_trackedPIDs.count(it->first)) {
                log("PROCESS", "Exited: PID=" + std::to_string(it->first) +
                    " Name=" + it->second);
                g_trackedPIDs.erase(it->first);
                it = g_knownProcesses.erase(it);
            } else ++it;
        }

        g_knownProcesses = current;
        SLEEP_MS(500);
    }
}

// ----------------------------------------------------------------------------
//  Monitor: threads
//  Each entry in /proc/<pid>/task/ is a thread ID.  We report any TID that
//  has not been seen before, skipping the main thread (tid == pid).
// ----------------------------------------------------------------------------
static void monitorThreads() {
    log("MONITOR", "Thread monitor started [Linux]");
    while (g_running) {
        std::set<pid_t> tracked;
        { std::lock_guard<std::mutex> lk(g_pidMutex); tracked = g_trackedPIDs; }

        for (pid_t pid : tracked) {
            std::string taskDir = "/proc/" + std::to_string(pid) + "/task";
            if (!std::filesystem::exists(taskDir)) continue;

            for (auto& entry : std::filesystem::directory_iterator(taskDir)) {
                std::string ts = entry.path().filename().string();
                if (!std::all_of(ts.begin(), ts.end(), ::isdigit)) continue;
                pid_t tid = std::stoi(ts);
                if (!g_knownThreads[pid].count(tid)) {
                    g_knownThreads[pid].insert(tid);
                    if (tid != pid) // skip the main thread — already reported as PROCESS
                        log("THREAD", "New TID=" + std::to_string(tid) +
                            " in PID=" + std::to_string(pid));
                }
            }
        }
        SLEEP_MS(500);
    }
}

// ----------------------------------------------------------------------------
//  Monitor: loaded shared libraries
//  Reads /proc/<pid>/maps every second.  Lines that contain ".so" are
//  shared-library mappings; we extract the path and report each one once.
// ----------------------------------------------------------------------------
static void monitorModules() {
    log("MONITOR", "Module monitor started [Linux /proc/maps]");
    while (g_running) {
        std::set<pid_t> tracked;
        { std::lock_guard<std::mutex> lk(g_pidMutex); tracked = g_trackedPIDs; }

        for (pid_t pid : tracked) {
            std::ifstream f("/proc/" + std::to_string(pid) + "/maps");
            if (!f) continue;

            std::string line;
            while (std::getline(f, line)) {
                // Map lines: "addr-addr perms offset dev inode [path]"
                auto pos = line.find('/');
                if (pos == std::string::npos) continue;
                std::string path = line.substr(pos);
                if (path.find(".so") == std::string::npos) continue;

                // Strip any trailing space or annotation (e.g. " (deleted)")
                auto sp = path.find(' ');
                if (sp != std::string::npos) path = path.substr(0, sp);

                std::string key = std::to_string(pid) + ":" + path;
                if (!g_knownModules.count(key)) {
                    g_knownModules.insert(key);
                    log("SOLIB", "PID=" + std::to_string(pid) + " Loaded: " + path);
                }
            }
        }
        SLEEP_MS(1000);
    }
}

// ----------------------------------------------------------------------------
//  Monitor: network connections
//  Reads /proc/net/tcp and /proc/net/udp.  Resolves socket inodes to PIDs
//  by scanning /proc/<pid>/fd/ symlinks.  Reports each unique connection once.
// ----------------------------------------------------------------------------

// Converts a little-endian hex IPv4 address string to dotted-decimal.
static std::string hexToIP(const std::string& hex) {
    unsigned int ip = std::stoul(hex, nullptr, 16);
    struct in_addr addr;
    addr.s_addr = ip;
    return inet_ntoa(addr);
}

static void monitorNetwork() {
    log("MONITOR", "Network monitor started [Linux /proc/net]");
    std::set<std::string> seen; // deduplication set

    while (g_running) {
        std::set<pid_t> tracked;
        { std::lock_guard<std::mutex> lk(g_pidMutex); tracked = g_trackedPIDs; }

        // Build a socket-inode -> PID mapping by reading each tracked
        // process's file-descriptor directory.
        std::map<std::string, pid_t> inodeToPID;
        for (pid_t pid : tracked) {
            std::string fdDir = "/proc/" + std::to_string(pid) + "/fd";
            if (!std::filesystem::exists(fdDir)) continue;

            for (auto& fd : std::filesystem::directory_iterator(fdDir)) {
                std::string target = readLink(fd.path().string());
                // Socket symlinks look like: "socket:[12345]"
                if (target.rfind("socket:[", 0) == 0) {
                    std::string inode = target.substr(8, target.size() - 9);
                    inodeToPID[inode] = pid;
                }
            }
        }

        // Parse /proc/net/tcp and /proc/net/udp and correlate with our PID map
        for (auto& [proto, procFile] :
             std::initializer_list<std::pair<const char*, const char*>>{
                 {"TCP", "/proc/net/tcp"}, {"UDP", "/proc/net/udp"}}) {

            std::ifstream f(procFile);
            if (!f) continue;

            std::string line;
            std::getline(f, line); // skip the header row

            while (std::getline(f, line)) {
                std::istringstream iss(line);
                std::string idx, laddr, raddr, state,
                            txrx, trTm, retrans, uid, to, inode;
                iss >> idx >> laddr >> raddr >> state
                    >> txrx >> trTm >> retrans >> uid >> to >> inode;

                if (!inodeToPID.count(inode)) continue;
                pid_t pid = inodeToPID[inode];

                // Parse "HEXIP:HEXPORT" into human-readable ip:port
                auto parseAddr = [](const std::string& s, std::string& ip, int& port) {
                    auto colon = s.find(':');
                    ip   = hexToIP(s.substr(0, colon));
                    port = std::stoi(s.substr(colon + 1), nullptr, 16);
                };

                std::string lip, rip;
                int lp = 0, rp = 0;
                parseAddr(laddr, lip, lp);
                parseAddr(raddr, rip, rp);

                std::string key = std::string(proto) + ":" + std::to_string(pid) +
                                  ":" + lip + ":" + std::to_string(lp) +
                                  "->" + rip + ":" + std::to_string(rp);
                if (!seen.count(key)) {
                    seen.insert(key);
                    log("NETWORK", "PID=" + std::to_string(pid) +
                        " " + proto + " " + lip + ":" + std::to_string(lp) +
                        " -> " + rip + ":" + std::to_string(rp));
                }
            }
        }
        SLEEP_MS(1000);
    }
}

// ----------------------------------------------------------------------------
//  Monitor: open file descriptors
//  Reads /proc/<pid>/fd/ every 800 ms and reports any new symlink target
//  that resolves to an absolute path (i.e. a real file on disk).
// ----------------------------------------------------------------------------
static void monitorOpenFiles() {
    log("MONITOR", "Open-files monitor started [Linux /proc/fd]");
    std::set<std::string> seen;

    while (g_running) {
        std::set<pid_t> tracked;
        { std::lock_guard<std::mutex> lk(g_pidMutex); tracked = g_trackedPIDs; }

        for (pid_t pid : tracked) {
            std::string fdDir = "/proc/" + std::to_string(pid) + "/fd";
            if (!std::filesystem::exists(fdDir)) continue;

            for (auto& fd : std::filesystem::directory_iterator(fdDir)) {
                std::string target = readLink(fd.path().string());
                // Only report real filesystem paths (not sockets, pipes, etc.)
                if (target.empty() || target.front() != '/') continue;
                std::string key = std::to_string(pid) + ":" + target;
                if (!seen.count(key)) {
                    seen.insert(key);
                    log("FILE", "PID=" + std::to_string(pid) + " Opened: " + target);
                }
            }
        }
        SLEEP_MS(800);
    }
}

// ----------------------------------------------------------------------------
//  Monitor: file system changes (inotify)
//  Watches a single directory non-recursively using Linux inotify.
//  Flags: CREATE, DELETE, MODIFY, CLOSE_WRITE, RENAME, ATTRIB.
// ----------------------------------------------------------------------------
static void monitorFileSystem(const std::string& watchDir) {
    log("MONITOR", "FileSystem monitor on: " + watchDir + " [Linux/inotify]");

    int fd = inotify_init1(IN_NONBLOCK);
    if (fd < 0) {
        log("FILESYS", "inotify_init failed: " + std::string(strerror(errno)));
        return;
    }

    int wd = inotify_add_watch(fd, watchDir.c_str(),
        IN_CREATE | IN_DELETE | IN_MODIFY | IN_MOVED_FROM |
        IN_MOVED_TO | IN_CLOSE_WRITE | IN_ATTRIB);
    if (wd < 0) {
        log("FILESYS", "inotify_add_watch failed: " + std::string(strerror(errno)));
        close(fd);
        return;
    }

    std::vector<char> buf(65536);
    while (g_running) {
        SLEEP_MS(200);
        ssize_t n = read(fd, buf.data(), buf.size());
        if (n <= 0) continue;

        for (ssize_t i = 0; i < n; ) {
            auto* ev = reinterpret_cast<inotify_event*>(buf.data() + i);
            std::string fileName = (ev->len > 0) ? std::string(ev->name) : "";
            std::string path     = watchDir + "/" + fileName;

            std::string action;
            if      (ev->mask & IN_CREATE)                     action = "CREATED";
            else if (ev->mask & IN_DELETE)                     action = "DELETED";
            else if (ev->mask & (IN_MODIFY | IN_CLOSE_WRITE))  action = "MODIFIED";
            else if (ev->mask & IN_MOVED_FROM)                 action = "MOVED_FROM";
            else if (ev->mask & IN_MOVED_TO)                   action = "MOVED_TO";
            else if (ev->mask & IN_ATTRIB)                     action = "ATTRIB";

            if (!action.empty())
                log("FILESYS", action + ": " + path);

            i += sizeof(inotify_event) + ev->len;
        }
    }

    inotify_rm_watch(fd, wd);
    close(fd);
}

// ----------------------------------------------------------------------------
//  Waits for the target process to finish, then signals all monitors to stop.
// ----------------------------------------------------------------------------
static void waitForTarget(pid_t pid) {
    int status;
    waitpid(pid, &status, 0);
    log("PROCESS", "Target process exited (PID=" + std::to_string(pid) + ")");
    SLEEP_MS(2000); // give monitors time to flush remaining events
    g_running = false;
}

// ----------------------------------------------------------------------------
//  Linux entry point: fork and exec the target, start all monitor threads,
//  wait for them to finish, then return.
// ----------------------------------------------------------------------------
static int platformRun(const std::string& exePath, const std::string& args,
                        const std::string& watchDir) {
    pid_t pid = fork();
    if (pid < 0) { std::cerr << "ERROR: fork() failed\n"; return 1; }

    if (pid == 0) {
        // --- Child process: build argv and exec the target -------------------
        std::vector<std::string> argList = { exePath };
        if (!args.empty()) {
            std::istringstream iss(args);
            std::string tok;
            while (iss >> tok) argList.push_back(tok);
        }
        std::vector<char*> argv;
        for (auto& a : argList) argv.push_back(const_cast<char*>(a.c_str()));
        argv.push_back(nullptr);

        execv(exePath.c_str(), argv.data());
        std::cerr << "ERROR: execv failed: " << strerror(errno) << "\n";
        _exit(1);
    }

    // --- Parent process: set up tracking and start all monitors --------------
    log("PROCESS", "Launched: " + exePath + " PID=" + std::to_string(pid));
    { std::lock_guard<std::mutex> lk(g_pidMutex); g_trackedPIDs.insert(pid); }
    g_knownProcesses[pid] = std::filesystem::path(exePath).filename().string();

    std::thread tP(monitorProcesses),
                tT(monitorThreads),
                tM(monitorModules),
                tN(monitorNetwork),
                tF(monitorOpenFiles),
                tFS(monitorFileSystem, watchDir),
                tW(waitForTarget, pid);

    tP.join(); tT.join(); tM.join(); tN.join(); tF.join(); tFS.join(); tW.join();
    return 0;
}

#endif // PLATFORM_LINUX

// ============================================================================
//  main — platform-agnostic entry point
//  Detects the OS at compile time, collects user input, opens the log file,
//  then delegates execution to platformRun().
// ============================================================================
int main() {
#ifdef PLATFORM_WINDOWS
    const char* OS_NAME   = "Windows";
    const char* WATCH_DEF = "C:\\Users";
    const char* NOTE      = "Run as Administrator for full access";
#else
    const char* OS_NAME   = "Linux";
    const char* WATCH_DEF = "/home";
    const char* NOTE      = "Run as root for full /proc access";
#endif

    // Print startup banner with detected OS
    std::cout << "╔══════════════════════════════════════════════════════╗\n"
              << "║       ProcessMonitor v2.0  —  Cross-Platform        ║\n"
              << "║  Detected OS : " << OS_NAME
              << std::string(38 - std::string(OS_NAME).size(), ' ') << "║\n"
              << "║  " << NOTE
              << std::string(52 - 2 - std::string(NOTE).size(), ' ') << "║\n"
              << "╚══════════════════════════════════════════════════════╝\n\n";

    // Collect the path to the executable to monitor
    std::string exePath;
    std::cout << "Path to executable: ";
    std::getline(std::cin, exePath);

    // Strip surrounding quotes (common when pasting paths from Explorer)
    if (!exePath.empty() && exePath.front() == '"') {
        exePath = exePath.substr(1);
        if (!exePath.empty() && exePath.back() == '"') exePath.pop_back();
    }
    if (!std::filesystem::exists(exePath)) {
        std::cerr << "ERROR: File not found: " << exePath << "\n";
        return 1;
    }

    // Optional command-line arguments to pass to the target
    std::string args;
    std::cout << "Arguments (blank = none): ";
    std::getline(std::cin, args);

    // Path for the output log file
    std::string logPath;
    std::cout << "Log file (blank = monitor_log.txt): ";
    std::getline(std::cin, logPath);
    if (logPath.empty()) logPath = "monitor_log.txt";

    // Store the absolute path so the noise filter can suppress self-writes
    g_logPath = std::filesystem::absolute(logPath).string();
    g_logFile.open(logPath, std::ios::out | std::ios::trunc);
    if (!g_logFile.is_open())
        std::cerr << "WARNING: Cannot open log file " << logPath << "\n";

    // Directory to watch for file-system changes
    std::string watchDir;
    std::cout << "Directory to watch (blank = " << WATCH_DEF << "): ";
    std::getline(std::cin, watchDir);
    if (watchDir.empty()) watchDir = WATCH_DEF;

    // Log the startup configuration
    log("INIT", std::string("OS Platform : ") + OS_NAME);
    log("INIT", "Target      : " + exePath);
    log("INIT", "Log file    : " + logPath);
    log("INIT", "Watch dir   : " + watchDir);

    // Hand off to the platform-specific implementation
    int ret = platformRun(exePath, args, watchDir);

    log("INIT", "Monitoring complete. Log saved to: " + logPath);
    if (g_logFile.is_open()) g_logFile.close();

#ifdef PLATFORM_WINDOWS
    // Keep the console window open after the run finishes on Windows
    std::cout << "\nPress Enter to exit...\n";
    std::cin.get();
#endif
    return ret;
}