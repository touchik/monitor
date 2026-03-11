#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <fstream>
#include <chrono>
#pragma comment(lib, "ws2_32.lib")

// ─── Helpers ─────────────────────────────────────────────────────────────────
void banner(const std::string& msg) {
    std::cout << "\n[TEST] ====== " << msg << " ======\n";
}

// ─── 1. Spawn child processes ─────────────────────────────────────────────────
void spawnProcesses() {
    banner("Spawning child processes");

    struct Cmd { std::string label, cmd; };
    std::vector<Cmd> cmds = {
        {"ping google.com",      "ping -n 2 google.com"},
        {"ping 8.8.8.8",         "ping -n 2 8.8.8.8"},
        {"ping cloudflare",      "ping -n 2 1.1.1.1"},
        {"nslookup github.com",  "nslookup github.com"},
        {"ipconfig",             "ipconfig /all"},
        {"tasklist snapshot",    "tasklist /fo csv > %TEMP%\\tasklist_snapshot.csv"},
    };

    for (auto& c : cmds) {
        std::cout << "  -> " << c.label << "\n";
        STARTUPINFOA si{}; si.cb = sizeof(si);
        // Hide console windows of children
        si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi{};
        std::string fullCmd = "cmd.exe /C " + c.cmd;
        if (CreateProcessA(nullptr, const_cast<char*>(fullCmd.c_str()),
                           nullptr, nullptr, FALSE, CREATE_NEW_CONSOLE,
                           nullptr, nullptr, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, 8000);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        Sleep(300);
    }
}

// ─── 2. Raw TCP connections ───────────────────────────────────────────────────
void tcpConnect(const std::string& host, int port) {
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return;

    addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    std::string portStr = std::to_string(port);
    if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) == 0 && res) {
        // Set non-blocking with timeout
        DWORD timeout = 4000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

        if (connect(s, res->ai_addr, (int)res->ai_addrlen) == 0) {
            std::cout << "  -> Connected to " << host << ":" << port << "\n";
            // Send minimal HTTP GET
            if (port == 80) {
                std::string req = "GET / HTTP/1.0\r\nHost: " + host + "\r\n\r\n";
                send(s, req.c_str(), (int)req.size(), 0);
                char buf[512] = {};
                recv(s, buf, sizeof(buf)-1, 0);
                std::cout << "     Response: " << std::string(buf, 64) << "...\n";
            }
        } else {
            std::cout << "  -> Failed to connect to " << host << ":" << port << "\n";
        }
        freeaddrinfo(res);
    }
    closesocket(s);
    WSACleanup();
}

void networkActivity() {
    banner("Network connections (TCP)");
    struct Target { std::string host; int port; };
    std::vector<Target> targets = {
        {"example.com",    80},
        {"google.com",     80},
        {"github.com",     443},
        {"8.8.8.8",        53},
        {"1.1.1.1",        80},
    };
    std::vector<std::thread> threads;
    for (auto& t : targets)
        threads.emplace_back(tcpConnect, t.host, t.port);
    for (auto& th : threads) th.join();
}

// ─── 3. File system activity ──────────────────────────────────────────────────
void fileSystemActivity() {
    banner("File system activity");
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    std::string base = std::string(tempPath) + "TestMonitor\\";

    // Create directory tree
    CreateDirectoryA(base.c_str(), nullptr);
    CreateDirectoryA((base + "subdir1").c_str(), nullptr);
    CreateDirectoryA((base + "subdir2\\deep").c_str(), nullptr);
    std::cout << "  -> Created dirs under " << base << "\n";

    // Create and write files
    for (int i = 1; i <= 5; ++i) {
        std::string path = base + "file_" + std::to_string(i) + ".txt";
        std::ofstream f(path);
        f << "TestMonitor data block " << i << "\n";
        f << std::string(256, 'A' + (i % 26)) << "\n";
        std::cout << "  -> Created " << path << "\n";
    }
    Sleep(500);

    // Modify files
    for (int i = 1; i <= 5; ++i) {
        std::string path = base + "file_" + std::to_string(i) + ".txt";
        std::ofstream f(path, std::ios::app);
        f << "  [MODIFIED at tick " << i << "]\n";
    }
    std::cout << "  -> Modified 5 files\n";
    Sleep(500);

    // Binary file
    std::ofstream bin(base + "data.bin", std::ios::binary);
    std::vector<char> data(1024, 0x42);
    bin.write(data.data(), data.size());
    std::cout << "  -> Created binary file data.bin\n";

    // Delete some
    for (int i = 1; i <= 3; ++i)
        DeleteFileA((base + "file_" + std::to_string(i) + ".txt").c_str());
    std::cout << "  -> Deleted 3 files\n";
}

// ─── 4. Registry activity ─────────────────────────────────────────────────────
void registryActivity() {
    banner("Registry writes");
    HKEY hk;
    const char* keyPath = "Software\\TestMonitor";
    if (RegCreateKeyExA(HKEY_CURRENT_USER, keyPath, 0, nullptr,
                        REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS,
                        nullptr, &hk, nullptr) == ERROR_SUCCESS) {
        const char* val1 = "TestValue_String";
        RegSetValueExA(hk, "AppName",   0, REG_SZ,
                       (BYTE*)val1, (DWORD)strlen(val1)+1);
        DWORD dword = 42;
        RegSetValueExA(hk, "Counter",   0, REG_DWORD, (BYTE*)&dword, sizeof(dword));
        const char* val2 = "C:\\Windows\\System32\\cmd.exe";
        RegSetValueExA(hk, "FakePath",  0, REG_SZ,
                       (BYTE*)val2, (DWORD)strlen(val2)+1);
        std::cout << "  -> Written 3 values to HKCU\\" << keyPath << "\n";
        RegCloseKey(hk);
    }
    Sleep(500);
    // Also touch Run key (common malware behaviour for monitor to detect)
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
                      "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                      0, KEY_READ, &hk) == ERROR_SUCCESS) {
        std::cout << "  -> Opened CurrentVersion\\Run (read-only peek)\n";
        RegCloseKey(hk);
    }
}

// ─── 5. Threads ───────────────────────────────────────────────────────────────
void threadWork(int id) {
    std::cout << "  -> Worker thread " << id << " (TID=" << GetCurrentThreadId() << ")\n";
    Sleep(300 * id);
}

void threadActivity() {
    banner("Creating worker threads");
    std::vector<std::thread> pool;
    for (int i = 1; i <= 6; ++i)
        pool.emplace_back(threadWork, i);
    for (auto& t : pool) t.join();
}

// ─── 6. Dynamic DLL loading ───────────────────────────────────────────────────
void dllActivity() {
    banner("Dynamic DLL loading");
    std::vector<std::string> dlls = {
        "shell32.dll", "wininet.dll", "urlmon.dll",
        "crypt32.dll", "advapi32.dll", "userenv.dll"
    };
    for (auto& d : dlls) {
        HMODULE h = LoadLibraryA(d.c_str());
        if (h) {
            char path[MAX_PATH] = {};
            GetModuleFileNameA(h, path, MAX_PATH);
            std::cout << "  -> Loaded " << d << " -> " << path << "\n";
            Sleep(200);
            FreeLibrary(h);
        }
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────────
int main() {
    std::cout << "╔══════════════════════════════════════════════╗\n";
    std::cout << "║  TestTarget v1.0  [Windows]                  ║\n";
    std::cout << "║  Generates activity for ProcessMonitor       ║\n";
    std::cout << "╚══════════════════════════════════════════════╝\n";
    std::cout << "PID = " << GetCurrentProcessId() << "\n";

    threadActivity();
    dllActivity();
    fileSystemActivity();
    registryActivity();
    networkActivity();
    spawnProcesses();

    banner("All done — process exiting normally");
    Sleep(1000);
    return 0;
}
