#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <csignal>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <dirent.h>

// ─── Helpers ─────────────────────────────────────────────────────────────────
void banner(const std::string& msg) {
    std::cout << "\n[TEST] ====== " << msg << " ======\n";
    std::cout.flush();
}

// Run a shell command as child process, wait for it
void runCmd(const std::string& label, const std::string& cmd) {
    std::cout << "  -> " << label << "\n";
    std::cout.flush();
    pid_t pid = fork();
    if (pid == 0) {
        // Redirect stdout/stderr to /dev/null to keep output clean
        int devnull = open("/dev/null", O_WRONLY);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        close(devnull);
        execl("/bin/sh", "sh", "-c", cmd.c_str(), nullptr);
        _exit(1);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        std::cout << "     done (exit=" << WEXITSTATUS(status) << ")\n";
        std::cout.flush();
    }
}

// ─── 1. Child processes ───────────────────────────────────────────────────────
void spawnProcesses() {
    banner("Spawning child processes");

    struct Cmd { std::string label, cmd; };
    std::vector<Cmd> cmds = {
        {"ping google.com x3",      "ping -c 3 google.com"},
        {"ping 8.8.8.8 x3",         "ping -c 3 8.8.8.8"},
        {"ping 1.1.1.1 x2",         "ping -c 2 1.1.1.1"},
        {"nslookup github.com",      "nslookup github.com"},
        {"dig google.com",           "dig +short google.com"},
        {"curl http example.com",    "curl -s --max-time 5 http://example.com -o /dev/null"},
        {"curl https httpbin.org",   "curl -s --max-time 5 https://httpbin.org/get -o /tmp/testmonitor_response.json"},
        {"wget google.com",          "wget -q --timeout=5 -O /tmp/testmonitor_wget.html http://google.com"},
        {"ps snapshot",              "ps aux > /tmp/testmonitor_ps.txt"},
        {"netstat snapshot",         "ss -tulnp > /tmp/testmonitor_netstat.txt"},
        {"ls /etc",                  "ls -la /etc > /tmp/testmonitor_etc.txt"},
        {"find /tmp",                "find /tmp -maxdepth 2 -ls > /tmp/testmonitor_find.txt 2>/dev/null"},
        {"uname info",               "uname -a > /tmp/testmonitor_uname.txt"},
        {"whoami",                   "whoami > /tmp/testmonitor_whoami.txt"},
        {"id",                       "id > /tmp/testmonitor_id.txt"},
        {"cat /etc/passwd head",     "head -5 /etc/passwd > /tmp/testmonitor_passwd_head.txt"},
        {"env dump",                 "env > /tmp/testmonitor_env.txt"},
    };

    for (auto& c : cmds) {
        runCmd(c.label, c.cmd);
        usleep(200000); // 200ms between commands
    }
}

// ─── 2. Raw TCP connections ───────────────────────────────────────────────────
bool tcpConnect(const std::string& host, int port, const std::string& httpRequest = "") {
    addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    std::string portStr = std::to_string(port);
    if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) != 0 || !res)
        return false;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { freeaddrinfo(res); return false; }

    // Timeout
    timeval tv{ .tv_sec = 5, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    bool ok = (connect(fd, res->ai_addr, res->ai_addrlen) == 0);
    if (ok) {
        std::cout << "  -> Connected to " << host << ":" << port << "\n";
        if (!httpRequest.empty()) {
            send(fd, httpRequest.c_str(), httpRequest.size(), 0);
            char buf[512] = {};
            recv(fd, buf, sizeof(buf)-1, 0);
            std::string resp(buf);
            auto nl = resp.find('\n');
            std::cout << "     <- " << (nl != std::string::npos ? resp.substr(0,nl) : resp) << "\n";
        }
    } else {
        std::cout << "  -> Could not connect to " << host << ":" << port
                  << " (" << strerror(errno) << ")\n";
    }
    close(fd);
    freeaddrinfo(res);
    return ok;
    std::cout.flush();
}

void networkActivity() {
    banner("Raw TCP connections");

    struct Target { std::string host; int port; std::string req; };
    std::vector<Target> targets = {
        {"example.com",   80,  "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"},
        {"google.com",    80,  "GET / HTTP/1.0\r\nHost: google.com\r\n\r\n"},
        {"github.com",    443, ""},   // TLS — just check TCP handshake
        {"8.8.8.8",       53,  ""},   // DNS port
        {"1.1.1.1",       80,  "GET / HTTP/1.0\r\nHost: 1.1.1.1\r\n\r\n"},
        {"httpbin.org",   80,  "GET /ip HTTP/1.0\r\nHost: httpbin.org\r\n\r\n"},
        {"neverssl.com",  80,  "GET / HTTP/1.0\r\nHost: neverssl.com\r\n\r\n"},
    };

    std::vector<std::thread> threads;
    for (auto& t : targets)
        threads.emplace_back(tcpConnect, t.host, t.port, t.req);
    for (auto& th : threads) th.join();
}

// ─── 3. File system activity ──────────────────────────────────────────────────
void fileSystemActivity() {
    banner("File system activity");

    const std::string base = "/tmp/testmonitor/";

    // Create directory tree
    system(("mkdir -p " + base + "subdir1").c_str());
    system(("mkdir -p " + base + "subdir2/deep/deeper").c_str());
    system(("mkdir -p " + base + "logs").c_str());
    std::cout << "  -> Created directory tree under " << base << "\n";

    // Create text files
    for (int i = 1; i <= 8; ++i) {
        std::string path = base + "file_" + std::to_string(i) + ".txt";
        std::ofstream f(path);
        f << "TestMonitor block " << i << "\n";
        f << std::string(512, 'A' + (i % 26)) << "\n";
        std::cout << "  -> Created " << path << "\n";
    }
    usleep(300000);

    // Modify files
    for (int i = 1; i <= 8; ++i) {
        std::ofstream f(base + "file_" + std::to_string(i) + ".txt", std::ios::app);
        f << "[modified tick=" << i << "]\n";
    }
    std::cout << "  -> Modified 8 files\n";
    usleep(300000);

    // Write binary file
    std::ofstream bin(base + "payload.bin", std::ios::binary);
    std::vector<char> data(2048, '\xDE');
    bin.write(data.data(), data.size());
    std::cout << "  -> Created binary file payload.bin (2KB)\n";

    // Create symlink
    ::symlink((base + "file_1.txt").c_str(), (base + "link_to_file1.txt").c_str());
    std::cout << "  -> Created symlink link_to_file1.txt\n";

    // Write log files
    for (int i = 0; i < 3; ++i) {
        std::ofstream log(base + "logs/app_" + std::to_string(i) + ".log");
        log << "[INFO]  App started\n[WARN]  Something happened\n[ERROR] Oh no\n";
    }

    // Delete some
    for (int i = 1; i <= 4; ++i)
        ::unlink((base + "file_" + std::to_string(i) + ".txt").c_str());
    std::cout << "  -> Deleted 4 files\n";

    // Read system files (triggers FILE events in monitor)
    std::cout << "  -> Reading system files:\n";
    for (auto& sf : {"/etc/passwd", "/etc/hostname", "/proc/cpuinfo",
                     "/proc/meminfo", "/proc/version", "/etc/os-release"}) {
        std::ifstream f(sf);
        if (f) {
            std::string line; std::getline(f, line);
            std::cout << "     " << sf << " -> \"" << line.substr(0, 60) << "\"\n";
        }
    }
}

// ─── 4. Thread activity ───────────────────────────────────────────────────────
void workerThread(int id, int sleepMs) {
    std::cout << "  -> Thread " << id << " TID=" << gettid() << " started\n";
    std::cout.flush();
    // Do some CPU work
    volatile double x = 0;
    for (int i = 0; i < 500000; ++i) x += i * 0.001;
    std::this_thread::sleep_for(std::chrono::milliseconds(sleepMs));
    std::cout << "  -> Thread " << id << " done\n";
    std::cout.flush();
}

void threadActivity() {
    banner("Creating worker threads");
    std::vector<std::thread> pool;
    for (int i = 1; i <= 8; ++i)
        pool.emplace_back(workerThread, i, 100 * i);
    for (auto& t : pool) t.join();
}

// ─── 5. Dynamic library loading ───────────────────────────────────────────────
void dlopenActivity() {
    banner("dlopen — loading shared libraries");
    std::vector<std::string> libs = {
        "libm.so.6",
        "libz.so.1",
        "libdl.so.2",
        "libpthread.so.0",
        "libc.so.6",
        "libstdc++.so.6",
    };
    for (auto& lib : libs) {
        void* h = dlopen(lib.c_str(), RTLD_LAZY | RTLD_LOCAL);
        if (h) {
            std::cout << "  -> Loaded " << lib << "\n";
            usleep(150000);
            dlclose(h);
        } else {
            std::cout << "  -> Skip " << lib << " (" << dlerror() << ")\n";
        }
        std::cout.flush();
    }
}

// ─── 6. /proc self inspection ────────────────────────────────────────────────
void procSelfActivity() {
    banner("Reading /proc/self");
    for (auto& f : {"/proc/self/maps", "/proc/self/status",
                    "/proc/self/cmdline", "/proc/self/environ"}) {
        std::ifstream in(f);
        if (!in) continue;
        std::string line; std::getline(in, line);
        std::cout << "  " << f << " -> [" << line.substr(0, 80) << "]\n";
    }
    std::cout.flush();
}

// ─── Main ─────────────────────────────────────────────────────────────────────
int main() {
    std::cout << "╔══════════════════════════════════════════════╗\n";
    std::cout << "║  TestTarget v1.0  [Linux]                    ║\n";
    std::cout << "║  Generates activity for ProcessMonitor       ║\n";
    std::cout << "╚══════════════════════════════════════════════╝\n";
    std::cout << "PID = " << getpid() << "  UID=" << getuid() << "\n\n";
    std::cout.flush();

    threadActivity();
    dlopenActivity();
    procSelfActivity();
    fileSystemActivity();
    networkActivity();
    spawnProcesses();

    banner("All done — process exiting normally");
    sleep(1);
    return 0;
}
