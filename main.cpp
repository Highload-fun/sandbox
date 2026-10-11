#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <iostream>
#include <fstream>
#include <array>
#include <vector>
#include <string>
#include <regex>
#include <chrono>
#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include <filesystem>
#include <unistd.h>
#include <poll.h>
#include <sched.h>          // unshare(2), CLONE_NEWNS
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <grp.h>            // setgroups
#include <mntent.h>
#include <linux/sched.h>    // struct clone_args, CLONE_INTO_CGROUP
#include <linux/filter.h>   // sock_filter, sock_fprog, BPF_*
#include <linux/seccomp.h>  // SECCOMP_*, struct seccomp_data
#include <linux/audit.h>    // AUDIT_ARCH_X86_64
#include <libcgroup.h>

// CLONE_INTO_CGROUP not always exposed even by current linux/sched.h
#ifndef CLONE_INTO_CGROUP
#define CLONE_INTO_CGROUP 0x200000000ULL
#endif

#ifndef __NR_clone3
#define __NR_clone3 435
#endif


#ifndef SANDBOX_VERSION
#error "SANDBOX_VERSION comes from CMakeLists.txt"
#endif

#define STACK_SIZE (1024 * 1024)
#define NOBODY_UID 65534
// --uid takes only IDs of this range
#define UID_RANGE_MIN 2000000000ULL
#define UID_RANGE_MAX 2000999999ULL
#define DEFAULT_STOP_GRACE 30
#define MAX_STOP_GRACE 3600

static_assert(UID_RANGE_MIN > NOBODY_UID && UID_RANGE_MAX < UINT32_MAX, "--uid range");

namespace fs = std::filesystem;

struct exe_opts {
    const fs::path &bin_path;
    const std::vector<char *> &args;
    const std::vector<char *> &env;
    const fs::path &exec_dir;
    const uid_t uid;
    const std::string &tmp_mount_opts;
};

static volatile sig_atomic_t got_signal = 0;
// Seconds between SIGTERM and SIGKILL on a stop; 0 makes SIGTERM/SIGINT to the tool kill the child at once
static volatile sig_atomic_t stop_grace = 0;
// Write end of the pipe that wakes the wait for the child
static volatile sig_atomic_t wake_fd = -1;
static pid_t pid;
static fs::path sandbox = {};
static cgroup *sandbox_cgroup = nullptr;
static uid_t caller_uid;
static gid_t caller_gid;

void fatal(const std::string &message) {
    std::cerr << message << std::endl;
    exit(EXIT_FAILURE);
}

void fatal_errno(const std::string &message) {
    std::cerr << message << ": " << strerror(errno) << std::endl;
    exit(EXIT_FAILURE);
}

void fatal_cgroup(const std::string &message) {
    std::cerr << message << ": " << cgroup_strerror(cgroup_get_last_errno()) << std::endl;
    exit(EXIT_FAILURE);
}

// Execute a command without shell interpolation (fix: command injection via popen)
std::string exec_command(const char *path, std::vector<const char *> args) {
    int pipefd[2];
    if (pipe(pipefd))
        fatal_errno("cannot create pipe");

    pid_t child = fork();
    if (child == -1)
        fatal_errno("cannot fork");

    if (child == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execv(path, const_cast<char *const *>(args.data()));
        _exit(EXIT_FAILURE);
    }

    close(pipefd[1]);

    std::string result;
    char buf[256];
    ssize_t n;
    while ((n = read(pipefd[0], buf, sizeof(buf))) > 0)
        result.append(buf, n);
    close(pipefd[0]);

    waitpid(child, nullptr, 0);
    return result;
}

// Validate sandbox path is safe (fix: unvalidated sandbox path)
void validate_sandbox_path(const fs::path &path) {
    if (!path.is_absolute())
        fatal("sandbox path must be absolute");

    fs::path normalized = path.lexically_normal();
    for (const auto &component : normalized) {
        if (component == "..")
            fatal("sandbox path must not contain '..'");
    }

    static const std::vector<std::string> forbidden = {
        "/", "/bin", "/sbin", "/usr", "/etc", "/var", "/home", "/root",
        "/boot", "/lib", "/lib64", "/dev", "/proc", "/sys", "/run", "/tmp"
    };
    std::string norm_str = normalized.string();
    if (norm_str.size() > 1 && norm_str.back() == '/')
        norm_str.pop_back();
    for (const auto &f : forbidden) {
        if (norm_str == f)
            fatal("sandbox path must not be a critical system directory: " + f);
    }
}

// Validate destination path doesn't escape sandbox via .. traversal (fix: path traversal)
void validate_path_in_sandbox(const fs::path &dst, const std::string &desc) {
    auto normalized = dst.lexically_normal();
    for (const auto &component : normalized) {
        if (component == "..")
            fatal(desc + " escapes sandbox: " + dst.string());
    }
}

// Validate cgroup name has no path traversal (fix: cgroup name path traversal)
void validate_cgroup_name(const std::string &name) {
    if (name.empty())
        return;
    if (name.find('/') != std::string::npos || name.find("..") != std::string::npos)
        fatal("cgroup name must not contain '/' or '..'");
    if (name[0] == '.')
        fatal("cgroup name must not start with '.'");
}

// Parses a command-line number: decimal digits only, no sign or spaces
static bool parse_number(const std::string &s, uint64_t &out) {
    if (s.empty() || s.size() > 19 || s.find_first_not_of("0123456789") != std::string::npos)
        return false;
    out = std::stoull(s);
    return true;
}

static std::vector<std::string> split_fields(const std::string &line) {
    std::vector<std::string> fields;
    size_t start = 0;
    for (;;) {
        auto end = line.find(':', start);
        fields.push_back(line.substr(start, end - start));
        if (end == std::string::npos)
            return fields;
        start = end + 1;
    }
}

// Reads a system file that --uid depends on; a missing file has no lines when missing_ok
static std::vector<std::string> read_lines(const char *path, bool missing_ok) {
    std::vector<std::string> lines;
    struct stat st;
    if (missing_ok && stat(path, &st) && errno == ENOENT)
        return lines;

    std::ifstream in(path);
    if (!in.is_open())
        fatal(std::string("--uid refused: cannot read ") + path);
    for (std::string line; std::getline(in, line);)
        lines.push_back(line);
    if (in.bad())
        fatal(std::string("--uid refused: cannot read ") + path);
    return lines;
}

// Reports whether a passwd or group line has id in a field at one of indexes. A field is read as glibc
// reads it (strtoul, clamped to 32 bits), so a line that glibc skips matches nothing.
static bool has_id_entry(const char *path, std::initializer_list<size_t> indexes, uint64_t id) {
    for (const auto &line: read_lines(path, false)) {
        auto fields = split_fields(line);
        for (auto index: indexes) {
            if (index >= fields.size() || fields[index].empty())
                continue;
            const char *field = fields[index].c_str();
            char *end;
            unsigned long long value = strtoull(field, &end, 10);
            if (end != field && *end == '\0' && std::min<unsigned long long>(value, UINT32_MAX) == id)
                return true;
        }
    }
    return false;
}

// Reports whether id lies in a range of /etc/subuid or /etc/subgid; a line it cannot parse refuses --uid
static bool in_subid_range(const char *path, uint64_t id) {
    for (const auto &line: read_lines(path, true)) {
        if (line.empty() || line[0] == '#')
            continue;
        auto fields = split_fields(line);
        uint64_t start, count;
        if (fields.size() != 3 || !parse_number(fields[1], start) || !parse_number(fields[2], count))
            fatal(std::string("--uid refused: cannot parse ") + path);
        if (id >= start && id - start < count)
            return true;
    }
    return false;
}

// Checks --uid: a caller other than root, and an ID of the reserved range that is not the caller's and
// that no account, group or subordinate range uses. Every refusal is a fixed message and exit 1.
uid_t check_uid(const char *value) {
    if (caller_uid == 0)
        fatal("--uid is refused for a root caller");

    uint64_t id;
    if (!parse_number(value, id) || id < UID_RANGE_MIN || id > UID_RANGE_MAX)
        fatal("--uid must be in the range " + std::to_string(UID_RANGE_MIN) + "-" + std::to_string(UID_RANGE_MAX));

    if (id == caller_uid || id == caller_gid)
        fatal("--uid must not be the caller's UID or GID");

    if (has_id_entry("/etc/passwd", {2, 3}, id))
        fatal("--uid has an /etc/passwd entry");

    if (has_id_entry("/etc/group", {2}, id))
        fatal("--uid has an /etc/group entry");

    if (in_subid_range("/etc/subuid", id) || in_subid_range("/etc/subgid", id))
        fatal("--uid lies in an /etc/subuid or /etc/subgid range");

    return static_cast<uid_t>(id);
}

// Returns --cpu_max, "<quota_us> <period_us>", as cpu.max reads back; the kernel checks the bounds
std::string parse_cpu_max(const std::string &value) {
    auto space = value.find(' ');
    uint64_t quota, period;
    if (space == std::string::npos || !parse_number(value.substr(0, space), quota) ||
        !parse_number(value.substr(space + 1), period))
        fatal("--cpu_max must be \"<quota_us> <period_us>\"");
    return std::to_string(quota) + " " + std::to_string(period);
}

// Opens the stop FIFO with the caller's rights and accepts only a FIFO that the caller owns and that
// neither its group nor others may write to. The checks are on the open fd, never the path.
int open_stop_fifo(const char *path) {
    if (setegid(caller_gid))
        fatal_errno("cannot drop privileges for --stop_fifo");
    if (seteuid(caller_uid))
        fatal_errno("cannot drop privileges for --stop_fifo");

    int fd = open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    int open_errno = errno;

    if (seteuid(0))
        fatal_errno("cannot restore privileges");
    if (setegid(0))
        fatal_errno("cannot restore privileges");

    if (fd < 0) {
        errno = open_errno;
        fatal_errno("cannot open --stop_fifo");
    }

    struct stat st;
    if (fstat(fd, &st))
        fatal_errno("cannot stat --stop_fifo");
    if (!S_ISFIFO(st.st_mode))
        fatal("--stop_fifo is not a FIFO");
    if (st.st_uid != caller_uid)
        fatal("--stop_fifo is not owned by the caller");
    if (st.st_mode & (S_IWGRP | S_IWOTH))
        fatal("--stop_fifo is writable by its group or others");

    // Hold a write end of the same FIFO, so a writer that closes is never seen as EOF or POLLHUP. It stays
    // open until the tool exits.
    auto same_fifo = "/proc/self/fd/" + std::to_string(fd);
    if (open(same_fifo.c_str(), O_WRONLY | O_NONBLOCK | O_CLOEXEC) < 0)
        fatal_errno("cannot hold --stop_fifo open");

    return fd;
}

void path_pids(std::vector<int> &res) {
    if (!fs::exists(sandbox)) {
        return;
    }

    std::string sandbox_str = sandbox.string();
    std::vector<const char *> args = {
        "/usr/bin/lsof", "-n", "-w", "-Fp", "+d", sandbox_str.c_str(), nullptr
    };
    std::string out_buf = exec_command("/usr/bin/lsof", args);

    static const std::regex re(R"(p([0-9]+))");

    for (std::sregex_iterator it(out_buf.begin(), out_buf.end(), re), end;
         it != end; ++it) {
        const std::smatch &m = *it;
        if (m.size() < 2) {
            continue;
        }

        int pid = std::stoi(m.str(1));
        res.push_back(pid);
    }
}

void kill_all_sandbox_processes() {
    // Kill all processes that use the path
    std::vector<int> pids;
    path_pids(pids);
    for (auto p: pids) {
        std::cerr << "Kill pid " << p << std::endl;
        kill(p, SIGKILL);
    }

    for (auto p: pids)
        waitpid(p, nullptr, 0);
}

// Match mount dir against sandbox path with a component-boundary check, so
// sandbox="/tmp/a" does not spuriously match a mount at "/tmp/abc/...".
static bool mount_is_under_sandbox(const char *mnt_dir) {
    const std::string &sb = sandbox.native();
    std::string m(mnt_dir);
    if (m.size() < sb.size())
        return false;
    if (m.compare(0, sb.size(), sb) != 0)
        return false;
    return m.size() == sb.size() || m[sb.size()] == '/';
}

void remove_sandbox_path() {
    if (!fs::exists(sandbox)) {
        return;
    }

    // Detach every mount that lives under the sandbox path. MNT_DETACH
    // (lazy unmount) removes the mount from the filesystem tree
    // immediately and lets the kernel finish cleanup once references drop.
    // The previous MNT_FORCE+1000-retry loop could hold a worker for ~10s
    // per busy mount (e.g. C# bind-mounts of /lib, /usr/lib), wedging the
    // checker's worker pool when several runs cleaned up back-to-back.
    auto mounts_f = setmntent("/proc/mounts", "r");
    if (!mounts_f)
        fatal_errno("cannot open /proc/mounts");
    while (auto mounts = getmntent(mounts_f)) {
        if (!mount_is_under_sandbox(mounts->mnt_dir))
            continue;

        if (umount2(mounts->mnt_dir, MNT_DETACH))
            fatal_errno(std::string("cannot umount ") + mounts->mnt_dir);
    }
    endmntent(mounts_f);

    // Defence in depth: re-scan /proc/mounts and refuse to call
    // fs::remove_all if anything is still mounted under sandbox. MNT_DETACH
    // should make this impossible, but if a mount ever survived we must
    // NOT walk into it - that path once deleted host /usr/lib via orphaned
    // bind mounts.
    mounts_f = setmntent("/proc/mounts", "r");
    if (!mounts_f)
        fatal_errno("cannot open /proc/mounts");
    while (auto mounts = getmntent(mounts_f)) {
        if (mount_is_under_sandbox(mounts->mnt_dir)) {
            endmntent(mounts_f);
            fatal(std::string("refusing to remove sandbox - live mount under it: ") + mounts->mnt_dir);
        }
    }
    endmntent(mounts_f);

    std::error_code ec;
    fs::remove_all(sandbox, ec);
    if (ec)
        fatal("cannot remove sandbox: " + ec.message());
}

void clean() {
    // Guard against re-entry: the atexit handler calls clean(), and any
    // fatal_* inside remove_sandbox_path() would exit() and trigger
    // atexit -> clean() -> ... again. One attempt is enough.
    static bool entered = false;
    if (entered)
        return;
    entered = true;

    // Remove cgroups
    if (sandbox_cgroup != nullptr) {
        cgroup_delete_cgroup(sandbox_cgroup, 0);
        cgroup_free(&sandbox_cgroup);
    }

    remove_sandbox_path();
}

void init_dirs() {
    kill_all_sandbox_processes();
    remove_sandbox_path();

    std::array<std::string, 5> dirs = {"dev", "etc", "proc", "root", "tmp"};

    std::error_code ec;
    for (auto &dir: dirs) {
        fs::create_directories(sandbox / dir, ec);
        if (ec)
            fatal("cannot create system dir: " + ec.message());
    }

    if (chmod((sandbox / "tmp").c_str(), 0777))
        fatal_errno("cannot set mode 777 for /tmp");
}

// Create minimal device nodes instead of full devtmpfs (fix: devtmpfs exposes all devices)
void create_dev_nodes() {
    struct dev_node {
        const char *name;
        mode_t mode;
        unsigned int major;
        unsigned int minor;
    };

    static const dev_node devices[] = {
        {"null",    S_IFCHR | 0666, 1, 3},
        {"zero",    S_IFCHR | 0666, 1, 5},
        {"full",    S_IFCHR | 0666, 1, 7},
        {"random",  S_IFCHR | 0666, 1, 8},
        {"urandom", S_IFCHR | 0666, 1, 9},
    };

    mode_t old_umask = umask(0);
    for (const auto &d : devices) {
        auto path = sandbox / "dev" / d.name;
        if (mknod(path.c_str(), d.mode, makedev(d.major, d.minor)))
            if (errno != EEXIST)
                fatal_errno(std::string("cannot create device ") + d.name);
    }
    umask(old_umask);
}

void libs_deps(fs::path &bin, std::vector<std::string> &res) {
    std::string bin_str = bin.string();
    std::vector<const char *> args = {
        "/usr/bin/ldd", bin_str.c_str(), nullptr
    };
    std::string out_buf = exec_command("/usr/bin/ldd", args);

    static const std::regex re(R"((?:.+?\s+=>)?\s+(/.+?)\s+\(.+?\))");

    for (std::sregex_iterator it(out_buf.begin(), out_buf.end(), re), end;
         it != end; ++it) {
        const std::smatch &m = *it;
        if (m.size() < 2) {
            continue;
        }
        res.push_back(m.str(1));
    }
}

// Use realpath for atomic symlink resolution (fix: TOCTOU race)
void create_hardlink(const fs::path &src, const fs::path &dst) {
    std::error_code ec;

    char *resolved = realpath(src.c_str(), nullptr);
    if (!resolved)
        fatal_errno("cannot resolve path: " + src.string());
    fs::path real_path(resolved);
    free(resolved);

    fs::create_directories(dst.parent_path(), ec);
    if (ec)
        fatal("cannot create directory for hard link: " + ec.message());

    fs::create_hard_link(real_path, dst, ec);
    if (ec) {
        if (ec == std::errc::file_exists)
            return;

        if (ec == std::errc::cross_device_link) {
            ec.clear();
            fs::copy_file(real_path, dst, ec);
            if (ec)
                fatal("cannot copy file " + real_path.string() + "->" + dst.string() + ": " + ec.message());
            return;
        }

        fatal("cannot create hardlink " + real_path.string() + "->" + dst.string() + ": " + ec.message());
    }
}

void add_file(const fs::path &src, const fs::path &dst, bool with_deps) {
    validate_path_in_sandbox(dst, "add_file destination");
    auto sbox_path = sandbox / dst.relative_path();

    create_hardlink(src, sbox_path);

    if (with_deps) {
        std::vector<std::string> libs;
        libs_deps(sbox_path, libs);

        for (auto &l: libs) {
            create_hardlink(l, sandbox / fs::path(l).relative_path());
        }
    }
}

void mount_dir(const fs::path &src, const fs::path &dst) {
    validate_path_in_sandbox(dst, "mount destination");
    auto sbox_path = sandbox / dst.relative_path();

    std::error_code ec;
    fs::create_directories(sbox_path, ec);
    if (ec)
        fatal("cannot create target mount directory: " + ec.message());

    if (mount(src.c_str(), sbox_path.c_str(), "", MS_BIND, nullptr))
        if (errno != EBUSY)
            fatal_errno("cannot mount dir " + src.string());
}

cgroup *create_cgroup(const std::string &name, const std::string &cpu_set, const std::string &cpu_max,
                      uint64_t mem_limit, bool no_swap, bool oom_group) {
    if (cgroup_init())
        fatal_cgroup("cannot init cgroup");

    auto cgroup = cgroup_new_cgroup(name.c_str());

    auto cpu_ctrl = cgroup_add_controller(cgroup, "cpu");
    if (!cpu_ctrl) {
        fatal_cgroup("cannot cpu controller");
    }

    if (!cpu_max.empty() && cgroup_set_value_string(cpu_ctrl, "cpu.max", cpu_max.c_str()))
        fatal_cgroup("cannot set cpu.max");

    if (!cpu_set.empty()) {
        if (cgroup_set_value_string(cpu_ctrl, "cpuset.cpus", cpu_set.c_str()))
            fatal_cgroup("cannot set cpuset.cpus");

        if (cgroup_set_value_string(cpu_ctrl, "cpuset.mems", "0"))
            fatal_cgroup("cannot set cpuset.mems");
    }

    if (mem_limit) {
        auto mem_ctrl = cgroup_add_controller(cgroup, "memory");

        if (cgroup_set_value_uint64(mem_ctrl, "memory.max", mem_limit))
            fatal_cgroup("cannot set memory limit");

        if (no_swap && cgroup_set_value_string(mem_ctrl, "memory.swap.max", "0"))
            fatal_cgroup("cannot set memory.swap.max");

        if (oom_group && cgroup_set_value_string(mem_ctrl, "memory.oom.group", "1"))
            fatal_cgroup("cannot set memory.oom.group");
    }

    if (!cgroup_add_controller(cgroup, "io")) {
        fatal_cgroup("cannot io controller");
    }

    auto pids_ctrl = cgroup_add_controller(cgroup, "pids");
    if (!pids_ctrl) {
        fatal_cgroup("cannot add pids controller");
    }
    if (cgroup_set_value_uint64(pids_ctrl, "pids.max", 1024))
        fatal_cgroup("cannot set pids.max");

    if (cgroup_create_cgroup(cgroup, 0) != 0)
        fatal_cgroup("cannot create cgroup");

    return cgroup;
}

static void install_seccomp_filter() {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x40000000, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone3, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA)),

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_setns, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_setup, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_enter, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_register, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_add_key, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_request_key, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_keyctl, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_unshare, 0, 4),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, CLONE_NEWUSER, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, CLONE_NEWUSER, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        static_cast<unsigned short>(sizeof(filter) / sizeof(filter[0])),
        filter,
    };
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog))
        fatal_errno("cannot install seccomp filter");
}

static int _execute(void *arg) {
    auto *opts = static_cast<exe_opts *>(arg);

    // pivot_root instead of chroot (fix: chroot escape)
    // Make all mounts private to prevent propagation issues with pivot_root
    if (mount("", "/", "", MS_PRIVATE | MS_REC, nullptr))
        fatal_errno("cannot make mounts private");

    if (mount(sandbox.c_str(), sandbox.c_str(), "", MS_BIND | MS_REC, nullptr))
        fatal_errno("cannot bind mount sandbox");

    auto put_old_path = sandbox / ".put_old";
    mkdir(put_old_path.c_str(), 0700);

    if (syscall(SYS_pivot_root, sandbox.c_str(), put_old_path.c_str()))
        fatal_errno("cannot pivot_root");

    if (chdir("/"))
        fatal_errno("cannot chdir");

    if (umount2("/.put_old", MNT_DETACH))
        fatal_errno("cannot unmount old root");

    rmdir("/.put_old");

    if (mount("proc", "/proc", "proc", 0, "subset=pid,hidepid=2"))
        if (errno != EBUSY)
            fatal_errno("cannot mount /proc");

    if (!opts->tmp_mount_opts.empty() &&
        mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV, opts->tmp_mount_opts.c_str()))
        fatal_errno("cannot mount /tmp");

    if (chdir(opts->exec_dir.empty() ? "/root" : opts->exec_dir.c_str()))
        fatal_errno("cannot chdir");

    static const char sandbox_hostname[] = "sandbox";
    static const char sandbox_domain[] = "(none)";
    if (sethostname(sandbox_hostname, sizeof(sandbox_hostname) - 1))
        fatal_errno("cannot set hostname");
    if (setdomainname(sandbox_domain, sizeof(sandbox_domain) - 1))
        fatal_errno("cannot set domainname");

    if (setgroups(0, nullptr))
        fatal_errno("cannot drop supplementary groups");

    if (setgid(opts->uid))
        fatal_errno("cannot set GID");

    if (setuid(opts->uid))
        fatal_errno("cannot set UID");

    // Fail closed unless every UID and GID is the sandbox's and no supplementary group is left
    uid_t ruid, euid, suid;
    gid_t rgid, egid, sgid;
    if (getresuid(&ruid, &euid, &suid) || getresgid(&rgid, &egid, &sgid) || getgroups(0, nullptr) != 0 ||
        ruid != opts->uid || euid != opts->uid || suid != opts->uid ||
        rgid != opts->uid || egid != opts->uid || sgid != opts->uid)
        fatal("cannot verify the dropped UID and GID");

    // Prevent privilege escalation via SUID binaries (fix: missing CLONE_NEWUSER)
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        fatal_errno("cannot set no_new_privs");

    install_seccomp_filter();

    // Close leaked file descriptors (fix: FD leak into sandbox)
    syscall(SYS_close_range, 3, ~0U, 0);

    execve(opts->bin_path.c_str(), opts->args.data(), opts->env.data());
    fatal("cannot run file: " + std::string(strerror(errno)));

    return EXIT_SUCCESS;
}

void save_usage_stat(const std::string &filename, const std::string &cgroup_name) {
    // Drop privileges when writing stat file (fix: arbitrary file overwrite as root)
    if (setegid(caller_gid))
        fatal_errno("cannot drop privileges for stat file");
    if (seteuid(caller_uid))
        fatal_errno("cannot drop privileges for stat file");

    std::ofstream out(filename);

    if (seteuid(0))
        fatal_errno("cannot restore privileges");
    if (setegid(0))
        fatal_errno("cannot restore privileges");

    if (!out.is_open())
        fatal("cannot create file for usage statistic");

    std::ifstream cpu_usage_in(fs::path("/sys/fs/cgroup") / cgroup_name / "cpu.stat");
    if (cpu_usage_in.is_open()) {
        uint64_t total_user = 0;
        uint64_t total_system = 0;
        while (cpu_usage_in) {
            std::string name;
            uint64_t value;
            cpu_usage_in >> name >> value;
            if (name == "user_usec")
                total_user = value;
            else if (name == "system_usec")
                total_system = value;
        }

        out << "cpu_user\t" << total_user << "\n";
        out << "cpu_system\t" << total_system << "\n";
    }

    std::ifstream memory_usage_in(fs::path("/sys/fs/cgroup") / cgroup_name / "memory.current");
    if (memory_usage_in.is_open()) {
        uint64_t bytes = 0;
        memory_usage_in >> bytes;
        out << "memory\t" << bytes << "\n";
    }
}

// Async-signal-safe: wakes the wait for the child
void wake(int) {
    int saved_errno = errno;
    if (wake_fd >= 0) {
        [[maybe_unused]] ssize_t n = write(wake_fd, "", 1);
    }
    errno = saved_errno;
}

// Waits for the child and returns its wait status. A stop - a byte read from the stop FIFO, or SIGTERM or
// SIGINT to the tool - sends the child SIGTERM, then SIGKILL once the grace has passed. Without a grace,
// SIGTERM or SIGINT kills the child at once.
int wait_child(int wake_read_fd, int stop_fifo) {
    using clock = std::chrono::steady_clock;
    bool stop_requested = false, stopping = false, killed = false;
    clock::time_point deadline;

    for (;;) {
        int wstatus;
        pid_t r = waitpid(pid, &wstatus, WNOHANG);
        if (r == pid)
            return wstatus;
        if (r == -1 && errno != EINTR)
            fatal_errno("waitpid failed");

        if ((got_signal || stop_requested) && !stopping) {
            stopping = true;
            if (stop_grace) {
                kill(pid, SIGTERM);
                deadline = clock::now() + std::chrono::seconds(stop_grace);
            } else {
                kill(pid, SIGKILL);
                killed = true;
            }
        }

        int timeout = -1;
        if (stopping && !killed) {
            auto left = std::chrono::ceil<std::chrono::milliseconds>(deadline - clock::now()).count();
            if (left > 0) {
                timeout = static_cast<int>(left);
            } else {
                kill(pid, SIGKILL);
                killed = true;
            }
        }

        struct pollfd fds[2] = {{wake_read_fd, POLLIN, 0}, {stop_fifo, POLLIN, 0}};
        nfds_t nfds = stop_fifo >= 0 && !stopping ? 2 : 1;
        if (poll(fds, nfds, timeout) == -1 && errno != EINTR)
            fatal_errno("poll failed");

        char buf[64];
        while (read(wake_read_fd, buf, sizeof(buf)) > 0) {
        }
        if (nfds == 2 && (fds[1].revents & POLLIN) && read(stop_fifo, buf, sizeof(buf)) > 0)
            stop_requested = true;
    }
}

int execute(const fs::path &bin, const std::vector<char *> &args, const std::vector<char *> &env, const int flags,
            const std::string &cgroup_name, const std::string &cpu_set, const std::string &cpu_max,
            const uint64_t mem_limit, const bool no_swap, const bool oom_group, const std::string &usage_stat_file,
            const fs::path &exec_dir, const uid_t uid, const uint64_t tmp_size, const int stop_fifo) {

    if (mem_limit && cgroup_name.empty())
        fatal("cannot set memory limit without cgroup name");

    if (no_swap && !mem_limit)
        fatal("cannot forbid swap without memory limit");

    if (oom_group && !mem_limit)
        fatal("cannot group OOM kills without memory limit");

    if (!cpu_max.empty() && cgroup_name.empty())
        fatal("cannot set cpu.max without cgroup name");

    std::string tmp_mount_opts;
    if (tmp_size)
        tmp_mount_opts = "size=" + std::to_string(tmp_size) + ",mode=1777";

    exe_opts opts{bin, args, env, exec_dir, uid, tmp_mount_opts};

    int cgroup_fd = -1;
    if (!cgroup_name.empty()) {
        sandbox_cgroup = create_cgroup(cgroup_name, cpu_set, cpu_max, mem_limit, no_swap, oom_group);

        if (!cpu_max.empty()) {
            std::ifstream in(fs::path("/sys/fs/cgroup") / cgroup_name / "cpu.max");
            std::string written;
            if (!std::getline(in, written) || written != cpu_max)
                fatal("cannot set cpu.max");
        }

        // Open the cgroup directory as an fd so clone3(CLONE_INTO_CGROUP) can
        // place the child directly into it without the parent ever joining.
        // Previously the parent was attached via cgroup_attach_task and then
        // moved back to the root cgroup after clone(). Between the chown of
        // cgroup.kill and the post-clone detach, the caller could write "1"
        // to cgroup.kill and SIGKILL the parent too - SIGKILL bypasses
        // atexit/clean(), leaving sandbox bind-mounts (/usr/lib, /lib,
        // /usr/libexec) leaked under /tmp/<sandbox>/. A later cleanup that
        // walked into one of those orphaned mounts deleted host /usr/lib.
        // CLONE_INTO_CGROUP closes that race entirely: parent never enters
        // the per-run cgroup, so cgroup.kill cannot reach it.
        auto cgroup_path = fs::path("/sys/fs/cgroup") / cgroup_name;
        cgroup_fd = open(cgroup_path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (cgroup_fd < 0)
            fatal_errno("cannot open cgroup as fd for CLONE_INTO_CGROUP");
    }

    // Create minimal device nodes before clone (fix: devtmpfs exposes all devices)
    create_dev_nodes();

    // SIGCHLD wakes the wait for the child through a pipe, so no exit is missed between checks
    int wake_pipe[2];
    if (pipe2(wake_pipe, O_CLOEXEC | O_NONBLOCK))
        fatal_errno("cannot create pipe");
    wake_fd = wake_pipe[1];

    struct sigaction sa = {};
    sa.sa_handler = wake;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sa, nullptr))
        fatal_errno("cannot handle SIGCHLD");

    // clone3() handles fork-style child stack via COW; no need for explicit
    // mmap'd stack like clone() required.
    struct clone_args cl_args = {};
    cl_args.flags = static_cast<uint64_t>(static_cast<uint32_t>(flags)) & ~0xffULL;
    cl_args.exit_signal = static_cast<uint64_t>(flags) & 0xff;
    if (cgroup_fd >= 0) {
        cl_args.flags |= CLONE_INTO_CGROUP;
        cl_args.cgroup = static_cast<uint64_t>(cgroup_fd);
    }

    pid = syscall(SYS_clone3, &cl_args, sizeof(cl_args));
    if (pid == -1)
        fatal_errno("clone3 failed");
    if (pid == 0) {
        // Child - never returns; either execs or _exit's
        _exit(_execute(&opts));
    }

    if (cgroup_fd >= 0)
        close(cgroup_fd);

    // Now safe to delegate cgroup.kill to the caller. The parent is NOT in
    // the per-run cgroup, so writing "1" to cgroup.kill from outside will
    // only kill the child (and its descendants) - the parent stays alive to
    // run clean() and unmount bind-mounts.
    if (!cgroup_name.empty()) {
        auto kill_path = fs::path("/sys/fs/cgroup") / cgroup_name / "cgroup.kill";
        if (chown(kill_path.c_str(), caller_uid, caller_gid))
            fatal_errno("cannot chown cgroup.kill");
    }

    int wstatus = wait_child(wake_pipe[0], stop_fifo);

    if (!usage_stat_file.empty())
        save_usage_stat(usage_stat_file, cgroup_name);

    clean();

    if (got_signal && !stop_grace)
        return EXIT_FAILURE;

    if (WIFSIGNALED(wstatus))
        return 128 + WTERMSIG(wstatus);

    return WEXITSTATUS(wstatus);
}

void print_usage() {
    std::cout << R"(Usage:
    sandbox <sandbox path> [args] -- <cmd to execute> [cmd args]
args:
    --add_file <src host path> <dst sandbox path>
        Copy a file from a host system to a sandbox

    --add_elf_file <src host path> <dst sandbox path>
        Copy an ELF file from a host system to a sandbox with needed libraries

    --mount_dir <src host path> <dst sandbox path>
        Mount a directory from a host system to a sandbox

    --env <value>
        Environ variables

    --no_new_net
        Do not isolate network

    --cgroup <name>
        Run a process in a cgroup

    --cpuset list
        Specifies the CPUs that are permitted to access

    --mem_limit 0
        Limit memory for a process

    --no_swap
        Forbid swap for a process (requires --mem_limit)

    --oom_group
        Kill every process of the sandbox when the OOM killer kills one (requires --mem_limit)

    --save_usage_stat <filename>
        Save usage statistic to file after exit

    --exec_dir <path>
        The directory inside a sandbox where the command will be executed

    --uid <uid>
        Run the command under this UID and GID instead of 65534: one of 2000000000-2000999999 that is not
        the caller's and has no passwd, group, subuid or subgid entry; refused for a root caller

    --cpu_max "<quota_us> <period_us>"
        Write cpu.max of the cgroup (requires --cgroup)

    --tmp_size <bytes>
        Mount a nosuid,nodev tmpfs of this size at /tmp

    --stop_fifo <path>
        Stop the command when a byte is read from this FIFO, which the caller makes and owns and which its
        group and others cannot write; EOF does not stop

    --stop_grace <seconds>
        Stop with SIGTERM, then SIGKILL after this many seconds (1-3600, default 30 with --stop_fifo);
        SIGTERM and SIGINT to sandbox stop the same way

    --version
        Print the version
)" << std::endl;

    exit(EXIT_FAILURE);
}

// Async-signal-safe handler (fix: signal handler race condition)
void signalHandler(int signum) {
    got_signal = signum;
    if (pid > 0 && !stop_grace)
        kill(pid, SIGKILL);
    wake(signum);
}

int main(int argc, char *argv[]) {
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        std::cout << SANDBOX_VERSION << std::endl;
        return EXIT_SUCCESS;
    }

    if (getuid() != 0 && geteuid() != 0)
        fatal("required root privileges");

    caller_uid = getuid();
    caller_gid = getgid();

    if (setreuid(0, 0))
        fatal_errno("cannot set reuid");

    if (argc < 2 || strncmp(argv[1], "--", 2) == 0)
        print_usage();

    sandbox = fs::path(argv[1]).lexically_normal();

    // Validate sandbox path (fix: unvalidated sandbox path)
    validate_sandbox_path(sandbox);

    // Ensure bind-mounts never leak onto the host if we exit via a fatal_*
    // path. clean() is idempotent, so running it again after execute() is
    // harmless.
    atexit([]() {
        if (!sandbox.empty())
            clean();
    });

    // Install signal handlers before init_dirs so a SIGTERM during setup
    // does not kill us via the default terminate disposition (which skips
    // atexit and leaks mounts). The handler sets got_signal and the normal
    // flow reaches atexit on return from execute() / print_usage().
    struct sigaction sa = {};
    sa.sa_handler = signalHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; // No SA_RESTART so waitpid gets EINTR
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    // Give the parent its OWN mount namespace before any --mount_dir bind (the
    // arg loop below creates them). Binds then exist only in this private
    // namespace and are torn down by the kernel the instant the process dies -
    // including SIGKILL, which bypasses atexit()/clean(). This is the
    // root-cause fix for the host /usr/lib wipe: even if the orchestrator
    // SIGKILLs us (ctx cancel) mid-compile, the /usr/lib /lib /usr/libexec
    // /usr/include binds never exist in the host namespace, so a later
    // os.RemoveAll of the build dir cannot cross a leaked bind into the real
    // host tree.
    if (unshare(CLONE_NEWNS))
        fatal_errno("cannot unshare mount namespace");

    // MS_REC|MS_PRIVATE is load-bearing: the host '/' is MS_SHARED on systemd
    // systems, so without this our binds would propagate back into the host's
    // peer group and re-leak. Mirrors the child-side make-private at _execute().
    if (mount("", "/", "", MS_REC | MS_PRIVATE, nullptr))
        fatal_errno("cannot make mounts private in new namespace");

    init_dirs();

    // link sandbox manager process with sandbox path
    if (!fopen(sandbox.c_str(), "r"))
        fatal_errno("cannot open sandbox path");

    fs::path cmd, exec_dir;
    std::string cgroup, cpu_set, cpu_max, usage_stat_file;
    uint64_t mem_limit = 0;
    uint64_t tmp_size = 0;
    uid_t uid = NOBODY_UID;
    int stop_fifo = -1;
    bool no_swap = false;
    bool oom_group = false;
    std::vector<char *> cmd_args = {nullptr}; // reserved for cmd path
    std::vector<char *> cmd_env;
    int ignored_flags = 0;

    auto i = 2;
    while (i < argc) {
        if (strcmp(argv[i], "--") == 0) {
            if (i + 1 > argc)
                print_usage();
            cmd = argv[i + 1];

            for (i = i + 2; i < argc; i++)
                cmd_args.emplace_back(argv[i]);

            break;
        } else if (strcmp(argv[i], "--add_file") == 0 || strcmp(argv[i], "--add_elf_file") == 0) {
            if (i + 3 > argc || strncmp(argv[i + 1], "--", 2) == 0 || strncmp(argv[i + 2], "--", 2) == 0)
                print_usage();

            add_file(argv[i + 1], argv[i + 2], strcmp(argv[i], "--add_elf_file") == 0);

            i += 3;

        } else if (strcmp(argv[i], "--mount_dir") == 0) {
            if (i + 3 > argc || strncmp(argv[i + 1], "--", 2) == 0 || strncmp(argv[i + 2], "--", 2) == 0)
                print_usage();

            mount_dir(argv[i + 1], argv[i + 2]);

            i += 3;

        } else if (strcmp(argv[i], "--env") == 0) {
            if (i + 2 > argc || strncmp(argv[i + 1], "--", 2) == 0)
                print_usage();

            cmd_env.push_back(argv[i + 1]);

            i += 2;

        } else if (strcmp(argv[i], "--no_new_net") == 0) {
            ignored_flags |= CLONE_NEWNET;

            i++;

        } else if (strcmp(argv[i], "--cgroup") == 0) {
            if (i + 2 > argc || strncmp(argv[i + 1], "--", 2) == 0)
                print_usage();

            cgroup = argv[i + 1];
            validate_cgroup_name(cgroup);

            i += 2;

        } else if (strcmp(argv[i], "--cpuset") == 0) {
            if (i + 2 > argc || strncmp(argv[i + 1], "--", 2) == 0)
                print_usage();

            cpu_set = argv[i + 1];

            i += 2;

        } else if (strcmp(argv[i], "--mem_limit") == 0) {
            if (i + 2 > argc || strncmp(argv[i + 1], "--", 2) == 0)
                print_usage();

            mem_limit = std::strtoll(argv[i + 1], nullptr, 10);

            i += 2;

        } else if (strcmp(argv[i], "--no_swap") == 0) {
            no_swap = true;

            i++;

        } else if (strcmp(argv[i], "--oom_group") == 0) {
            oom_group = true;

            i++;

        } else if (strcmp(argv[i], "--save_usage_stat") == 0) {
            if (i + 2 > argc || strncmp(argv[i + 1], "--", 2) == 0)
                print_usage();

            usage_stat_file = argv[i + 1];

            i += 2;

        } else if (strcmp(argv[i], "--exec_dir") == 0) {
            if (i + 2 > argc || strncmp(argv[i + 1], "--", 2) == 0)
                print_usage();

            exec_dir = argv[i + 1];

            i += 2;

        } else if (strcmp(argv[i], "--uid") == 0) {
            if (i + 2 > argc || strncmp(argv[i + 1], "--", 2) == 0)
                print_usage();

            uid = check_uid(argv[i + 1]);

            i += 2;

        } else if (strcmp(argv[i], "--cpu_max") == 0) {
            if (i + 2 > argc || strncmp(argv[i + 1], "--", 2) == 0)
                print_usage();

            cpu_max = parse_cpu_max(argv[i + 1]);

            i += 2;

        } else if (strcmp(argv[i], "--tmp_size") == 0) {
            if (i + 2 > argc || strncmp(argv[i + 1], "--", 2) == 0)
                print_usage();

            // tmpfs takes size=0 as no limit
            if (!parse_number(argv[i + 1], tmp_size) || tmp_size == 0)
                fatal("--tmp_size must be a positive number of bytes");

            i += 2;

        } else if (strcmp(argv[i], "--stop_fifo") == 0) {
            if (i + 2 > argc || strncmp(argv[i + 1], "--", 2) == 0)
                print_usage();

            if (stop_fifo >= 0)
                fatal("--stop_fifo is given twice");
            stop_fifo = open_stop_fifo(argv[i + 1]);

            i += 2;

        } else if (strcmp(argv[i], "--stop_grace") == 0) {
            if (i + 2 > argc || strncmp(argv[i + 1], "--", 2) == 0)
                print_usage();

            uint64_t grace;
            if (!parse_number(argv[i + 1], grace) || grace < 1 || grace > MAX_STOP_GRACE)
                fatal("--stop_grace must be 1-" + std::to_string(MAX_STOP_GRACE) + " seconds");
            stop_grace = static_cast<sig_atomic_t>(grace);

            i += 2;

        } else {
            print_usage();
        }
    }

    if (stop_fifo >= 0 && !stop_grace)
        stop_grace = DEFAULT_STOP_GRACE;

    int flags = CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWPID | CLONE_NEWCGROUP | SIGCHLD;
    if ((ignored_flags & CLONE_NEWNET) == 0)
        flags |= CLONE_NEWNET;

    cmd_args[0] = const_cast<char *>(cmd.c_str());
    cmd_args.push_back(nullptr);
    cmd_env.push_back(nullptr);

    return execute(cmd, cmd_args, cmd_env, flags, cgroup, cpu_set, cpu_max, mem_limit, no_swap, oom_group,
                   usage_stat_file, exec_dir, uid, tmp_size, stop_fifo);
}
