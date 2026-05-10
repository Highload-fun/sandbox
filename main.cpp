#include <iostream>
#include <fstream>
#include <array>
#include <vector>
#include <string>
#include <regex>
#include <cstdlib>
#include <cstring>

#include <filesystem>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <mntent.h>
#include <linux/sched.h>    // struct clone_args, CLONE_INTO_CGROUP
#include <libcgroup.h>

// CLONE_INTO_CGROUP not always exposed even by current linux/sched.h
#ifndef CLONE_INTO_CGROUP
#define CLONE_INTO_CGROUP 0x200000000ULL
#endif


#define STACK_SIZE (1024 * 1024)
#define NOBODY_UID 65534

namespace fs = std::filesystem;

struct exe_opts {
    const fs::path &bin_path;
    const std::vector<char *> &args;
    const std::vector<char *> &env;
    const fs::path &exec_dir;
};

static volatile sig_atomic_t got_signal = 0;
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

cgroup *create_cgroup(const std::string &name, const std::string &cpu_set, uint64_t mem_limit) {
    if (cgroup_init())
        fatal_cgroup("cannot init cgroup");

    auto cgroup = cgroup_new_cgroup(name.c_str());

    auto cpu_ctrl = cgroup_add_controller(cgroup, "cpu");
    if (!cpu_ctrl) {
        fatal_cgroup("cannot cpu controller");
    }

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
    }

    if (!cgroup_add_controller(cgroup, "io")) {
        fatal_cgroup("cannot io controller");
    }

    if (cgroup_create_cgroup(cgroup, 0) != 0)
        fatal_cgroup("cannot create cgroup");

    return cgroup;
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

    // Mount proc inside new root
    if (mount("proc", "/proc", "proc", 0, nullptr))
        if (errno != EBUSY)
            fatal_errno("cannot mount /proc");

    if (chdir(opts->exec_dir.empty() ? "/root" : opts->exec_dir.c_str()))
        fatal_errno("cannot chdir");

    if (setgid(NOBODY_UID))
        fatal_errno("cannot set GID");

    if (setuid(NOBODY_UID))
        fatal_errno("cannot set UID");

    // Prevent privilege escalation via SUID binaries (fix: missing CLONE_NEWUSER)
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        fatal_errno("cannot set no_new_privs");

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

int execute(const fs::path &bin, const std::vector<char *> &args, const std::vector<char *> &env, const int flags,
            const std::string &cgroup_name, const std::string &cpu_set, const uint64_t mem_limit,
            const std::string &usage_stat_file, const fs::path &exec_dir) {

    if (mem_limit && cgroup_name.empty())
        fatal("cannot set memory limit without cgroup name");

    exe_opts opts{bin, args, env, exec_dir};

    int cgroup_fd = -1;
    if (!cgroup_name.empty()) {
        sandbox_cgroup = create_cgroup(cgroup_name, cpu_set, mem_limit);

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

    // Handle EINTR from signal handler (fix: signal handler race condition)
    int wstatus;
    while (waitpid(pid, &wstatus, 0) == -1) {
        if (errno == EINTR)
            continue;
        fatal_errno("waitpid failed");
    }

    if (!usage_stat_file.empty())
        save_usage_stat(usage_stat_file, cgroup_name);

    clean();

    if (got_signal)
        return EXIT_FAILURE;

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

    --save_usage_stat <filename>
        Save usage statistic to file after exit

    --exec_dir <path>
        The directory inside a sandbox where the command will be executed
)" << std::endl;

    exit(EXIT_FAILURE);
}

// Async-signal-safe handler (fix: signal handler race condition)
void signalHandler(int signum) {
    got_signal = signum;
    if (pid > 0)
        kill(pid, SIGKILL);
}

int main(int argc, char *argv[]) {
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

    init_dirs();

    // link sandbox manager process with sandbox path
    if (!fopen(sandbox.c_str(), "r"))
        fatal_errno("cannot open sandbox path");

    fs::path cmd, exec_dir;
    std::string cgroup, cpu_set, usage_stat_file;
    uint64_t mem_limit = 0;
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

        } else {
            print_usage();
        }
    }

    int flags = CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWPID | CLONE_NEWCGROUP | SIGCHLD;
    if ((ignored_flags & CLONE_NEWNET) == 0)
        flags |= CLONE_NEWNET;

    cmd_args[0] = const_cast<char *>(cmd.c_str());
    cmd_args.push_back(nullptr);
    cmd_env.push_back(nullptr);

    return execute(cmd, cmd_args, cmd_env, flags, cgroup, cpu_set, mem_limit, usage_stat_file, exec_dir);
}
