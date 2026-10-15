#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <iostream>
#include <fstream>
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
#include <sys/resource.h>
#include <fcntl.h>
#include <dirent.h>
#include <grp.h>            // setgroups
#include <linux/openat2.h>  // struct open_how, RESOLVE_*
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

#ifndef __NR_open_tree
#define __NR_open_tree 428
#endif
#ifndef __NR_move_mount
#define __NR_move_mount 429
#endif
#ifndef __NR_openat2
#define __NR_openat2 437
#endif
#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE 1
#endif
#ifndef OPEN_TREE_CLOEXEC
#define OPEN_TREE_CLOEXEC O_CLOEXEC
#endif
#ifndef MOVE_MOUNT_F_EMPTY_PATH
#define MOVE_MOUNT_F_EMPTY_PATH 0x00000004
#endif
#ifndef AT_RECURSIVE
#define AT_RECURSIVE 0x8000
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
// --fsize_max takes at most 1 TiB
#define MAX_FSIZE (1ULL << 40)
// The removal walk keeps at most this many folders open; a deeper subtree is moved up
#define MAX_WALK_DEPTH 256
#define MAX_HOISTS UINT32_MAX

static_assert(UID_RANGE_MIN > NOBODY_UID && UID_RANGE_MAX < UINT32_MAX, "--uid range");

namespace fs = std::filesystem;

struct exe_opts {
    const fs::path &bin_path;
    const std::vector<char *> &args;
    const std::vector<char *> &env;
    const fs::path &exec_dir;
    const uid_t uid;
    const std::string &tmp_mount_opts;
    const uint64_t fsize_max;
};

static volatile sig_atomic_t got_signal = 0;
// Seconds between SIGTERM and SIGKILL on a stop; 0 makes SIGTERM/SIGINT to the tool kill the child at once
static volatile sig_atomic_t stop_grace = 0;
// Write end of the pipe that wakes the wait for the child
static volatile sig_atomic_t wake_fd = -1;
static pid_t pid;
static bool is_child = false;
// The sandbox path: its parent is opened once, with the caller's rights, and then the tree is reached only
// through parent_fd and sandbox_fd
static fs::path sandbox = {};
static std::string leaf;
static int parent_fd = -1;
static bool parent_is_callers = false;
static int sandbox_fd = -1;
static int tmp_fd = -1;
// A detached clone of the tree, the child's root to be
static int tree_fd = -1;
static cgroup *sandbox_cgroup = nullptr;
static std::string sandbox_cgroup_name;
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

// Opens paths with the caller's rights until restore_privileges()
static void drop_privileges(const std::string &what) {
    if (setegid(caller_gid) || seteuid(caller_uid))
        fatal_errno("cannot drop privileges for " + what);
}

static void restore_privileges() {
    if (seteuid(0) || setegid(0))
        fatal_errno("cannot restore privileges");
}

// Runs a command with the caller's IDs, without a shell (fix: command injection via popen), and returns
// its stdout
std::string exec_as_caller(const char *path, std::vector<const char *> args) {
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC))
        fatal_errno("cannot create pipe");

    pid_t child = fork();
    if (child == -1)
        fatal_errno("cannot fork");

    if (child == 0) {
        if (setresgid(caller_gid, caller_gid, caller_gid) || setresuid(caller_uid, caller_uid, caller_uid))
            _exit(EXIT_FAILURE);
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
// neither its group nor others may read or write. The checks are on the open fd, never the path.
int open_stop_fifo(const char *path) {
    drop_privileges("--stop_fifo");
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    int open_errno = errno;
    restore_privileges();

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
    if (st.st_mode & (S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH))
        fatal("--stop_fifo is readable or writable by its group or others");

    // Hold a write end of the same FIFO, so a writer that closes is never seen as EOF or POLLHUP. It stays
    // open until the tool exits.
    auto same_fifo = "/proc/self/fd/" + std::to_string(fd);
    if (open(same_fifo.c_str(), O_WRONLY | O_NONBLOCK | O_CLOEXEC) < 0)
        fatal_errno("cannot hold --stop_fifo open");

    return fd;
}

// Opens the folder name of dir_fd without following a link or crossing into a mount
static int open_child_dir(int dir_fd, const char *name) {
    struct open_how how = {};
    how.flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
    how.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV;
    return static_cast<int>(syscall(__NR_openat2, dir_fd, name, &how, sizeof(how)));
}

// Detaches the mount on the entry name of dir_fd. The tool's mount namespace is its own, so this never
// touches the host's mounts.
static void detach_mount(int dir_fd, const char *name) {
    int fd = openat(dir_fd, name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        fatal_errno("cannot open a mount in the sandbox");
    auto mounted = "/proc/self/fd/" + std::to_string(fd);
    if (umount2(mounted.c_str(), MNT_DETACH))
        fatal_errno("cannot umount a mount in the sandbox");
    close(fd);
}

// Opens the folder name of dir_fd; a mount on it is detached first
static int open_dir_detaching(int dir_fd, const char *name) {
    int fd;
    for (int i = 0; (fd = open_child_dir(dir_fd, name)) < 0 && errno == EXDEV && i < 100; i++)
        detach_mount(dir_fd, name);
    return fd;
}

static std::vector<std::string> list_dir(int dir_fd) {
    int fd = openat(dir_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *dir = fd < 0 ? nullptr : fdopendir(fd);
    if (!dir)
        fatal_errno("cannot read a folder of the sandbox");
    std::vector<std::string> names;
    while (auto entry = readdir(dir))
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
            names.emplace_back(entry->d_name);
    closedir(dir);
    return names;
}

// Removes everything in the folder top_fd, without recursion. It never follows a link and never enters a
// mount: a mount inside is detached, and the folder under it removed. At most MAX_WALK_DEPTH folders are
// open at a time: a subtree deeper than that is moved up into top_fd, on the same mount, and removed from
// there in its turn, so any depth is removed.
static void empty_tree(int top_fd) {
    struct frame {
        int fd;
        std::vector<std::string> names;
        size_t next;
        unsigned long rounds;
    };
    int top = fcntl(top_fd, F_DUPFD_CLOEXEC, 0);
    if (top < 0)
        fatal_errno("cannot remove sandbox");
    std::vector<frame> stack;
    stack.push_back({top, {}, 0, 0});
    // Each move is progress, so only moves count against MAX_HOISTS; the listing bound guards the loop
    unsigned long hoisted = 0;
    unsigned long long moved_name = 0;

    while (!stack.empty()) {
        frame &f = stack.back();
        if (f.next == f.names.size()) {
            f.names = list_dir(f.fd);
            f.next = 0;
            if (f.names.empty()) {
                close(f.fd);
                stack.pop_back();
                // An entry added meanwhile keeps the folder for the parent's next listing
                if (!stack.empty() &&
                    unlinkat(stack.back().fd, stack.back().names[stack.back().next - 1].c_str(), AT_REMOVEDIR) &&
                    errno != ENOENT && errno != ENOTEMPTY && errno != EEXIST)
                    fatal_errno("cannot remove sandbox");
                continue;
            }
            // Every subtree moved up into top_fd costs it one more listing
            if (++f.rounds > 3 + (stack.size() == 1 ? hoisted : 0))
                fatal("cannot remove sandbox: its folders keep changing");
        }

        // What fails here and changes meanwhile shows up again in the folder's next listing
        const char *name = f.names[f.next++].c_str();
        if (unlinkat(f.fd, name, 0) == 0 || errno == ENOENT)
            continue;
        if (errno == EBUSY) {
            detach_mount(f.fd, name);
            continue;
        }
        if (errno != EISDIR)
            fatal_errno("cannot remove sandbox");

        if (stack.size() >= MAX_WALK_DEPTH) {
            // A mount point cannot be moved: detach what is mounted on the folder first
            int fd = open_dir_detaching(f.fd, name);
            if (fd < 0) {
                if (errno != ENOENT && errno != ENOTDIR && errno != ELOOP)
                    fatal_errno("cannot remove sandbox");
                continue;
            }
            close(fd);
            if (hoisted >= MAX_HOISTS)
                fatal("cannot remove sandbox: its folders keep changing");
            for (;;) {
                auto moved = ".sandbox-deep-" + std::to_string(++moved_name);
                if (renameat2(f.fd, name, stack.front().fd, moved.c_str(), RENAME_NOREPLACE) == 0) {
                    hoisted++;
                    break;
                }
                if (errno == ENOENT || errno == EBUSY)
                    break;
                if (errno != EEXIST)
                    fatal_errno("cannot remove sandbox");
            }
            continue;
        }

        int fd = open_dir_detaching(f.fd, name);
        if (fd >= 0)
            stack.push_back({fd, {}, 0, 0});
        else if (errno != ENOENT && errno != ENOTDIR && errno != ELOOP)
            fatal_errno("cannot remove sandbox");
    }
}

// Removes the sandbox folder from its parent, unless the name no longer leads to it
static void remove_leaf(const struct stat &dir) {
    struct stat now;
    if (fstatat(parent_fd, leaf.c_str(), &now, AT_SYMLINK_NOFOLLOW) || now.st_dev != dir.st_dev ||
        now.st_ino != dir.st_ino)
        fatal("cannot remove sandbox: its folder was moved");
    if (unlinkat(parent_fd, leaf.c_str(), AT_REMOVEDIR))
        fatal_errno("cannot remove sandbox");
}

// Reports whether path leads to the file st
static bool leads_to(const std::string &path, const struct stat &st) {
    struct stat now;
    return stat(path.c_str(), &now) == 0 && now.st_dev == st.st_dev && now.st_ino == st.st_ino;
}

// Kills what an earlier run on this sandbox path left running. A process of the caller, nobody or the
// --uid range is killed when its root, working folder or an open file is the folder dir. A root process
// is killed only when its root is dir, as an earlier run's command has, or when it is this tool and its
// working folder or an open file is dir, as an earlier run of the tool; no other root process is the
// caller's to kill.
static void kill_processes_using(const struct stat &dir) {
    struct stat tool;
    if (stat("/proc/self/exe", &tool))
        fatal_errno("cannot stat the tool");

    std::vector<pid_t> pids;
    DIR *proc = opendir("/proc");
    if (!proc)
        fatal_errno("cannot open /proc");
    while (auto entry = readdir(proc)) {
        char *end;
        long p = strtol(entry->d_name, &end, 10);
        if (*end != '\0' || p <= 0 || p == getpid())
            continue;

        auto base = std::string("/proc/") + entry->d_name;
        struct stat st;
        if (stat(base.c_str(), &st) || !(st.st_uid == 0 || st.st_uid == caller_uid || st.st_uid == NOBODY_UID ||
                                         (st.st_uid >= UID_RANGE_MIN && st.st_uid <= UID_RANGE_MAX)))
            continue;

        bool uses = leads_to(base + "/root", dir);
        if (!uses && (st.st_uid != 0 || leads_to(base + "/exe", tool))) {
            uses = leads_to(base + "/cwd", dir);
            if (DIR *fds = uses ? nullptr : opendir((base + "/fd").c_str())) {
                while (auto fd = readdir(fds))
                    if (fd->d_name[0] != '.' && leads_to(base + "/fd/" + fd->d_name, dir))
                        uses = true;
                closedir(fds);
            }
        }
        if (uses)
            pids.push_back(static_cast<pid_t>(p));
    }
    closedir(proc);

    for (auto p: pids) {
        std::cerr << "Kill pid " << p << std::endl;
        kill(p, SIGKILL);
    }
    for (auto p: pids)
        waitpid(p, nullptr, 0);
}

// Opens the sandbox's parent folder with the caller's rights. It is accepted when the caller is root or
// owns it, or when it is a root-owned sticky folder that everyone may write, such as /tmp.
void open_parent() {
    leaf = sandbox.filename().string();
    if (leaf.empty() || leaf == "." || leaf == "..")
        fatal("sandbox path must name a folder");

    drop_privileges("the sandbox parent");
    parent_fd = open(sandbox.parent_path().c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC);
    int open_errno = errno;
    restore_privileges();
    if (parent_fd < 0) {
        errno = open_errno;
        fatal_errno("cannot open the sandbox parent");
    }

    struct stat st;
    if (fstat(parent_fd, &st))
        fatal_errno("cannot stat the sandbox parent");
    parent_is_callers = caller_uid == 0 || st.st_uid == caller_uid;
    bool shared = st.st_uid == 0 && (st.st_mode & S_ISVTX) && (st.st_mode & S_IWOTH);
    if (!parent_is_callers && !shared)
        fatal("sandbox parent must be owned by the caller");
}

// Removes what an earlier run left at the sandbox path, then makes the sandbox folder, owned by root.
// From here on the tree is reached only through sandbox_fd, so moving or replacing the folder by its
// name redirects nothing.
void make_sandbox() {
    int old = open_dir_detaching(parent_fd, leaf.c_str());
    if (old >= 0) {
        struct stat st;
        if (fstat(old, &st))
            fatal_errno("cannot stat the sandbox path");
        // In a shared parent such as /tmp a root-owned folder may be anyone's, not an earlier run's
        if (!(st.st_uid == caller_uid || (st.st_uid == 0 && parent_is_callers) || caller_uid == 0))
            fatal("sandbox path holds a folder of someone else");
        kill_processes_using(st);
        empty_tree(old);
        close(old);
        remove_leaf(st);
    } else if (errno == ELOOP || errno == ENOTDIR) {
        fatal("sandbox path is a link or a file");
    } else if (errno != ENOENT) {
        fatal_errno("cannot open the sandbox path");
    }

    if (mkdirat(parent_fd, leaf.c_str(), 0755))
        fatal_errno("cannot create the sandbox folder");
    sandbox_fd = open_child_dir(parent_fd, leaf.c_str());
    struct stat st;
    if (sandbox_fd < 0 || fstat(sandbox_fd, &st))
        fatal_errno("cannot open the sandbox folder");
    if (st.st_uid != 0 || !list_dir(sandbox_fd).empty())
        fatal("sandbox folder was replaced while it was made");
    if (fchmod(sandbox_fd, 0755))
        fatal_errno("cannot set mode 755 for the sandbox folder");
}

void remove_sandbox() {
    if (sandbox_fd < 0)
        return;

    struct stat st;
    if (fstat(sandbox_fd, &st))
        fatal_errno("cannot stat the sandbox folder");
    empty_tree(sandbox_fd);
    close(sandbox_fd);
    sandbox_fd = -1;
    remove_leaf(st);
}

void clean() {
    // The child's fatal_* exits run atexit too; the parent cleans up after it
    if (is_child)
        return;

    // Guard against re-entry: the atexit handler calls clean(), and any
    // fatal_* inside remove_sandbox() would exit() and trigger
    // atexit -> clean() -> ... again. One attempt is enough.
    static bool entered = false;
    if (entered)
        return;
    entered = true;

    // An open clone keeps the tree's mount points busy
    if (tree_fd >= 0) {
        close(tree_fd);
        tree_fd = -1;
    }

    // Remove the cgroup only when it is empty. rmdir never moves processes, unlike libcgroup's delete,
    // which would move another run's processes out of a reused cgroup and free them from its limits. A
    // cgroup that still holds processes is left in place; the exit code stays the command's.
    if (sandbox_cgroup != nullptr)
        cgroup_free(&sandbox_cgroup);
    if (!sandbox_cgroup_name.empty()) {
        auto path = fs::path("/sys/fs/cgroup") / sandbox_cgroup_name;
        if (rmdir(path.c_str()) && errno != ENOENT)
            std::cerr << "cannot remove cgroup " << sandbox_cgroup_name << ", left in place: " << strerror(errno)
                      << std::endl;
    }

    remove_sandbox();
}

// Create minimal device nodes instead of full devtmpfs (fix: devtmpfs exposes all devices)
void create_dev_nodes(int dev_fd) {
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
        if (mknodat(dev_fd, d.name, d.mode, makedev(d.major, d.minor)))
            if (errno != EEXIST)
                fatal_errno(std::string("cannot create device ") + d.name);
    }
    umask(old_umask);
}

// Makes the sandbox's own folders and device nodes. /tmp stays 0755 until everything is in place.
void init_dirs() {
    for (const char *name: {"dev", "etc", "proc", "root", "tmp"}) {
        if (mkdirat(sandbox_fd, name, 0755))
            fatal_errno(std::string("cannot create system dir ") + name);
        int fd = open_child_dir(sandbox_fd, name);
        if (fd < 0 || fchmod(fd, 0755))
            fatal_errno(std::string("cannot open system dir ") + name);
        if (strcmp(name, "dev") == 0)
            create_dev_nodes(fd);
        if (strcmp(name, "tmp") == 0)
            tmp_fd = fd;
        else
            close(fd);
    }
}

// Opens the folder rel inside the sandbox one component at a time, making the missing ones with create.
// A link, a file or a mount on the way is refused, so nothing outside the sandbox is ever reached.
static int open_beneath(const fs::path &rel, bool create) {
    int fd = fcntl(sandbox_fd, F_DUPFD_CLOEXEC, 0);
    if (fd < 0)
        fatal_errno("cannot open the sandbox folder");
    for (const auto &part: rel) {
        auto name = part.string();
        if (name.empty() || name == ".")
            continue;
        if (create && mkdirat(fd, name.c_str(), 0755) && errno != EEXIST)
            fatal_errno("cannot create " + rel.string() + " in the sandbox");
        int next = open_child_dir(fd, name.c_str());
        if (next < 0) {
            if (errno == ELOOP || errno == ENOTDIR || errno == EXDEV)
                fatal("refusing " + rel.string() + " in the sandbox: a link, a file or a mount is in the way");
            fatal_errno("cannot open " + rel.string() + " in the sandbox");
        }
        close(fd);
        fd = next;
    }
    return fd;
}

void libs_deps(const std::string &bin, std::vector<std::string> &res) {
    std::vector<const char *> args = {
        "/usr/bin/ldd", bin.c_str(), nullptr
    };
    std::string out_buf = exec_as_caller("/usr/bin/ldd", args);

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

// Copies the regular file in, open for reading, to name in dir_fd, as root, with its mode but no set-ID
// bits
static void copy_file_into(int in, const struct stat &st, int dir_fd, const std::string &name) {
    int out = openat(dir_fd, name.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (out < 0) {
        if (errno != EEXIST)
            fatal_errno("cannot copy file to " + name);
        return;
    }

    char buf[65536];
    ssize_t n;
    while ((n = read(in, buf, sizeof(buf))) > 0) {
        for (ssize_t done = 0; done < n;) {
            ssize_t w = write(out, buf + done, n - done);
            if (w < 0)
                fatal_errno("cannot copy file to " + name);
            done += w;
        }
    }
    if (n < 0 || fchmod(out, st.st_mode & 0777))
        fatal_errno("cannot copy file to " + name);
    close(out);
}

// Opens the host file src for reading with the caller's rights, so the caller puts in only what it could
// read itself. Only a regular file is opened for reading, and its stat is st.
static int open_source_file(const std::string &src, struct stat &st) {
    drop_privileges("--add_file");
    int path_fd = open(src.c_str(), O_PATH | O_CLOEXEC);
    int open_errno = errno;
    restore_privileges();
    if (path_fd < 0) {
        errno = open_errno;
        fatal_errno("cannot resolve path: " + src);
    }
    if (fstat(path_fd, &st))
        fatal_errno("cannot stat " + src);
    if (!S_ISREG(st.st_mode))
        fatal("add_file source must be a regular file: " + src);

    // The same file is opened again, now with the caller's read rights checked
    auto same_file = "/proc/self/fd/" + std::to_string(path_fd);
    drop_privileges("--add_file");
    int fd = open(same_file.c_str(), O_RDONLY | O_CLOEXEC);
    open_errno = errno;
    restore_privileges();
    close(path_fd);
    if (fd < 0) {
        errno = open_errno;
        fatal_errno("cannot read " + src);
    }
    if (fstat(fd, &st))
        fatal_errno("cannot stat " + src);
    return fd;
}

// Puts the host file src at dst in the sandbox: a hard link, or a copy across filesystems
static void place_file(const std::string &src, const fs::path &dst) {
    struct stat st;
    int src_fd = open_source_file(src, st);

    auto name = dst.filename().string();
    if (name.empty() || name == ".")
        fatal("add_file destination must name a file: " + dst.string());
    int dir_fd = open_beneath(dst.parent_path().relative_path(), true);

    auto src_link = "/proc/self/fd/" + std::to_string(src_fd);
    // Someone else's set-ID file is copied for a non-root caller, so no new link keeps its inode alive
    bool foreign_setid = caller_uid != 0 && st.st_uid != caller_uid && (st.st_mode & (S_ISUID | S_ISGID));
    if (foreign_setid) {
        copy_file_into(src_fd, st, dir_fd, name);
    } else if (linkat(AT_FDCWD, src_link.c_str(), dir_fd, name.c_str(), AT_SYMLINK_FOLLOW) && errno != EEXIST) {
        if (errno != EXDEV)
            fatal_errno("cannot create hardlink " + src + "->" + dst.string());
        copy_file_into(src_fd, st, dir_fd, name);
    }
    close(dir_fd);
    close(src_fd);
}

void add_file(const std::string &src, const fs::path &dst, bool with_deps) {
    place_file(src, dst);

    if (with_deps) {
        // ldd runs the loader on the binary, so it runs as the caller, on the host's file
        std::vector<std::string> libs;
        libs_deps(src, libs);

        for (auto &l: libs) {
            validate_path_in_sandbox(l, "add_elf_file library");
            place_file(l, fs::path(l).lexically_normal());
        }
    }
}

void mount_dir(const std::string &src, const fs::path &dst) {
    auto rel = dst.relative_path();
    if (rel.empty())
        fatal("mount destination must not be the sandbox root");

    // The caller must be able to read the folder, not only to reach it
    drop_privileges("--mount_dir");
    int src_fd = open(src.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int open_errno = errno;
    restore_privileges();
    if (src_fd < 0) {
        errno = open_errno;
        fatal_errno("cannot mount dir " + src);
    }

    int dst_fd = open_beneath(rel, true);
    auto from = "/proc/self/fd/" + std::to_string(src_fd);
    auto to = "/proc/self/fd/" + std::to_string(dst_fd);
    if (mount(from.c_str(), to.c_str(), "", MS_BIND, nullptr))
        if (errno != EBUSY)
            fatal_errno("cannot mount dir " + src);
    close(dst_fd);
    close(src_fd);
}

// Opens the cgroup name when it exists, and accepts it only as an empty leaf: no child cgroup and no
// process. A non-root caller may reuse only a cgroup the tool made for it earlier, whose cgroup.kill it
// was given. The checks are made before anything is written, through the fd the child is cloned into.
// Returns -1 when there is no such cgroup.
int open_existing_cgroup(const std::string &name) {
    auto path = fs::path("/sys/fs/cgroup") / name;
    int fd = open(path.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT)
            return -1;
        fatal_errno("cannot open cgroup " + name);
    }

    struct stat st;
    bool callers = caller_uid == 0 || (fstatat(fd, "cgroup.kill", &st, AT_SYMLINK_NOFOLLOW) == 0 &&
                                       S_ISREG(st.st_mode) && st.st_uid == caller_uid);
    bool leaf = true;
    for (const auto &entry: list_dir(fd))
        if (fstatat(fd, entry.c_str(), &st, AT_SYMLINK_NOFOLLOW) || S_ISDIR(st.st_mode))
            leaf = false;
    char c;
    int procs = openat(fd, "cgroup.procs", O_RDONLY | O_CLOEXEC);
    bool empty = procs >= 0 && read(procs, &c, 1) == 0;
    if (procs >= 0)
        close(procs);

    if (!callers || !leaf || !empty)
        fatal("--cgroup names an existing cgroup that is not an empty leaf the tool made for the caller");
    return fd;
}

// Claims the cgroup name and returns the fd of its folder. A new cgroup is made with mkdir, which only
// one run can win; a run that loses, or finds the cgroup there, must pass open_existing_cgroup, which
// refuses another caller's cgroup since its cgroup.kill is root's until the run starts, then that caller's.
int claim_cgroup(const std::string &name) {
    int fd = open_existing_cgroup(name);
    if (fd < 0) {
        auto path = fs::path("/sys/fs/cgroup") / name;
        if (mkdir(path.c_str(), 0755) == 0) {
            sandbox_cgroup_name = name;
            fd = open(path.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (fd < 0)
                fatal_errno("cannot open cgroup " + name);
            return fd;
        }
        if (errno != EEXIST)
            fatal_errno("cannot create cgroup " + name);
        fd = open_existing_cgroup(name);
        if (fd < 0)
            fatal("cgroup " + name + " changed while it was claimed");
    }
    // Only a claimed or accepted cgroup is the tool's to remove
    sandbox_cgroup_name = name;
    return fd;
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

    // The parent cloned the sandbox tree through its fd: attach the clone and make it the root, so no
    // path is looked up by name
    if (syscall(__NR_move_mount, tree_fd, "", AT_FDCWD, "/", MOVE_MOUNT_F_EMPTY_PATH))
        fatal_errno("cannot attach the sandbox tree");

    if (fchdir(tree_fd))
        fatal_errno("cannot chdir");

    if (syscall(SYS_pivot_root, ".", "."))
        fatal_errno("cannot pivot_root");

    if (umount2(".", MNT_DETACH))
        fatal_errno("cannot unmount old root");

    if (chdir("/"))
        fatal_errno("cannot chdir");

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

    // No file the command writes, stdout and stderr included, grows past --fsize_max: a write there fails
    // with EFBIG, as SIGXFSZ is ignored rather than ending the command. The limit is never above the one
    // the command would have had, and nothing in the sandbox can raise it.
    if (opts->fsize_max) {
        struct rlimit fsize;
        if (getrlimit(RLIMIT_FSIZE, &fsize))
            fatal_errno("cannot limit file size");
        fsize.rlim_cur = fsize.rlim_max = std::min<rlim_t>(opts->fsize_max, fsize.rlim_max);
        if (setrlimit(RLIMIT_FSIZE, &fsize) || signal(SIGXFSZ, SIG_IGN) == SIG_ERR)
            fatal_errno("cannot limit file size");
    }

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
            const fs::path &exec_dir, const uid_t uid, const uint64_t tmp_size, const int stop_fifo,
            const uint64_t fsize_max) {

    std::string tmp_mount_opts;
    if (tmp_size)
        tmp_mount_opts = "size=" + std::to_string(tmp_size) + ",mode=1777";

    // Everything is in place: only now may others write /tmp, sticky so they cannot move or remove what
    // they do not own; it stays 0755 under a tmpfs
    if (!tmp_size && fchmod(tmp_fd, 01777))
        fatal_errno("cannot set mode 1777 for /tmp");
    close(tmp_fd);
    tmp_fd = -1;

    exe_opts opts{bin, args, env, exec_dir, uid, tmp_mount_opts, fsize_max};

    int cgroup_fd = -1;
    if (!cgroup_name.empty()) {
        // libcgroup only writes the values: its mkdir finds the folder claimed here
        cgroup_fd = claim_cgroup(cgroup_name);
        sandbox_cgroup = create_cgroup(cgroup_name, cpu_set, cpu_max, mem_limit, no_swap, oom_group);

        if (!cpu_max.empty()) {
            std::ifstream in(fs::path("/sys/fs/cgroup") / cgroup_name / "cpu.max");
            std::string written;
            if (!std::getline(in, written) || written != cpu_max)
                fatal("cannot set cpu.max");
        }

        // The cgroup's fd, from claim_cgroup, lets clone3(CLONE_INTO_CGROUP)
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
        //
        // libcgroup wrote the values by name: the name must still lead to the folder claimed or checked
        auto cgroup_path = fs::path("/sys/fs/cgroup") / cgroup_name;
        struct stat claimed, now;
        if (fstat(cgroup_fd, &claimed) || stat(cgroup_path.c_str(), &now) || claimed.st_dev != now.st_dev ||
            claimed.st_ino != now.st_ino)
            fatal("cgroup " + cgroup_name + " was replaced while it was set up");
    }

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

    // The child's root is a clone of the tree reached through sandbox_fd, with its mounts
    tree_fd = static_cast<int>(syscall(__NR_open_tree, sandbox_fd, "",
                                       OPEN_TREE_CLONE | AT_RECURSIVE | AT_EMPTY_PATH | OPEN_TREE_CLOEXEC));
    if (tree_fd < 0)
        fatal_errno("cannot clone the sandbox tree");

    pid = syscall(SYS_clone3, &cl_args, sizeof(cl_args));
    if (pid == -1)
        fatal_errno("clone3 failed");
    if (pid == 0) {
        // Child - never returns; either execs or _exit's
        is_child = true;
        _exit(_execute(&opts));
    }

    if (cgroup_fd >= 0)
        close(cgroup_fd);
    close(tree_fd);
    tree_fd = -1;

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

    The sandbox path's parent must be the caller's own folder, or a root-owned sticky folder that everyone
    may write, such as /tmp. Files are put in place before folders are mounted. Host files and folders are
    opened with the caller's rights and must be readable by it.
args:
    --add_file <src host path> <dst sandbox path>
        Copy a regular file from a host system to a sandbox

    --add_elf_file <src host path> <dst sandbox path>
        Copy an ELF file from a host system to a sandbox with needed libraries

    --mount_dir <src host path> <dst sandbox path>
        Mount a directory from a host system to a sandbox, not under another mount

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
        group and others can neither read nor write; EOF does not stop

    --stop_grace <seconds>
        Stop with SIGTERM, then SIGKILL after this many seconds (1-3600, default 30 with --stop_fifo);
        SIGTERM and SIGINT to sandbox stop the same way

    --fsize_max <bytes>
        Limit every file the command writes, its stdout and stderr included, to this size (up to 1 TiB);
        past it a write fails with EFBIG

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
    if (!sandbox.has_filename())
        sandbox = sandbox.parent_path();

    // Validate sandbox path (fix: unvalidated sandbox path)
    validate_sandbox_path(sandbox);

    // Ensure bind-mounts never leak onto the host if we exit via a fatal_*
    // path. clean() is idempotent, so running it again after execute() is
    // harmless.
    atexit([]() {
        if (!sandbox.empty())
            clean();
    });

    // Install signal handlers before the setup so a SIGTERM during it
    // does not kill us via the default terminate disposition (which skips
    // atexit and leaks mounts). The handler sets got_signal and the normal
    // flow reaches atexit on return from execute() / print_usage().
    struct sigaction sa = {};
    sa.sa_handler = signalHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; // No SA_RESTART so waitpid gets EINTR
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    fs::path cmd, exec_dir;
    std::string cgroup, cpu_set, cpu_max, usage_stat_file;
    uint64_t mem_limit = 0;
    uint64_t tmp_size = 0;
    uint64_t fsize_max = 0;
    uid_t uid = NOBODY_UID;
    int stop_fifo = -1;
    bool no_swap = false;
    bool oom_group = false;
    std::vector<char *> cmd_args = {nullptr}; // reserved for cmd path
    std::vector<char *> cmd_env;
    int ignored_flags = 0;
    struct file_arg {
        std::string src;
        fs::path dst;
        bool elf;
    };
    std::vector<file_arg> files;
    std::vector<std::pair<std::string, fs::path>> mounts;

    // All arguments are checked before anything is made, so --uid reads /etc before any mount

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

            validate_path_in_sandbox(argv[i + 2], "add_file destination");
            files.push_back({argv[i + 1], fs::path(argv[i + 2]).lexically_normal(),
                             strcmp(argv[i], "--add_elf_file") == 0});

            i += 3;

        } else if (strcmp(argv[i], "--mount_dir") == 0) {
            if (i + 3 > argc || strncmp(argv[i + 1], "--", 2) == 0 || strncmp(argv[i + 2], "--", 2) == 0)
                print_usage();

            validate_path_in_sandbox(argv[i + 2], "mount destination");
            mounts.emplace_back(argv[i + 1], fs::path(argv[i + 2]).lexically_normal());

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

        } else if (strcmp(argv[i], "--fsize_max") == 0) {
            if (i + 2 > argc || strncmp(argv[i + 1], "--", 2) == 0)
                print_usage();

            if (fsize_max)
                fatal("--fsize_max is given twice");
            if (!parse_number(argv[i + 1], fsize_max) || fsize_max == 0 || fsize_max > MAX_FSIZE)
                fatal("--fsize_max must be 1-" + std::to_string(MAX_FSIZE) + " bytes");

            i += 2;

        } else {
            print_usage();
        }
    }

    if (stop_fifo >= 0 && !stop_grace)
        stop_grace = DEFAULT_STOP_GRACE;

    if (mem_limit && cgroup.empty())
        fatal("cannot set memory limit without cgroup name");

    if (no_swap && !mem_limit)
        fatal("cannot forbid swap without memory limit");

    if (oom_group && !mem_limit)
        fatal("cannot group OOM kills without memory limit");

    if (!cpu_max.empty() && cgroup.empty())
        fatal("cannot set cpu.max without cgroup name");

    // Give the parent its OWN mount namespace before any --mount_dir bind (made
    // below). Binds then exist only in this private namespace and are torn
    // down by the kernel the instant the process dies -
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

    open_parent();
    make_sandbox();
    init_dirs();

    // Files first: a file is never put through a mount into a host folder
    for (const auto &f: files)
        add_file(f.src, f.dst, f.elf);
    for (const auto &m: mounts)
        mount_dir(m.first, m.second);

    int flags = CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWPID | CLONE_NEWCGROUP | SIGCHLD;
    if ((ignored_flags & CLONE_NEWNET) == 0)
        flags |= CLONE_NEWNET;

    cmd_args[0] = const_cast<char *>(cmd.c_str());
    cmd_args.push_back(nullptr);
    cmd_env.push_back(nullptr);

    return execute(cmd, cmd_args, cmd_env, flags, cgroup, cpu_set, cpu_max, mem_limit, no_swap, oom_group,
                   usage_stat_file, exec_dir, uid, tmp_size, stop_fifo, fsize_max);
}
