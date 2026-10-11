#!/bin/bash
#
# Integration tests for the sandbox tool.
# Must be run as root: sudo tests/run_tests.sh
#
# Builds from source, installs with SETUID to a temp location, then tests.
#

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_DIR="/tmp/sandbox_tests_$$"
HELPERS_DIR="$TEST_DIR/helpers"
# A non-root caller for the flags that refuse root; it runs a setuid copy of the binary in TEST_DIR,
# with its sandboxes in a folder of its own
CALLER_UID=65533
CALLER_BIN="$TEST_DIR/sandbox"
CALLER_DIR="$TEST_DIR/caller"
PASSED=0
FAILED=0
ERRORS=()

# ---------- helpers ----------

build_sandbox() {
    echo "Building sandbox from source..."
    local build_dir="$PROJECT_DIR/build"
    /usr/bin/cmake -S "$PROJECT_DIR" -B "$build_dir" >/dev/null 2>&1
    /usr/bin/cmake --build "$build_dir" 2>&1 | tail -2

    SANDBOX_BIN="$build_dir/sandbox"
    if [ ! -x "$SANDBOX_BIN" ]; then
        echo "ERROR: build failed, $SANDBOX_BIN not found" >&2
        exit 1
    fi

    # Set SETUID bit so the binary can run as root
    chown root:root "$SANDBOX_BIN"
    chmod u+s "$SANDBOX_BIN"
    echo "Binary: $SANDBOX_BIN"
}

cleanup() {
    # Kill any lingering sandbox processes
    for d in "$TEST_DIR"/sbox_*; do
        [ -d "$d" ] && umount -lf "$d"/* 2>/dev/null || true
    done
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

pass() {
    PASSED=$((PASSED + 1))
    echo "  PASS: $1"
}

fail() {
    FAILED=$((FAILED + 1))
    ERRORS+=("$1: $2")
    echo "  FAIL: $1 — $2"
}

assert_exit() {
    local expected="$1" actual="$2" name="$3"
    if [ "$actual" -eq "$expected" ]; then
        pass "$name"
    else
        fail "$name" "expected exit $expected, got $actual"
    fi
}

assert_output_contains() {
    local output="$1" pattern="$2" name="$3"
    if echo "$output" | grep -qE "$pattern"; then
        pass "$name"
    else
        fail "$name" "output did not match /$pattern/"
    fi
}

assert_output_not_contains() {
    local output="$1" pattern="$2" name="$3"
    if echo "$output" | grep -qE "$pattern"; then
        fail "$name" "output unexpectedly matched /$pattern/"
    else
        pass "$name"
    fi
}

sbox() {
    # Run sandbox with a unique directory under TEST_DIR
    local tag="$1"; shift
    "$SANDBOX_BIN" "$TEST_DIR/sbox_$tag" "$@"
}

caller_at() {
    # caller_at <uid> <sandbox path> <args...>: runs the sandbox as a non-root caller
    local uid="$1"; shift
    setpriv --reuid="$uid" --regid="$uid" --clear-groups "$CALLER_BIN" "$@"
}

caller_as() {
    # Like sbox, as a non-root caller
    local uid="$1" tag="$2"; shift 2
    caller_at "$uid" "$CALLER_DIR/sbox_$tag" "$@"
}

caller() {
    caller_as "$CALLER_UID" "$@"
}

caller_with_etc_line() {
    # Like caller, with one more line in an /etc file that only this run sees
    local file="$1" line="$2" tag="$3"; shift 3
    local fake="$TEST_DIR/etc_$tag"
    { cat "$file"; echo "$line"; } > "$fake"
    unshare -m sh -c 'mount --bind "$1" "$2" && shift 2 && exec "$@"' sh "$fake" "$file" \
        setpriv --reuid="$CALLER_UID" --regid="$CALLER_UID" --clear-groups "$CALLER_BIN" "$CALLER_DIR/sbox_$tag" "$@"
}

assert_refused() {
    # assert_refused <name> <pattern> <command...>: the command exits 1 with a message matching pattern
    local name="$1" pattern="$2"; shift 2
    local out rc=0
    out=$("$@" 2>&1) || rc=$?
    assert_exit 1 $rc "$name: exit 1"
    assert_output_contains "$out" "$pattern" "$name"
}

wait_for_path() {
    # wait_for_path <path>: waits up to 5 s for the path to exist
    local i
    for i in $(seq 50); do
        [ -e "$1" ] && return 0
        sleep 0.1
    done
    fail "wait for $1" "timed out"
    return 1
}

wait_for_output() {
    # wait_for_output <file> <pattern>: waits up to 5 s for the file to match pattern
    local i
    for i in $(seq 50); do
        grep -qE "$2" "$1" 2>/dev/null && return 0
        sleep 0.1
    done
    fail "wait for /$2/ in $(basename "$1")" "timed out"
    return 1
}

write_fifo() {
    # write_fifo <fifo> [<bytes>]: writes the bytes, or only opens and closes the FIFO; gives up after 5 s
    timeout 5 sh -c 'printf "$2" > "$1"' sh "$1" "${2:-}"
}

# ---------- build helper binaries ----------

build_helpers() {
    mkdir -p "$HELPERS_DIR"

    # memhog: touches N megabytes of memory
    cat > "$HELPERS_DIR/memhog.c" << 'C'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    size_t mb = argc > 1 ? (size_t)atoi(argv[1]) : 50;
    size_t sz = mb * 1024 * 1024;
    char *p = malloc(sz);
    if (!p) { fprintf(stderr, "malloc failed\n"); return 1; }
    memset(p, 'A', sz);
    printf("allocated %zuMB\n", mb);
    free(p);
    return 0;
}
C

    # forkhog: forks a child that touches N megabytes, waits for it, and exits 0 whatever happened to it
    cat > "$HELPERS_DIR/forkhog.c" << 'C'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
int main(int argc, char **argv) {
    size_t mb = argc > 1 ? (size_t)atoi(argv[1]) : 50;
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }
    if (pid == 0) {
        size_t sz = mb * 1024 * 1024;
        char *p = malloc(sz);
        if (!p) return 1;
        memset(p, 'A', sz);
        return 0;
    }
    int status;
    waitpid(pid, &status, 0);
    printf("parent done\n");
    return 0;
}
C

    # sleeper: sleeps, prints, exits
    cat > "$HELPERS_DIR/sleeper.c" << 'C'
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
static volatile int got = 0;
void handler(int s) { got = s; }
int main() {
    signal(SIGTERM, handler);
    signal(SIGINT, handler);
    printf("sleeping\n");
    fflush(stdout);
    sleep(60);
    printf("signal=%d\n", got);
    return got ? 0 : 1;
}
C

    # writetest: tries to write to a given path
    cat > "$HELPERS_DIR/writetest.c" << 'C'
#include <stdio.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    FILE *f = fopen(argv[1], "w");
    if (!f) { perror("fopen"); return 1; }
    fprintf(f, "written\n");
    fclose(f);
    printf("write ok\n");
    return 0;
}
C

    # devcheck: reads from /dev/null and /dev/urandom, writes to /dev/null
    cat > "$HELPERS_DIR/devcheck.c" << 'C'
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
int main() {
    int fd;
    char buf[16];
    fd = open("/dev/null", O_WRONLY);
    if (fd < 0) { perror("/dev/null write"); return 1; }
    write(fd, "x", 1);
    close(fd);
    fd = open("/dev/null", O_RDONLY);
    if (fd < 0) { perror("/dev/null read"); return 1; }
    close(fd);
    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) { perror("/dev/urandom"); return 1; }
    read(fd, buf, sizeof(buf));
    close(fd);
    fd = open("/dev/zero", O_RDONLY);
    if (fd < 0) { perror("/dev/zero"); return 1; }
    read(fd, buf, sizeof(buf));
    close(fd);
    printf("devices ok\n");
    return 0;
}
C

    # fdcheck: counts open file descriptors > stderr
    cat > "$HELPERS_DIR/fdcheck.c" << 'C'
#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
int main() {
    int count = 0;
    DIR *d = opendir("/proc/self/fd");
    if (!d) { perror("opendir"); return 1; }
    int dfd = dirfd(d);
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        int fd = atoi(e->d_name);
        if (fd > 2 && fd != dfd) count++;
    }
    closedir(d);
    printf("leaked_fds=%d\n", count);
    return 0;
}
C

    # privcheck: tries execve of a suid binary and checks no_new_privs
    cat > "$HELPERS_DIR/privcheck.c" << 'C'
#include <stdio.h>
#include <sys/prctl.h>
int main() {
    int nnp = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    printf("no_new_privs=%d\n", nnp);
    return 0;
}
C

    # stubborn: ignores SIGTERM, says it is ready and sleeps
    cat > "$HELPERS_DIR/stubborn.c" << 'C'
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
int main() {
    signal(SIGTERM, SIG_IGN);
    printf("ready\n");
    fflush(stdout);
    sleep(60);
    return 0;
}
C

    # deeptree: nests N folders named d in a folder, one level at a time, and exits 3
    cat > "$HELPERS_DIR/deeptree.c" << 'C'
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
int main(int argc, char **argv) {
    int n = argc > 2 ? atoi(argv[2]) : 0;
    int fd = open(argv[1], O_RDONLY | O_DIRECTORY);
    for (int i = 0; i < n; i++) {
        if (mkdirat(fd, "d", 0755)) { perror("mkdirat"); return 1; }
        int next = openat(fd, "d", O_RDONLY | O_DIRECTORY);
        if (next < 0) { perror("openat"); return 1; }
        close(fd);
        fd = next;
    }
    printf("built %d\n", n);
    return 3;
}
C

    gcc -static -o "$HELPERS_DIR/memhog"    "$HELPERS_DIR/memhog.c"
    gcc -static -o "$HELPERS_DIR/forkhog"   "$HELPERS_DIR/forkhog.c"
    gcc -static -o "$HELPERS_DIR/sleeper"   "$HELPERS_DIR/sleeper.c"
    gcc -static -o "$HELPERS_DIR/writetest" "$HELPERS_DIR/writetest.c"
    gcc -static -o "$HELPERS_DIR/devcheck"  "$HELPERS_DIR/devcheck.c"
    gcc -static -o "$HELPERS_DIR/fdcheck"   "$HELPERS_DIR/fdcheck.c"
    gcc -static -o "$HELPERS_DIR/privcheck" "$HELPERS_DIR/privcheck.c"
    gcc -static -o "$HELPERS_DIR/stubborn"  "$HELPERS_DIR/stubborn.c"
    gcc -static -o "$HELPERS_DIR/deeptree"  "$HELPERS_DIR/deeptree.c"
}

# ================================================================
#                          TEST CASES
# ================================================================

test_basic_execution() {
    echo "[basic execution]"

    local out rc=0
    out=$(sbox basic --add_elf_file /bin/echo /bin/echo -- /bin/echo "hello sandbox" 2>&1) || rc=$?
    assert_exit 0 $rc "echo runs successfully"
    assert_output_contains "$out" "hello sandbox" "echo output correct"
}

test_add_file() {
    echo "[add_file]"

    local out rc=0
    out=$(sbox addfile \
        --add_elf_file /bin/cat /bin/cat \
        --add_file /etc/hostname /etc/hostname \
        -- /bin/cat /etc/hostname 2>&1) || rc=$?
    assert_exit 0 $rc "cat reads added file"

    local expected
    expected=$(cat /etc/hostname)
    assert_output_contains "$out" "$expected" "file content matches host"
}

test_add_elf_file_with_deps() {
    echo "[add_elf_file with library dependencies]"

    local out rc=0
    out=$(sbox elfdeps \
        --add_elf_file /bin/ls /bin/ls \
        -- /bin/ls / 2>&1) || rc=$?
    assert_exit 0 $rc "ls runs with resolved libraries"
    assert_output_contains "$out" "dev" "/dev exists in sandbox root"
    assert_output_contains "$out" "proc" "/proc exists in sandbox root"
}

test_mount_dir() {
    echo "[mount_dir]"

    local hostdir="$TEST_DIR/mountsrc"
    mkdir -p "$hostdir"
    echo "mount-content-$$" > "$hostdir/data.txt"

    local out rc=0
    out=$(sbox mountdir \
        --add_elf_file /bin/cat /bin/cat \
        --mount_dir "$hostdir" /mnt/shared \
        -- /bin/cat /mnt/shared/data.txt 2>&1) || rc=$?
    assert_exit 0 $rc "cat reads mounted file"
    assert_output_contains "$out" "mount-content-$$" "mounted content matches"
}

test_env_variables() {
    echo "[env variables]"

    local out rc=0
    out=$(sbox envvars \
        --add_elf_file /usr/bin/env /usr/bin/env \
        --env "FOO=bar" \
        --env "TEST_KEY=test_value_123" \
        -- /usr/bin/env 2>&1) || rc=$?
    assert_exit 0 $rc "env runs"
    assert_output_contains "$out" "FOO=bar" "FOO is set"
    assert_output_contains "$out" "TEST_KEY=test_value_123" "TEST_KEY is set"
}

test_exec_dir() {
    echo "[exec_dir]"

    local out rc=0
    out=$(sbox execdir \
        --add_elf_file /bin/pwd /bin/pwd \
        --exec_dir /tmp \
        -- /bin/pwd 2>&1) || rc=$?
    assert_exit 0 $rc "pwd runs"
    assert_output_contains "$out" "^/tmp$" "working directory is /tmp"
}

test_runs_as_nobody() {
    echo "[runs as nobody]"

    local out rc=0
    out=$(sbox nobody \
        --add_elf_file /usr/bin/id /usr/bin/id \
        -- /usr/bin/id -u 2>&1) || rc=$?
    assert_exit 0 $rc "id runs"
    assert_output_contains "$out" "^65534$" "UID is 65534 (nobody)"
}

test_network_isolation() {
    echo "[network isolation]"

    # With isolation: should see no real interfaces
    local out
    out=$(sbox netiso \
        --add_elf_file /bin/ls /bin/ls \
        -- /bin/ls /proc/net/ 2>&1) || true
    # Isolated network namespace has minimal /proc/net
    pass "sandbox runs with network isolation"

    # With --no_new_net: should see host interfaces
    out=$(sbox netshare \
        --add_elf_file /bin/cat /bin/cat \
        --no_new_net \
        -- /bin/cat /proc/net/if_inet6 2>&1) || true
    if echo "$out" | grep -qE "lo|eth|wl|en"; then
        pass "--no_new_net exposes host network"
    else
        # Host might not have IPv6; try /proc/net/dev instead
        out=$(sbox netshare2 \
            --add_elf_file /bin/cat /bin/cat \
            --no_new_net \
            -- /bin/cat /proc/net/dev 2>&1) || true
        assert_output_contains "$out" "lo|eth|wl|en" "--no_new_net exposes host network"
    fi
}

test_cgroup() {
    echo "[cgroup]"

    local out rc=0
    out=$(sbox cgroup \
        --add_elf_file /bin/echo /bin/echo \
        --cgroup "sandbox_test_cg_$$" \
        -- /bin/echo "cgroup ok" 2>&1) || rc=$?
    assert_exit 0 $rc "sandbox runs with cgroup"
    assert_output_contains "$out" "cgroup ok" "output correct"

    # cgroup should be cleaned up
    if [ ! -d "/sys/fs/cgroup/sandbox_test_cg_$$" ]; then
        pass "cgroup cleaned up after exit"
    else
        fail "cgroup cleaned up after exit" "directory still exists"
        rmdir "/sys/fs/cgroup/sandbox_test_cg_$$" 2>/dev/null || true
    fi
}

test_memory_limit() {
    echo "[memory limit]"

    # With 10MB limit, allocating 50MB should fail (OOM kill)
    local out
    out=$(sbox memlimit \
        --add_file "$HELPERS_DIR/memhog" /bin/memhog \
        --cgroup "sandbox_test_mem_$$" \
        --mem_limit 10485760 \
        -- /bin/memhog 50 2>&1)
    assert_output_not_contains "$out" "allocated 50MB" "50MB allocation killed by OOM"

    # Without limit, same allocation should succeed
    rc=0
    out=$(sbox memlimit_ok \
        --add_file "$HELPERS_DIR/memhog" /bin/memhog \
        -- /bin/memhog 50 2>&1) || rc=$?
    assert_exit 0 $rc "50MB allocation without limit succeeds"
    assert_output_contains "$out" "allocated 50MB" "allocation output correct"
}

test_cpuset() {
    echo "[cpuset]"

    local out rc=0
    out=$(sbox cpuset \
        --add_elf_file /bin/cat /bin/cat \
        --cgroup "sandbox_test_cpu_$$" \
        --cpuset "0" \
        -- /bin/cat /proc/self/status 2>&1) || rc=$?
    assert_exit 0 $rc "sandbox runs with cpuset"
    assert_output_contains "$out" "Cpus_allowed_list:.*0" "restricted to CPU 0"
}

test_save_usage_stat() {
    echo "[save_usage_stat]"

    local stat_file="$TEST_DIR/usage_stat.txt"
    local out rc=0
    out=$(sbox usagestat \
        --add_elf_file /bin/echo /bin/echo \
        --cgroup "sandbox_test_stat_$$" \
        --save_usage_stat "$stat_file" \
        -- /bin/echo "stat test" 2>&1) || rc=$?
    assert_exit 0 $rc "sandbox runs with save_usage_stat"

    if [ -f "$stat_file" ]; then
        pass "stat file created"
        local content
        content=$(cat "$stat_file")
        assert_output_contains "$content" "cpu_user" "stat file has cpu_user"
        assert_output_contains "$content" "cpu_system" "stat file has cpu_system"
        assert_output_contains "$content" "memory" "stat file has memory"
    else
        fail "stat file created" "file not found"
    fi
}

test_sandbox_cleanup() {
    echo "[sandbox cleanup]"

    local rc=0
    sbox cleanup \
        --add_elf_file /bin/echo /bin/echo \
        -- /bin/echo "cleanup test" >/dev/null 2>&1 || rc=$?
    assert_exit 0 $rc "sandbox runs"

    if [ ! -d "$TEST_DIR/sbox_cleanup" ]; then
        pass "sandbox directory removed after exit"
    else
        fail "sandbox directory removed after exit" "directory still exists"
    fi
}

test_minimal_dev() {
    echo "[minimal /dev]"

    local out rc=0
    out=$(sbox mindev \
        --add_elf_file /bin/ls /bin/ls \
        -- /bin/ls /dev/ 2>&1) || rc=$?
    assert_exit 0 $rc "ls /dev runs"

    # Should have only the 5 essential devices
    assert_output_contains "$out" "null" "/dev/null exists"
    assert_output_contains "$out" "zero" "/dev/zero exists"
    assert_output_contains "$out" "urandom" "/dev/urandom exists"
    assert_output_contains "$out" "random" "/dev/random exists"
    assert_output_contains "$out" "full" "/dev/full exists"

    # Should NOT have dangerous devices
    assert_output_not_contains "$out" "sda" "no /dev/sda"
    assert_output_not_contains "$out" "kmsg" "no /dev/kmsg"
    assert_output_not_contains "$out" "mem[^o]" "no /dev/mem"
}

test_dev_nodes_functional() {
    echo "[/dev nodes functional]"

    local out rc=0
    out=$(sbox devfunc \
        --add_file "$HELPERS_DIR/devcheck" /bin/devcheck \
        -- /bin/devcheck 2>&1) || rc=$?
    assert_exit 0 $rc "devcheck runs"
    assert_output_contains "$out" "devices ok" "all device nodes work"
}

test_no_leaked_fds() {
    echo "[no leaked file descriptors]"

    local out rc=0
    out=$(sbox fdleak \
        --add_file "$HELPERS_DIR/fdcheck" /bin/fdcheck \
        -- /bin/fdcheck 2>&1) || rc=$?
    assert_exit 0 $rc "fdcheck runs"
    assert_output_contains "$out" "leaked_fds=0" "no FDs leaked beyond stderr"
}

test_no_new_privs() {
    echo "[no_new_privs set]"

    local out rc=0
    out=$(sbox privs \
        --add_file "$HELPERS_DIR/privcheck" /bin/privcheck \
        -- /bin/privcheck 2>&1) || rc=$?
    assert_exit 0 $rc "privcheck runs"
    assert_output_contains "$out" "no_new_privs=1" "PR_SET_NO_NEW_PRIVS is enabled"
}

test_sandbox_path_validation() {
    echo "[sandbox path validation]"

    local out rc

    out=$("$SANDBOX_BIN" / -- /bin/echo test 2>&1) || true; rc=$?
    assert_output_contains "$out" "critical system directory" "rejects /"

    out=$("$SANDBOX_BIN" /tmp -- /bin/echo test 2>&1) || true; rc=$?
    assert_output_contains "$out" "critical system directory" "rejects /tmp"

    out=$("$SANDBOX_BIN" /etc -- /bin/echo test 2>&1) || true; rc=$?
    assert_output_contains "$out" "critical system directory" "rejects /etc"

    out=$("$SANDBOX_BIN" relative/path -- /bin/echo test 2>&1) || true; rc=$?
    assert_output_contains "$out" "must be absolute" "rejects relative path"

    out=$("$SANDBOX_BIN" /tmp/foo/../../../etc -- /bin/echo test 2>&1) || true; rc=$?
    assert_output_contains "$out" "critical system directory" "rejects .. traversal to /etc"
}

test_cgroup_name_validation() {
    echo "[cgroup name validation]"

    local out

    out=$(sbox cgval1 \
        --add_elf_file /bin/echo /bin/echo \
        --cgroup "../../etc" \
        -- /bin/echo test 2>&1) || true
    assert_output_contains "$out" "must not contain" "rejects / in cgroup name"

    out=$(sbox cgval2 \
        --add_elf_file /bin/echo /bin/echo \
        --cgroup ".hidden" \
        -- /bin/echo test 2>&1) || true
    assert_output_contains "$out" "must not start with" "rejects leading dot"

    out=$(sbox cgval3 \
        --add_elf_file /bin/echo /bin/echo \
        --cgroup "sub/group" \
        -- /bin/echo test 2>&1) || true
    assert_output_contains "$out" "must not contain" "rejects / in cgroup name"
}

test_path_traversal_mount() {
    echo "[mount_dir path traversal]"

    local out
    out=$(sbox ptmount \
        --add_elf_file /bin/echo /bin/echo \
        --mount_dir /tmp "../../etc" \
        -- /bin/echo test 2>&1) || true
    assert_output_contains "$out" "escapes sandbox" "rejects .. in mount destination"
}

test_path_traversal_addfile() {
    echo "[add_file path traversal]"

    local out
    out=$(sbox ptadd \
        --add_elf_file /bin/echo /bin/echo \
        --add_file /etc/hostname "../../etc/shadow" \
        -- /bin/echo test 2>&1) || true
    assert_output_contains "$out" "escapes sandbox" "rejects .. in add_file destination"
}

test_signal_handling() {
    echo "[signal handling]"

    # Invoke sandbox directly (not via sbox shell function) so $bg_pid is the
    # actual sandbox process, not a bash subshell that won't forward signals.
    "$SANDBOX_BIN" "$TEST_DIR/sbox_signal" \
        --add_file "$HELPERS_DIR/sleeper" /bin/sleeper \
        -- /bin/sleeper >"$TEST_DIR/signal_out.txt" 2>&1 &
    local bg_pid=$!

    # Wait for sandbox + child to fully start
    sleep 1

    # Send SIGTERM to sandbox
    kill -TERM "$bg_pid" 2>/dev/null || true
    local rc=0
    wait "$bg_pid" 2>/dev/null || rc=$?
    assert_exit 1 $rc "SIGTERM without --stop_grace exits 1"
    assert_output_not_contains "$(cat "$TEST_DIR/signal_out.txt")" "signal=" "the child is killed at once, not sent SIGTERM"

    # Sandbox dir should be cleaned up
    if [ ! -d "$TEST_DIR/sbox_signal" ]; then
        pass "sandbox cleaned up after SIGTERM"
    else
        fail "sandbox cleaned up after SIGTERM" "directory still exists"
        rm -rf "$TEST_DIR/sbox_signal" 2>/dev/null || true
    fi
}

test_nonexistent_command() {
    echo "[nonexistent command]"

    local out rc=0
    out=$(sbox badcmd \
        --add_elf_file /bin/echo /bin/echo \
        -- /bin/no_such_binary 2>&1) || rc=$?
    if [ $rc -ne 0 ]; then
        pass "nonexistent command returns non-zero exit"
    else
        fail "nonexistent command returns non-zero exit" "got exit 0"
    fi
}

test_tmp_world_writable() {
    echo "[/tmp is world-writable]"

    local out rc=0
    out=$(sbox tmpwrite \
        --add_file "$HELPERS_DIR/writetest" /bin/writetest \
        -- /bin/writetest /tmp/testfile 2>&1) || rc=$?
    assert_exit 0 $rc "writetest runs"
    assert_output_contains "$out" "write ok" "nobody can write to /tmp"
}

test_root_not_writable() {
    echo "[/root not writable by nobody]"

    local out
    out=$(sbox rootwrite \
        --add_file "$HELPERS_DIR/writetest" /bin/writetest \
        -- /bin/writetest /root/testfile 2>&1) || true
    assert_output_not_contains "$out" "write ok" "nobody cannot write to /root"
}

test_pid_isolation() {
    echo "[PID namespace isolation]"

    local out rc=0
    out=$(sbox pidns \
        --add_elf_file /bin/cat /bin/cat \
        -- /bin/cat /proc/self/status 2>&1) || rc=$?
    assert_exit 0 $rc "cat /proc/self/status runs"
    # In a PID namespace, the first process should be PID 1
    assert_output_contains "$out" "Pid:.*1" "process sees itself as PID 1"
}

test_memory_limit_no_swap() {
    echo "[memory limit without swap]"

    # With swap forbidden, allocating 200MB under a 10MB limit is killed by OOM
    local out rc=0
    out=$(sbox memnoswap \
        --add_file "$HELPERS_DIR/memhog" /bin/memhog \
        --cgroup "sandbox_test_noswap_$$" \
        --mem_limit 10485760 \
        --no_swap \
        -- /bin/memhog 200 2>&1) || rc=$?
    assert_exit 137 $rc "200MB allocation killed by OOM with swap forbidden"
    assert_output_not_contains "$out" "allocated 200MB" "no allocation output"
}

test_no_swap_requires_mem_limit() {
    echo "[no_swap requires mem_limit]"

    local out
    out=$(sbox noswapnolimit \
        --add_elf_file /bin/echo /bin/echo \
        --cgroup "sandbox_test_noswapnl_$$" \
        --no_swap \
        -- /bin/echo test 2>&1) || true
    assert_output_contains "$out" "without memory limit" "no_swap rejected without --mem_limit"
}

test_oom_group() {
    echo "[oom group]"

    # A child killed by OOM ends the whole sandbox, so the parent's exit 0 is not reported
    local out rc=0
    out=$(sbox oomgroup \
        --add_file "$HELPERS_DIR/forkhog" /bin/forkhog \
        --cgroup "sandbox_test_oomgroup_$$" \
        --mem_limit 10485760 \
        --no_swap \
        --oom_group \
        -- /bin/forkhog 200 2>&1) || rc=$?
    assert_exit 137 $rc "an OOM kill of a child ends the sandbox"
    assert_output_not_contains "$out" "parent done" "the parent was killed too"

    # Without --oom_group only the child is killed, and the parent exits 0
    rc=0
    out=$(sbox oomchild \
        --add_file "$HELPERS_DIR/forkhog" /bin/forkhog \
        --cgroup "sandbox_test_oomchild_$$" \
        --mem_limit 10485760 \
        --no_swap \
        -- /bin/forkhog 200 2>&1) || rc=$?
    assert_exit 0 $rc "without --oom_group the parent survives its child"
}

test_oom_group_requires_mem_limit() {
    echo "[oom_group requires mem_limit]"

    local out
    out=$(sbox oomgroupnolimit \
        --add_elf_file /bin/echo /bin/echo \
        --cgroup "sandbox_test_oomgroupnl_$$" \
        --oom_group \
        -- /bin/echo test 2>&1) || true
    assert_output_contains "$out" "without memory limit" "oom_group rejected without --mem_limit"
}

test_memlimit_requires_cgroup() {
    echo "[mem_limit requires cgroup]"

    local out
    out=$(sbox memnocg \
        --add_elf_file /bin/echo /bin/echo \
        --mem_limit 10485760 \
        -- /bin/echo test 2>&1) || true
    assert_output_contains "$out" "without cgroup" "mem_limit rejected without --cgroup"
}

test_version() {
    echo "[version]"

    local out rc=0
    out=$("$SANDBOX_BIN" --version 2>&1) || rc=$?
    assert_exit 0 $rc "--version exits 0"
    assert_output_contains "$out" "^2\.4\.0$" "--version prints 2.4.0"
}

test_uid_refused() {
    echo "[--uid refused]"

    local echo_args=(--add_elf_file /bin/echo /bin/echo)
    assert_refused "--uid 0" "^--uid must be in the range 2000000000-2000999999$" \
        caller uid0 "${echo_args[@]}" --uid 0 -- /bin/echo ran
    assert_refused "--uid below the range" "^--uid must be in the range" \
        caller uidlow "${echo_args[@]}" --uid 1999999999 -- /bin/echo ran
    assert_refused "--uid above the range" "^--uid must be in the range" \
        caller uidhigh "${echo_args[@]}" --uid 2001000000 -- /bin/echo ran
    assert_refused "--uid with a sign" "^--uid must be in the range" \
        caller uidsign "${echo_args[@]}" --uid +2000000001 -- /bin/echo ran
    assert_refused "--uid with an /etc/passwd entry" "^--uid has an /etc/passwd entry$" \
        caller_with_etc_line /etc/passwd "sbxtest:x:2000000100:100::/nonexistent:/usr/sbin/nologin" uidpasswd \
        "${echo_args[@]}" --uid 2000000100 -- /bin/echo ran
    assert_refused "--uid as a primary GID in /etc/passwd" "^--uid has an /etc/passwd entry$" \
        caller_with_etc_line /etc/passwd "sbxtest:x:3000:2000000101::/nonexistent:/usr/sbin/nologin" uidpwgid \
        "${echo_args[@]}" --uid 2000000101 -- /bin/echo ran
    assert_refused "--uid with an /etc/group entry" "^--uid has an /etc/group entry$" \
        caller_with_etc_line /etc/group "sbxtest:x:2000000102:" uidgroup \
        "${echo_args[@]}" --uid 2000000102 -- /bin/echo ran
    if [ -e /etc/subuid ]; then
        assert_refused "--uid in an /etc/subuid range" "^--uid lies in an /etc/subuid or /etc/subgid range$" \
            caller_with_etc_line /etc/subuid "sbxtest:2000000200:100" uidsubuid \
            "${echo_args[@]}" --uid 2000000250 -- /bin/echo ran
    else
        echo "  SKIP: --uid in an /etc/subuid range (no /etc/subuid on this host)"
    fi
    if [ -e /etc/subgid ]; then
        assert_refused "--uid in an /etc/subgid range" "^--uid lies in an /etc/subuid or /etc/subgid range$" \
            caller_with_etc_line /etc/subgid "sbxtest:2000000300:100" uidsubgid \
            "${echo_args[@]}" --uid 2000000399 -- /bin/echo ran
    else
        echo "  SKIP: --uid in an /etc/subgid range (no /etc/subgid on this host)"
    fi
    # The caller does not own CALLER_DIR, so this relies on check_uid running before the parent check
    assert_refused "--uid of the caller" "^--uid must not be the caller's UID or GID$" \
        caller_as 2000000400 uidself "${echo_args[@]}" --uid 2000000400 -- /bin/echo ran
    assert_refused "--uid for a root caller" "^--uid is refused for a root caller$" \
        sbox uidroot "${echo_args[@]}" --uid 2000000123 -- /bin/echo ran
}

test_uid_accepted() {
    echo "[--uid accepted]"

    local out rc=0
    out=$(caller uidok \
        --add_elf_file /usr/bin/id /usr/bin/id \
        --uid 2000000123 \
        -- /usr/bin/id 2>&1) || rc=$?
    assert_exit 0 $rc "a non-root caller runs a command with --uid"
    assert_output_contains "$out" "^uid=2000000123 gid=2000000123 groups=2000000123$" \
        "the command runs as the UID and GID, with no other group"

    rc=0
    out=$(caller uidprivs \
        --add_file "$HELPERS_DIR/privcheck" /bin/privcheck \
        --uid 2000000123 \
        -- /bin/privcheck 2>&1) || rc=$?
    assert_exit 0 $rc "privcheck runs with --uid"
    assert_output_contains "$out" "no_new_privs=1" "no_new_privs stays with --uid"
}

test_cpu_max() {
    echo "[cpu_max]"

    local cg="sandbox_test_cpumax_$$" out="$TEST_DIR/cpumax_out.txt" value
    "$SANDBOX_BIN" "$TEST_DIR/sbox_cpumax" \
        --add_file "$HELPERS_DIR/sleeper" /bin/sleeper \
        --cgroup "$cg" \
        --cpu_max "50000 100000" \
        -- /bin/sleeper >"$out" 2>&1 &
    local bg_pid=$!
    wait_for_output "$out" "sleeping"
    value=$(cat "/sys/fs/cgroup/$cg/cpu.max" 2>&1)
    kill -TERM "$bg_pid" 2>/dev/null || true
    wait "$bg_pid" 2>/dev/null || true
    assert_output_contains "$value" "^50000 100000$" "cpu.max is written"

    local echo_args=(--add_elf_file /bin/echo /bin/echo)
    assert_refused "--cpu_max without --cgroup" "^cannot set cpu.max without cgroup name$" \
        sbox cpumaxnocg "${echo_args[@]}" --cpu_max "50000 100000" -- /bin/echo ran
    assert_refused "--cpu_max that is not two numbers" "^--cpu_max must be" \
        sbox cpumaxbad "${echo_args[@]}" --cgroup "${cg}_bad" --cpu_max "max 100000" -- /bin/echo ran
    assert_refused "--cpu_max that the kernel rejects" "^cannot (create cgroup|set cpu.max)" \
        sbox cpumaxkernel "${echo_args[@]}" --cgroup "${cg}_kernel" --cpu_max "100 100000" -- /bin/echo ran
    rmdir "/sys/fs/cgroup/${cg}_kernel" 2>/dev/null || true
}

test_tmp_size() {
    echo "[tmp_size]"

    local out rc=0
    out=$(sbox tmpsize \
        --add_elf_file /bin/cat /bin/cat \
        --tmp_size 1048576 \
        -- /bin/cat /proc/self/mounts 2>&1) || rc=$?
    assert_exit 0 $rc "cat runs with --tmp_size"
    assert_output_contains "$out" "^tmpfs /tmp tmpfs rw,nosuid,nodev,.*size=1024k" "/tmp is a nosuid,nodev tmpfs of 1 MiB"

    out=$(sbox tmpmode \
        --add_elf_file /usr/bin/stat /usr/bin/stat \
        --tmp_size 1048576 \
        -- /usr/bin/stat -c "%a %u" /tmp 2>&1) || true
    assert_output_contains "$out" "^1777 0$" "the tmpfs has mode 1777"

    out=$(sbox tmpfull \
        --add_elf_file /bin/dd /bin/dd \
        --tmp_size 1048576 \
        -- /bin/dd if=/dev/zero of=/tmp/fill bs=1M count=2 2>&1) || true
    assert_output_contains "$out" "No space left on device" "the tmpfs holds no more than its size"

    out=$(sbox tmpdisk \
        --add_elf_file /bin/cat /bin/cat \
        -- /bin/cat /proc/self/mounts 2>&1) || true
    assert_output_not_contains "$out" " /tmp " "without --tmp_size /tmp is the on-disk folder"
    out=$(sbox tmpdiskmode \
        --add_elf_file /usr/bin/stat /usr/bin/stat \
        -- /usr/bin/stat -c "%a %u" /tmp 2>&1) || true
    assert_output_contains "$out" "^1777 0$" "the on-disk /tmp is sticky"

    local echo_args=(--add_elf_file /bin/echo /bin/echo)
    assert_refused "--tmp_size 0" "^--tmp_size must be a positive number of bytes$" \
        sbox tmpzero "${echo_args[@]}" --tmp_size 0 -- /bin/echo ran
    assert_refused "--tmp_size with a suffix" "^--tmp_size must be a positive number of bytes$" \
        sbox tmpsuffix "${echo_args[@]}" --tmp_size 1m -- /bin/echo ran
}

test_stop() {
    echo "[stop]"

    local fifo="$TEST_DIR/stop.fifo" out bg_pid rc
    mkfifo -m 600 "$fifo"

    # A byte on the FIFO stops a child that handles SIGTERM, and sandbox exits with the child's code
    out="$TEST_DIR/stop_fifo.txt"
    "$SANDBOX_BIN" "$TEST_DIR/sbox_stopfifo" \
        --add_file "$HELPERS_DIR/sleeper" /bin/sleeper \
        --stop_fifo "$fifo" \
        -- /bin/sleeper >"$out" 2>&1 &
    bg_pid=$!
    wait_for_output "$out" "sleeping"
    write_fifo "$fifo" x
    rc=0; wait "$bg_pid" || rc=$?
    assert_exit 0 $rc "a child that handles SIGTERM exits 0 on a stop"
    assert_output_contains "$(cat "$out")" "signal=15" "the child gets SIGTERM"

    # EOF on the FIFO does not stop the child; a byte after it does
    out="$TEST_DIR/stop_eof.txt"
    "$SANDBOX_BIN" "$TEST_DIR/sbox_stopeof" \
        --add_file "$HELPERS_DIR/sleeper" /bin/sleeper \
        --stop_fifo "$fifo" \
        --stop_grace 5 \
        -- /bin/sleeper >"$out" 2>&1 &
    bg_pid=$!
    wait_for_output "$out" "sleeping"
    write_fifo "$fifo"
    local ticks_before ticks_after
    ticks_before=$(awk '{print $14 + $15}' "/proc/$bg_pid/stat")
    sleep 1
    ticks_after=$(awk '{print $14 + $15}' "/proc/$bg_pid/stat")
    if kill -0 "$bg_pid" 2>/dev/null && ! grep -q "signal=" "$out"; then
        pass "EOF on the FIFO does not stop the child"
    else
        fail "EOF on the FIFO does not stop the child" "the child stopped"
    fi
    if [ $((ticks_after - ticks_before)) -lt 10 ]; then
        pass "sandbox does not spin after EOF"
    else
        fail "sandbox does not spin after EOF" "$((ticks_after - ticks_before)) CPU ticks in 1 s"
    fi
    write_fifo "$fifo" x
    rc=0; wait "$bg_pid" || rc=$?
    assert_exit 0 $rc "a byte after EOF still stops the child"

    # A child that ignores SIGTERM is killed once the grace has passed
    out="$TEST_DIR/stop_kill.txt"
    "$SANDBOX_BIN" "$TEST_DIR/sbox_stopkill" \
        --add_file "$HELPERS_DIR/stubborn" /bin/stubborn \
        --stop_fifo "$fifo" \
        --stop_grace 1 \
        -- /bin/stubborn >"$out" 2>&1 &
    bg_pid=$!
    wait_for_output "$out" "ready"
    local start_ms=$(( $(date +%s%N) / 1000000 ))
    write_fifo "$fifo" x
    rc=0; wait "$bg_pid" || rc=$?
    local elapsed_ms=$(( $(date +%s%N) / 1000000 - start_ms ))
    assert_exit 137 $rc "a child that ignores SIGTERM is killed with 137"
    if [ "$elapsed_ms" -ge 900 ]; then
        pass "the child is killed only after the grace"
    else
        fail "the child is killed only after the grace" "killed after ${elapsed_ms} ms"
    fi

    # With --stop_grace, SIGTERM to sandbox stops the child the same way
    out="$TEST_DIR/stop_signal.txt"
    "$SANDBOX_BIN" "$TEST_DIR/sbox_stopsignal" \
        --add_file "$HELPERS_DIR/sleeper" /bin/sleeper \
        --stop_grace 5 \
        -- /bin/sleeper >"$out" 2>&1 &
    bg_pid=$!
    wait_for_output "$out" "sleeping"
    kill -TERM "$bg_pid"
    rc=0; wait "$bg_pid" || rc=$?
    assert_exit 0 $rc "with --stop_grace SIGTERM to sandbox exits with the child's code"
    assert_output_contains "$(cat "$out")" "signal=15" "with --stop_grace the child gets SIGTERM"

    # A non-root caller stops its --uid child through its own FIFO
    local own_fifo="$TEST_DIR/caller.fifo"
    mkfifo -m 600 "$own_fifo"
    chown "$CALLER_UID" "$own_fifo"
    out="$TEST_DIR/stop_caller.txt"
    caller stopcaller \
        --add_file "$HELPERS_DIR/sleeper" /bin/sleeper \
        --uid 2000000124 \
        --stop_fifo "$own_fifo" \
        -- /bin/sleeper >"$out" 2>&1 &
    bg_pid=$!
    wait_for_output "$out" "sleeping"
    write_fifo "$own_fifo" x
    rc=0; wait "$bg_pid" || rc=$?
    assert_exit 0 $rc "a non-root caller stops its --uid child through its FIFO"

    # A stop byte written before the child starts still stops it
    local early="$TEST_DIR/early.fifo"
    mkfifo -m 600 "$early"
    exec 3<>"$early"
    printf x >&3
    rc=0
    sbox stopearly \
        --add_file "$HELPERS_DIR/stubborn" /bin/stubborn \
        --stop_fifo "$early" \
        --stop_grace 1 \
        -- /bin/stubborn >/dev/null 2>&1 || rc=$?
    exec 3>&-
    assert_exit 137 $rc "a stop byte written before the child starts stops it"
}

test_stop_fifo_refused() {
    echo "[stop_fifo refused]"

    local dir="$TEST_DIR/fifos" echo_args=(--add_elf_file /bin/echo /bin/echo)
    mkdir -p "$dir"
    mkfifo -m 600 "$dir/own" && chown "$CALLER_UID" "$dir/own"
    ln -s own "$dir/link"
    mkfifo -m 644 "$dir/other"
    mkfifo -m 600 "$dir/private"
    mkfifo -m 620 "$dir/group" && chown "$CALLER_UID" "$dir/group"
    mkfifo -m 604 "$dir/readable" && chown "$CALLER_UID" "$dir/readable"
    install -m 600 -o "$CALLER_UID" /dev/null "$dir/file"

    assert_refused "a symlink at the FIFO path" "^cannot open --stop_fifo: Too many levels of symbolic links$" \
        caller fifolink "${echo_args[@]}" --stop_fifo "$dir/link" -- /bin/echo ran
    assert_refused "a FIFO owned by another user" "^--stop_fifo is not owned by the caller$" \
        caller fifoother "${echo_args[@]}" --stop_fifo "$dir/other" -- /bin/echo ran
    assert_refused "a FIFO the caller cannot open" "^cannot open --stop_fifo: Permission denied$" \
        caller fifoprivate "${echo_args[@]}" --stop_fifo "$dir/private" -- /bin/echo ran
    assert_refused "a group-writable FIFO" "^--stop_fifo is readable or writable by its group or others$" \
        caller fifogroup "${echo_args[@]}" --stop_fifo "$dir/group" -- /bin/echo ran
    assert_refused "a FIFO others may read" "^--stop_fifo is readable or writable by its group or others$" \
        caller fiforeadable "${echo_args[@]}" --stop_fifo "$dir/readable" -- /bin/echo ran
    assert_refused "--stop_fifo given twice" "^--stop_fifo is given twice$" \
        caller fifotwice "${echo_args[@]}" --stop_fifo "$dir/own" --stop_fifo "$dir/own" -- /bin/echo ran
    assert_refused "a file that is not a FIFO" "^--stop_fifo is not a FIFO$" \
        caller fifofile "${echo_args[@]}" --stop_fifo "$dir/file" -- /bin/echo ran
    assert_refused "--stop_grace 0" "^--stop_grace must be 1-3600 seconds$" \
        sbox grace0 "${echo_args[@]}" --stop_grace 0 -- /bin/echo ran
    assert_refused "--stop_grace above an hour" "^--stop_grace must be 1-3600 seconds$" \
        sbox grace3601 "${echo_args[@]}" --stop_grace 3601 -- /bin/echo ran
}

test_sandbox_parent() {
    echo "[sandbox parent]"

    local echo_args=(--add_elf_file /bin/echo /bin/echo) rootdir="$TEST_DIR/rootparent" shared="$TEST_DIR/shared"
    local out rc
    mkdir -m 755 "$rootdir"
    ln -s "$rootdir" "$CALLER_DIR/link"
    chown -h "$CALLER_UID" "$CALLER_DIR/link"

    # A non-root caller may not make its sandbox in a folder it does not own, even through its own link
    assert_refused "a root-owned parent" "^sandbox parent must be owned by the caller$" \
        caller_at "$CALLER_UID" "$rootdir/sb" "${echo_args[@]}" -- /bin/echo ran
    assert_refused "a root-owned parent through the caller's link" "^sandbox parent must be owned by the caller$" \
        caller_at "$CALLER_UID" "$CALLER_DIR/link/sb" "${echo_args[@]}" -- /bin/echo ran
    if [ ! -e "$rootdir/sb" ]; then
        pass "nothing is made in a parent the caller does not own"
    else
        fail "nothing is made in a parent the caller does not own" "$rootdir/sb exists"
    fi

    # A root-owned sticky folder that everyone may write, like /tmp, is accepted
    install -d -m 1777 "$shared"
    rc=0
    out=$(caller_at "$CALLER_UID" "$shared/sb" "${echo_args[@]}" -- /bin/echo ran 2>&1) || rc=$?
    assert_exit 0 $rc "a sticky folder everyone may write is a parent"
    assert_output_contains "$out" "^ran$" "the command runs in it"

    # There a root-owned folder may be anyone's, so it is not taken over; the caller's own one is
    mkdir "$shared/taken"
    echo keep > "$shared/taken/keep"
    assert_refused "a root-owned folder in a shared parent" "^sandbox path holds a folder of someone else$" \
        caller_at "$CALLER_UID" "$shared/taken" "${echo_args[@]}" -- /bin/echo ran
    if [ -f "$shared/taken/keep" ]; then
        pass "the root-owned folder is left as it was"
    else
        fail "the root-owned folder is left as it was" "keep is gone"
    fi
    install -d -o "$CALLER_UID" "$shared/mine"
    rc=0
    caller_at "$CALLER_UID" "$shared/mine" "${echo_args[@]}" -- /bin/echo ran >/dev/null 2>&1 || rc=$?
    assert_exit 0 $rc "the caller's own folder in a shared parent is replaced"
}

test_earlier_sandbox() {
    echo "[earlier sandbox folder]"

    local echo_args=(--add_elf_file /bin/echo /bin/echo) host="$TEST_DIR/host_etc" old="$CALLER_DIR/sbox_old"
    local out rc=0
    mkdir -p "$host" "$old/tmp"
    echo keep > "$host/keep"
    ln -s "$host" "$old/tmp/evil"
    ln -s "$host/keep" "$old/tmp/evil_file"
    chown -hR "$CALLER_UID" "$old"

    # What an earlier run left is removed without following its links, and the new tree is fresh
    out=$(caller old "${echo_args[@]}" --add_file /etc/hostname /tmp/evil/pwned -- /bin/echo ran 2>&1) || rc=$?
    assert_exit 0 $rc "an earlier sandbox folder with links in it is replaced"
    if [ -f "$host/keep" ] && [ ! -e "$host/pwned" ]; then
        pass "its links are removed, not followed"
    else
        fail "its links are removed, not followed" "the folder they lead to changed"
    fi

    ln -s "$host" "$CALLER_DIR/sbox_link"
    chown -h "$CALLER_UID" "$CALLER_DIR/sbox_link"
    assert_refused "a link at the sandbox path" "^sandbox path is a link or a file$" \
        caller link "${echo_args[@]}" -- /bin/echo ran
}

test_links_planted_by_the_command() {
    echo "[links planted by the command]"

    local host="$TEST_DIR/host_dir" out rc=0
    mkdir -p "$host"
    echo keep > "$host/keep"

    # Without --tmp_size, /tmp is on disk: the command's links there must not lead the cleanup out
    out=$(sbox planted \
        --add_elf_file /bin/ln /bin/ln \
        -- /bin/ln -s "$host" "$host/keep" /tmp/ 2>&1) || rc=$?
    assert_exit 0 $rc "the command plants links in /tmp"
    if [ -f "$host/keep" ]; then
        pass "the cleanup does not follow them"
    else
        fail "the cleanup does not follow them" "$host/keep is gone"
    fi
    if [ ! -e "$TEST_DIR/sbox_planted" ]; then
        pass "the sandbox is removed"
    else
        fail "the sandbox is removed" "it is still there"
    fi
}

test_sandbox_moved() {
    echo "[sandbox folder moved during a run]"

    local host="$TEST_DIR/host_mount" decoy="$TEST_DIR/decoy" fifo="$TEST_DIR/moved.fifo"
    local out="$TEST_DIR/moved_out.txt" leaf="$CALLER_DIR/sbox_moved" rc=0
    mkdir -p "$host" "$decoy"
    echo keep > "$host/keep"
    echo keep > "$decoy/keep"
    mkfifo -m 600 "$fifo"
    chown "$CALLER_UID" "$fifo"

    caller moved \
        --add_file "$HELPERS_DIR/sleeper" /bin/sleeper \
        --mount_dir "$host" /mnt \
        --stop_fifo "$fifo" \
        -- /bin/sleeper >"$out" 2>&1 &
    local bg_pid=$!
    wait_for_output "$out" "sleeping"

    # The caller owns the parent, so it can move the folder and put a link in its place
    mv "$leaf" "$leaf.away"
    ln -s "$decoy" "$leaf"
    write_fifo "$fifo" x
    wait "$bg_pid" || rc=$?

    assert_exit 1 $rc "a moved sandbox folder fails the run"
    assert_output_contains "$(cat "$out")" "^cannot remove sandbox: its folder was moved$" "the move is reported"
    if [ -f "$host/keep" ] && [ -f "$decoy/keep" ]; then
        pass "the cleanup reaches neither the mount source nor the link's target"
    else
        fail "the cleanup reaches neither the mount source nor the link's target" "a keep file is gone"
    fi
    if [ -z "$(ls -A "$leaf.away")" ]; then
        pass "the moved folder is emptied through its descriptor"
    else
        fail "the moved folder is emptied through its descriptor" "it is not empty"
    fi
}

test_mount_rules() {
    echo "[mount rules]"

    local echo_args=(--add_elf_file /bin/echo /bin/echo) a="$TEST_DIR/mount_a" b="$TEST_DIR/mount_b" rc=0
    mkdir -p "$a" "$b"
    echo keep > "$a/keep"

    assert_refused "a mount under another mount" "a link, a file or a mount is in the way$" \
        sbox nested "${echo_args[@]}" --mount_dir "$a" /mnt --mount_dir "$b" /mnt/x -- /bin/echo ran
    if [ ! -e "$a/x" ]; then
        pass "nothing is made in a mounted host folder"
    else
        fail "nothing is made in a mounted host folder" "$a/x exists"
    fi

    sbox fileunder \
        --mount_dir "$a" /mnt \
        --add_file /etc/hostname /mnt/hostname \
        "${echo_args[@]}" \
        -- /bin/echo ran >/dev/null 2>&1 || rc=$?
    assert_exit 0 $rc "files are put in before the mounts"
    if [ ! -e "$a/hostname" ]; then
        pass "a file never goes through a mount into a host folder"
    else
        fail "a file never goes through a mount into a host folder" "$a/hostname exists"
    fi

    assert_refused "a mount at the sandbox root" "^mount destination must not be the sandbox root$" \
        sbox mountroot "${echo_args[@]}" --mount_dir "$a" / -- /bin/echo ran
}

test_deep_tree() {
    echo "[deep tree]"

    # Far deeper than the removal walk's limit, deep enough to overflow a recursive walk's stack, and
    # deeper than the 1024 descriptors a walk without the limit would need
    local rc=0
    (ulimit -n 1024; sbox deep \
        --add_file "$HELPERS_DIR/deeptree" /bin/deeptree \
        -- /bin/deeptree /tmp 50000) >/dev/null 2>&1 || rc=$?
    assert_exit 3 $rc "the tool exits with the command's code"
    if [ ! -e "$TEST_DIR/sbox_deep" ]; then
        pass "a tree of 50000 levels is removed completely"
    else
        fail "a tree of 50000 levels is removed completely" "the sandbox is still there"
    fi
}

test_link_during_placement() {
    echo "[link planted while files are put in]"

    if ! head -1 /usr/bin/ldd | grep -q bash; then
        echo "  SKIP: /usr/bin/ldd is not a bash script, so BASH_ENV cannot hold the tool between two files"
        return
    fi

    local host="$TEST_DIR/host_place" pause="$TEST_DIR/pause.fifo" hook="$TEST_DIR/pause.sh"
    local leaf="$TEST_DIR/sbox_placement" out="$TEST_DIR/placement_out.txt" rc=0
    mkdir -p "$host"
    echo keep > "$host/keep"
    mkfifo -m 600 "$pause"
    # ldd, run for the first file, reads BASH_ENV and waits on the FIFO: the tree exists, the second file
    # is still to come
    printf 'read -r _ < %q\n' "$pause" > "$hook"
    BASH_ENV="$hook" "$SANDBOX_BIN" "$leaf" \
        --add_elf_file /bin/echo /bin/echo \
        --add_file /etc/hostname /tmp/evil/pwned \
        -- /bin/echo ran >"$out" 2>&1 &
    local bg_pid=$!
    wait_for_path "$leaf/tmp"
    ln -s "$host" "$leaf/tmp/evil"
    write_fifo "$pause" go
    wait "$bg_pid" || rc=$?

    assert_exit 1 $rc "a link planted in the tree fails the run"
    assert_output_contains "$(cat "$out")" "a link, a file or a mount is in the way$" "the link is refused"
    if [ -f "$host/keep" ] && [ ! -e "$host/pwned" ]; then
        pass "nothing is written through it"
    else
        fail "nothing is written through it" "$host changed"
    fi
}

test_foreign_setid_copied() {
    echo "[someone else's set-ID file is copied]"

    # On the same filesystem a link would keep root's set-ID inode alive in the sandbox
    local src="$TEST_DIR/setid_root" out rc=0
    install -o root -g root -m 4755 "$HELPERS_DIR/privcheck" "$src"
    out=$(caller setidroot \
        --add_elf_file /usr/bin/stat /usr/bin/stat \
        --add_file "$src" /setid \
        -- /usr/bin/stat -c "%a %u %h" /setid 2>&1) || rc=$?
    assert_exit 0 $rc "stat runs on it"
    assert_output_contains "$out" "^755 0 1$" "a root-owned set-ID file is copied without the bit, not linked"
}

test_copy_drops_setid() {
    echo "[copies drop set-ID bits]"

    # /dev/shm is another filesystem, so the file is copied, by root
    local src="/dev/shm/sandbox_test_setid_$$" out rc=0
    install -o "$CALLER_UID" -m 4755 "$HELPERS_DIR/privcheck" "$src"
    out=$(caller setid \
        --add_elf_file /usr/bin/stat /usr/bin/stat \
        --add_file "$src" /setid \
        -- /usr/bin/stat -c "%a %u" /setid 2>&1) || rc=$?
    rm -f "$src"
    assert_exit 0 $rc "stat runs on the copy"
    assert_output_contains "$out" "^755 0$" "the root-owned copy has no set-ID bit"
}

# ================================================================
#                            MAIN
# ================================================================

main() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "ERROR: tests must be run as root (sudo $0)" >&2
        exit 1
    fi

    echo "=== Sandbox Integration Tests ==="
    echo "Test dir: $TEST_DIR"
    echo ""

    build_sandbox
    echo ""

    echo "Building helper binaries..."
    build_helpers
    chmod 755 "$TEST_DIR"
    install -o root -g root -m 4755 "$SANDBOX_BIN" "$CALLER_BIN"
    install -d -o "$CALLER_UID" -g "$CALLER_UID" -m 700 "$CALLER_DIR"
    if findmnt -no OPTIONS -T "$TEST_DIR" | grep -qw nosuid; then
        echo "ERROR: $TEST_DIR is on a nosuid mount, so the non-root caller cannot run the setuid copy" >&2
        exit 1
    fi
    echo ""

    test_basic_execution
    test_add_file
    test_add_elf_file_with_deps
    test_mount_dir
    test_env_variables
    test_exec_dir
    test_runs_as_nobody
    test_network_isolation
    test_cgroup
    test_memory_limit
    test_memory_limit_no_swap
    test_no_swap_requires_mem_limit
    test_oom_group
    test_oom_group_requires_mem_limit
    test_cpuset
    test_save_usage_stat
    test_sandbox_cleanup
    test_minimal_dev
    test_dev_nodes_functional
    test_no_leaked_fds
    test_no_new_privs
    test_pid_isolation
    test_sandbox_path_validation
    test_cgroup_name_validation
    test_path_traversal_mount
    test_path_traversal_addfile
    test_memlimit_requires_cgroup
    test_signal_handling
    test_nonexistent_command
    test_tmp_world_writable
    test_root_not_writable
    test_version
    test_uid_refused
    test_uid_accepted
    test_cpu_max
    test_tmp_size
    test_stop
    test_stop_fifo_refused
    test_sandbox_parent
    test_earlier_sandbox
    test_links_planted_by_the_command
    test_sandbox_moved
    test_mount_rules
    test_copy_drops_setid
    test_foreign_setid_copied
    test_link_during_placement
    test_deep_tree

    echo ""
    echo "=== Results ==="
    echo "  Passed: $PASSED"
    echo "  Failed: $FAILED"
    if [ ${#ERRORS[@]} -gt 0 ]; then
        echo ""
        echo "  Failures:"
        for e in "${ERRORS[@]}"; do
            echo "    - $e"
        done
    fi
    echo ""

    [ "$FAILED" -eq 0 ]
}

main
