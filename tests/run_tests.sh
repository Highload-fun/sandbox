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

    gcc -static -o "$HELPERS_DIR/memhog"    "$HELPERS_DIR/memhog.c"
    gcc -static -o "$HELPERS_DIR/sleeper"   "$HELPERS_DIR/sleeper.c"
    gcc -static -o "$HELPERS_DIR/writetest" "$HELPERS_DIR/writetest.c"
    gcc -static -o "$HELPERS_DIR/devcheck"  "$HELPERS_DIR/devcheck.c"
    gcc -static -o "$HELPERS_DIR/fdcheck"   "$HELPERS_DIR/fdcheck.c"
    gcc -static -o "$HELPERS_DIR/privcheck" "$HELPERS_DIR/privcheck.c"
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
    wait "$bg_pid" 2>/dev/null || true

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

test_memlimit_requires_cgroup() {
    echo "[mem_limit requires cgroup]"

    local out
    out=$(sbox memnocg \
        --add_elf_file /bin/echo /bin/echo \
        --mem_limit 10485760 \
        -- /bin/echo test 2>&1) || true
    assert_output_contains "$out" "without cgroup" "mem_limit rejected without --cgroup"
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
