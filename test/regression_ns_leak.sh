#!/usr/bin/env bash
# Regression test for the host /usr/lib wipe bug.
#
# Verifies that bind mounts created by the sandbox do NOT leak into the host
# mount namespace even when the sandbox PARENT is SIGKILLed mid-run, so a later
# os.RemoveAll of the build dir cannot cross a leaked bind and delete the real
# host backing files.
#
# MUST run as root. Usage: regression_ns_leak.sh [path-to-sandbox-binary]
#   default binary: ../build/sandbox (relative to this script)
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX_BIN="${1:-$HERE/../build/sandbox}"

if [[ $EUID -ne 0 ]]; then echo "FAIL: must run as root"; exit 1; fi
if [[ ! -x "$SANDBOX_BIN" ]]; then echo "FAIL: sandbox binary not found at $SANDBOX_BIN"; exit 1; fi

# Sentinel host dir with a file we try to protect, and a build dir on the SAME
# filesystem (/tmp), mirroring builders.Build()'s os.MkdirTemp("", "build").
SENTINEL="$(mktemp -d /tmp/sentinel.XXXXXX)"
echo "do-not-delete" > "$SENTINEL/canary.txt"
TMPDIR_SB="$(mktemp -d /tmp/build.XXXXXX)"
CG="nsleak-$$-$RANDOM"

echo "== sandbox:   $SANDBOX_BIN"
echo "== sentinel:  $SENTINEL"
echo "== build dir: $TMPDIR_SB"
echo "== cgroup:    $CG"

cleanup() {
	# Reap any sandboxed child that outlived a SIGKILLed parent.
	echo 1 > "/sys/fs/cgroup/$CG/cgroup.kill" 2>/dev/null || true
	rm -rf "$SENTINEL" "$TMPDIR_SB" 2>/dev/null
	cgdelete -g cpu,memory,io,pids:"$CG" 2>/dev/null || true
}
trap cleanup EXIT

# Launch the sandbox with the sentinel bind-mounted; a sleep running INSIDE the
# sandbox keeps the bind live for the duration. sleep + its libs are hardlinked
# in via --add_elf_file so it can actually exec inside the empty sandbox root.
SLEEP_BIN="$(command -v sleep)"
"$SANDBOX_BIN" "$TMPDIR_SB" \
	--cgroup "$CG" \
	--mount_dir "$SENTINEL" /sentinel \
	--add_elf_file "$SLEEP_BIN" /sleep \
	-- /sleep 30 &
SB_PID=$!

# Wait until the parent has set up its mounts (poll its own mountinfo).
SETUP_OK=0
for _ in $(seq 1 100); do
	if grep -q "$SENTINEL" "/proc/$SB_PID/mountinfo" 2>/dev/null; then SETUP_OK=1; break; fi
	# If the sandbox process already exited, setup failed (e.g. exec error).
	kill -0 "$SB_PID" 2>/dev/null || break
	sleep 0.1
done
if [[ "$SETUP_OK" -ne 1 ]]; then
	echo "FAIL(setup): sandbox did not establish the sentinel bind (child exec failed?)"
	wait "$SB_PID" 2>/dev/null
	echo "RESULT: FAIL"; exit 1
fi

HOST_LEAK=0
# (a) the HOST namespace must NOT see the bind. Buggy binary leaks it here.
if grep -q "$SENTINEL" /proc/self/mountinfo; then
	echo "FAIL(a): sentinel bind LEAKED into host mount namespace"
	HOST_LEAK=1
else
	echo "PASS(a): no sentinel bind in host mount namespace"
fi

# SIGKILL the sandbox PARENT mid-run (bypasses atexit/clean()).
kill -9 "$SB_PID" 2>/dev/null
wait "$SB_PID" 2>/dev/null
sleep 0.5

# (a') after the kill, host mountinfo still must show nothing.
if grep -q "$SENTINEL" /proc/self/mountinfo; then
	echo "FAIL(a'): sentinel bind present in host ns after parent SIGKILL"
	HOST_LEAK=1
fi

# (b) deleting the build dir (as the Go orchestrator does) must NOT cross a
# leaked bind into the real sentinel.
rm -rf "$TMPDIR_SB"
CANARY_OK=0
if [[ "$(cat "$SENTINEL/canary.txt" 2>/dev/null)" == "do-not-delete" ]]; then
	echo "PASS(b): sentinel canary intact after rm -rf of build dir"
	CANARY_OK=1
else
	echo "FAIL(b): sentinel canary DESTROYED - rm crossed a leaked bind"
fi

if [[ "$HOST_LEAK" -eq 0 && "$CANARY_OK" -eq 1 ]]; then
	echo "RESULT: PASS"; exit 0
else
	echo "RESULT: FAIL"; exit 1
fi
