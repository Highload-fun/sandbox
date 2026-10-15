# sandbox

A lightweight Linux container tool that isolates program execution using Linux namespaces and cgroups v2. Runs untrusted binaries in a minimal chroot environment with restricted privileges (UID nobody), isolated PID/network/mount/IPC namespaces, and optional CPU/memory limits.

## Requirements

- Linux 5.9 or later, and 5.14 or later with `--cgroup` (for `cgroup.kill`)
- cgroups v2 enabled
- Root privileges (binary is installed with SETUID bit)

## Build

```bash
sudo apt-get install cmake build-essential libcgroup-dev

cmake -S . -B build
cmake --build build
```

To install (requires root, installs to `/usr/local/bin` with SETUID bit):

```bash
sudo cmake --install build
```

To build a Debian package:

```bash
debuild -b
```

## Usage

```
sudo sandbox <sandbox_path> [options] -- <cmd> [cmd_args]
```

The `<sandbox_path>` is a temporary directory created by the tool to serve as the chroot filesystem. It is cleaned up automatically on exit. See [Sandbox path](#sandbox-path) for the folders it may live in.

### Options

| Option | Description |
|---|---|
| `--add_file <src> <dst>` | Put a regular file from the host into the sandbox: a hard link, or a copy without set-ID bits across filesystems or when a non-root caller adds someone else's set-ID file |
| `--add_elf_file <src> <dst>` | Copy an ELF binary and its shared library dependencies |
| `--mount_dir <src> <dst>` | Bind-mount a host directory into the sandbox, not under another mount and not at its root |
| `--env <value>` | Set an environment variable (e.g. `--env PATH=/usr/bin`) |
| `--no_new_net` | Share the host network namespace instead of isolating |
| `--cgroup <name>` | Run the process in a named cgroup |
| `--cpuset <list>` | Restrict to specific CPUs (e.g. `0,1,2`) |
| `--mem_limit <bytes>` | Set a memory limit, a positive number of bytes (requires `--cgroup`) |
| `--no_swap` | Forbid swap, so the memory limit is a hard limit (requires `--mem_limit`) |
| `--oom_group` | Kill every process of the sandbox when the OOM killer kills one (requires `--mem_limit`) |
| `--save_usage_stat <file>` | Write CPU and memory usage stats after execution |
| `--exec_dir <path>` | Working directory inside the sandbox (default: `/root`) |
| `--uid <uid>` | Run the command under this UID and GID instead of 65534 (see [Own UID](#own-uid)) |
| `--cpu_max "<quota_us> <period_us>"` | Write `cpu.max` of the cgroup, e.g. `"50000 100000"` for half a CPU (requires `--cgroup`) |
| `--tmp_size <bytes>` | Mount a `nosuid,nodev` tmpfs of this size, mode 1777, at `/tmp` (default: an on-disk folder) |
| `--stop_fifo <path>` | Stop the command when a byte is read from this FIFO (see [Graceful stop](#graceful-stop)) |
| `--stop_grace <seconds>` | Stop with SIGTERM, then SIGKILL after this many seconds, 1-3600 (default 30 with `--stop_fifo`) |
| `--fsize_max <bytes>` | Limit every file the command writes, stdout and stderr included, to this size, up to 1 TiB (see [File size limit](#file-size-limit)) |
| `--version` | Print the version and exit |

### Examples

Run a dynamically linked binary with automatic library resolution:

```bash
sudo sandbox /tmp/sbox --add_elf_file /usr/bin/echo /usr/bin/echo -- /usr/bin/echo "Hello"
```

Run with resource limits:

```bash
sudo sandbox /tmp/sbox \
  --add_elf_file /usr/bin/ls /usr/bin/ls \
  --mount_dir /home/user/data /data \
  --cgroup my_sandbox \
  --cpuset 0,1 \
  --mem_limit 268435456 \
  --save_usage_stat /tmp/stats.txt \
  -- /usr/bin/ls /data
```

## How it works

1. Checks every argument, then creates a minimal filesystem at the sandbox path (`/dev`, `/etc`, `/proc`, `/root`, `/tmp`)
2. Puts in the requested files and libraries, then sets up the bind mounts
3. Optionally creates a cgroup with CPU and memory constraints
4. Clones a child process with isolated namespaces (`CLONE_NEWNS`, `CLONE_NEWPID`, `CLONE_NEWNET`, `CLONE_NEWUTS`, `CLONE_NEWIPC`, `CLONE_NEWCGROUP`)
5. Inside the child: makes a clone of the sandbox tree its root with `pivot_root`, mounts `/proc`, drops privileges to nobody (UID 65534) or the `--uid` one, then exec's the target binary
6. On exit, unmounts all filesystems and removes the sandbox directory

## Sandbox path

The sandbox path's parent must be the caller's own folder, or a root-owned sticky folder that everyone may write, such as `/tmp`; a root caller may use any. The tool opens the parent with the caller's rights, so a link on the way leads only where the caller could go.

A folder already at the sandbox path, left by an earlier run, is removed first. It must be the caller's, or root's in the caller's own parent; in a shared parent such as `/tmp` a root-owned folder may be anyone's, so the tool refuses it. A link at the sandbox path is refused.

Before it removes that folder, the tool kills what the earlier run left running in it: processes of the caller, of nobody and of the `--uid` range whose root, working folder or an open file is the folder. Root's processes are killed only when their root is the folder, as an earlier run's command has, or when they are this tool and use the folder, as an earlier run of it does; root's other processes are never the caller's to kill.

The tool builds and removes the tree through file descriptors, never by its path: it follows no link inside the tree, enters no mount when it removes it, and a rename of the folder during a run redirects nothing. `/tmp` in the tree becomes writable by others, sticky (1777), only once everything is in place. The removal walks the tree without recursion and keeps a bounded number of folders open, moving a deeper subtree up as it goes, so a tree of any depth is removed. `ldd` runs as the caller, on the host's file.

The sources of `--add_file`, `--add_elf_file` and `--mount_dir` are opened with the caller's rights, for reading, so a caller cannot put into the sandbox a file or a folder it could not read itself; a source the caller cannot read is refused with "Permission denied".

## Own UID

`--uid <uid>` runs the command under that UID and the same GID, with no supplementary groups. The tool checks the IDs after the drop and refuses to run the command otherwise. It accepts only a UID that:

- lies in 2000000000-2000999999, a range fixed at build time;
- is not the caller's UID or GID;
- appears in no `/etc/passwd` entry (as UID or primary GID) and no `/etc/group` entry;
- lies in no `/etc/subuid` or `/etc/subgid` range (a missing file has none; a line it cannot parse refuses).

A root caller cannot use `--uid`. Every refusal prints a fixed message and exits 1.

## Graceful stop

`--stop_fifo <path>` names a FIFO that the caller makes, owns, and that neither its group nor others can read or write. The tool never creates or changes it: it opens it with the caller's rights, without following a symlink, and refuses anything else. Writing a byte to it stops the command; a writer that closes without writing does not.

A stop sends SIGTERM to the command and SIGKILL once the `--stop_grace` seconds have passed. With `--stop_fifo` or `--stop_grace`, SIGTERM and SIGINT sent to the tool stop the command the same way; without them they kill it at once, and the tool exits 1. After a stop the tool exits with the command's own code, or 137 when the grace ran out.

The command runs as PID 1 of its PID namespace, so it receives SIGTERM only when it handles the signal; a command that does not is killed when the grace ends.

## External termination

When `--cgroup` is used, sandbox delegates ownership of the `cgroup.kill` file to the calling user. This allows the caller to terminate all processes in the sandbox from outside by writing `1` to `/sys/fs/cgroup/<name>/cgroup.kill`:

```bash
echo 1 > /sys/fs/cgroup/my_sandbox/cgroup.kill
```

This is the only reliable way to kill sandbox processes externally — the sandbox parent runs as root and children run as nobody, so sending signals from a non-root caller would fail with EPERM. Writing to `cgroup.kill` is a kernel-level operation that atomically kills all processes in the cgroup regardless of their UIDs.

## File size limit

`--fsize_max <bytes>` sets `RLIMIT_FSIZE`, soft and hard, on the command just before it starts, so it applies to every file the command or its children write, including a host file passed as stdout or stderr, and to a write at any offset. The tool's own copies for `--add_file` are made before and are not limited. SIGXFSZ is ignored, so a write past the limit fails with `EFBIG` and the command goes on; a Go program installs its own SIGXFSZ handler, which ignores it too, so its write returns "file too large". The limit is never set above the one the command would have had, and nothing in the sandbox can raise it.

## Existing cgroups

A `--cgroup` that already exists is used only when it is an empty leaf: no process and no child cgroup. A non-root caller may reuse only a cgroup the tool made for it earlier, whose `cgroup.kill` it was given, such as one a killed run left behind. Anything else is refused before a value is written or `cgroup.kill` is handed over, so a caller cannot put limits on, or kill, the host's own cgroups.

## Cgroup removal

On exit the tool removes the cgroup only when it is empty, and never moves processes out of it. A cgroup that still holds processes, such as one another run has reused, is left in place with a message on stderr, and the tool still exits with the command's code.

## Runtime statistics

When `--save_usage_stat <file>` is used (requires `--cgroup`), sandbox collects resource usage from the cgroup after the process exits and writes it to the specified file in tab-separated format:

```
cpu_user	<microseconds>
cpu_system	<microseconds>
memory	<bytes>
```

- `cpu_user` - total user-space CPU time in microseconds
- `cpu_system` - total kernel CPU time in microseconds
- `memory` - current memory usage in bytes at the time of exit

## License

This project is licensed under the GNU General Public License v3.0. See [LICENSE](LICENSE) for details.
