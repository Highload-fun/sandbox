# sandbox

A lightweight Linux container tool that isolates program execution using Linux namespaces and cgroups v2. Runs untrusted binaries in a minimal chroot environment with restricted privileges (UID nobody), isolated PID/network/mount/IPC namespaces, and optional CPU/memory limits.

## Requirements

- Linux with cgroups v2 enabled
- Root privileges (binary is installed with SETUID bit)
- `lsof` and `objdump` available on the host

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

The `<sandbox_path>` is a temporary directory created by the tool to serve as the chroot filesystem. It is cleaned up automatically on exit.

### Options

| Option | Description |
|---|---|
| `--add_file <src> <dst>` | Copy a file from the host into the sandbox |
| `--add_elf_file <src> <dst>` | Copy an ELF binary and its shared library dependencies |
| `--mount_dir <src> <dst>` | Bind-mount a host directory into the sandbox |
| `--env <value>` | Set an environment variable (e.g. `--env PATH=/usr/bin`) |
| `--no_new_net` | Share the host network namespace instead of isolating |
| `--cgroup <name>` | Run the process in a named cgroup |
| `--cpuset <list>` | Restrict to specific CPUs (e.g. `0,1,2`) |
| `--mem_limit <bytes>` | Set a memory limit (requires `--cgroup`) |
| `--save_usage_stat <file>` | Write CPU and memory usage stats after execution |
| `--exec_dir <path>` | Working directory inside the sandbox (default: `/root`) |

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

1. Creates a minimal filesystem at the sandbox path (`/dev`, `/etc`, `/proc`, `/root`, `/tmp`)
2. Copies requested files/libraries and sets up bind mounts
3. Optionally creates a cgroup with CPU and memory constraints
4. Clones a child process with isolated namespaces (`CLONE_NEWNS`, `CLONE_NEWPID`, `CLONE_NEWNET`, `CLONE_NEWUTS`, `CLONE_NEWIPC`, `CLONE_NEWCGROUP`)
5. Inside the child: chroots, mounts `/dev` and `/proc`, drops privileges to nobody (UID 65534), then exec's the target binary
6. On exit, unmounts all filesystems and removes the sandbox directory

## External termination

When `--cgroup` is used, sandbox delegates ownership of the `cgroup.kill` file to the calling user. This allows the caller to terminate all processes in the sandbox from outside by writing `1` to `/sys/fs/cgroup/<name>/cgroup.kill`:

```bash
echo 1 > /sys/fs/cgroup/my_sandbox/cgroup.kill
```

This is the only reliable way to kill sandbox processes externally — the sandbox parent runs as root and children run as nobody, so sending signals from a non-root caller would fail with EPERM. Writing to `cgroup.kill` is a kernel-level operation that atomically kills all processes in the cgroup regardless of their UIDs.

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
