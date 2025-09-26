# Ubuntu VPS System Analysis and Useful Commands

## System Identification
- **Virtualization**: The system is virtualized using QEMU/KVM or similar hypervisor, evidenced by Virtio devices (network, SCSI, console, memory balloon), Cirrus Logic GD 5446 VGA, and Intel PIIX components.
- **Hardware Specs** (from `lshw` and `lspci`):
  - **CPUs**: 6 vCPUs, each Intel Core Processor (Haswell, no TSX), model 6.60.1, 64-bit, with features like AVX2, VMX (virtualization support), and Hypervisor flag.
  - **Memory**: 11 GiB system memory.
  - **Network**: Virtio Ethernet interface (ens3)
  - **Storage**: Virtio SCSI controller.
  - **USB Devices**: Linux Foundation root hub and QEMU USB Tablet.
  - **Other**: Virtio console and memory balloon for dynamic resource allocation.
- **Kernel/Access Notes**: Some commands (e.g., `dmesg`, `dmidecode`) require superuser privileges (`sudo`) to access kernel buffers or DMI tables. Tools like `lsdev` and `inxi` are not installed by default.

This setup is typical for cloud VPS providers, where resources are virtualized for scalability.

## Decoding the Outputs

Here's a breakdown of the key provided commands and their outputs:

- **`cat /etc/os-release`** and **`cat /etc/os*`**:
  - Confirms the OS as Ubuntu 25.04 (codename: plucky).
  - Derived from Debian (ID_LIKE=debian).
  - Includes URLs for home, support, bugs, and privacy.

- **`htop`**:
  - Ran but was stopped (likely backgrounded with Ctrl+Z, as shown by `[1]+ Stopped htop`).
  - `htop` is an interactive process viewer; install if missing with `sudo apt install htop`.

- **`lshw`**:
  - Partial output due to lack of sudo (warning: run as super-user for complete details).
  - Shows virtual hardware: Multiple identical CPUs (hypervisor-allocated), system memory, PCI devices (Host bridge, ISA, IDE, USB, VGA, Ethernet, SCSI, etc.).
  - Indicates a 64-bit SMP-capable system in a virtual environment.

- **`lsdev`**:
  - Not found; it's from the `procinfo` package. Install with `sudo apt install procinfo`.

- **`inxi`**:
  - Not found; install with `sudo apt install inxi`. Useful for detailed system info.

- **`lspci`**:
  - Lists PCI devices: Intel bridges, Cirrus VGA, Red Hat Virtio devices (network, SCSI, console, balloon).
  - Confirms virtualized hardware.

- **`lsusb`**:
  - Shows USB bus with root hub and QEMU tablet (emulated input device).

- **`dmesg`**:
  - Permission denied; requires sudo. Used for kernel messages, e.g., hardware detection.

- **`dmidecode`**:
  - Permission denied; requires sudo. Retrieves BIOS/DMI info, but in VMs, this may be limited or emulated.

### Hardware Inspection Commands

These help identify and monitor hardware (virtual in this case).

| Command | Description | Example Usage | Notes |
|---------|-------------|---------------|-------|
| `cat /etc/os-release` | Displays OS version and details. | `cat /etc/os-release` | Worked in output; no sudo needed. |
| `lshw` | Detailed hardware info (run with sudo for complete output). | `sudo lshw` or `sudo lshw -short` | Partial in output; shows VMs well. |
| `lspci` | Lists PCI devices (e.g., network, storage controllers). | `lspci -v` (verbose) | Worked; shows Virtio devices. |
| `lsusb` | Lists USB devices. | `lsusb -v` | Worked; shows QEMU tablet. |
| `dmesg` | Kernel messages for hardware events. | `sudo dmesg \| grep -i error` | Permission denied; use sudo. |
| `dmidecode` | BIOS/DMI hardware info. | `sudo dmidecode --type memory` | Permission denied; use sudo. |
| `inxi` | Comprehensive system overview (install first). | `sudo apt install inxi && inxi -F` | Not found; install required. |
| `lsdev` | Basic hardware from /proc (install procinfo). | `sudo apt install procinfo && lsdev` | Not found; install required. |
| `htop` | Interactive process/CPU/memory monitor. | `sudo apt install htop && htop` | Ran but stopped; fg to resume. |
| `free -h` | Memory usage. | `free -h` | Human-readable. |
| `lscpu` | CPU architecture details. | `lscpu` | Not in output; try it for vCPU info. |
| `lsblk` | Block devices (disks). | `lsblk -f` | For storage partitions. |

### SSH Management Commands

For secure remote access.

| Command | Description | Example Usage | Notes |
|---------|-------------|---------------|-------|
| `sudo apt install openssh-server` | Install SSH server. | `sudo apt update && sudo apt install openssh-server` | Enable remote login. |
| `ssh username@host` | Connect to remote host. | `ssh ubuntu@1.1.1.1IPV4` | From client. |
| `ssh-keygen` | Generate SSH key pair. | `ssh-keygen -t ed25519` | For key-based auth. |
| `ssh-copy-id` | Copy public key to remote. | `ssh-copy-id ubuntu@host` | Passwordless login. |
| `sudo systemctl status ssh` | Check SSH service status. | `sudo systemctl restart ssh` | Manage service. |
| `sudo ufw allow ssh` | Allow SSH in firewall. | `sudo ufw enable` | Secure access. |
| `scp` | Secure file copy. | `scp file.txt ubuntu@host:/path` | Transfer files. |
| `sudo nano /etc/ssh/sshd_config` | Edit SSH config. | Then restart SSH. | Change port, disable passwords. |

### SRE and Server Management Commands

For reliability, monitoring, and administration.

| Command | Description | Example Usage | Notes |
|---------|-------------|---------------|-------|
| `uptime` | System uptime and load. | `uptime` | Quick health check. |
| `top` or `htop` | Process monitoring. | `top` (built-in) or `htop` | Interactive. |
| `journalctl` | Systemd logs. | `journalctl -u ssh -f` | Follow service logs. |
| `df -h` | Disk usage. | `df -h` | Filesystems. |
| `du -sh /path` | Directory usage. | `du -sh /var` | Estimate space. |
| `useradd` | Add user. | `sudo useradd -m newuser` | With home dir. |
| `passwd` | Set password. | `sudo passwd newuser` | User management. |
| `systemctl` | Manage services. | `sudo systemctl restart nginx` | For daemons. |
| `iostat` | CPU/I/O stats (install sysstat). | `sudo apt install sysstat && iostat -x` | Performance. |
| `ss` | Network sockets. | `ss -tuln` | Listening ports. |
| `netstat` | Network stats (if installed). | `netstat -tuln` | Alternative to ss. |
| `apt update && apt upgrade` | Update packages. | `sudo apt update && sudo apt upgrade` | Keep system current. |
| `reboot` | Restart system. | `sudo reboot` | After updates. |
| `uname -a` | Kernel and system info. | `uname -a` | Basic OS details. |
| `whoami` | Current user. | `whoami` | Verify context. |
| `sudo` | Run as superuser. | `sudo command` | Essential for privileged ops. |

### Installation and Troubleshooting Commands

| Command | Description | Example Usage | Notes |
|---------|-------------|---------------|-------|
| `sudo apt install <package>` | Install software. | `sudo apt install inxi` | For missing tools. |
| `apt search <term>` | Search packages. | `apt search htop` | Find tools. |
| `sudo apt autoremove` | Remove unused packages. | `sudo apt autoremove` | Clean up. |
| `ping` | Test network. | `ping 8.8.8.8` | Connectivity. |
| `ifconfig` or `ip addr` | Network interfaces. | `ip addr show` | IP details. |
| `curl ifconfig.me` | Get public IP. | `curl ifconfig.me` | External IP. |

For security, enable UFW firewall (`sudo ufw enable`), use key-based SSH, and monitor logs regularly. If you need scripts or automation, consider tools like Ansible. Let me know for more specifics!

### FreeBSD 14 Commands for SSH Management

FreeBSD includes OpenSSH in the base system, but you can install the portable version if needed. Configuration is similar to Ubuntu but uses `sysrc` for enabling services and `service` for management instead of `systemctl`. The config file is `/etc/ssh/sshd_config`. Below are key commands for installing, configuring, and managing SSH.

| Command | Description | Example Usage |
|---------|-------------|---------------|
| `pkg install openssh-portable` | Installs the portable OpenSSH server (if not using base system version). | `pkg install openssh-portable` (requires root). |
| `sysrc sshd_enable="YES"` | Enables the SSH server to start at boot. | `sysrc sshd_enable="YES"` (persistent in `/etc/rc.conf`). |
| `service sshd start` | Starts the SSH service. | `service sshd start` or `service sshd onestart` to start once. |
| `ssh username@remote_host` | Connects to a remote server via SSH (client-side). | `ssh user@192.168.1.100` (same as Linux). |
| `ssh-keygen -t ed25519` | Generates an SSH key pair for passwordless authentication. | `ssh-keygen -t ed25519 -C "your_email@example.com"`. |
| `ssh-copy-id username@remote_host` | Copies your public key to the remote server. | `ssh-copy-id user@192.168.1.100` (requires password initially). |
| `service sshd status` | Checks the status of the SSH service. | `service sshd status`. Use `stop`, `restart`, or `reload` similarly. |
| `pfctl -e` or `service pf start` | Enables the PF firewall and allows SSH (edit `/etc/pf.conf` to allow tcp port 22). | Add rule to `/etc/pf.conf`: `pass in on $ext_if proto tcp from any to any port 22`. Then `pfctl -f /etc/pf.conf`. |
| `scp local_file username@remote_host:/path` | Securely copies files to/from a remote server. | `scp /local/file.txt user@remote:/home/user/`. |
| `ee /etc/ssh/sshd_config` | Edits the SSH server configuration file (ee is a simple editor; use vi or nano if installed). | Edit, then `service sshd reload` to apply (after verifying with `sshd -t`). |

For security, prefer public key authentication (`PubkeyAuthentication yes` in config) and disable password auth if possible. Use tools like `fail2ban` (available via pkg) for brute-force protection.

### FreeBSD 14 Commands for SRE and Server Management

FreeBSD focuses on reliability with tools like `service` for daemons (no systemd), `sysctl` for kernel tuning, and standard UNIX utilities for monitoring. Many commands are similar to Linux, but package management uses `pkg`, logs are in `/var/log/`, and users are managed with `adduser`. Below are equivalents for SRE tasks like monitoring, troubleshooting, and automation.

| Command | Description | Example Usage |
|---------|-------------|---------------|
| `uptime` | Shows system uptime, load average, and users logged in. | `uptime` (same as Linux). |
| `tail -f /var/log/messages` | Views system logs (equivalent to journalctl). | `tail -f /var/log/messages` or `tail -f /var/log/auth.log` for auth logs. |
| `top` or `htop` | Interactive process viewer for CPU/memory (htop via `pkg install htop`). | `top` or `htop`. |
| `sysctl vm.stats` or `top` | Displays memory usage (no direct `free`; use sysctl or top for stats). | `sysctl vm.stats.vm.v_free_count` for free pages; `top` shows Mem overview. |
| `df -h` | Shows disk space usage for filesystems. | `df -h` (same as Linux). |
| `du -sh /path` | Estimates disk usage for a directory. | `du -sh /var/log` (same as Linux). |
| `adduser` | Creates a new user account interactively. | `adduser` (prompts for details; equivalent to useradd -m). |
| `passwd` | Sets or changes a user's password. | `passwd newuser` (as root). |
| `service` | Manages system services (start, stop, enable). | `service apache24 restart` (equivalent to systemctl). |
| `iostat` | Reports CPU and I/O statistics. | `iostat -x 1 5` (install sysstat if needed? Built-in on FreeBSD). |
| `netstat` or `sockstat` | Displays network connections and sockets (sockstat is FreeBSD-specific). | `netstat -an` or `sockstat -4l` (equivalent to ss -tuln). |
| `sysctl -a` | Views or tunes kernel parameters (equivalent to sysctl on Linux). | `sysctl kern.maxproc=10000` to set. |

For advanced SRE, use `pkg` for packages (`pkg update && pkg upgrade`), `zfs` for filesystems if using ZFS, and firewalls like PF (`pfctl`). Consider tools like Prometheus via pkg for monitoring. If you need details on a specific command or scenario, provide more info!


### Amazon Linux 2 / Red Hat Linux / Alma Linux (Replacement of Cent OS) Commands for SSH Management

Amazon Linux 2 is based on Red Hat Enterprise Linux (RHEL) 7, so commands are largely similar to RHEL, CentOS 7, or other RPM-based distros. Package management uses `yum` (not `apt`), services use `systemctl` (like Ubuntu), and the firewall is `firewalld` (not UFW). SSH is provided by OpenSSH. For RHEL 8+ (or AlmaLinux, see below), `dnf` replaces `yum`, but the rest is similar. Below are key commands for SSH management.

| Command | Description | Example Usage |
|---------|-------------|---------------|
| `yum install openssh-server` | Installs the OpenSSH server (often pre-installed on servers). | `sudo yum update && sudo yum install openssh-server` (update first). |
| `yum install openssh-clients` | Installs the SSH client (often pre-installed). | `sudo yum install openssh-clients` |
| `ssh username@remote_host` | Connects to a remote server via SSH. | `ssh user@192.168.1.100` (same as Ubuntu). |
| `ssh-keygen -t ed25519` | Generates an SSH key pair for passwordless authentication. | `ssh-keygen -t ed25519 -C "your_email@example.com"` |
| `ssh-copy-id username@remote_host` | Copies your public key to the remote server. | `ssh-copy-id user@192.168.1.100` |
| `systemctl status sshd` | Checks the status of the SSH service. | `sudo systemctl status sshd` (use `start`, `stop`, or `restart` to manage). |
| `firewall-cmd --permanent --add-service=ssh` | Allows SSH through the firewall (firewalld). | `sudo firewall-cmd --permanent --add-service=ssh && sudo firewall-cmd --reload` |
| `scp local_file username@remote_host:/path` | Securely copies files to/from a remote server. | `scp /local/file.txt user@remote:/home/user/` |
| `ssh -X username@remote_host` | Enables X11 forwarding for GUI apps. | `ssh -X user@remote xclock` |
| `sudo vi /etc/ssh/sshd_config` | Edits the SSH server configuration file (use vi, nano if installed). | Edit, then `sudo systemctl restart sshd` to apply. |

For security, enable key-based auth and consider `fail2ban` (install via `yum install fail2ban`).

### Amazon Linux 2 / Red Hat Linux Commands for SRE and Server Management

SRE commands are similar to Ubuntu, focusing on monitoring and management. Use `yum` for packages, `systemctl` for services, and tools like `top` or `iotop`. Hardware commands (e.g., `lshw`, `lspci`) are identical to Ubuntu.

| Command | Description | Example Usage |
|---------|-------------|---------------|
| `uptime` | Shows system uptime, load average, and users. | `uptime` |
| `journalctl` | Views system logs from systemd. | `journalctl -u sshd` (logs for SSH); add `-f` to follow. |
| `top` or `htop` | Interactive process viewer (install htop with `yum install htop`). | `top` or `htop` |
| `free -h` | Displays memory usage. | `free -h` |
| `df -h` | Shows disk space usage. | `df -h` |
| `du -sh /path` | Estimates disk usage for a directory. | `du -sh /var/log` |
| `useradd` | Creates a new user account. | `sudo useradd -m newuser` |
| `passwd` | Sets or changes a user's password. | `sudo passwd newuser` |
| `systemctl` | Manages system services. | `sudo systemctl restart httpd` |
| `iostat` | Reports CPU and I/O statistics (install sysstat with `yum install sysstat`). | `iostat -x 1 5` |
| `netstat` or `ss` | Displays network connections (ss is preferred). | `ss -tuln` |
| `dmesg` | Prints kernel messages. | `dmesg \| grep error` |

For advanced SRE, use `yum update` for packages, and tools like Prometheus (via yum/epel repos). Enable EPEL repo with `yum install epel-release` for extra packages.