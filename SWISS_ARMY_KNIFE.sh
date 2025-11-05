#!/bin/bash

# ═══════════════════════════════════════════════════════════════════════════
# COMPREHENSIVE SYSTEM DIAGNOSTIC TOOLKIT - SWISS ARMY KNIFE EDITION
# ═══════════════════════════════════════════════════════════════════════════
# Dependencies: whiptail, bash, coreutils, less
# Version: 3.0 - Complete Edition
# ═══════════════════════════════════════════════════════════════════════════

declare -A MENU
declare -A COMMAND_SAFETY  # Track command safety levels
HISTORY_FILE="$HOME/.diagnostic_history"
FAVORITES_FILE="$HOME/.diagnostic_favorites"

# Format: MENU["Category:Command"]="Description"

# ═══════════════════════════════════════════════════════════════════════════
# EXISTING CATEGORIES (Enhanced)
# ═══════════════════════════════════════════════════════════════════════════

# 🧨 SYSTEM ERRORS
MENU["System Errors:journalctl -p err..alert -b"]="Boot-time system errors"
MENU["System Errors:journalctl -xe"]="Recent system errors"
MENU["System Errors:dmesg --level=err,warn"]="Kernel error/warning messages"
MENU["System Errors:dmesg | grep -i 'fail\\|error'"]="Search dmesg for failures/errors"
MENU["System Errors:grep -i 'fail\\|error' /var/log/syslog"]="Syslog failures/errors"
MENU["System Errors:grep -i 'segfault\\|panic' /var/log/syslog"]="Syslog segfaults/panics"
MENU["System Errors:grep -i 'critical' /var/log/syslog"]="Syslog critical issues"
MENU["System Errors:grep -i 'oom' /var/log/kern.log"]="Kernel OOM events"
MENU["System Errors:journalctl -b -1 | grep systemd"]="Previous boot systemd logs"
MENU["System Errors:journalctl --boot=-1"]="Full previous boot log"
MENU["System Errors:last -x"]="Last shutdown/reboot events"
MENU["System Errors:systemd-analyze blame"]="Boot time per service"
MENU["System Errors:systemd-analyze critical-chain"]="Critical boot chain"
MENU["System Errors:systemd-analyze plot > ~/boot_plot.svg && echo 'Saved to ~/boot_plot.svg'"]="Generate boot plot SVG"
MENU["System Errors:journalctl -u systemd-shutdown"]="Shutdown logs"
MENU["System Errors:journalctl -u systemd-halt"]="Halt logs"
MENU["System Errors:journalctl -u systemd-poweroff"]="Poweroff logs"
MENU["System Errors:grep -i plymouth /var/log/syslog"]="Plymouth shutdown errors"
MENU["System Errors:journalctl -u plymouth*"]="Plymouth service logs"

# 🛠️ SNAP MANAGEMENT
MENU["Snap Management:snap list"]="List installed snaps"
MENU["Snap Management:snap changes"]="Recent snap changes"
MENU["Snap Management:snap refresh --list"]="List available snap updates"
MENU["Snap Management:snap debug sandbox-features"]="Snap sandbox features"
MENU["Snap Management:snap debug confinement"]="Snap confinement mode"
MENU["Snap Management:snap debug seeding"]="Snap seeding status"

# 🔐 TPM + FDE + SNAP BOOT
MENU["TPM & FDE:ls -la /dev/tpm*"]="List TPM devices"
MENU["TPM & FDE:dmesg | grep -i tpm"]="TPM kernel messages"
MENU["TPM & FDE:journalctl -b | grep -i tpm"]="TPM journal messages"
MENU["TPM & FDE:lsblk -o NAME,FSTYPE,SIZE,MOUNTPOINT,UUID"]="List block devices with filesystem info"
MENU["TPM & FDE:snap debug boot"]="Snap boot info"
MENU["TPM & FDE:snap debug boot --verbose"]="Verbose snap boot info"
MENU["TPM & FDE:snap debug fde-status"]="Full disk encryption status"
MENU["TPM & FDE:snap debug secureboot-status"]="Secure boot status"
MENU["TPM & FDE:snap debug tpm-status"]="TPM status via snap"
MENU["TPM & FDE:snap recover --show"]="Show recovery status"

# 🧍 NETWORK MANAGER
MENU["Network Manager:nmcli general status"]="NM general status"
MENU["Network Manager:nmcli device status"]="Device status"
MENU["Network Manager:nmcli connection show"]="List connections"
MENU["Network Manager:nmcli radio all"]="Radio status"
MENU["Network Manager:nmcli networking connectivity check"]="Connectivity check"
MENU["Network Manager:nmcli device wifi list"]="List WiFi networks"
MENU["Network Manager:ip a"]="Show IP addresses"
MENU["Network Manager:ip r"]="Show routing table"
MENU["Network Manager:ip link"]="Show network interfaces"
MENU["Network Manager:ip -s link"]="Show interface statistics"
MENU["Network Manager:ip -br a"]="Brief IP address list"

# 🧱 IPTABLES FIREWALL
MENU["Firewall:iptables -L -v -n"]="List firewall rules"
MENU["Firewall:iptables -S"]="List rules in save format"
MENU["Firewall:iptables -t nat -L -n -v"]="List NAT table rules"
MENU["Firewall:iptables -t mangle -L -n -v"]="List mangle table rules"
MENU["Firewall:iptables-save"]="Save current rules to stdout"
COMMAND_SAFETY["Firewall:iptables -F"]="DANGEROUS"
MENU["Firewall:iptables -F"]="⚠️  Flush all rules (WARNING: May disconnect)"

# 🧍 NETWORK DIAGNOSTICS
MENU["Network Diagnostics:ping -c 4 8.8.8.8"]="Ping Google DNS (4 packets)"
MENU["Network Diagnostics:ping -c 4 1.1.1.1"]="Ping Cloudflare DNS (4 packets)"
MENU["Network Diagnostics:traceroute 8.8.8.8"]="Traceroute to Google"
MENU["Network Diagnostics:netstat -tulnp"]="Show open ports"
MENU["Network Diagnostics:ss -tuln"]="Show socket stats"
MENU["Network Diagnostics:ss -tulnp"]="Show socket stats with processes"
MENU["Network Diagnostics:dig example.com"]="DNS lookup for example.com"
MENU["Network Diagnostics:nslookup example.com"]="DNS lookup via nslookup"
MENU["Network Diagnostics:host example.com"]="DNS lookup via host"
MENU["Network Diagnostics:curl -I https://example.com"]="HTTP header check"
MENU["Network Diagnostics:wget --spider https://example.com"]="Test URL reachability"

# 🔍 SYSTEM INSIGHTS
MENU["System Insights:systemctl list-units --failed"]="List failed units"
MENU["System Insights:systemctl list-units --type=service"]="List all services"
MENU["System Insights:systemctl list-timers"]="List systemd timers"
MENU["System Insights:lshw -short"]="Hardware overview"
MENU["System Insights:lsblk"]="List block devices"
MENU["System Insights:lscpu"]="CPU information"
MENU["System Insights:lsusb"]="USB devices"
MENU["System Insights:lspci"]="PCI devices"
MENU["System Insights:uname -a"]="System information"
MENU["System Insights:cat /proc/cpuinfo"]="Detailed CPU info"
MENU["System Insights:cat /proc/meminfo"]="Detailed memory info"
MENU["System Insights:cat /proc/version"]="Kernel version details"
MENU["System Insights:free -h"]="Memory usage"

# 🧰 SERVICE & DAEMON CONTROL
MENU["Service Control:systemctl list-units --type=service --state=running"]="List running services"
MENU["Service Control:systemctl list-units --type=service --state=failed"]="List failed services"
MENU["Service Control:systemctl daemon-reload"]="Reload systemd manager"
COMMAND_SAFETY["Service Control:systemctl daemon-reload"]="MODIFIES"

# 🧩 KERNEL & MODULE INFO
MENU["Kernel Info:uname -r"]="Show kernel version"
MENU["Kernel Info:lsmod"]="List loaded kernel modules"
MENU["Kernel Info:lsmod | wc -l"]="Count loaded modules"
MENU["Kernel Info:modprobe -c | grep -v '^#' | head -50"]="Module configuration (first 50)"
MENU["Kernel Info:dmesg | grep -i module"]="Search dmesg for module messages"

# 🧬 USER & GROUP MANAGEMENT
MENU["User Management:id"]="Show current user ID"
MENU["User Management:groups"]="Show user groups"
MENU["User Management:getent passwd"]="List all users"
MENU["User Management:getent group"]="List all groups"
MENU["User Management:sudo -l"]="Show sudo privileges"
MENU["User Management:who"]="Show logged-in users"
MENU["User Management:w"]="Show who is logged in and what they are doing"
MENU["User Management:last | head -30"]="Show last login records (30 entries)"
MENU["User Management:lastlog | head -30"]="Show last login for all users (30 entries)"

# 🧼 CLEANUP & MAINTENANCE
MENU["Cleanup:apt autoremove --dry-run"]="Preview unused packages to remove"
MENU["Cleanup:apt clean --dry-run"]="Preview package cache cleanup"
MENU["Cleanup:journalctl --disk-usage"]="Show journal disk usage"
MENU["Cleanup:journalctl --vacuum-size=100M"]="Limit journal to 100MB"
MENU["Cleanup:journalctl --vacuum-time=7d"]="Remove journal entries older than 7 days"
MENU["Cleanup:journalctl --rotate"]="Rotate journal logs"
MENU["Cleanup:systemd-tmpfiles --clean"]="Clean temporary files"
COMMAND_SAFETY["Cleanup:apt autoremove"]="MODIFIES"
COMMAND_SAFETY["Cleanup:apt clean"]="MODIFIES"

# 🧰 PACKAGE INTEGRITY
MENU["Package Integrity:dpkg -l | wc -l"]="Count installed packages"
MENU["Package Integrity:dpkg -l | tail -50"]="List installed packages (last 50)"
MENU["Package Integrity:apt list --installed | wc -l"]="Count installed packages (apt)"
MENU["Package Integrity:apt-mark showmanual | head -50"]="Show manually installed packages (first 50)"
MENU["Package Integrity:apt-mark showauto | head -50"]="Show automatically installed packages (first 50)"
MENU["Package Integrity:dpkg --verify"]="Verify package integrity"
MENU["Package Integrity:debsums -s"]="Check package checksums (silent)"

# 🧬 ENVIRONMENT & CONFIG
MENU["Environment:env | sort"]="Show environment variables (sorted)"
MENU["Environment:printenv | grep -i path"]="Show PATH-related variables"
MENU["Environment:locale"]="Show locale settings"
MENU["Environment:ulimit -a"]="Show resource limits"
MENU["Environment:hostnamectl"]="Show hostname info"
MENU["Environment:timedatectl"]="Show time and date settings"
MENU["Environment:loginctl show-user $USER"]="Show session info for current user"

# 🧱 FILESYSTEM & STORAGE
MENU["Storage:df -h"]="Disk space usage"
MENU["Storage:df -i"]="Inode usage"
MENU["Storage:du -sh /* 2>/dev/null | sort -h"]="Directory sizes in root (sorted)"
MENU["Storage:mount | column -t"]="Show mounted filesystems (formatted)"
MENU["Storage:lsblk"]="List block devices"
MENU["Storage:lsblk -f"]="List block devices with filesystems"
MENU["Storage:blkid"]="Show block device UUIDs"
MENU["Storage:findmnt"]="Find mounted filesystems"
MENU["Storage:ls -lah /"]="List root directory"

# 🧾 LOG FILE LOCATIONS
MENU["Log Files:ls -lh /var/log/ | head -50"]="List log files (first 50)"
MENU["Log Files:cat /var/log/syslog | tail -100"]="Last 100 lines of syslog"
MENU["Log Files:cat /var/log/kern.log | tail -100"]="Last 100 lines of kern.log"
MENU["Log Files:cat /var/log/auth.log | tail -100"]="Last 100 lines of auth.log"
MENU["Log Files:cat /var/log/dmesg"]="Kernel ring buffer log"
MENU["Log Files:ls /var/log/apt/"]="List APT log files"

# 🧠 DEBUGGING & MONITORING
MENU["Debugging:ps aux | head -30"]="List processes (first 30)"
MENU["Debugging:ps aux --sort=-pcpu | head -20"]="Top 20 CPU consumers"
MENU["Debugging:ps aux --sort=-%mem | head -20"]="Top 20 memory consumers"
MENU["Debugging:top -b -n 1 | head -30"]="Process snapshot (first 30 lines)"
MENU["Debugging:lsof -i"]="List open network files"
MENU["Debugging:lsof +D /var/log"]="Files open in /var/log"
MENU["Debugging:vmstat 1 5"]="Virtual memory stats (5 samples)"
MENU["Debugging:iostat -xz 1 5"]="I/O statistics (5 samples)"

# 🧪 SYSTEM AUDIT
MENU["System Audit:ausearch -ts recent 2>/dev/null | head -50"]="Recent audit events (first 50)"
MENU["System Audit:aureport -x --summary 2>/dev/null"]="Audit executable summary"
MENU["System Audit:aureport -u --summary 2>/dev/null"]="Audit user summary"
MENU["System Audit:auditctl -l 2>/dev/null"]="List audit rules"

# 🕵️ SECURITY
MENU["Security:find /tmp -type f -name '.*' 2>/dev/null | head -30"]="Find hidden files in /tmp (first 30)"
MENU["Security:find / -type f -perm -4000 2>/dev/null | head -50"]="Find SUID files (first 50)"
MENU["Security:find / -type f -size +100M 2>/dev/null | head -20"]="Find large files >100MB (first 20)"
MENU["Security:find /etc -type f -exec grep -l 'password' {} \\; 2>/dev/null | head -20"]="Files with 'password' in /etc (first 20)"

# ═══════════════════════════════════════════════════════════════════════════
# NEW CATEGORIES - HIGH PRIORITY
# ═══════════════════════════════════════════════════════════════════════════

# 📊 PERFORMANCE MONITORING
MENU["Performance:uptime"]="System uptime and load average"
MENU["Performance:sar -u 1 5"]="CPU utilization (5 samples)"
MENU["Performance:sar -r 1 5"]="Memory utilization (5 samples)"
MENU["Performance:sar -n DEV 1 5"]="Network statistics (5 samples)"
MENU["Performance:mpstat -P ALL 1 5"]="Per-CPU statistics (5 samples)"
MENU["Performance:dstat -cdngy 1 5"]="Versatile resource stats (5 samples)"
MENU["Performance:atop -1"]="Advanced system monitor snapshot"
MENU["Performance:nmon -c 5 -s 1"]="Performance monitor (5 snapshots)"

# 🐳 DOCKER & CONTAINERS
MENU["Containers:docker ps -a"]="List all Docker containers"
MENU["Containers:docker images"]="List Docker images"
MENU["Containers:docker stats --no-stream"]="Container resource usage snapshot"
MENU["Containers:docker system df"]="Docker disk usage"
MENU["Containers:docker network ls"]="List Docker networks"
MENU["Containers:docker volume ls"]="List Docker volumes"
MENU["Containers:docker info"]="Docker system information"
MENU["Containers:podman ps -a"]="List Podman containers"
MENU["Containers:podman images"]="List Podman images"
MENU["Containers:lxc list"]="List LXC containers"
COMMAND_SAFETY["Containers:docker system prune -a"]="DANGEROUS"

# 💾 DISK I/O & FILESYSTEM
MENU["Disk I/O:iotop -b -n 1"]="I/O usage by process (1 iteration)"
MENU["Disk I/O:iostat -xz 1 5"]="Extended I/O statistics (5 samples)"
MENU["Disk I/O:fdisk -l"]="Partition tables"
MENU["Disk I/O:parted -l"]="Partition information"
MENU["Disk I/O:lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE"]="Block devices detailed"
MENU["Disk I/O:findmnt -t ext4,xfs,btrfs"]="Find specific filesystem types"
MENU["Disk I/O:cat /proc/diskstats"]="Disk statistics"

# 🧠 MEMORY ANALYSIS
MENU["Memory:free -m -t"]="Memory with totals in MB"
MENU["Memory:free -h"]="Memory usage human-readable"
MENU["Memory:vmstat -s"]="Virtual memory statistics"
MENU["Memory:slabtop -o"]="Kernel slab cache info (once)"
MENU["Memory:cat /proc/meminfo"]="Detailed memory information"
MENU["Memory:ps aux --sort=-%mem | head -20"]="Top 20 memory consumers"
MENU["Memory:swapon --show"]="Swap usage details"
MENU["Memory:cat /proc/sys/vm/swappiness"]="Swappiness value"
MENU["Memory:smem -tk 2>/dev/null"]="Memory reporting with totals"

# 🔧 HARDWARE INFORMATION
MENU["Hardware:hwinfo --short"]="Hardware info summary"
MENU["Hardware:inxi -Fxz"]="Comprehensive system info"
MENU["Hardware:dmidecode -t memory"]="Memory hardware details"
MENU["Hardware:dmidecode -t processor"]="CPU hardware details"
MENU["Hardware:dmidecode -t bios"]="BIOS information"
MENU["Hardware:dmidecode -t system"]="System information"
MENU["Hardware:sensors"]="Temperature sensors"
MENU["Hardware:lspci -v | head -100"]="Verbose PCI devices (first 100 lines)"
MENU["Hardware:lsusb -v | head -100"]="Verbose USB devices (first 100 lines)"
MENU["Hardware:lshw -class disk"]="Disk hardware info"
MENU["Hardware:lshw -class network"]="Network hardware info"

# 🔄 PROCESS MANAGEMENT
MENU["Processes:pstree -p"]="Process tree with PIDs"
MENU["Processes:ps aux --sort=-pcpu | head -20"]="Top 20 CPU consumers"
MENU["Processes:ps aux --sort=-%mem | head -20"]="Top 20 memory consumers"
MENU["Processes:pgrep -a systemd"]="Find systemd processes"
MENU["Processes:jobs"]="List background jobs"
MENU["Processes:lsof +D /var"]="Files open under /var"
MENU["Processes:fuser -v /var/log"]="Processes using /var/log"
MENU["Processes:pidof systemd"]="Find PID of systemd"

# ⚙️ SYSTEMD DEEP DIVE
MENU["Systemd:systemctl list-unit-files | head -50"]="Unit files and states (first 50)"
MENU["Systemd:systemctl list-unit-files --state=enabled"]="Enabled unit files"
MENU["Systemd:systemctl list-unit-files --state=disabled"]="Disabled unit files"
MENU["Systemd:systemctl list-sockets"]="Active sockets"
MENU["Systemd:systemctl list-jobs"]="Active jobs"
MENU["Systemd:systemd-cgtop -n 1"]="Control group resource usage (1 iteration)"
MENU["Systemd:systemd-cgls"]="Control group hierarchy"
MENU["Systemd:systemd-delta"]="Configuration overrides"
MENU["Systemd:systemd-analyze security"]="Security analysis of units"

# 🌐 NETWORK ADVANCED
MENU["Network Advanced:arp -a"]="ARP cache table"
MENU["Network Advanced:route -n"]="Routing table (numeric)"
MENU["Network Advanced:ip neigh"]="Neighbor table (ARP/NDP)"
MENU["Network Advanced:ss -s"]="Socket statistics summary"
MENU["Network Advanced:ss -antp"]="All TCP connections with processes"
MENU["Network Advanced:ss -anup"]="All UDP connections with processes"
MENU["Network Advanced:iftop -n -t -s 5"]="Bandwidth by connection (5 sec)"
MENU["Network Advanced:tcpdump -i any -c 100 -nn"]="Packet capture (100 packets)"
MENU["Network Advanced:netstat -i"]="Network interface statistics"
MENU["Network Advanced:ip -s -s link"]="Detailed interface statistics"

# 🔒 SECURITY & HARDENING
MENU["Security Audit:aa-status"]="AppArmor status"
MENU["Security Audit:sestatus"]="SELinux status"
MENU["Security Audit:getenforce"]="SELinux enforcement mode"
MENU["Security Audit:ufw status verbose"]="UFW firewall status"
MENU["Security Audit:fail2ban-client status"]="Fail2ban service status"
MENU["Security Audit:lastb | head -20"]="Failed login attempts (first 20)"
MENU["Security Audit:w -i"]="Who with IP addresses"
MENU["Security Audit:find / -perm -4000 -ls 2>/dev/null | head -30"]="SUID files (first 30)"
MENU["Security Audit:find / -perm -2000 -ls 2>/dev/null | head -30"]="SGID files (first 30)"

# ⏰ TIME & NTP
MENU["Time & NTP:timedatectl status"]="Time and date status"
MENU["Time & NTP:timedatectl show-timesync --all"]="Detailed time sync info"
MENU["Time & NTP:chronyc tracking"]="Chrony NTP tracking"
MENU["Time & NTP:chronyc sources"]="Chrony time sources"
MENU["Time & NTP:ntpq -p"]="NTP peers"
MENU["Time & NTP:date"]="Current date and time"
MENU["Time & NTP:hwclock --show"]="Hardware clock"

# ═══════════════════════════════════════════════════════════════════════════
# NEW CATEGORIES - MEDIUM PRIORITY
# ═══════════════════════════════════════════════════════════════════════════

# ⏱️ CRON & SCHEDULED TASKS
MENU["Scheduled Tasks:crontab -l"]="Current user's crontab"
MENU["Scheduled Tasks:sudo crontab -l"]="Root's crontab"
MENU["Scheduled Tasks:ls -la /etc/cron.d/"]="Cron.d directory"
MENU["Scheduled Tasks:ls -la /etc/cron.daily/"]="Daily cron jobs"
MENU["Scheduled Tasks:ls -la /etc/cron.hourly/"]="Hourly cron jobs"
MENU["Scheduled Tasks:ls -la /etc/cron.weekly/"]="Weekly cron jobs"
MENU["Scheduled Tasks:cat /etc/crontab"]="System crontab"
MENU["Scheduled Tasks:systemctl list-timers --all"]="All systemd timers"
MENU["Scheduled Tasks:at -l"]="Pending at jobs"

# 🔐 CERTIFICATES & SSL
MENU["Certificates:certbot certificates"]="Let's Encrypt certificates"
MENU["Certificates:openssl version -a"]="OpenSSL version"
MENU["Certificates:ls -lh /etc/ssl/certs/ | head -30"]="SSL certificates directory (first 30)"
MENU["Certificates:update-ca-certificates --fresh --verbose"]="Update CA certificates"

# 🥾 BOOT & GRUB
MENU["Boot:efibootmgr -v"]="EFI boot entries"
MENU["Boot:grub-install --version"]="GRUB version"
MENU["Boot:cat /boot/grub/grub.cfg | head -50"]="GRUB config (first 50 lines)"
MENU["Boot:cat /proc/cmdline"]="Kernel boot parameters"
MENU["Boot:dmesg | head -100"]="Early boot messages (first 100)"
MENU["Boot:journalctl -b 0 | head -100"]="Current boot log (first 100)"

# 🌐 WEB SERVERS
MENU["Web Servers:apache2ctl -S"]="Apache virtual hosts"
MENU["Web Servers:apache2ctl -V"]="Apache version and settings"
MENU["Web Servers:nginx -t"]="Nginx config test"
MENU["Web Servers:nginx -T"]="Nginx config dump"
MENU["Web Servers:nginx -v"]="Nginx version"
MENU["Web Servers:curl -I localhost"]="Local web server check"
MENU["Web Servers:systemctl status apache2"]="Apache service status"
MENU["Web Servers:systemctl status nginx"]="Nginx service status"

# 📦 QUOTA & LIMITS
MENU["Quotas:quota -v"]="User disk quota"
MENU["Quotas:repquota -a"]="All quotas"
MENU["Quotas:cat /etc/security/limits.conf"]="System limits config"
MENU["Quotas:ulimit -a"]="Current shell limits"

# 🔊 SOUND & AUDIO
MENU["Audio:aplay -l"]="List playback devices"
MENU["Audio:arecord -l"]="List recording devices"
MENU["Audio:pactl list sinks short"]="PulseAudio sinks"
MENU["Audio:pactl list sources short"]="PulseAudio sources"
MENU["Audio:amixer scontrols"]="ALSA mixer controls"

# 🖥️ GRAPHICS & DISPLAY
MENU["Graphics:xrandr"]="Display configuration"
MENU["Graphics:glxinfo | grep OpenGL"]="OpenGL information"
MENU["Graphics:xdpyinfo | head -30"]="X display info (first 30 lines)"
MENU["Graphics:cat /var/log/Xorg.0.log | grep EE"]="X errors"
MENU["Graphics:nvidia-smi"]="NVIDIA GPU info"

# 🔋 POWER MANAGEMENT
MENU["Power:acpi -V"]="ACPI information"
MENU["Power:cat /sys/class/power_supply/BAT0/capacity 2>/dev/null || echo 'No battery found'"]="Battery percentage"
MENU["Power:cat /sys/class/power_supply/BAT0/status 2>/dev/null || echo 'No battery found'"]="Battery status"
MENU["Power:powertop --html=~/powertop.html && echo 'Report saved to ~/powertop.html'"]="Power consumption report"

# 🔌 USB & PERIPHERALS
MENU["USB:usb-devices"]="USB device details"
MENU["USB:lsusb -t"]="USB device tree"
MENU["USB:dmesg | grep -i usb | tail -50"]="Recent USB messages (last 50)"

# 📡 BLUETOOTH
MENU["Bluetooth:bluetoothctl show"]="Bluetooth controller info"
MENU["Bluetooth:hciconfig -a"]="Bluetooth device info"
MENU["Bluetooth:rfkill list"]="Radio device status"

# 📋 SYSTEM INFO SUMMARY
MENU["System Info:screenfetch"]="System info with ASCII art"
MENU["System Info:neofetch"]="Modern system info"
MENU["System Info:landscape-sysinfo"]="Ubuntu landscape info"
MENU["System Info:hostnamectl"]="Hostname information"

# ═══════════════════════════════════════════════════════════════════════════
# SPECIAL ACTIONS
# ═══════════════════════════════════════════════════════════════════════════

MENU["Quick Actions:HEALTH_CHECK"]="🏥 Run comprehensive health check"
MENU["Quick Actions:EXPORT_REPORT"]="📄 Export full diagnostic report"
MENU["Quick Actions:SEARCH_COMMANDS"]="🔍 Search all commands"
MENU["Quick Actions:VIEW_HISTORY"]="📜 View command history"
MENU["Quick Actions:VIEW_FAVORITES"]="⭐ View favorite commands"

# ═══════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

# Check if command exists
check_command_exists() {
  local cmd=$1
  local base_cmd=$(echo "$cmd" | awk '{print $1}')
  
  if ! command -v "$base_cmd" &> /dev/null; then
    whiptail --title "Command Not Found" --msgbox \
      "Command '$base_cmd' is not installed.\n\nInstall with:\nsudo apt install $base_cmd\n\nOr check if it's available in your distribution's repositories." 12 70
    return 1
  fi
  return 0
}

# Check if command needs sudo
needs_sudo() {
  local cmd=$1
  if [[ "$cmd" =~ ^(iptables|dmidecode|hwinfo|smartctl|hdparm|fsck|docker|systemctl.*restart|systemctl.*stop|systemctl.*start|apt|dpkg) ]]; then
    return 0
  fi
  return 1
}

# Display output with size handling
display_output() {
  local cmd="$1"
  local output="$2"
  local exit_code="$3"
  
  # Count lines in output
  local line_count=$(echo "$output" | wc -l)
  local char_count=$(echo "$output" | wc -c)
  
  # Whiptail has a limit of ~100KB for arguments
  if [[ $char_count -gt 50000 ]] || [[ $line_count -gt 1000 ]]; then
    local temp_file=$(mktemp /tmp/diagnostic_output.XXXXXX)
    echo "$output" > "$temp_file"
    
    if whiptail --title "Large Output Detected" --yesno "Output is very large ($line_count lines, $(($char_count / 1024))KB).\n\nView in 'less' pager for better navigation?\n\nYes = Open in less (recommended)\nNo = Show truncated output in dialog" 15 70 3>&1 1>&2 2>&3; then
      clear
      echo "=========================================="
      echo "Command: $cmd"
      echo "=========================================="
      echo ""
      less "$temp_file"
      rm -f "$temp_file"
    else
      local truncated_output=$(echo "$output" | head -500)
      local warning_msg="⚠️  OUTPUT TRUNCATED ⚠️\n\nShowing first 500 of $line_count lines\nFull output: $(($char_count / 1024))KB\n\n"
      warning_msg+="Run command manually to see full output:\n$cmd\n\n"
      warning_msg+="----------------------------------------\n\n"
      warning_msg+="$truncated_output"
      
      if [[ $exit_code -ne 0 ]]; then
        whiptail --title "Command Failed (Exit Code: $exit_code)" --scrolltext --msgbox "$warning_msg" 30 100
      else
        whiptail --title "Output: $cmd" --scrolltext --msgbox "$warning_msg" 30 100
      fi
      rm -f "$temp_file"
    fi
  else
    if [[ $exit_code -ne 0 ]]; then
      whiptail --title "Command Failed (Exit Code: $exit_code)" --scrolltext --msgbox "Command: $cmd\n\n$output" 30 100
    else
      whiptail --title "Output: $cmd" --scrolltext --msgbox "$output" 30 100
    fi
  fi
}

# Log command to history
log_to_history() {
  local cmd="$1"
  echo "$(date '+%Y-%m-%d %H:%M:%S') | $cmd" >> "$HISTORY_FILE"
}

# Add to favorites
add_to_favorites() {
  local key="$1"
  if ! grep -q "^$key$" "$FAVORITES_FILE" 2>/dev/null; then
    echo "$key" >> "$FAVORITES_FILE"
    whiptail --title "Added to Favorites" --msgbox "Command added to favorites!\n\nAccess via: Quick Actions → View Favorites" 10 60
  else
    whiptail --title "Already in Favorites" --msgbox "This command is already in your favorites." 8 50
  fi
}

# Health check function
run_health_check() {
  local report=""
  report+="═══════════════════════════════════════════════════════════\n"
  report+="SYSTEM HEALTH CHECK REPORT\n"
  report+="Generated: $(date)\n"
  report+="═══════════════════════════════════════════════════════════\n\n"
  
  # System Info
  report+="[SYSTEM INFO]\n"
  report+="Hostname: $(hostname)\n"
  report+="Kernel: $(uname -r)\n"
  report+="Uptime: $(uptime -p)\n\n"
  
  # Load Average
  report+="[LOAD AVERAGE]\n"
  report+="$(uptime | awk -F'load average:' '{print $2}')\n\n"
  
  # CPU
  report+="[CPU]\n"
  report+="$(lscpu | grep -E '^Model name|^CPU\(s\):|^Thread|^Core')\n\n"
  
  # Memory
  report+="[MEMORY]\n"
  report+="$(free -h)\n\n"
  
  # Disk Space
  report+="[DISK SPACE]\n"
  report+="$(df -h | grep -v tmpfs | grep -v loop)\n\n"
  
  # Failed Services
  report+="[FAILED SERVICES]\n"
  local failed=$(systemctl --failed --no-pager --no-legend)
  if [[ -z "$failed" ]]; then
    report+="✓ No failed services\n\n"
  else
    report+="$failed\n\n"
  fi
  
  # Recent Errors
  report+="[RECENT ERRORS - Last 20]\n"
  report+="$(journalctl -p err -n 20 --no-pager 2>/dev/null || echo 'Unable to read journal')\n\n"
  
  # Network
  report+="[NETWORK]\n"
  report+="$(ip -br a)\n\n"
  
  # Top Processes by CPU
  report+="[TOP 5 CPU CONSUMERS]\n"
  report+="$(ps aux --sort=-pcpu | head -6 | tail -5)\n\n"
  
  # Top Processes by Memory
  report+="[TOP 5 MEMORY CONSUMERS]\n"
  report+="$(ps aux --sort=-%mem | head -6 | tail -5)\n\n"
  
  report+="═══════════════════════════════════════════════════════════\n"
  report+="END OF HEALTH CHECK REPORT\n"
  report+="═══════════════════════════════════════════════════════════\n"
  
  display_output "Health Check" "$report" 0
  
  # Offer to save
  if whiptail --title "Save Report?" --yesno "Would you like to save this health check report to a file?" 8 60 3>&1 1>&2 2>&3; then
    local filename="health_check_$(date +%Y%m%d_%H%M%S).txt"
    echo -e "$report" > ~/"$filename"
    whiptail --title "Report Saved" --msgbox "Health check report saved to:\n\n~/$filename" 10 60
  fi
}

# Export full diagnostic report
export_full_report() {
  local filename="diagnostic_report_$(date +%Y%m%d_%H%M%S).txt"
  local report_file=~/"$filename"
  
  whiptail --title "Generating Report" --infobox "Generating comprehensive diagnostic report...\n\nThis may take a few minutes." 8 60
  
  {
    echo "═══════════════════════════════════════════════════════════"
    echo "COMPREHENSIVE SYSTEM DIAGNOSTIC REPORT"
    echo "Generated: $(date)"
    echo "Hostname: $(hostname)"
    echo "═══════════════════════════════════════════════════════════"
    echo ""
    
    # Run a selection of key commands
    local key_commands=(
      "uname -a"
      "uptime"
      "free -h"
      "df -h"
      "lsblk"
      "ip a"
      "systemctl --failed"
      "journalctl -p err -n 50 --no-pager"
    )
    
    for cmd in "${key_commands[@]}"; do
      echo ""
      echo "───────────────────────────────────────────────────────────"
      echo "Command: $cmd"
      echo "───────────────────────────────────────────────────────────"
      eval "$cmd" 2>&1 || echo "Command failed or not available"
      echo ""
    done
    
    echo "═══════════════════════════════════════════════════════════"
    echo "END OF REPORT"
    echo "═══════════════════════════════════════════════════════════"
  } > "$report_file"
  
  whiptail --title "Report Generated" --msgbox "Comprehensive diagnostic report saved to:\n\n$report_file\n\nYou can view it with:\nless $report_file" 12 70
}

# Search commands
search_commands() {
  local keyword=$(whiptail --inputbox "Enter search keyword:" 10 60 3>&1 1>&2 2>&3)
  [[ -z "$keyword" ]] && return
  
  local results=()
  for key in "${!MENU[@]}"; do
    if [[ "$key" =~ $keyword ]] || [[ "${MENU[$key]}" =~ $keyword ]]; then
      results+=("$key" "${MENU[$key]}")
    fi
  done
  
  if [[ ${#results[@]} -eq 0 ]]; then
    whiptail --title "No Results" --msgbox "No commands found matching: $keyword" 8 60
    return
  fi
  
  local choice=$(whiptail --title "Search Results for: $keyword" --menu "Found ${#results[@]} matches:" 25 100 15 "${results[@]}" 3>&1 1>&2 2>&3)
  [[ -z "$choice" ]] && return
  
  # Execute the selected command
  execute_command "$choice"
}

# View history
view_history() {
  if [[ ! -f "$HISTORY_FILE" ]]; then
    whiptail --title "No History" --msgbox "No command history found yet." 8 50
    return
  fi
  
  local history_content=$(tail -50 "$HISTORY_FILE")
  whiptail --title "Command History (Last 50)" --scrolltext --msgbox "$history_content" 25 100
}

# View favorites
view_favorites() {
  if [[ ! -f "$FAVORITES_FILE" ]] || [[ ! -s "$FAVORITES_FILE" ]]; then
    whiptail --title "No Favorites" --msgbox "No favorite commands yet.\n\nAdd favorites by selecting a command and choosing 'Add to Favorites'." 10 60
    return
  fi
  
  local fav_options=()
  while IFS= read -r key; do
    [[ -n "$key" ]] && fav_options+=("$key" "${MENU[$key]}")
  done < "$FAVORITES_FILE"
  
  if [[ ${#fav_options[@]} -eq 0 ]]; then
    whiptail --title "No Favorites" --msgbox "No favorite commands found." 8 50
    return
  fi
  
  local choice=$(whiptail --title "Favorite Commands" --menu "Select a favorite command:" 25 100 15 "${fav_options[@]}" 3>&1 1>&2 2>&3)
  [[ -z "$choice" ]] && return
  
  execute_command "$choice"
}

# Execute command (extracted for reuse)
execute_command() {
  local CHOICE="$1"
  local CMD=$(echo "$CHOICE" | cut -d: -f2-)
  
  # Check if command requires user input (contains placeholders)
  if [[ "$CMD" =~ \<.*\> ]]; then
    whiptail --title "Command Requires Input" --msgbox "This command contains placeholders:\n\n$CMD\n\nPlease run it manually in your terminal and replace the placeholders with actual values." 12 80
    return
  fi
  
  # Check if command exists
  if ! check_command_exists "$CMD"; then
    return
  fi
  
  # Check if dangerous
  if [[ "${COMMAND_SAFETY[$CHOICE]}" == "DANGEROUS" ]]; then
    if ! whiptail --title "⚠️  DANGEROUS COMMAND WARNING ⚠️" --yesno "This command can cause system disruption:\n\n$CMD\n\nAre you SURE you want to proceed?" 12 70 3>&1 1>&2 2>&3; then
      return
    fi
  fi
  
  # Execute command and capture output
  OUTPUT=$(eval "$CMD" 2>&1)
  EXIT_CODE=$?
  
  # Log to history
  log_to_history "$CMD"
  
  # Display output with size handling
  display_output "$CMD" "$OUTPUT" "$EXIT_CODE"
  
  # Offer to add to favorites
  if whiptail --title "Add to Favorites?" --yesno "Would you like to add this command to your favorites for quick access?" 8 60 3>&1 1>&2 2>&3; then
    add_to_favorites "$CHOICE"
  fi
}

# ═══════════════════════════════════════════════════════════════════════════
# MAIN LOOP
# ═══════════════════════════════════════════════════════════════════════════

while true; do
  # Build category list
  CATEGORIES=()
  for key in "${!MENU[@]}"; do
    CATEGORY="${key%%:*}"
    if [[ ! " ${CATEGORIES[*]} " =~ " ${CATEGORY} " ]]; then
      CATEGORIES+=("$CATEGORY")
    fi
  done

  # Sort categories alphabetically
  IFS=$'\n' CATEGORIES=($(sort <<<"${CATEGORIES[*]}"))
  unset IFS

  # Build whiptail menu with label-description pairs
  CATEGORY_OPTIONS=()
  for c in "${CATEGORIES[@]}"; do
    CATEGORY_OPTIONS+=("$c" "$c")
  done

  CATEGORY=$(whiptail --title "🧰 System Diagnostic Toolkit - Swiss Army Knife Edition v3.0" --menu "Select a category:" 25 70 15 "${CATEGORY_OPTIONS[@]}" 3>&1 1>&2 2>&3)
  [[ $? -ne 0 ]] && exit 0

  # Handle special actions
  if [[ "$CATEGORY" == "Quick Actions" ]]; then
    # Build Quick Actions submenu
    QA_COMMANDS=()
    for key in "${!MENU[@]}"; do
      [[ "$key" == "Quick Actions:"* ]] && QA_COMMANDS+=("$key" "${MENU[$key]}")
    done
    
    QA_CHOICE=$(whiptail --title "Quick Actions" --menu "Select an action:" 20 70 10 "${QA_COMMANDS[@]}" 3>&1 1>&2 2>&3)
    [[ $? -ne 0 ]] && continue
    
    case "$QA_CHOICE" in
      "Quick Actions:HEALTH_CHECK")
        run_health_check
        ;;
      "Quick Actions:EXPORT_REPORT")
        export_full_report
        ;;
      "Quick Actions:SEARCH_COMMANDS")
        search_commands
        ;;
      "Quick Actions:VIEW_HISTORY")
        view_history
        ;;
      "Quick Actions:VIEW_FAVORITES")
        view_favorites
        ;;
    esac
    continue
  fi

  PAGE=0
  while true; do
    # Build command list for selected category
    COMMANDS=()
    for key in "${!MENU[@]}"; do
      [[ "$key" == "$CATEGORY:"* ]] && COMMANDS+=("$key" "${MENU[$key]}")
    done

    # Calculate pagination
    PAGE_SIZE=10
    ITEMS_PER_PAGE=$((PAGE_SIZE * 2))
    START=$((PAGE * ITEMS_PER_PAGE))
    TOTAL_ITEMS=${#COMMANDS[@]}
    
    # Extract page items
    PAGE_OPTIONS=("${COMMANDS[@]:$START:$ITEMS_PER_PAGE}")

    # Add navigation options
    TOTAL_PAGES=$(( (TOTAL_ITEMS + ITEMS_PER_PAGE - 1) / ITEMS_PER_PAGE ))
    [[ $((START + ITEMS_PER_PAGE)) -lt $TOTAL_ITEMS ]] && PAGE_OPTIONS+=("NEXT" "Next page →")
    [[ $PAGE -gt 0 ]] && PAGE_OPTIONS+=("PREV" "← Previous page")
    PAGE_OPTIONS+=("BACK" "↩ Return to category menu")

    CHOICE=$(whiptail --title "$CATEGORY Commands (Page $((PAGE+1))/$TOTAL_PAGES)" --menu "Select a command to run:" 25 100 15 "${PAGE_OPTIONS[@]}" 3>&1 1>&2 2>&3)
    [[ $? -ne 0 ]] && break

    case "$CHOICE" in
      "NEXT") PAGE=$((PAGE + 1)); continue ;;
      "PREV") PAGE=$((PAGE - 1)); continue ;;
      "BACK") break ;;
      *)
        execute_command "$CHOICE"
        ;;
    esac
  done
done
