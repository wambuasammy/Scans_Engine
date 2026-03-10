#!/bin/bash

CSV_FILE="ubuntu_security_assessment.csv"

# Initialize CSV
echo "Ubuntu security assessment posture,Pass/Fail,Remediation" > $CSV_FILE

write_csv() {
    echo "\"$1\",\"$2\",\"$3\"" >> $CSV_FILE
}

# Output helpers
print_section() { echo ""; echo "************ $1 ************"; }
check_msg() { echo "Checking $1..."; }
pass_msg() { echo "PASS: $1"; }
fail_msg() { echo "FAIL: $1"; }

# -------------------------------------------
# 1. UBUNTU VERSION AND PACKAGE UPDATES
# -------------------------------------------
print_section "1. UBUNTU VERSION AND PACKAGE UPDATES"

check_msg "Ubuntu LTS version"
ubuntu_version=$(lsb_release -sr)

if [[ "$ubuntu_version" == "24.04" ]]; then
    pass_msg "Ubuntu is on LTS version $ubuntu_version"
    write_csv "Ubuntu LTS version" "PASS" "Remediation not needed"
else
    fail_msg "Ubuntu is on non-LTS version $ubuntu_version"
    write_csv "Ubuntu LTS version" "FAIL" "Upgrade to Ubuntu 24.04 LTS"
fi

# -------------------------------------------
# 2. FILE SYSTEM CONFIGURATION
# -------------------------------------------
print_section "2. FILE SYSTEM CONFIGURATION"

check_module_disabled() {
    local module="$1"; local name="$2"
    check_msg "$name"

    modprobe_check=$(modprobe -n -v "$module" 2>/dev/null)
    lsmod_check=$(lsmod | grep -w "$module")

    if [[ "$modprobe_check" == "install /bin/true" && -z "$lsmod_check" ]]; then
        pass_msg "$name"
        write_csv "$name" "PASS" "Remediation not needed"
    else
        fail_msg "$name"
        write_csv "$name" "FAIL" "Add 'install $module /bin/true' to /etc/modprobe.d/CIS.conf and rmmod $module"
    fi
}

check_module_disabled "cramfs" "Ensure cramfs disabled"
check_module_disabled "freevxfs" "Ensure freevxfs disabled"
check_module_disabled "jffs2" "Ensure jffs2 disabled"
check_module_disabled "usb-storage" "Ensure USB storage disabled"

check_mount_option() {
    local mount_point="$1"; local option="$2"; local name="$3"
    check_msg "$name"

    mount | grep -E "\s$mount_point\s" | grep -vq "$option"
    if [[ $? -ne 0 ]]; then
        pass_msg "$name"
        write_csv "$name" "PASS" "Remediation not needed"
    else
        fail_msg "$name"
        write_csv "$name" "FAIL" "Add $option to /etc/fstab and remount $mount_point"
    fi
}

check_mount_option "/var/tmp" "noexec" "Ensure noexec on /var/tmp"

check_partition() {
    local partition="$1"; local name="$2"
    check_msg "$name"

    mount | grep -q " $partition "
    if [[ $? -eq 0 ]]; then
        pass_msg "$name"
        write_csv "$name" "PASS" "Remediation not needed"
    else
        fail_msg "$name"
        write_csv "$name" "FAIL" "Create separate partition and configure /etc/fstab"
    fi
}

check_partition "/var/log" "Separate partition for /var/log"
check_partition "/var/log/audit" "Separate partition for /var/log/audit"
check_partition "/home" "Separate partition for /home"

check_msg "Sticky bit on world-writable directories"
sticky_check=$(df --local -P | awk 'NR!=1 {print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null)
if [[ -z "$sticky_check" ]]; then
    pass_msg "Sticky bit set"
    write_csv "Sticky bit on world writable dirs" "PASS" "Remediation not needed"
else
    fail_msg "Sticky bit missing"
    write_csv "Sticky bit on world writable dirs" "FAIL" "Run chmod a+t on affected directories"
fi

# -------------------------------------------
# 3. CONFIGURE SOFTWARE UPDATES
# -------------------------------------------
print_section "3. CONFIGURE SOFTWARE UPDATES"

check_msg "Package manager repositories"
apt_policy=$(apt-cache policy 2>/dev/null)
if [[ -n "$apt_policy" ]]; then
    pass_msg "Package manager repositories configured"
    write_csv "Package manager repositories configured" "PASS" "Remediation not needed"
else
    fail_msg "Package manager repositories not configured"
    write_csv "Package manager repositories configured" "FAIL" "Configure repositories per site policy"
fi

check_msg "Package manager GPG keys"
gpg_keys=$(apt-key list 2>/dev/null)
if [[ -n "$gpg_keys" ]]; then
    pass_msg "GPG keys configured"
    write_csv "GPG keys configured" "PASS" "Remediation not needed"
else
    fail_msg "GPG keys missing"
    write_csv "GPG keys configured" "FAIL" "Update GPG keys per site policy"
fi

# -------------------------------------------
# 4. CONFIGURE SUDO
# -------------------------------------------
print_section "4. CONFIGURE SUDO"

check_msg "sudo installation"
dpkg -s sudo &>/dev/null && pass_msg "sudo installed" || fail_msg "sudo not installed"
write_csv "Sudo installed" "$([[ $? -eq 0 ]] && echo PASS || echo FAIL)" "apt install sudo"

check_msg "sudo use_pty"
grep -Ei 'Defaults\s+use_pty' /etc/sudoers /etc/sudoers.d/* &>/dev/null && pass_msg "sudo uses pty" || fail_msg "sudo does not use pty"
write_csv "Sudo use_pty" "$([[ $? -eq 0 ]] && echo PASS || echo FAIL)" "Add Defaults use_pty"

check_msg "sudo logfile"
grep -Ei 'Defaults\s+logfile=' /etc/sudoers /etc/sudoers.d/* &>/dev/null && pass_msg "sudo logfile configured" || fail_msg "sudo logfile missing"
write_csv "Sudo logfile" "$([[ $? -eq 0 ]] && echo PASS || echo FAIL)" "Add Defaults logfile=/var/log/sudo.log"

# -------------------------------------------
# 5. FILE SYSTEM INTEGRITY CHECKING
# -------------------------------------------
print_section "5. FILE SYSTEM INTEGRITY CHECKING"

check_msg "AIDE installation"
dpkg -s aide aide-common &>/dev/null && pass_msg "AIDE installed" || fail_msg "AIDE not installed"
write_csv "AIDE installed" "$([[ $? -eq 0 ]] && echo PASS || echo FAIL)" "apt install aide aide-common"

check_msg "AIDE scheduling"
systemctl is-enabled aidecheck.timer &>/dev/null && pass_msg "AIDE scheduled" || fail_msg "AIDE not scheduled"
write_csv "AIDE scheduled" "$([[ $? -eq 0 ]] && echo PASS || echo FAIL)" "Configure cron or systemd timer"

# -------------------------------------------
# 6. SECURE BOOT SETTINGS
# -------------------------------------------
print_section "6. SECURE BOOT SETTINGS"

check_msg "Bootloader password"
grep "^set superusers" /boot/grub/grub.cfg &>/dev/null && grep "^password_pbkdf2" /boot/grub/grub.cfg &>/dev/null \
&& pass_msg "Bootloader password set" || fail_msg "Bootloader password missing"
write_csv "Bootloader password" "$([[ $? -eq 0 ]] && echo PASS || echo FAIL)" "Use grub-mkpasswd-pbkdf2 and update-grub"

check_msg "GRUB permissions"
stat -c "%a %u %g" /boot/grub/grub.cfg | grep -q "^400 0 0$" && pass_msg "GRUB permissions secure" || fail_msg "GRUB permissions insecure"
write_csv "GRUB permissions" "$([[ $? -eq 0 ]] && echo PASS || echo FAIL)" "chmod 400 /boot/grub/grub.cfg"

check_msg "Root authentication for single-user mode"
grep '^root:[*!]:' /etc/shadow &>/dev/null && fail_msg "Root has no password" || pass_msg "Root requires authentication"
write_csv "Single user auth" "$([[ $? -ne 0 ]] && echo PASS || echo FAIL)" "passwd root"

# -------------------------------------------
# 7. ADDITIONAL PROCESS HARDENING
# -------------------------------------------
print_section "7. ADDITIONAL PROCESS HARDENING"

check_msg "NX/XD protection"
journalctl | grep -q "NX (Execute Disable) protection: active" && pass_msg "NX/XD enabled" || fail_msg "NX/XD not active"
write_csv "NX/XD enabled" "$([[ $? -eq 0 ]] && echo PASS || echo FAIL)" "Enable in BIOS or install PAE kernel"

check_msg "ASLR"
sysctl kernel.randomize_va_space | grep -q "= 2" && pass_msg "ASLR enabled" || fail_msg "ASLR disabled"
write_csv "ASLR enabled" "$([[ $? -eq 0 ]] && echo PASS || echo FAIL)" "Set kernel.randomize_va_space=2"

check_msg "Prelink"
dpkg -s prelink &>/dev/null && fail_msg "prelink installed" || pass_msg "prelink not installed"
write_csv "Prelink disabled" "$([[ $? -ne 0 ]] && echo PASS || echo FAIL)" "apt purge prelink"

# -------------------------------------------
# 8. APPARMOR
# -------------------------------------------
print_section "8. APPARMOR"

check_msg "AppArmor installation"
dpkg -s apparmor &>/dev/null && pass_msg "AppArmor is installed" || fail_msg "AppArmor not installed"
write_csv "AppArmor installed" "$([[ $? -eq 0 ]] && echo PASS || echo FAIL)" "apt install apparmor"

check_msg "AppArmor boot parameters"
grep "apparmor=1" /boot/grub/grub.cfg &>/dev/null && grep "security=apparmor" /boot/grub/grub.cfg &>/dev/null \
&& pass_msg "AppArmor boot parameters present" || fail_msg "AppArmor boot parameters missing"
write_csv "AppArmor boot enabled" "$([[ $? -eq 0 ]] && echo PASS || echo FAIL)" "Edit GRUB_CMDLINE_LINUX and update-grub"

check_msg "AppArmor profiles (enforce/complain)"
profiles_loaded=$(apparmor_status | awk '/profiles are loaded/ {print $1}')
if [[ "$profiles_loaded" =~ ^[0-9]+$ && "$profiles_loaded" -gt 0 ]]; then
    pass_msg "AppArmor profiles loaded in enforce or complain mode"
    write_csv "AppArmor profiles loaded" "PASS" "Remediation not needed"
else
    fail_msg "No AppArmor profiles loaded"
    write_csv "AppArmor profiles loaded" "FAIL" "Run aa-enforce /etc/apparmor.d/*"
fi

check_msg "AppArmor profiles enforcing"
complain=$(apparmor_status | awk '/profiles are in complain mode/ {print $1}')
complain=${complain:-0}
if [[ "$complain" -eq 0 ]]; then
    pass_msg "All AppArmor profiles are enforcing"
    write_csv "AppArmor enforce mode" "PASS" "Remediation not needed"
else
    fail_msg "Some AppArmor profiles in complain mode"
    write_csv "AppArmor enforce mode" "FAIL" "Run aa-enforce /etc/apparmor.d/*"
fi

echo ""

# -------------------------------------------
# 9. WARNING BANNERS
# -------------------------------------------
echo "************ 9. WARNING BANNERS ************"

# Function to check banner content for OS leakage
check_banner_content() {
    local file="$1"
    local name="$2"

    if [[ ! -f "$file" ]]; then
        echo "FAIL: $name missing"
        write_csv "$name" "FAIL" "Create banner file per site policy"
        return
    fi

    grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed 's/\"//g'))" "$file" &>/dev/null
    if [[ $? -eq 0 ]]; then
        echo "FAIL: $name contains OS information"
        write_csv "$name" "FAIL" "Remove OS info (\\m \\r \\s \\v) and OS references"
    else
        echo "PASS: $name configured properly"
        write_csv "$name" "PASS" "Remediation not needed"
    fi
}

# Check MOTD banner
echo "Checking message of the day banner..."
check_banner_content "/etc/motd" "MOTD banner configured"

# Check local login banner
echo "Checking local login warning banner..."
check_banner_content "/etc/issue" "Local login banner configured"

# Check remote login banner
echo "Checking remote login warning banner..."
check_banner_content "/etc/issue.net" "Remote login banner configured"

# Function to check banner permissions
check_banner_permissions() {
    local file="$1"
    local name="$2"

    if [[ ! -f "$file" ]]; then
        echo "PASS: $name not present"
        write_csv "$name permissions" "PASS" "Remediation not needed"
        return
    fi

    perms=$(stat -c "%a %u %g" "$file")
    if [[ "$perms" == "644 0 0" ]]; then
        echo "PASS: $name permissions correct"
        write_csv "$name permissions" "PASS" "Remediation not needed"
    else
        echo "FAIL: $name permissions incorrect"
        write_csv "$name permissions" "FAIL" "chown root:root $file && chmod 644 $file"
    fi
}

# Check permissions
echo "Checking /etc/motd permissions..."
check_banner_permissions "/etc/motd" "/etc/motd"

echo "Checking /etc/issue permissions..."
check_banner_permissions "/etc/issue" "/etc/issue"

echo "Checking /etc/issue.net permissions..."
check_banner_permissions "/etc/issue.net" "/etc/issue.net"

# Ensure system updates installed (policy-level check)
echo "Checking pending system updates..."
updates=$(apt -s upgrade 2>/dev/null | grep -c "^Inst")
if [[ "$updates" -eq 0 ]]; then
    echo "PASS: No pending updates"
    write_csv "System updates installed" "PASS" "Remediation not needed"
else
    echo "FAIL: $updates pending updates"
    write_csv "System updates installed" "FAIL" "Run apt upgrade or apt dist-upgrade per policy"
fi

# Check GDM configuration
echo "Checking GDM login banner configuration..."
if dpkg -s gdm3 &>/dev/null; then
    if grep -q "banner-message-enable=true" /etc/gdm3/greeter.dconf-defaults 2>/dev/null && \
       grep -q "disable-user-list=true" /etc/gdm3/greeter.dconf-defaults 2>/dev/null; then
        echo "PASS: GDM banner configured and user list disabled"
        write_csv "GDM banner configured" "PASS" "Remediation not needed"
    else
        echo "FAIL: GDM banner not configured securely"
        write_csv "GDM banner configured" "FAIL" "Configure banner-message-enable and disable-user-list in greeter.dconf-defaults"
    fi
else
    echo "PASS: GDM not installed"
    write_csv "GDM installed" "PASS" "Remediation not needed"
fi

# -------------------------------------------
# 10. INETD SERVICES
# -------------------------------------------
echo "************ 10. INETD SERVICES ************"

# Check if xinetd is installed
dpkg -s xinetd &>/dev/null
if [[ $? -ne 0 ]]; then
    echo "PASS: xinetd not installed"
    write_csv "xinetd not installed" "PASS" "Remediation not needed"
else
    echo "FAIL: xinetd installed"
    write_csv "xinetd not installed" "FAIL" "apt purge xinetd"
fi

# Check if openbsd-inetd is installed
dpkg -s openbsd-inetd &>/dev/null
if [[ $? -ne 0 ]]; then
    echo "PASS: openbsd-inetd not installed"
    write_csv "openbsd-inetd not installed" "PASS" "Remediation not needed"
else
    echo "FAIL: openbsd-inetd installed"
    write_csv "openbsd-inetd not installed" "FAIL" "apt purge openbsd-inetd"
fi

# -------------------------------------------
# 11. TIME SYNCHRONIZATION
# -------------------------------------------
echo "************ 11. TIME SYNCHRONIZATION ************"

# Check if systemd-timesyncd is enabled
systemctl is-enabled systemd-timesyncd &>/dev/null
timesyncd_enabled=$?

# Check if chrony is installed
dpkg -s chrony &>/dev/null
chrony_installed=$?

# Check if ntp is installed
dpkg -s ntp &>/dev/null
ntp_installed=$?

# Determine which time sync method is in use
if [[ $timesyncd_enabled -eq 0 && $chrony_installed -ne 0 && $ntp_installed -ne 0 ]]; then
    echo "PASS: systemd-timesyncd is in use"
    write_csv "systemd-timesyncd in use" "PASS" "Remediation not needed"
elif [[ $chrony_installed -eq 0 && $timesyncd_enabled -ne 0 && $ntp_installed -ne 0 ]]; then
    echo "PASS: chrony is in use"
    write_csv "chrony in use" "PASS" "Remediation not needed"
elif [[ $ntp_installed -eq 0 && $timesyncd_enabled -ne 0 && $chrony_installed -ne 0 ]]; then
    echo "PASS: NTP is in use"
    write_csv "NTP in use" "PASS" "Remediation not needed"
else
    echo "FAIL: Multiple or no time synchronization methods configured"
    write_csv "Time synchronization method" "FAIL" "Remove additional methods and configure only one"
fi

# Check configuration of systemd-timesyncd
if [[ $timesyncd_enabled -eq 0 ]]; then
    echo "Checking systemd-timesyncd configuration..."
    timedatectl status | grep -q "NTP synchronized: yes"
    if [[ $? -eq 0 ]]; then
        echo "PASS: systemd-timesyncd synchronized"
        write_csv "systemd-timesyncd synchronized" "PASS" "Remediation not needed"
    else
        echo "FAIL: systemd-timesyncd not synchronized"
        write_csv "systemd-timesyncd synchronized" "FAIL" "Check /etc/systemd/timesyncd.conf and enable/start the service"
    fi
fi

# Check chrony configuration
if [[ $chrony_installed -eq 0 ]]; then
    echo "Checking chrony configuration..."
    grep -E "^(server|pool)" /etc/chrony/chrony.conf &>/dev/null
    if [[ $? -eq 0 ]]; then
        echo "PASS: chrony servers configured"
        write_csv "chrony servers configured" "PASS" "Remediation not needed"
    else
        echo "FAIL: chrony servers not configured"
        write_csv "chrony servers configured" "FAIL" "Edit /etc/chrony/chrony.conf and add server or pool entries"
    fi
fi

# Check NTP configuration
if [[ $ntp_installed -eq 0 ]]; then
    echo "Checking NTP configuration..."
    grep "^restrict" /etc/ntp.conf &>/dev/null
    grep -E "^(server|pool)" /etc/ntp.conf &>/dev/null
    grep "RUNASUSER=ntp" /etc/init.d/ntp &>/dev/null
    if [[ $? -eq 0 ]]; then
        echo "PASS: NTP configured properly"
        write_csv "NTP configured" "PASS" "Remediation not needed"
    else
        echo "FAIL: NTP configuration incomplete"
        write_csv "NTP configured" "FAIL" "Edit /etc/ntp.conf and /etc/init.d/ntp per policy"
    fi
fi

# -------------------------------------------
# 12. CHECKING FOR SOFTWARE
# -------------------------------------------
echo "************ 12. CHECKING FOR SOFTWARE ************"

declare -A software_checks=(
    ["X Windows System"]="xserver-xorg*"
    ["Avahi Server"]="avahi-daemon"
    ["CUPS"]="cups"
    ["DHCP Server"]="isc-dhcp-server"
    ["LDAP Server"]="slapd"
    ["NFS Server"]="nfs-kernel-server"
    ["DNS Server"]="bind9"
    ["FTP Server"]="vsftpd"
    ["HTTP Server"]="apache2"
    ["IMAP/POP3 Server"]="dovecot-imapd dovecot-pop3d"
    ["Samba"]="samba"
    ["HTTP Proxy Server"]="squid"
    ["SNMP Server"]="snmpd"
    ["Rsync Service"]="rsync"
    ["NIS Server"]="nis"
)

for software in "${!software_checks[@]}"; do
    package="${software_checks[$software]}"
    
    dpkg -s $package &>/dev/null
    if [[ $? -ne 0 ]]; then
        echo "PASS: $software is not installed"
        write_csv "$software not installed" "PASS" "Remediation not needed"
    else
        echo "FAIL: $software is installed"
        write_csv "$software not installed" "FAIL" "Remove package using: apt purge $package"
    fi
done

# Special handling: Mail Transfer Agent (local-only mode)
echo "Checking MTA for local-only mode..."
ss -lntu | grep -E ':25\s' | grep -E -v '\s(127.0.0.1|::1):25\s' &>/dev/null
if [[ $? -ne 0 ]]; then
    echo "PASS: MTA configured for local-only"
    write_csv "MTA local-only mode" "PASS" "Remediation not needed"
else
    echo "FAIL: MTA listening on non-loopback interface"
    write_csv "MTA local-only mode" "FAIL" "Edit /etc/exim4/update-exim4.conf.conf and restart exim4"
fi

# Special handling: Avahi daemon stop before removal
if dpkg -s avahi-daemon &>/dev/null; then
    echo "Stopping Avahi services before removal..."
    systemctl stop avahi-daemon.service &>/dev/null
    systemctl stop avahi-daemon.socket &>/dev/null
fi

# -------------------------------------------
# 13. SERVICE CLIENT
# -------------------------------------------
echo "************ 13. SERVICE CLIENT ************"

declare -A client_checks=(
    ["NIS Client"]="nis"
    ["rsh Client"]="rsh-client"
    ["talk Client"]="talk"
    ["telnet Client"]="telnet"
    ["LDAP Client"]="ldap-utils"
    ["RPC Service"]="rpcbind"
)

for client in "${!client_checks[@]}"; do
    package="${client_checks[$client]}"
    
    dpkg -s $package &>/dev/null
    if [[ $? -ne 0 ]]; then
        echo "PASS: $client is not installed"
        write_csv "$client not installed" "PASS" "Remediation not needed"
    else
        echo "FAIL: $client is installed"
        write_csv "$client not installed" "FAIL" "Remove package using: apt purge $package"
    fi
done

# Nonessential services
echo "Checking for nonessential listening services..."
lsof -i -P -n | grep -v "(ESTABLISHED)" > /tmp/nonessential_services.txt

if [[ -s /tmp/nonessential_services.txt ]]; then
    echo "WARNING: Nonessential services detected listening on ports:"
    cat /tmp/nonessential_services.txt
    write_csv "Nonessential listening services" "WARN" "Review / remove unneeded packages or mask services"
else
    echo "PASS: No nonessential services detected"
    write_csv "Nonessential listening services" "PASS" "Remediation not needed"
fi

# Clean up temporary file
rm -f /tmp/nonessential_services.txt

# -------------------------------------------
# 14. NETWORK CONFIGURATION
# -------------------------------------------
echo "************ 14. NETWORK CONFIGURATION ************"

# -----------------------------
# Disable IPv6
# -----------------------------
if grep "^\s*linux" /boot/grub/grub.cfg | grep -qv "ipv6.disable=1"; then
    echo "FAIL: IPv6 not disabled in GRUB"
    write_csv "Disable IPv6" "FAIL" "Edit /etc/default/grub, add ipv6.disable=1 to GRUB_CMDLINE_LINUX and run update-grub"
else
    echo "PASS: IPv6 disabled or not in use"
    write_csv "Disable IPv6" "PASS" "Remediation not needed"
fi

# -----------------------------
# Ensure wireless interfaces are disabled
# -----------------------------
wireless_enabled=0
if command -v nmcli >/dev/null 2>&1; then
    nmcli radio all | grep -vq "disabled" && wireless_enabled=1
elif [ -n "$(find /sys/class/net/*/ -type d -name wireless)" ]; then
    wireless_enabled=1
fi

if [ $wireless_enabled -eq 1 ]; then
    echo "FAIL: Wireless interfaces are enabled"
    write_csv "Disable wireless interfaces" "FAIL" "Disable via nmcli or /etc/modprobe.d/disable_wireless.conf"
else
    echo "PASS: Wireless interfaces disabled"
    write_csv "Disable wireless interfaces" "PASS" "Remediation not needed"
fi

# -----------------------------
# Function to check sysctl settings
# -----------------------------
check_sysctl() {
    local key="$1"
    local expected="$2"
    value=$(sysctl -n "$key" 2>/dev/null)
    if [ "$value" = "$expected" ]; then
        write_csv "$key" "PASS" "Remediation not needed"
    else
        write_csv "$key" "FAIL" "Set $key=$expected in /etc/sysctl.conf or /etc/sysctl.d/* and run sysctl -w $key=$expected"
    fi
}

# IPv4 and IPv6 sysctl checks
declare -A sysctl_checks_ipv4=(
    ["net.ipv4.conf.all.send_redirects"]=0
    ["net.ipv4.conf.default.send_redirects"]=0
    ["net.ipv4.ip_forward"]=0
    ["net.ipv4.conf.all.accept_source_route"]=0
    ["net.ipv4.conf.default.accept_source_route"]=0
    ["net.ipv4.conf.all.accept_redirects"]=0
    ["net.ipv4.conf.default.accept_redirects"]=0
    ["net.ipv4.conf.all.secure_redirects"]=0
    ["net.ipv4.conf.default.secure_redirects"]=0
    ["net.ipv4.conf.all.log_martians"]=1
    ["net.ipv4.conf.default.log_martians"]=1
    ["net.ipv4.icmp_echo_ignore_broadcasts"]=1
    ["net.ipv4.icmp_ignore_bogus_error_responses"]=1
    ["net.ipv4.conf.all.rp_filter"]=1
    ["net.ipv4.conf.default.rp_filter"]=1
    ["net.ipv4.tcp_syncookies"]=1
)

for key in "${!sysctl_checks_ipv4[@]}"; do
    check_sysctl "$key" "${sysctl_checks_ipv4[$key]}"
done

# IPv6 only if enabled
if ! grep -q "ipv6.disable=1" /boot/grub/grub.cfg; then
    declare -A sysctl_checks_ipv6=(
        ["net.ipv6.conf.all.forwarding"]=0
        ["net.ipv6.conf.all.accept_source_route"]=0
        ["net.ipv6.conf.default.accept_source_route"]=0
        ["net.ipv6.conf.all.accept_redirects"]=0
        ["net.ipv6.conf.default.accept_redirects"]=0
        ["net.ipv6.conf.all.accept_ra"]=0
        ["net.ipv6.conf.default.accept_ra"]=0
    )
    for key in "${!sysctl_checks_ipv6[@]}"; do
        check_sysctl "$key" "${sysctl_checks_ipv6[$key]}"
    done
fi

# -----------------------------
# Disable unnecessary kernel modules
# -----------------------------
declare -A kernel_modules=(
    ["dccp"]="install /bin/true"
    ["sctp"]="install /bin/true"
    ["rds"]="install /bin/true"
    ["tipc"]="install /bin/true"
)

for module in "${!kernel_modules[@]}"; do
    if modprobe -n -v $module | grep -q "$module"; then
        echo "FAIL: $module module not disabled"
        write_csv "Disable $module" "FAIL" "Add 'install $module /bin/true' in /etc/modprobe.d/$module.conf"
    else
        echo "PASS: $module module disabled"
        write_csv "Disable $module" "PASS" "Remediation not needed"
    fi
done

# -------------------------------------------
# 15. FIREWALL CONFIGURATION
# -------------------------------------------
echo "************ 15. FIREWALL CONFIGURATION ************"

# -----------------------------
# Ensure Uncomplicated Firewall (UFW) is installed
# -----------------------------
if dpkg -s ufw 2>/dev/null | grep -q "Status: install ok installed"; then
    echo "PASS: UFW is installed"
    write_csv "UFW Installed" "PASS" "Remediation not needed"
else
    echo "FAIL: UFW is not installed"
    write_csv "UFW Installed" "FAIL" "Install UFW using: apt install ufw"
fi

# -----------------------------
# Ensure iptables-persistent is not installed
# -----------------------------
if ! dpkg-query -s iptables-persistent >/dev/null 2>&1; then
    echo "PASS: iptables-persistent is not installed"
    write_csv "iptables-persistent Not Installed" "PASS" "Remediation not needed"
else
    echo "FAIL: iptables-persistent is installed"
    write_csv "iptables-persistent Not Installed" "FAIL" "Remove using: apt purge iptables-persistent"
fi

# -----------------------------
# Ensure ufw service is enabled and active
# -----------------------------
ufw_enabled=$(systemctl is-enabled ufw 2>/dev/null)
ufw_active=$(ufw status | grep -i "Status" | awk '{print $2}')

if [ "$ufw_enabled" = "enabled" ] && [ "$ufw_active" = "active" ]; then
    echo "PASS: UFW service enabled and running"
    write_csv "UFW Service Enabled" "PASS" "Remediation not needed"
else
    echo "FAIL: UFW service not enabled or inactive"
    write_csv "UFW Service Enabled" "FAIL" "Enable with: ufw enable"
fi

# -----------------------------
# Ensure loopback traffic is configured
# -----------------------------
loopback_rules=$(ufw status verbose)
if echo "$loopback_rules" | grep -q "Anywhere on lo.*ALLOW IN" && \
   echo "$loopback_rules" | grep -q "127.0.0.0/8.*DENY IN" && \
   echo "$loopback_rules" | grep -q "Anywhere (v6) on lo.*ALLOW IN" && \
   echo "$loopback_rules" | grep -q "::1.*DENY IN"; then
    echo "PASS: Loopback traffic configured"
    write_csv "Loopback Traffic Configured" "PASS" "Remediation not needed"
else
    echo "FAIL: Loopback traffic rules missing"
    write_csv "Loopback Traffic Configured" "FAIL" "Apply rules using: ufw allow in on lo; ufw allow out from lo; ufw deny in from 127.0.0.0/8; ufw deny in from ::1"
fi

# -----------------------------
# Ensure outbound connections are configured
# -----------------------------
if ufw status | grep -q "ALLOW OUT"; then
    echo "PASS: Outbound connections configured"
    write_csv "Outbound Connections Configured" "PASS" "Remediation not needed"
else
    echo "FAIL: Outbound connections rules missing"
    write_csv "Outbound Connections Configured" "FAIL" "Allow outbound traffic using: ufw allow out on all"
fi

# -----------------------------
# Ensure firewall rules exist for all open ports
# -----------------------------
open_ports=$(ss -4tuln | awk '{print $5}' | grep -v '127.0.0.1' | grep -Eo '[0-9]+$' | sort -u)
for port in $open_ports; do
    if ! ufw status | grep -q "$port"; then
        echo "FAIL: No firewall rule for port $port"
        write_csv "Firewall Rule Port $port" "FAIL" "Apply rule: ufw allow in $port/tcp"
    else
        echo "PASS: Firewall rule exists for port $port"
        write_csv "Firewall Rule Port $port" "PASS" "Remediation not needed"
    fi
done

# -----------------------------
# NFTABLES SECTION
# -----------------------------
echo "************ NFTABLES CONFIGURATION ************"

# Ensure nftables is installed
if dpkg-query -s nftables 2>/dev/null | grep -q "Status: install ok installed"; then
    echo "PASS: nftables installed"
    write_csv "nftables Installed" "PASS" "Remediation not needed"
else
    echo "FAIL: nftables not installed"
    write_csv "nftables Installed" "FAIL" "Install using: apt install nftables"
fi

# Ensure iptables rules are flushed
iptables_rules=$(iptables -L 2>/dev/null)
ip6tables_rules=$(ip6tables -L 2>/dev/null)
if [ -z "$iptables_rules" ] && [ -z "$ip6tables_rules" ]; then
    echo "PASS: iptables flushed"
    write_csv "iptables Flushed" "PASS" "Remediation not needed"
else
    echo "FAIL: iptables rules exist"
    write_csv "iptables Flushed" "FAIL" "Flush using: iptables -F; ip6tables -F"
fi

# Ensure nftables table exists
if nft list tables 2>/dev/null | grep -q "inet filter"; then
    echo "PASS: nftables table exists"
    write_csv "nftables Table Exists" "PASS" "Remediation not needed"
else
    echo "FAIL: nftables table missing"
    write_csv "nftables Table Exists" "FAIL" "Create table using: nft create table inet filter"
fi

# Ensure base chains exist
for chain in input forward output; do
    if nft list ruleset 2>/dev/null | grep -q "hook $chain"; then
        echo "PASS: nftables base chain $chain exists"
        write_csv "nftables Base Chain $chain" "PASS" "Remediation not needed"
    else
        echo "FAIL: nftables base chain $chain missing"
        write_csv "nftables Base Chain $chain" "FAIL" "Create using: nft create chain inet filter $chain { type filter hook $chain priority 0; }"
    fi
done

# Ensure loopback traffic is configured
if nft list ruleset 2>/dev/null | grep -q 'iif "lo" accept' && \
   nft list ruleset 2>/dev/null | grep -q 'ip saddr 127.0.0.0/8 counter drop'; then
    echo "PASS: nftables loopback traffic configured"
    write_csv "nftables Loopback Configured" "PASS" "Remediation not needed"
else
    echo "FAIL: nftables loopback traffic rules missing"
    write_csv "nftables Loopback Configured" "FAIL" "Apply using: nft add rule inet filter input iif lo accept; nft add rule inet filter input ip saddr 127.0.0.0/8 counter drop"
fi

# Ensure outbound and established connections are configured
established_rules=$(nft list ruleset 2>/dev/null | grep 'ct state established')
outbound_rules=$(nft list ruleset 2>/dev/null | grep 'ct state new,related,established')
if [ -n "$established_rules" ] && [ -n "$outbound_rules" ]; then
    echo "PASS: nftables outbound and established connections configured"
    write_csv "nftables Outbound/Established Configured" "PASS" "Remediation not needed"
else
    echo "FAIL: nftables outbound/established connection rules missing"
    write_csv "nftables Outbound/Established Configured" "FAIL" "Apply rules using: nft add rule inet filter input ip protocol tcp ct state established accept; nft add rule inet filter output ip protocol tcp ct state new,related,established accept"
fi

# Ensure default deny firewall policy
for chain in input forward output; do
    policy=$(nft list chain inet filter $chain 2>/dev/null | grep 'policy drop')
    if [ -n "$policy" ]; then
        echo "PASS: nftables default DROP policy on $chain"
        write_csv "nftables Default DROP $chain" "PASS" "Remediation not needed"
    else
        echo "FAIL: nftables default DROP policy missing on $chain"
        write_csv "nftables Default DROP $chain" "FAIL" "Set using: nft chain inet filter $chain { policy drop; }"
    fi
done

# Ensure nftables service is enabled
if systemctl is-enabled nftables 2>/dev/null | grep -q "enabled"; then
    echo "PASS: nftables service enabled"
    write_csv "nftables Service Enabled" "PASS" "Remediation not needed"
else
    echo "FAIL: nftables service not enabled"
    write_csv "nftables Service Enabled" "FAIL" "Enable using: systemctl enable nftables"
fi

# Ensure nftables rules are permanent (Automated)
if grep -q 'include' /etc/nftables.conf 2>/dev/null; then
    echo "PASS: nftables rules configured to persist on boot"
    write_csv "nftables Rules Persistent" "PASS" "Remediation not needed"
else
    echo "FAIL: nftables rules not persistent"
    write_csv "nftables Rules Persistent" "FAIL" "Edit /etc/nftables.conf to include rules file, e.g., include \"/etc/nftables.rules\""
fi

# -------------------------------------------
# 16. LOGGING AND AUDITING
# -------------------------------------------
print_section "16. LOGGING AND AUDITING"

# -----------------------------
# Ensure auditd is installed
# -----------------------------
dpkg -s auditd audispd-plugins &>/dev/null
if [[ $? -eq 0 ]]; then
    pass_msg "auditd and audispd-plugins installed"
    write_csv "auditd installed" "PASS" "Remediation not needed"
else
    fail_msg "auditd or audispd-plugins not installed"
    write_csv "auditd installed" "FAIL" "apt install auditd audispd-plugins"
fi

# -----------------------------
# Ensure auditd service is enabled
# -----------------------------
systemctl is-enabled auditd &>/dev/null
if [[ $? -eq 0 ]]; then
    pass_msg "auditd service enabled"
    write_csv "auditd service enabled" "PASS" "Remediation not needed"
else
    fail_msg "auditd service not enabled"
    write_csv "auditd service enabled" "FAIL" "systemctl --now enable auditd"
fi

# -----------------------------
# Ensure auditing for processes that start prior to auditd is enabled
# -----------------------------
grep '^\s*linux' /boot/grub/grub.cfg | grep -v 'audit=1' &>/dev/null
if [[ $? -eq 1 ]]; then
    pass_msg "audit=1 parameter set for pre-auditd processes"
    write_csv "audit pre-start processes" "PASS" "Remediation not needed"
else
    fail_msg "audit=1 parameter missing in GRUB"
    write_csv "audit pre-start processes" "FAIL" "Edit /etc/default/grub, add audit=1 to GRUB_CMDLINE_LINUX and run update-grub"
fi

# -----------------------------
# Ensure audit_backlog_limit is sufficient
# -----------------------------
grep '^\s*linux' /boot/grub/grub.cfg | grep -v 'audit_backlog_limit=' &>/dev/null
if [[ $? -eq 0 ]]; then
    fail_msg "audit_backlog_limit not configured in GRUB"
    write_csv "audit_backlog_limit" "FAIL" "Add audit_backlog_limit=<BACKLOG SIZE> to GRUB_CMDLINE_LINUX and run update-grub"
else
    # check the actual value if present
    backlog_val=$(grep 'audit_backlog_limit=' /boot/grub/grub.cfg | head -n1 | grep -oP 'audit_backlog_limit=\K\d+')
    if [[ -z "$backlog_val" || $backlog_val -lt 8192 ]]; then
        fail_msg "audit_backlog_limit too low"
        write_csv "audit_backlog_limit" "FAIL" "Set audit_backlog_limit >= 8192 in GRUB_CMDLINE_LINUX and run update-grub"
    else
        pass_msg "audit_backlog_limit sufficient ($backlog_val)"
        write_csv "audit_backlog_limit" "PASS" "Remediation not needed"
    fi
fi

# -------------------------------------------
# 17. CONFIGURE DATA RETENTION
# -------------------------------------------
print_section "17. CONFIGURE DATA RETENTION"

AUDIT_CONF="/etc/audit/auditd.conf"

# -----------------------------
# Ensure audit log storage size is configured
# -----------------------------
log_file_size=$(grep -E '^\s*max_log_file\s*=' "$AUDIT_CONF" | awk -F'=' '{print $2}' | tr -d ' ')
if [[ -n "$log_file_size" ]]; then
    pass_msg "max_log_file set to $log_file_size MB"
    write_csv "Audit log max size" "PASS" "Remediation not needed"
else
    fail_msg "max_log_file not configured"
    write_csv "Audit log max size" "FAIL" "Set max_log_file = <MB> in /etc/audit/auditd.conf"
fi

# -----------------------------
# Ensure audit logs are not automatically deleted
# -----------------------------
log_file_action=$(grep -E '^\s*max_log_file_action\s*=' "$AUDIT_CONF" | awk -F'=' '{print $2}' | tr -d ' ')
if [[ "$log_file_action" == "keep_logs" ]]; then
    pass_msg "max_log_file_action set to keep_logs"
    write_csv "Audit log retention" "PASS" "Remediation not needed"
else
    fail_msg "max_log_file_action not configured or incorrect"
    write_csv "Audit log retention" "FAIL" "Set max_log_file_action = keep_logs in /etc/audit/auditd.conf"
fi

# -----------------------------
# Ensure system is disabled when audit logs are full
# -----------------------------
space_left_action=$(grep -E '^\s*space_left_action\s*=' "$AUDIT_CONF" | awk -F'=' '{print $2}' | tr -d ' ')
action_mail_acct=$(grep -E '^\s*action_mail_acct\s*=' "$AUDIT_CONF" | awk -F'=' '{print $2}' | tr -d ' ')
admin_space_left_action=$(grep -E '^\s*admin_space_left_action\s*=' "$AUDIT_CONF" | awk -F'=' '{print $2}' | tr -d ' ')

if [[ "$space_left_action" == "email" && "$action_mail_acct" == "root" && "$admin_space_left_action" == "halt" ]]; then
    pass_msg "Audit log full actions configured properly"
    write_csv "Audit log full actions" "PASS" "Remediation not needed"
else
    fail_msg "Audit log full actions misconfigured"
    write_csv "Audit log full actions" "FAIL" "Set space_left_action=email, action_mail_acct=root, admin_space_left_action=halt in /etc/audit/auditd.conf"
fi

# -------------------------------------------
# 18. INDEPENDENT CHECKS
# -------------------------------------------
print_section "18. INDEPENDENT CHECKS"

RULES_DIR="/etc/audit/rules.d"

# Function to check rules existence and log
check_audit_rule() {
    local identifier="$1"
    local pattern="$2"
    local file="$RULES_DIR/$identifier.rules"

    grep -E "$pattern" $RULES_DIR/*.rules &>/dev/null
    if [[ $? -eq 0 ]]; then
        pass_msg "Audit rules for $identifier exist"
        write_csv "$identifier audit rules" "PASS" "Remediation not needed"
    else
        fail_msg "Audit rules for $identifier missing or incorrect"
        write_csv "$identifier audit rules" "FAIL" "Create or edit $file with correct rules"
    fi
}

# -----------------------------
# Time Change Events
# -----------------------------
check_audit_rule "time-change" "time-change"

# -----------------------------
# User/Group Changes
# -----------------------------
check_audit_rule "identity" "identity"

# -----------------------------
# System Network Environment Changes
# -----------------------------
check_audit_rule "system-locale" "system-locale"

# -----------------------------
# Mandatory Access Control Changes (AppArmor)
# -----------------------------
check_audit_rule "MAC-policy" "MAC-policy"

# -----------------------------
# Login/Logout Events
# -----------------------------
check_audit_rule "logins" "logins"

# -----------------------------
# Session Initiation
# -----------------------------
check_audit_rule "session" "(session|logins)"

# -----------------------------
# DAC Permission Modifications
# -----------------------------
check_audit_rule "perm_mod" "perm_mod"

# -----------------------------
# Unsuccessful File Access Attempts
# -----------------------------
check_audit_rule "access" "access"

# -----------------------------
# Privileged Commands Execution
# -----------------------------
check_audit_rule "privileged" "privileged"

# -----------------------------
# Successful File System Mounts
# -----------------------------
check_audit_rule "mounts" "mounts"

# -----------------------------
# File Deletion Events
# -----------------------------
check_audit_rule "delete" "delete"

# -----------------------------
# System Admin Scope Changes (sudoers)
# -----------------------------
check_audit_rule "scope" "scope"

# -----------------------------
# System Administrator Command Execution (sudo)
# -----------------------------
check_audit_rule "actions" "actions"

# -----------------------------
# Kernel Module Loading/Unloading
# -----------------------------
check_audit_rule "modules" "modules"

# -----------------------------
# Immutable Audit Configuration
# -----------------------------
grep -E "^-e 2" $RULES_DIR/99-finalize.rules &>/dev/null
if [[ $? -eq 0 ]]; then
    pass_msg "Audit configuration is immutable"
    write_csv "Audit immutable" "PASS" "Remediation not needed"
else
    fail_msg "Audit configuration is not immutable"
    write_csv "Audit immutable" "FAIL" "Add '-e 2' to /etc/audit/rules.d/99-finalize.rules"
fi

# -------------------------------------------
# 19. CONFIGURE LOGGING
# -------------------------------------------
print_section "19. CONFIGURE LOGGING"

# -----------------------------
# Ensure rsyslog is installed
# -----------------------------
dpkg -s rsyslog &>/dev/null
if [[ $? -eq 0 ]]; then
    pass_msg "rsyslog is installed"
    write_csv "rsyslog installation" "PASS" "Remediation not needed"
else
    fail_msg "rsyslog is not installed"
    write_csv "rsyslog installation" "FAIL" "Install with 'apt install rsyslog'"
fi

# -----------------------------
# Ensure rsyslog service is enabled
# -----------------------------
systemctl is-enabled rsyslog &>/dev/null
if [[ $? -eq 0 ]]; then
    pass_msg "rsyslog service is enabled"
    write_csv "rsyslog service" "PASS" "Remediation not needed"
else
    fail_msg "rsyslog service is not enabled"
    write_csv "rsyslog service" "FAIL" "Enable with 'systemctl --now enable rsyslog'"
fi

# -----------------------------
# Ensure logging is configured
# -----------------------------
LOG_FILES_OK=$(ls -l /var/log/ &>/dev/null && echo "OK")
if [[ "$LOG_FILES_OK" == "OK" ]]; then
    pass_msg "Logging files exist and are being used"
    write_csv "logging configuration" "PASS" "Remediation not needed"
else
    fail_msg "Logging files missing or not recording"
    write_csv "logging configuration" "FAIL" "Check /etc/rsyslog.conf and /etc/rsyslog.d/*.conf"
fi

# -----------------------------
# Ensure rsyslog default file permissions
# -----------------------------
grep ^\s*\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf &>/dev/null
if [[ $? -eq 0 ]]; then
    FILE_MODE=$(grep ^\s*\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf | awk '{print $2}')
    if [[ $FILE_MODE -le 0640 ]]; then
        pass_msg "rsyslog default file permissions configured correctly ($FILE_MODE)"
        write_csv "rsyslog file permissions" "PASS" "Remediation not needed"
    else
        fail_msg "rsyslog default file permissions too permissive ($FILE_MODE)"
        write_csv "rsyslog file permissions" "FAIL" "Set $FileCreateMode to 0640 or more restrictive"
    fi
else
    fail_msg "rsyslog $FileCreateMode not set"
    write_csv "rsyslog file permissions" "FAIL" "Add '$FileCreateMode 0640' to /etc/rsyslog.conf or /etc/rsyslog.d/*.conf"
fi

# -----------------------------
# Ensure rsyslog is configured to send logs to a remote host
# -----------------------------
grep -E "^[^#]\s*\S+\.\*\s+@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf &>/dev/null
if [[ $? -eq 0 ]]; then
    pass_msg "rsyslog configured to send logs to remote host"
    write_csv "rsyslog remote logging" "PASS" "Remediation not needed"
else
    fail_msg "rsyslog not sending logs to remote host"
    write_csv "rsyslog remote logging" "FAIL" "Add omfwd configuration to /etc/rsyslog.conf or /etc/rsyslog.d/*.conf"
fi

# -------------------------------------------
# 20. CONFIGURE JOURNALD
# -------------------------------------------
print_section "20. CONFIGURE JOURNALD"

# -----------------------------
# Ensure journald is configured to send logs to rsyslog
# -----------------------------
grep -e ForwardToSyslog /etc/systemd/journald.conf | grep -i "yes" &>/dev/null
if [[ $? -eq 0 ]]; then
    pass_msg "journald is configured to forward logs to rsyslog"
    write_csv "journald -> rsyslog forwarding" "PASS" "Remediation not needed"
else
    fail_msg "journald is NOT forwarding logs to rsyslog"
    write_csv "journald -> rsyslog forwarding" "FAIL" "Set 'ForwardToSyslog=yes' in /etc/systemd/journald.conf"
fi

# -----------------------------
# Ensure journald is configured to compress large log files
# -----------------------------
grep -e Compress /etc/systemd/journald.conf | grep -i "yes" &>/dev/null
if [[ $? -eq 0 ]]; then
    pass_msg "journald configured to compress large log files"
    write_csv "journald compression" "PASS" "Remediation not needed"
else
    fail_msg "journald is NOT configured to compress large log files"
    write_csv "journald compression" "FAIL" "Set 'Compress=yes' in /etc/systemd/journald.conf"
fi

# -----------------------------
# Ensure journald is configured to write logfiles to persistent disk
# -----------------------------
grep -e Storage /etc/systemd/journald.conf | grep -i "persistent" &>/dev/null
if [[ $? -eq 0 ]]; then
    pass_msg "journald logs are persisted to disk"
    write_csv "journald persistent storage" "PASS" "Remediation not needed"
else
    fail_msg "journald logs are NOT persisted to disk"
    write_csv "journald persistent storage" "FAIL" "Set 'Storage=persistent' in /etc/systemd/journald.conf"
fi

# -------------------------------------------
# 21. INDEPENDENT CHECKS 2
# -------------------------------------------
print_section "21. INDEPENDENT CHECKS 2"

# -----------------------------
# Ensure permissions on all logfiles are configured
# -----------------------------
find /var/log -type f ! -perm 0640 -o -type d ! -perm 0750 &>/dev/null
if [[ $? -eq 0 ]]; then
    fail_msg "Some log files or directories in /var/log have incorrect permissions"
    write_csv "logfile permissions" "FAIL" "Run 'find /var/log -type f -exec chmod g-wx,o-rwx {} + -o -type d -exec chmod g-wx,o-rwx {} +'"
else
    pass_msg "All log files and directories in /var/log have correct permissions"
    write_csv "logfile permissions" "PASS" "Remediation not needed"
fi

# -----------------------------
# Ensure logrotate is configured
# -----------------------------
grep -q "rsyslog" /etc/logrotate.d/rsyslog &>/dev/null
if [[ $? -eq 0 ]]; then
    pass_msg "logrotate is configured for rsyslog logs"
    write_csv "logrotate configuration" "PASS" "Remediation not needed"
else
    fail_msg "logrotate is NOT configured for rsyslog logs"
    write_csv "logrotate configuration" "FAIL" "Edit /etc/logrotate.d/rsyslog to rotate logs according to site policy"
fi

# -----------------------------
# Ensure logrotate assigns appropriate permissions
# -----------------------------
grep -E "^\s*create\s+\S+" /etc/logrotate.conf | grep -E -v "\s(0)?[06][04]0\s" &>/dev/null
if [[ $? -eq 0 ]]; then
    fail_msg "logrotate 'create' permissions do not meet site policy"
    write_csv "logrotate permissions" "FAIL" "Update 'create' lines in /etc/logrotate.conf to '0640 root utmp' or as per site policy"
else
    pass_msg "logrotate 'create' permissions meet site policy"
    write_csv "logrotate permissions" "PASS" "Remediation not needed"
fi

# -------------------------------------------
# 22. ACCESS, AUTHORIZATION AND AUTHENTICATION
# -------------------------------------------
print_section "22. ACCESS, AUTHORIZATION AND AUTHENTICATION"

# -----------------------------
# Ensure password expiration is 365 days or less
# -----------------------------
grep -qE '^PASS_MAX_DAYS\s+([0-9]+)' /etc/login.defs
if [[ $? -eq 0 ]]; then
    MAX_DAYS=$(grep '^PASS_MAX_DAYS' /etc/login.defs | awk '{print $2}')
    if [[ $MAX_DAYS -le 365 ]]; then
        pass_msg "PASS_MAX_DAYS is set to $MAX_DAYS"
        write_csv "password expiration" "PASS" "Remediation not needed"
    else
        fail_msg "PASS_MAX_DAYS is set to $MAX_DAYS (should be 365 or less)"
        write_csv "password expiration" "FAIL" "Set PASS_MAX_DAYS to 365 in /etc/login.defs and chage --maxdays 365 <user> for all users"
    fi
else
    fail_msg "PASS_MAX_DAYS not configured in /etc/login.defs"
    write_csv "password expiration" "FAIL" "Add PASS_MAX_DAYS 365 in /etc/login.defs"
fi

# -----------------------------
# Ensure minimum days between password changes is configured
# -----------------------------
grep -qE '^PASS_MIN_DAYS\s+([0-9]+)' /etc/login.defs
if [[ $? -eq 0 ]]; then
    MIN_DAYS=$(grep '^PASS_MIN_DAYS' /etc/login.defs | awk '{print $2}')
    if [[ $MIN_DAYS -ge 1 ]]; then
        pass_msg "PASS_MIN_DAYS is set to $MIN_DAYS"
        write_csv "minimum password days" "PASS" "Remediation not needed"
    else
        fail_msg "PASS_MIN_DAYS is set to $MIN_DAYS (should be 1 or more)"
        write_csv "minimum password days" "FAIL" "Set PASS_MIN_DAYS to 1 in /etc/login.defs and chage --mindays 1 <user> for all users"
    fi
else
    fail_msg "PASS_MIN_DAYS not configured in /etc/login.defs"
    write_csv "minimum password days" "FAIL" "Add PASS_MIN_DAYS 1 in /etc/login.defs"
fi

# -----------------------------
# Ensure password expiration warning days is 7 or more
# -----------------------------
grep -qE '^PASS_WARN_AGE\s+([0-9]+)' /etc/login.defs
if [[ $? -eq 0 ]]; then
    WARN_DAYS=$(grep '^PASS_WARN_AGE' /etc/login.defs | awk '{print $2}')
    if [[ $WARN_DAYS -ge 7 ]]; then
        pass_msg "PASS_WARN_AGE is set to $WARN_DAYS"
        write_csv "password warning days" "PASS" "Remediation not needed"
    else
        fail_msg "PASS_WARN_AGE is set to $WARN_DAYS (should be 7 or more)"
        write_csv "password warning days" "FAIL" "Set PASS_WARN_AGE to 7 in /etc/login.defs and chage --warndays 7 <user> for all users"
    fi
else
    fail_msg "PASS_WARN_AGE not configured in /etc/login.defs"
    write_csv "password warning days" "FAIL" "Add PASS_WARN_AGE 7 in /etc/login.defs"
fi

# -----------------------------
# Ensure inactive password lock is 30 days or less
# -----------------------------
DEFAULT_INACTIVE=$(useradd -D | grep INACTIVE | awk -F= '{print $2}')
if [[ $DEFAULT_INACTIVE -le 30 ]]; then
    pass_msg "Default INACTIVE is $DEFAULT_INACTIVE days"
    write_csv "inactive password lock" "PASS" "Remediation not needed"
else
    fail_msg "Default INACTIVE is $DEFAULT_INACTIVE days (should be 30 or less)"
    write_csv "inactive password lock" "FAIL" "Set default INACTIVE to 30 days: useradd -D -f 30 and chage --inactive 30 <user>"
fi

# -----------------------------
# Ensure all users last password change date is in the past
# -----------------------------
FUTURE_USERS=$(awk -F: '($2!~/^!|^\*/) {print $1}' /etc/shadow | while read user; do
    LAST_CHANGE=$(chage --list "$user" | grep "Last Change" | awk -F: '{print $2}')
    if [[ $(date -d "$LAST_CHANGE" +%s) -gt $(date +%s) ]]; then
        echo $user
    fi
done)

if [[ -z "$FUTURE_USERS" ]]; then
    pass_msg "All users have last password change date in the past"
    write_csv "last password change" "PASS" "Remediation not needed"
else
    fail_msg "Users with future last password change date: $FUTURE_USERS"
    write_csv "last password change" "FAIL" "Investigate users and correct their password change date"
fi

# -----------------------------
# Ensure system accounts are non-login
# -----------------------------
NON_LOGIN_USERS=$(egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7!="/sbin/nologin" && $7!="/bin/false"){print $1}')
if [[ -z "$NON_LOGIN_USERS" ]]; then
    pass_msg "All system accounts are non-login"
    write_csv "system accounts non-login" "PASS" "Remediation not needed"
else
    fail_msg "System accounts with login shells found: $NON_LOGIN_USERS"
    write_csv "system accounts non-login" "FAIL" "Set shell to /sbin/nologin and lock accounts as required"
fi

# -----------------------------
# Ensure default group for the root account is GID 0
# -----------------------------
ROOT_GID=$(grep "^root:" /etc/passwd | cut -d: -f4)
if [[ $ROOT_GID -eq 0 ]]; then
    pass_msg "Root account default group is GID 0"
    write_csv "root default group" "PASS" "Remediation not needed"
else
    fail_msg "Root account default group is GID $ROOT_GID (should be 0)"
    write_csv "root default group" "FAIL" "Set root default group to GID 0: usermod -g 0 root"
fi

# -----------------------------
# Ensure default user umask is 027 or more restrictive
# -----------------------------
UMASKS=$(grep -h "umask" /etc/bash.bashrc.local /etc/profile.local /etc/profile.d/*.sh 2>/dev/null | awk '{print $2}')
UMASK_FAIL=0
for UM in $UMASKS; do
    if [[ $UM -gt 027 ]]; then
        UMASK_FAIL=1
        break
    fi
done

if [[ $UMASK_FAIL -eq 0 ]]; then
    pass_msg "All umask settings are 027 or more restrictive"
    write_csv "default umask" "PASS" "Remediation not needed"
else
    fail_msg "Found umask settings less restrictive than 027"
    write_csv "default umask" "FAIL" "Set umask to 027 in shell configuration files"
fi

# -----------------------------
# Ensure access to the su command is restricted
# -----------------------------
grep -q "pam_wheel.so" /etc/pam.d/su
if [[ $? -eq 0 ]]; then
    pass_msg "su command restricted via pam_wheel.so"
    write_csv "su command access" "PASS" "Remediation not needed"
else
    fail_msg "su command not restricted"
    write_csv "su command access" "FAIL" "Add 'auth required pam_wheel.so use_uid' to /etc/pam.d/su and configure wheel group"
fi

# -------------------------------------------
# 23. SYSTEM MAINTENANCE
# -------------------------------------------
print_section "23. SYSTEM MAINTENANCE"

# -----------------------------
# Ensure permissions on /etc/passwd are configured
# -----------------------------
PASSWD_STAT=$(stat -c "%a %u %g" /etc/passwd)
if [[ "$PASSWD_STAT" == "644 0 0" ]]; then
    pass_msg "/etc/passwd permissions are correct"
    write_csv "passwd permissions" "PASS" "Remediation not needed"
else
    fail_msg "/etc/passwd permissions are incorrect ($PASSWD_STAT)"
    write_csv "passwd permissions" "FAIL" "Run: chown root:root /etc/passwd && chmod 644 /etc/passwd"
fi

# -----------------------------
# Ensure permissions on /etc/shadow are configured
# -----------------------------
SHADOW_STAT=$(stat -c "%a %u %g" /etc/shadow)
if [[ "$SHADOW_STAT" == "640 0 0" || "$SHADOW_STAT" == "640 0 15" ]]; then
    pass_msg "/etc/shadow permissions are correct"
    write_csv "shadow permissions" "PASS" "Remediation not needed"
else
    fail_msg "/etc/shadow permissions are incorrect ($SHADOW_STAT)"
    write_csv "shadow permissions" "FAIL" "Run: chown root:shadow /etc/shadow && chmod o-rwx,g-wx /etc/shadow"
fi

# -----------------------------
# Ensure permissions on /etc/group are configured
# -----------------------------
GROUP_STAT=$(stat -c "%a %u %g" /etc/group)
if [[ "$GROUP_STAT" == "644 0 0" ]]; then
    pass_msg "/etc/group permissions are correct"
    write_csv "group permissions" "PASS" "Remediation not needed"
else
    fail_msg "/etc/group permissions are incorrect ($GROUP_STAT)"
    write_csv "group permissions" "FAIL" "Run: chown root:root /etc/group && chmod 644 /etc/group"
fi

# -----------------------------
# Ensure permissions on /etc/gshadow are configured
# -----------------------------
GSHADOW_STAT=$(stat -c "%a %u %g" /etc/gshadow)
if [[ "$GSHADOW_STAT" == "640 0 0" || "$GSHADOW_STAT" == "640 0 15" ]]; then
    pass_msg "/etc/gshadow permissions are correct"
    write_csv "gshadow permissions" "PASS" "Remediation not needed"
else
    fail_msg "/etc/gshadow permissions are incorrect ($GSHADOW_STAT)"
    write_csv "gshadow permissions" "FAIL" "Run: chown root:root /etc/gshadow or chown root:shadow /etc/gshadow && chmod o-rwx,g-rw /etc/gshadow"
fi

# -----------------------------
# Ensure permissions on /etc/passwd- are configured
# -----------------------------
PASSWD_BACK_STAT=$(stat -c "%a %u %g" /etc/passwd-)
if [[ "$PASSWD_BACK_STAT" == "644 0 0" ]]; then
    pass_msg "/etc/passwd- permissions are correct"
    write_csv "passwd- permissions" "PASS" "Remediation not needed"
else
    fail_msg "/etc/passwd- permissions are incorrect ($PASSWD_BACK_STAT)"
    write_csv "passwd- permissions" "FAIL" "Run: chown root:root /etc/passwd- && chmod u-x,go-wx /etc/passwd-"
fi

# -----------------------------
# Ensure permissions on /etc/shadow- are configured
# -----------------------------
SHADOW_BACK_STAT=$(stat -c "%a %u %g" /etc/shadow-)
if [[ "$SHADOW_BACK_STAT" == "640 0 0" || "$SHADOW_BACK_STAT" == "640 0 15" ]]; then
    pass_msg "/etc/shadow- permissions are correct"
    write_csv "shadow- permissions" "PASS" "Remediation not needed"
else
    fail_msg "/etc/shadow- permissions are incorrect ($SHADOW_BACK_STAT)"
    write_csv "shadow- permissions" "FAIL" "Run: chown root:root /etc/shadow- or chown root:shadow /etc/shadow- && chmod o-rwx,g-rw /etc/shadow-"
fi

# -----------------------------
# Ensure permissions on /etc/group- are configured
# -----------------------------
GROUP_BACK_STAT=$(stat -c "%a %u %g" /etc/group-)
if [[ "$GROUP_BACK_STAT" == "644 0 0" ]]; then
    pass_msg "/etc/group- permissions are correct"
    write_csv "group- permissions" "PASS" "Remediation not needed"
else
    fail_msg "/etc/group- permissions are incorrect ($GROUP_BACK_STAT)"
    write_csv "group- permissions" "FAIL" "Run: chown root:root /etc/group- && chmod u-x,go-wx /etc/group-"
fi

# -----------------------------
# Ensure permissions on /etc/gshadow- are configured
# -----------------------------
GSHADOW_BACK_STAT=$(stat -c "%a %u %g" /etc/gshadow-)
if [[ "$GSHADOW_BACK_STAT" == "640 0 0" || "$GSHADOW_BACK_STAT" == "640 0 15" ]]; then
    pass_msg "/etc/gshadow- permissions are correct"
    write_csv "gshadow- permissions" "PASS" "Remediation not needed"
else
    fail_msg "/etc/gshadow- permissions are incorrect ($GSHADOW_BACK_STAT)"
    write_csv "gshadow- permissions" "FAIL" "Run: chown root:root /etc/gshadow- or chown root:shadow /etc/gshadow- && chmod o-rwx,g-rw /etc/gshadow-"
fi

# -----------------------------
# Ensure no world writable files exist
# -----------------------------
WORLD_WRITABLE=$(df --local -P | awk 'NR!=1 {print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002 2>/dev/null)
if [[ -z "$WORLD_WRITABLE" ]]; then
    pass_msg "No world writable files found"
    write_csv "world writable files" "PASS" "Remediation not needed"
else
    fail_msg "World writable files found"
    write_csv "world writable files" "FAIL" "Remove world write access: chmod o-w <file>"
fi

# -----------------------------
# Ensure no unowned files or directories exist
# -----------------------------
UNOWNED_FILES=$(df --local -P | awk 'NR!=1 {print $6}' | xargs -I '{}' find '{}' -xdev -nouser 2>/dev/null)
if [[ -z "$UNOWNED_FILES" ]]; then
    pass_msg "No unowned files found"
    write_csv "unowned files" "PASS" "Remediation not needed"
else
    fail_msg "Unowned files found"
    write_csv "unowned files" "FAIL" "Locate and assign ownership to active users as appropriate"
fi

# -----------------------------
# Ensure no ungrouped files or directories exist
# -----------------------------
UNGROUPED_FILES=$(df --local -P | awk 'NR!=1 {print $6}' | xargs -I '{}' find '{}' -xdev -nogroup 2>/dev/null)
if [[ -z "$UNGROUPED_FILES" ]]; then
    pass_msg "No ungrouped files found"
    write_csv "ungrouped files" "PASS" "Remediation not needed"
else
    fail_msg "Ungrouped files found"
    write_csv "ungrouped files" "FAIL" "Locate and assign group ownership to active groups as appropriate"
fi

# -------------------------------------------
# 24. USER AND GROUP SETTINGS
# -------------------------------------------
print_section "24. USER AND GROUP SETTINGS"

# -----------------------------
# Ensure password fields are not empty
# -----------------------------
EMPTY_PASSWORDS=$(awk -F: '($2=="") {print $1 " does not have a password"}' /etc/shadow)
if [[ -z "$EMPTY_PASSWORDS" ]]; then
    pass_msg "No accounts with empty password fields"
    write_csv "empty passwords" "PASS" "Remediation not needed"
else
    fail_msg "Accounts with empty password fields found"
    write_csv "empty passwords" "FAIL" "Lock accounts: passwd -l <username> and investigate usage"
fi

# -----------------------------
# Ensure no legacy "+" entries exist in /etc/passwd
# -----------------------------
LEGACY_PASSWD=$(grep '^\+:' /etc/passwd)
if [[ -z "$LEGACY_PASSWD" ]]; then
    pass_msg "No legacy + entries in /etc/passwd"
    write_csv "legacy passwd entries" "PASS" "Remediation not needed"
else
    fail_msg "Legacy + entries found in /etc/passwd"
    write_csv "legacy passwd entries" "FAIL" "Remove any '+' entries from /etc/passwd"
fi

# -----------------------------
# Ensure no legacy "+" entries exist in /etc/shadow
# -----------------------------
LEGACY_SHADOW=$(grep '^\+:' /etc/shadow)
if [[ -z "$LEGACY_SHADOW" ]]; then
    pass_msg "No legacy + entries in /etc/shadow"
    write_csv "legacy shadow entries" "PASS" "Remediation not needed"
else
    fail_msg "Legacy + entries found in /etc/shadow"
    write_csv "legacy shadow entries" "FAIL" "Remove any '+' entries from /etc/shadow"
fi

# -----------------------------
# Ensure no legacy "+" entries exist in /etc/group
# -----------------------------
LEGACY_GROUP=$(grep '^\+:' /etc/group)
if [[ -z "$LEGACY_GROUP" ]]; then
    pass_msg "No legacy + entries in /etc/group"
    write_csv "legacy group entries" "PASS" "Remediation not needed"
else
    fail_msg "Legacy + entries found in /etc/group"
    write_csv "legacy group entries" "FAIL" "Remove any '+' entries from /etc/group"
fi

# -----------------------------
# Ensure root is the only UID 0 account
# -----------------------------
UID0_USERS=$(awk -F: '($3==0){print $1}' /etc/passwd)
if [[ "$UID0_USERS" == "root" ]]; then
    pass_msg "Only root has UID 0"
    write_csv "UID 0 accounts" "PASS" "Remediation not needed"
else
    fail_msg "Other accounts with UID 0 found: $UID0_USERS"
    write_csv "UID 0 accounts" "FAIL" "Remove other UID 0 accounts or assign new UID"
fi

# -----------------------------
# Ensure root PATH integrity
# -----------------------------
PATH_ISSUES=$(bash -c '
if [[ "$PATH" == *::* ]]; then echo "Empty directory (::) in PATH"; fi
if [[ "$PATH" == *: ]]; then echo "Trailing colon in PATH"; fi
p=$(echo $PATH | sed -e "s/::/:/g" -e "s/:$//")
for dir in $(echo $p | tr ":" " "); do
  if [[ "$dir" == "." ]]; then echo "PATH contains ."; fi
  if [[ -d "$dir" ]]; then
    perm=$(ls -ldH "$dir" | cut -f1 -d" ")
    owner=$(stat -c "%U" "$dir")
    [[ "${perm:5:1}" != "-" ]] && echo "Group write set on $dir"
    [[ "${perm:8:1}" != "-" ]] && echo "Other write set on $dir"
    [[ "$owner" != "root" ]] && echo "$dir not owned by root"
  else
    echo "$dir is not a directory"
  fi
done
')
if [[ -z "$PATH_ISSUES" ]]; then
    pass_msg "Root PATH integrity is correct"
    write_csv "root PATH integrity" "PASS" "Remediation not needed"
else
    fail_msg "Root PATH integrity issues found"
    write_csv "root PATH integrity" "FAIL" "Correct PATH directories, permissions, and ownership"
fi

# -----------------------------
# Ensure all users' home directories exist
# -----------------------------
MISSING_HOMES=$(grep -E -v '^(root|halt|sync|shutdown)' /etc/passwd | \
awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") {print $1 " " $6}' | \
while read user dir; do [ ! -d "$dir" ] && echo "The home directory ($dir) of user $user does not exist"; done)
if [[ -z "$MISSING_HOMES" ]]; then
    pass_msg "All users' home directories exist"
    write_csv "home directories exist" "PASS" "Remediation not needed"
else
    fail_msg "Missing home directories found"
    write_csv "home directories exist" "FAIL" "Create missing home directories and assign correct ownership"
fi

# -----------------------------
# Ensure users' home directories permissions are 750 or more restrictive
# -----------------------------
HOME_PERMS_ISSUES=$(grep -E -v '^(halt|sync|shutdown)' /etc/passwd | \
awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") {print $1 " " $6}' | \
while read user dir; do
  if [ -d "$dir" ]; then
    perm=$(ls -ld $dir | cut -f1 -d" ")
    [[ "${perm:5:1}" != "-" ]] && echo "Group write set on $dir of $user"
    [[ "${perm:7:1}" != "-" ]] && echo "Other read set on $dir of $user"
    [[ "${perm:8:1}" != "-" ]] && echo "Other write set on $dir of $user"
    [[ "${perm:9:1}" != "-" ]] && echo "Other execute set on $dir of $user"
  fi
done)
if [[ -z "$HOME_PERMS_ISSUES" ]]; then
    pass_msg "All users' home directories have secure permissions"
    write_csv "home directories permissions" "PASS" "Remediation not needed"
else
    fail_msg "Users' home directories with insecure permissions found"
    write_csv "home directories permissions" "FAIL" "Adjust permissions to 750 or more restrictive"
fi

# -----------------------------
# Ensure users own their home directories
# -----------------------------
HOME_OWNERSHIP_ISSUES=$(grep -E -v '^(halt|sync|shutdown)' /etc/passwd | \
awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") {print $1 " " $6}' | \
while read user dir; do
  if [ -d "$dir" ]; then
    owner=$(stat -c "%U" "$dir")
    [[ "$owner" != "$user" ]] && echo "Home directory ($dir) of $user is owned by $owner"
  fi
done)
if [[ -z "$HOME_OWNERSHIP_ISSUES" ]]; then
    pass_msg "All users own their home directories"
    write_csv "home directories ownership" "PASS" "Remediation not needed"
else
    fail_msg "Users with incorrect home directory ownership found"
    write_csv "home directories ownership" "FAIL" "Assign correct ownership to user home directories"
fi

# -----------------------------
# Ensure users' dot files are not group or world writable
# -----------------------------
DOTFILE_PERMS_ISSUES=$(grep -E -v '^(halt|sync|shutdown)' /etc/passwd | \
awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") {print $1 " " $6}' | \
while read user dir; do
  if [ -d "$dir" ]; then
    for file in $dir/.[A-Za-z0-9]*; do
      if [ -f "$file" ] && [ ! -h "$file" ]; then
        perm=$(ls -ld "$file" | cut -f1 -d" ")
        [[ "${perm:5:1}" != "-" ]] && echo "Group write on $file"
        [[ "${perm:8:1}" != "-" ]] && echo "Other write on $file"
      fi
    done
  fi
done)
if [[ -z "$DOTFILE_PERMS_ISSUES" ]]; then
    pass_msg "Users' dot files are not group or world writable"
    write_csv "dotfiles permissions" "PASS" "Remediation not needed"
else
    fail_msg "Insecure permissions on users' dot files found"
    write_csv "dotfiles permissions" "FAIL" "Adjust permissions to remove group/world write"
fi

# -----------------------------
# Ensure no users have .forward files
# -----------------------------
FORWARD_FILES=$(grep -E -v '^(root|halt|sync|shutdown)' /etc/passwd | \
awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") {print $1 " " $6}' | \
while read user dir; do
  [ -f "$dir/.forward" ] && echo ".forward file exists in $dir for $user"
done)
if [[ -z "$FORWARD_FILES" ]]; then
    pass_msg "No users have .forward files"
    write_csv "forward files" "PASS" "Remediation not needed"
else
    fail_msg ".forward files found"
    write_csv "forward files" "FAIL" "Remove .forward files and notify users"
fi

# -----------------------------
# Ensure no users have .netrc files
# -----------------------------
NETRC_FILES=$(grep -E -v '^(root|halt|sync|shutdown)' /etc/passwd | \
awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") {print $1 " " $6}' | \
while read user dir; do
  [ -f "$dir/.netrc" ] && echo ".netrc file exists in $dir for $user"
done)
if [[ -z "$NETRC_FILES" ]]; then
    pass_msg "No users have .netrc files"
    write_csv "netrc files" "PASS" "Remediation not needed"
else
    fail_msg ".netrc files found"
    write_csv "netrc files" "FAIL" "Remove .netrc files and notify users"
fi

# -----------------------------
# Ensure users' .netrc files are not group or world accessible
# -----------------------------
NETRC_PERMS_ISSUES=$(grep -E -v '^(root|halt|sync|shutdown)' /etc/passwd | \
awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") {print $1 " " $6}' | \
while read user dir; do
  for file in $dir/.netrc; do
    if [ -f "$file" ]; then
      perm=$(ls -ld "$file" | cut -f1 -d" ")
      [[ "${perm:4:6}" != "------" ]] && echo "Insecure .netrc permissions on $file"
    fi
  done
done)
if [[ -z "$NETRC_PERMS_ISSUES" ]]; then
    pass_msg "Users' .netrc files have secure permissions"
    write_csv "netrc permissions" "PASS" "Remediation not needed"
else
    fail_msg "Insecure permissions on users' .netrc files found"
    write_csv "netrc permissions" "FAIL" "Adjust .netrc file permissions"
fi

# -----------------------------
# Ensure no users have .rhosts files
# -----------------------------
RHOSTS_FILES=$(grep -E -v '^(root|halt|sync|shutdown)' /etc/passwd | \
awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false") {print $1 " " $6}' | \
while read user dir; do
  [ -f "$dir/.rhosts" ] && echo ".rhosts file exists in $dir for $user"
done)
if [[ -z "$RHOSTS_FILES" ]]; then
    pass_msg "No users have .rhosts files"
    write_csv "rhosts files" "PASS" "Remediation not needed"
else
    fail_msg ".rhosts files found"
    write_csv "rhosts files" "FAIL" "Remove .rhosts files and notify users"
fi





echo "************ SECURITY ASSESSMENT COMPLETE ************"
