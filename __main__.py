"""Bootstrap script for Amazon Linux to comply CIS Amazon Linux Benchmark v2.0.0"""

import argparse
import logging
import os
import re
from subprocess import CalledProcessError
import pkg_resources

from util import exec_shell, set_backup_enabled, File, Package, Service, PropertyFile


def get_string_asset(path):
    """Returns the content of the specified asset file"""
    return pkg_resources.resource_string(__name__, 'assets/{}'.format(path))


def disable_unused_filesystems():
    """1.1.1 Disable unused filesystems"""
    filesystems = [
        'cramfs', 'freevxfs', 'jffs2', 'hfs', 'hfsplus', 'squashfs', 'udf', 'vfat'
    ]

    prop = PropertyFile('/etc/modprobe.d/CIS.conf', ' ')
    for filesystem in filesystems:
        prop.override({'install {}'.format(filesystem): '/bin/true'})
    prop.write()


def set_mount_options():
    """1.1.2 - 1.1.17"""
    # options = {
    #     '/tmp': 'tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime 0 0',
    #     '/var/tmp': 'tmpfs /var/tmp tmpfs rw,nosuid,nodev,noexec,relatime 0 0',
    #     '/home': '/dev/xvdf1 /home ext4 rw,nodev,relatime,data=ordered 0 0',
    #     '/dev/shm': 'tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec,relatime 0 0'
    # }

    # with open('/etc/fstab', 'r') as f:
    #     for line in f:
    #         if line.startswith('#'):
    #             continue
    #         partition = line.split()[1]
    #         if partition not in options:
    #             options[partition] = line.strip()

    # with open('/etc/fstab', 'w') as f:
    #     for record in options.values():
    #         f.write('{}\n'.format(record))


def ensure_sticky_bit():
    """1.1.18 Ensure sticky bit is set on all world - writable directories"""
    try:
        return exec_shell(['df --local -P | awk {\'if (NR!=1) print $6\'} | xargs -I \'{}\' find \'{}\' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t'])
    except CalledProcessError:
        return 1


def disable_automounting():
    """1.1.19 Disable Automounting"""
#    Service('autofs').disable()

# 1.2 Not-Scored 

def enable_aide():
    """1.3 Filesystem Integrity Checking"""

    cron_job = '0 5 * * * /usr/sbin/aide --check'

    Package('aide').install()

    return exec_shell([
        'aide --init',
        'mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz',
        '(crontab -u root -l 2>/dev/null | grep -v /usr/sbin/aide; echo "{}") | crontab -'.format(cron_job)
    ])


def secure_boot_settings():
    """1.4 Secure Boot Settings"""

    if os.path.isfile('/boot/grub/menu.lst'):
        exec_shell([
            'chown root:root /boot/grub/menu.lst',
            'chmod og-rwx /boot/grub/menu.lst'
        ])

    PropertyFile('/etc/sysconfig/init', '=').override({
        'SINGLE': '/sbin/sulogin',
        'PROMPT': 'no'
    }).write()


def apply_process_hardenings():
    """1.5 Additional Process Hardening"""
    # 1.5.1 Ensure core dumps are restricted
    PropertyFile('/etc/security/limits.conf', ' ').override({
        '* hard core': '0'
    }).write()

    PropertyFile('/etc/sysctl.conf', ' = ').override({
        'fs.suid_dumpable': '0'
    }).write()

    # 1.5.3 Ensure address space layout randomization (ASLR) is enable
    PropertyFile('/etc/sysctl.conf', ' = ').override({
        'kernel.randomize_va_space': '2'
    }).write()

    # 1.5.4 Ensure prelink is disabled
    Package('prelink').remove()


def configure_warning_banners():
    """1.7 Warning Banners"""

    # 1.7.1 Command Line Warning Banners
    exec_shell([
        'update-motd --disable',
        'chown root:root /etc/motd',
        'chmod 644 /etc/motd'
    ])
    File('/etc/motd').write(get_string_asset('/etc/motd'))

    exec_shell(['chown root:root /etc/issue', 'chmod 644 /etc/issue'])
    File('/etc/issue').write('Authorized uses only. All activity may be monitored and reported.\n')

#Not-Scored
  
#    exec_shell(['chown root:root /etc/issue.net', 'chmod 644 /etc/issue.net'])
#    File('/etc/issue.net').write('Authorized uses only. All activity may be monitored and reported.\n')


def ensure_updated():
    """1.8 Ensure updates, patches, and additional security software are installed"""
    Package.update_all()


def disable_inetd_services():
    """2.1 inetd Services"""
    services = [
        'chargen-dgram', 'chargen-stream', 'daytime-dgram', 'daytime-stream',
        'discard-dgram', 'discard-stream', 'echo-dgram', 'echo-stream',
        'time-dgram', 'time-stream', 'rexec', 'rlogin', 'rsh', 'talk',
        'telnet', 'tftp', 'rsync', 'xinetd'
    ]

    for srv in services:
        Service(srv).disable()


def configure_time_synchronization(upstream, chrony=True):
    """2.2.1 Time Synchronization"""
    if chrony:
        configure_chrony(upstream)
    else:
        configure_ntp(upstream)


def configure_ntp(upstream):
    """2.2.1 Time Synchronization"""
    # 2.2.1.1 Ensure time synchronization is in use
 #   Package('chrony').remove()
 #   Package('ntp').install()

    # 2.2.1.2 Ensure ntp is configured
    PropertyFile('/etc/ntp.conf', ' ').override({
        'restrict default': None,
        'restrict -4 default': 'kod nomodify notrap nopeer noquery',
        'restrict -6 default': 'kod nomodify notrap nopeer noquery',
        'server': upstream
    }).write()

    PropertyFile('/etc/sysconfig/ntpd', '=').override({
        'OPTIONS': '"-u ntp:ntp"'
    }).write()


def configure_chrony(upstream):
    """2.2.1 Time Synchronization"""

    # 2.2.1.1 Ensure time synchronization is in use
#    Package('ntp').remove()
#    Package('chrony').install()

    # 2.2.1.3 Ensure chrony is configured
    PropertyFile('/etc/chrony.conf', ' ').override({
        'server': upstream
    }).write()

    PropertyFile('/etc/sysconfig/chronyd', '=').override({
        'OPTIONS': '"-u chrony"'
    }).write()

    exec_shell([
        'chkconfig chronyd on',
    ])


def remove_x11_packages():
    """2.2.2 Ensure X Window System is not installed"""
    Package('xorg-x11*').remove()


def disable_special_services():
    """2.2.3 - 2.2.14, 2.2.16"""
    services = [
        'avahi-daemon', 'cups',
        'dhcpd', 'slapd', 'nfs', 'rpcbind', 'named', 'vsftpd', 'nfs-server',
        'httpd', 'dovecot', 'smb', 'snmpd', 'ypserv', ' rsh.socket','rlogin.socket',
        'rexec.socket', 'telnet.socket', 'tftp.socket', ' rsyncd', 'ntalk'
    ]

    for srv in services:
        Service(srv).disable()


def configure_mta():
    """2.2.15 Ensure mail transfer agent is configured for local - only mode"""
    # replaced localhost with loopback-only
    exec_shell([
        'mkdir -p /etc/postfix',
        'touch /etc/postfix/main.cf'
    ])
    PropertyFile('/etc/postfix/main.cf', ' = ').override({
        'inet_interfaces': 'loopback-only'
    }).write()


def remove_insecure_clients():
    """2.3 Service Clients"""
    packages = [
        'ypbind', 'rsh', 'talk',
        'telnet', 'openldap-clients'
    ]

    for package in packages:
        Package(package).remove()


def configure_host_network_params():
    """3.1 Network Parameters(Host Only)"""
    # added new line for ipv6
    PropertyFile('/etc/sysctl.conf', ' = ').override({
        'net.ipv4.ip_forward': '0',
        'net.ipv4.conf.all.send_redirects': '0',
        'net.ipv4.conf.default.send_redirects': '0',
        'net.ipv6.conf.all.forwarding':'0'
    }).write()


def configure_network_params():
    """3.2 Network Parameters(Host and Router)"""
    PropertyFile('/etc/sysctl.conf', ' = ').override({
        'net.ipv4.conf.all.accept_source_route': '0',
        'net.ipv4.conf.default.accept_source_route': '0',
        'net.ipv4.conf.all.accept_redirects': '0',
        'net.ipv4.conf.default.accept_redirects': '0',
        'net.ipv4.conf.all.secure_redirects': '0',
        'net.ipv4.conf.default.secure_redirects': '0',
        'net.ipv4.conf.all.log_martians': '1',
        'net.ipv4.conf.default.log_martians': '1',
        'net.ipv4.icmp_echo_ignore_broadcasts': '1',
        'net.ipv4.icmp_ignore_bogus_error_responses': '1',
        'net.ipv4.conf.all.rp_filter': '1',
        'net.ipv4.conf.default.rp_filter': '1',
        'net.ipv4.tcp_syncookies': '1',
        'net.ipv6.conf.all.accept_source_route': '0',
        'net.ipv6.conf.default.accept_source_route': '0'
#        'net.ipv6.conf.all.accept_redirects = 0',
#        'net.ipv6.conf.default.accept_redirects = 0',
#        'net.ipv6.conf.all.accept_ra = 0',
#        'net.ipv6.conf.default.accept_ra = 0'
    }).write()


def configure_ipv6_params():
    """3.3 IPv6"""
    PropertyFile('/etc/sysctl.conf', ' = ').override({
        'net.ipv6.conf.all.accept_ra': '0',
        'net.ipv6.conf.default.accept_ra': '0',
        'net.ipv6.conf.all.accept_redirects': '0',
        'net.ipv6.conf.default.accept_redirects': '0'
    }).write()

    # 3.3.3 Ensure IPv6 is disabled
    PropertyFile('/etc/modprobe.d/CIS.conf', ' ').override({
        'options ipv6': 'disable=1'
    }).write()


def configure_tcp_wrappers(hosts):
    """3.4 TCP Wrappers"""
    # 3.4.1 Ensure TCP Wrappers is installed
    Package('tcp_wrappers').install()

#    if hosts:
        # 3.4.2 Ensure /etc/hosts.allow is configured
#        allowed_hosts = ','.join(hosts)
#        exec_shell('echo "ALL: {}" > /etc/hosts.allow'.format(allowed_hosts))

#        # 3.4.3 Ensure /etc/hosts.deny is configured
#        exec_shell('echo "ALL: ALL" > /etc/hosts.deny')

    # 3.4.4 Ensure permissions on /etc/hosts.allow are configured
    exec_shell([
        'chown root:root /etc/hosts.allow',
        'chmod 644 /etc/hosts.allow'
    ])

    # 3.4.5 Ensure permissions on /etc/hosts.deny are configured
    exec_shell([
        'chown root:root /etc/hosts.deny',
        'chmod 644 /etc/hosts.deny'
    ])


def disable_uncommon_protocols():
    """3.5 Uncommon Network Protocols"""
"""    modules = [
        'dccp', 'sctp', 'rds', 'tipc'
    ]
    prop = PropertyFile('/etc/modprobe.d/CIS.conf', ' ')
    for mod in modules:
        prop.override({'install {}'.format(mod): '/bin/true'})
    prop.write()
"""

def configure_iptables():
    """3.6 Firewall Configuration"""
"""    Package('iptables').install()

    exec_shell([
        'iptables -F',
        'iptables -P INPUT DROP',
        'iptables -P OUTPUT DROP',
        'iptables -P FORWARD DROP',
        'iptables -A INPUT -i lo -j ACCEPT',
        'iptables -A OUTPUT -o lo -j ACCEPT',
        'iptables -A INPUT -s 127.0.0.0/8 -j DROP',
        'iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT',
        'iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT',
        'iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT',
        'iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT',
        'iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT',
        'iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT',
        'iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT',
        'iptables-save'
    ])
"""

def configure_rsyslog():
    """4.2.1 Configure rsyslog"""
    """Package('rsyslog').install()

    PropertyFile('/etc/rsyslog.conf', ' ').override({
    
        '*.emerg': ':omusrmsg:*',
        'mail.*': '-/var/log/mail',
        'mail.info': '-/var/log/mail.info',
        'mail.warning': '-/var/log/mail.warn',
        'mail.err': '/var/log/mail.err',
        'news.crit': '-/var/log/news/news.crit',
        'news.err': '-/var/log/news/news.err',
        'news.notice': '-/var/log/news/news.notice',
        '*.=warning;*.=err': '-/var/log/warn',
        '*.crit': '/var/log/warn',
        '*.*;mail.none;news.none': '-/var/log/messages',
        'local0,local1.*': '-/var/log/localmessages',
        'local2,local3.*': '-/var/log/localmessages',
        'local4,local5.*': '-/var/log/localmessages',
        'local6,local7.*': '-/var/log/localmessages ',
        '$FileCreateMode': '0640'
    }).write()
    """

def configure_log_file_permissions():
    """4.2.4 Ensure permissions on all logfiles are configured"""

#    exec_shell([r'find /var/log -type f -exec chmod g-wx,o-rwx {} +'])


def configure_cron():
    """5.1 Configure cron"""
    # 5.1.1 Ensure cron daemon is enabled
    Service('crond').enable()

    # 5.1.2 - 5.1.8
    exec_shell([
        'chown root:root /etc/crontab',
        'chmod og-rwx /etc/crontab',
        'chown root:root /etc/cron.hourly',
        'chmod og-rwx /etc/cron.hourly',
        'chown root:root /etc/cron.daily',
        'chmod og-rwx /etc/cron.daily',
        'chown root:root /etc/cron.weekly',
        'chmod og-rwx /etc/cron.weekly',
        'chown root:root /etc/cron.monthly',
        'chmod og-rwx /etc/cron.monthly',
        'chown root:root /etc/cron.d',
        'chmod og-rwx /etc/cron.d',
        'rm -f /etc/cron.deny',
        'rm -f /etc/at.deny',
        'touch /etc/cron.allow',
        'touch /etc/at.allow',
        'chmod og-rwx /etc/cron.allow',
        'chmod og-rwx /etc/at.allow',
        'chown root:root /etc/cron.allow',
        'chown root:root /etc/at.allow'
    ])


def configure_sshd():
    """5.2 SSH Server Configuration"""
    # 5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured
    exec_shell([
        'chown root:root /etc/ssh/sshd_config',
        'chmod og-rwx /etc/ssh/sshd_config'
    ])

    # 5.2.2 - 5.2.16
    PropertyFile('/etc/ssh/sshd_config', ' ').override({
        'Protocol': '2',
        'LogLevel': 'INFO',
        'X11Forwarding': 'no',
        'MaxAuthTries': '4',
        'IgnoreRhosts': 'yes',
        'HostbasedAuthentication': 'no',
        'PermitRootLogin': 'no',
        'PermitEmptyPasswords': 'no',
        'PermitUserEnvironment': 'no',
        'Ciphers': 'aes256-ctr,aes192-ctr,aes128-ctr',
        'MACs': 'hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com',
        'KexAlgorithms': 'curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellmangroup14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffiehellman-group-exchange-sha256',
        'ClientAliveInterval': '300',
        'ClientAliveCountMax': '0',
        'LoginGraceTime': '60',
        'AllowUsers': 'ec2-user',
        'Banner': '/etc/issue.net'
    }).write()


def configure_pam():
    """5.3 Configure PAM"""

    def convert_password(line):
        if password_unix_re.match(line):
            if 'remember=5' not in line:
                line += ' remember=5'
            if 'sha512' not in line:
                line += ' sha512'
        return line
    password_unix_re = re.compile(r'^password\s+sufficient\s+pam_unix.so')

    password_auth_content = get_string_asset('/etc/pam.d/password-auth')
    password_auth_content += exec_shell([
        'cat /etc/pam.d/password-auth | grep -v "^auth"'
    ])
    password_auth_content = '\n'.join([
        convert_password(line) for line in password_auth_content.splitlines()
    ])

    with open('/etc/pam.d/password-auth-local', 'w') as f:
        f.write(password_auth_content)

    exec_shell(['ln -sf /etc/pam.d/password-auth-local /etc/pam.d/password-auth'])

    system_auth_content = get_string_asset('/etc/pam.d/system-auth')
    system_auth_content += exec_shell([
        'cat /etc/pam.d/system-auth | grep -v "^auth"'
    ])
    system_auth_content = '\n'.join([
        convert_password(line) for line in system_auth_content.splitlines()
    ])
    with open('/etc/pam.d/system-auth-local', 'w') as f:
        f.write(system_auth_content)

    exec_shell(
        ['ln -sf /etc/pam.d/system-auth-local /etc/pam.d/system-auth'])

    PropertyFile('/etc/security/pwquality.conf', '=').override({
        'minlen': '14',
        'dcredit': '-1',
        'ucredit': '-1',
        'ocredit': '-1',
        'lcredit': '-1'
    }).write()


def configure_password_parmas():
    """5.4.1 Set Shadow Password Suite Parameters"""
    PropertyFile('/etc/login.defs', '\t').override({
        'PASS_MAX_DAYS': '90',
        'PASS_MIN_DAYS': '7',
        'PASS_WARN_AGE': '7'
    }).write()

    exec_shell([
        'useradd -D -f 30'
    ])


def configure_umask():
    """5.4.3, 5.4.4"""

    exec_shell([
        'usermod -g 0 root'
    ])
     
    umask_reg = r'^(\s*)umask\s+[0-7]+(\s*)$'

    bashrc = exec_shell([
        'cat /etc/bashrc | sed -E "s/{}/\\1umask 027\\2/g"'.format(umask_reg)
    ])
    File('/etc/bashrc').write(bashrc)

    profile = exec_shell([
        'cat /etc/profile | sed -E "s/{}/\\1umask 027\\2/g"'.format(
            umask_reg)
    ])
    File('/etc/profile').write(profile)
#    TMOUT=600


def configure_su():
    """5.5 Ensure access to the su command is restricted"""
    File('/etc/pam.d/su').write(get_string_asset('/etc/pam.d/su'))
    exec_shell('usermod -aG wheel root')

    """6.1.2---6.1.9"""
    exec_shell([
        'chown root:root /etc/passwd',
        'chmod 644 /etc/passwd',
        'chown root:root /etc/shadow',
        'chmod 000 /etc/shadow',
        'chown root:root /etc/group',
        'chmod 644 /etc/group',
        'chown root:root /etc/gshadow',
        'chmod 000 /etc/gshadow',
        'chown root:root /etc/passwd-',
        'chmod u-x,go-wx /etc/passwd',
        'chown root:root /etc/shadow-',
        'chmod 000 /etc/shadow',
        'chown root:root /etc/group-',
        'chmod u-x,go-wx /etc/group',
        'chown root:root /etc/gshadow-',
        'chmod 000 /etc/gshadow'

    ])
    
def missing_rules():
#    PropertyFile('/etc/default/grub', ' ').override({
#       'GRUB_CMDLINE_LINUX':'"audit=1"'
        
#    }).write()

    #4.1.4

    exec_shell([
        'chmod +rw /etc/audit/audit.rules'
    ])

    with open('/etc/audit/audit.rules', 'a') as f:
        f.write('-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change \n')
        f.write('-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change \n')
        f.write('-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k timechange \n')
        f.write('-a always,exit -F arch=b64 -S clock_settime -k time-change \n')
        f.write('-a always,exit -F arch=b32 -S clock_settime -k time-change \n')
        f.write('-w /etc/localtime -p wa -k time-change \n')

    #4.1.5-5.1.11
    exec_shell([
        'chmod +rw /etc/audit/rules.d/audit.rules'
    ])

    with open(' /etc/audit/rules.d/audit.rules','a') as f:
        f.write('-w /etc/group -p wa -k identity \n')    
        f.write('-w /etc/passwd -p wa -k identity \n')
        f.write('-w /etc/gshadow -p wa -k identity \n')
        f.write('-w /etc/shadow -p wa -k identity \n')
        f.write('-w /etc/security/opasswd -p wa -k identity \n')
        f.write('-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale \n')
        f.write('-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale \n')
        f.write('-w /etc/issue -p wa -k system-locale \n')
        f.write('-w /etc/issue.net -p wa -k system-locale \n')
        f.write('-w /etc/hosts -p wa -k system-locale \n')
        f.write('-w /etc/sysconfig/network -p wa -k system-locale \n')
        f.write('-w /etc/sysconfig/network-scripts/ -p wa -k system-locale \n')
        f.write('-w /etc/selinux/ -p wa -k MAC-policy \n')
        f.write('-w /usr/share/selinux/ -p wa -k MAC-policy \n')
        f.write('-w /var/log/lastlog -p wa -k logins \n')
        f.write('-w /var/run/faillock/ -p wa -k logins \n')
        f.write('-w /var/run/utmp -p wa -k session \n')
        f.write('-w /var/log/wtmp -p wa -k logins \n')
        f.write('-w /var/log/btmp -p wa -k logins \n')
        f.write('-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod \n')
        f.write('-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod \n')
        f.write('-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod \n')
        f.write('-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod \n')
        f.write('-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod \n')
        f.write('-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod \n')
        f.write('-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod \n')
        f.write('-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access \n')
        f.write('-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access \n')
        f.write('-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access \n')
        f.write('-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access \n')
        f.write('-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts \n')
        f.write('-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts \n')
        f.write('-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete \n')
        f.write('-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete \n')
        f.write('-w /etc/sudoers -p wa -k scope \n')
        f.write('-w /etc/sudoers.d/ -p wa -k scope \n')
        f.write('-w /var/log/sudo.log -p wa -k actions \n')
        f.write('-w /sbin/insmod -p x -k modules \n')
        f.write('-w /sbin/rmmod -p x -k modules \n')
        f.write('-w /sbin/modprobe -p x -k modules \n')
        f.write('-a always,exit -F arch=b64 -S init_module -S delete_module -k modules \n')
        f.write('-e 2 \n')

    #4.1.1.2-4.1.1.3

    exec_shell([
        'chmod +rw /etc/audit/auditd.conf'
    ])

    PropertyFile('/etc/audit/auditd.conf', '\t').override({
        'space_left_action': 'email',
        'action_mail_acct': 'root',
        'admin_space_left_action': 'halt',
        'max_log_file_action': 'keep_logs'
    }).write()

    

    

def main():
    parser = argparse.ArgumentParser(
        description='A script to harden Amazon Linux instance.')

    # The Amazon Time Sync Service is available through NTP
    # at the 169.254.169.123 IP address for any instance running in a VPC.
    # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/set-time.html
    parser.add_argument('--time', metavar='<time server>', default ='169.254.169.123',
                        help='Specify the upstream time server.')
    parser.add_argument('--chrony', action='store', type=bool, default=True,
                        help='Use chrony for time synchronization')
    parser.add_argument('--no-backup', action='store_true',
                        help='Automatic config backup is disabled')
    parser.add_argument('--clients', nargs='+', metavar='<allowed clients>',
                        help='Specify a comma separated list of hostnames and host IP addresses.')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Display details including debugging output etc.')
    parser.add_argument('--disable-tcp-wrappers', action='store_true',
                        help='disable tcp-wrappers')
    parser.add_argument('--disable-pam', action='store_true',
                        help='disable pam')
    parser.add_argument('--disable-iptables', action='store_true',
                        help='disable iptables')
    parser.add_argument('--disable-mount-options', action='store_true',
                        help='disable set mount options')

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.WARN)

    logging.info(
        '[Config] Upstream time server is set as "%s"', args.time)
    if args.chrony:
        logging.info(
            '[Config] chrony will be used for time synchronization')
    else:
        logging.info(
            '[Config] ntp will be used for time synchronization')
    if args.clients:
        logging.info('[Config] Allowed clients are set as %s',
            args.clients)

    if args.no_backup:
        logging.info('[Config] Automatic config backup is disabled')
        set_backup_enabled(False)

    # 1 Initial Setup
    disable_unused_filesystems()
#    if not args.disable_mount_options:
#        set_mount_options()
    ensure_sticky_bit()
#    disable_automounting()
    enable_aide()
    secure_boot_settings()
    apply_process_hardenings()
    configure_warning_banners()
    ensure_updated()

    # 2 Services
    disable_inetd_services()
    configure_time_synchronization(args.time, chrony=args.chrony)
    remove_x11_packages()
    disable_special_services()
    configure_mta()
    remove_insecure_clients()

    # 3 Network Configuration
    configure_host_network_params()
    configure_network_params()
    configure_ipv6_params()
    if not args.disable_tcp_wrappers:
        configure_tcp_wrappers(args.clients)
    disable_uncommon_protocols()
#    if not args.disable_iptables:
#        configure_iptables()

    # 4 Logging and Auditing
#    configure_rsyslog()
#    configure_log_file_permissions()

    # 5 Access, Authentication and Authorization
    configure_cron()
    configure_sshd()
    if not args.disable_pam:
        configure_pam()
    configure_password_parmas()
    configure_umask()
    configure_su()
    missing_rules()


if __name__ == '__main__':
    main()
