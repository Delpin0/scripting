#!/bin/bash
echo "Beginning STIG process for a CLEAN install of Ubuntu 16.04.  If this is an existing installation, press Ctrl-C now.  Otherwise, press Enter to continue"
read RUMBLE

echo "What is the desired hostname for the system?"
read NEW_HOSTNAME

#Hostname configuration
echo $NEW_HOSTNAME > /proc/sys/kernel/hostname
sed -i 's/127.0.1.1.*/127.0.1.1\t'"$NEW_HOSTNAME"'/g' /etc/hosts
echo $NEW_HOSTNAME > /etc/hostname

#Remove all disallowed packages (72077, 72299, 72301, 
apt remove rsh-server telnet ftp tftp snmpd unattended-upgrades vsftpd -y

#Remove unnecessary users   72001
userdel games
userdel news
userdel proxy
userdel www-data
userdel irc
userdel gnats
userdel list
userdel uucp
userdel lp

#Update and install base allowable packages
apt update -o Acquire::ForceIPv4=true
apt upgrade -y -o Acquire::ForceIPv4=true
apt install vim wget -y -o Acquire::ForceIPv4=true
apt autoremove -o Acquire::ForceIPv4=true
apt autoclean -o Acquire::ForceIPv4=true

#Install screen as required per 71897
apt install screen -y -o Acquire::ForceIPv4=true

#Install ubuntu-support-status to verify 71997
apt install ubuntu-support-status -y -o Acquire::ForceIPv4=true

#Install OpenSSH as required 
apt install openssh-server -y -o Acquire::ForceIPv4=true

#Install pam_cracklib for password security
apt install libpam-cracklib -y -o Acquire::ForceIPv4=true

#Install pam_pwquality to enforce quality passwords
apt install libpam-pwquality -y -o Acquire::ForceIPv4=true

#Install sudo
apt install sudo -y -o Acquire::ForceIPv4=true


#Disable ctrl-alt-del   71993
systemctl mask ctrl-alt-del.target
systemctl daemon-reload

#Modify the permissions on shared memory
echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" >> /etc/fstab

#Disable USB storage  71983
echo "#Disable USB storage" >> /etc/modprobe.d/blacklist.conf
echo "blacklist usb-storage" >> /etc/modprobe.d/blacklist.conf

#Disable dccp
echo "install dccp /bin/true" > /etc/modprobe.d/nodccp

#Install and configure NTP
apt install ntp -y -o Acquire::ForceIPv4=true
#disable network time
timedatectl set-ntp 0
#set system to UTC
timedatectl set-timezone Etc/UTC
#Set maxpoll for NTP
echo "maxpoll 10" >> /etc/ntp.conf
#Restart NTP to enable changes
service ntp restart



#Basic firewall configuration   72219  72313
echo "#!/bin/bash" >> /etc/iptables.rules
echo "iptables -F" >> /etc/iptables.rules
echo "iptables -P FORWARD DROP" >> /etc/iptables.rules
echo "iptables -N syn-flood" >> /etc/iptables.rules
echo "iptables -A syn-flood -m limit --limit 100/second --limit-burst 150 -j RETURN" >> /etc/iptables.rules
echo 'iptables -A syn-flood -j LOG #-log-prefix "SYN flood: "' >> /etc/iptables.rules
echo "iptables -A syn-flood -j DROP" >> /etc/iptables.rules
echo 'iptables -A INPUT -p tcp --dport 22 -j f2b-sshd -m comment --comment "Allow SSH access, pass it to Fail2Ban"' >> /etc/iptables.rules
echo 'iptables -A f2b-sshd -j RETURN' >> /etc/iptables.rules
echo 'iptables -A INPUT -p tcp --dport 22 -j ACCEPT -m comment --comment "Allow SSH access"' >> /etc/iptables.rules
echo 'iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT -m comment --comment "Allow return traffic for locally created connections"' >> /etc/iptables.rules
echo "iptables -A INPUT -i lo -j ACCEPT" >> /etc/iptables.rules
echo "iptables -A INPUT -j DROP" >> /etc/iptables.rules
echo "iptables -A OUTPUT -j ACCEPT" >> /etc/iptables.rules
chmod +x /etc/iptables.rules
#
#Sysctl configuration
#

#Disable IPV6
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >>/etc/sysctl.conf
echo "net.ipv6.conf.lo.disable_ipv6 = 1" >>/etc/sysctl.conf
#Mitigate IP spoofing
echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
#Ignore broadcast ICMP  72287
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
#Disable source routed packets  72283 72285 72319
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
#Ignore send redirects  72291 and 72293
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
#Rate limit to help prevent DDOS
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 2048" >> /etc/sysctl.conf
echo "net.ipv4.tcp_synack_retries = 2" >> /etc/sysctl.conf
echo "net.ipv4.tcp_syn_retries = 5" >> /etc/sysctl.conf
#Log martians
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
#Ignore ICMP redirects  72289  73175
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
#Disable packet forwarding allowed  72309
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding = 0" >> /etc/sysctl.conf
#Reset on kernel panic
echo "vm.panic_on_oom = 1" >> /etc/sysctl.conf
echo "kernel.panic = 10" >> /etc/sysctl.conf
#Randomize virtual address space  77825
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf


#Prevent host spoofing
sed -i 's/order hosts,bind/order bind,hosts/' /etc/host.conf
echo "nospoof on" >> /etc/host.conf

#Set max simultaneous logins to 10  72217
echo "* hard maxlogins 10" >> /etc/security/limits.conf
echo "* hard maxsyslogins 10" >> /etc/security/limits.conf 

#Disable core dumps
echo "* hard core 0" >> /etc/security/limits.conf 
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf

#Password policy
#1 day minimum password time  71925
sed -i 's/PASS_MIN_DAYS\t0/PASS_MIN_DAYS\t1/' /etc/login.defs 
#60 day password maximum    71929
sed -i 's/PASS_MAX_DAYS\t99999/PASS_MAX_DAYS\t60/' /etc/login.defs 
#Force 4 seconds between retries
sed -i 's/#FAIL_DELAY/FAIL_DELAY 4/' /etc/login.defs
#Force a home directory be created on account creation     72013
echo -e "\n#Force home directory creation when adding a user" >> /etc/login.defs 
echo "CREATE_HOME yes" >> /etc/login.defs 
#Force users to create good passwords via pam  73159
echo "password required pam_pwquality.so retry=3" >> /etc/pam.d/passwd

#Password complexity requirements  This includes the following:
#minlen=15  Minimum password length of 15
#ucredit=-1  Uppercase letter counts as 1
#lcredit=-1  Lowercase letter counts as 1
#dcredit=-1  Number counts as 1
#difok=8  A new password must have 8 different characters
#ocredit=-1 Special character counts as 1
#minclass=4  Requires Upper, Lower, Number, and Special characters
#maxrepeat=4  Cannot have more than 4 of the same character in a row
#maxclassrepeat=4 Cannot have more than 4 of the same character type in a row  e.g. 1234
#retry=3  Allows user 3 times to make a proper conforming password
#This satisfies 71903 71905 71907 71909 71911 71913 71915 and 71917
echo "password        required                        pam_cracklib.so minlen=15 ucredit=-1 lcredit=-1 dcredit=-1 difok=8 ocredit=-1 minclass=4 maxrepeat=3 maxclassrepeat=4 retry=3" >> /etc/pam.d/common-password

#Prevent password reuse 71933 71919
echo "#Ensures users cannot reuse the last 5 passwords" >> /etc/pam.d/common-auth
echo "password sufficient pam_unix.so use_authtok sha512 shadow remember=5" >> /etc/pam.d/common-auth

#Lock account after 3 failed tries 71943 71945
sed -i 's/# pam-auth-update(8) for details./# pam-auth-update(8) for details.\n#Locks account after 3 failed login attempts.\nauth        required      pam_tally2.so   onerr=fail audit deny=3 even_deny_root unlock_time=604800/' /etc/pam.d/common-auth

#Create a group for sudoers
groupadd admin
dpkg-statoverride --update --add root admin 4750 /bin/su

#Force sudo authentication to last per command only, and to add a timestamp
chmod 640 /etc/sudoers
sed -i 's/Defaults\tenv_reset/Defaults\tenv_reset,timestamp_timeout=0/' /etc/sudoers

#Set default UMASK to 077    71995
sed -i 's/UMASK\t\t022/UMASK\t\t077/' /etc/login.defs

#Set the fail delay to 4  71951
sed -i 's/#FAIL_DELAY/FAIL_DELAY\t4/' /etc/login.defs

#Disable accounts if their password expires  71941
sed -i 's/# INACTIVE=-1/INACTIVE=0/' /etc/default/useradd

#Set all home directories to 750 permissions  72017
chmod  0750 /home/*

#Set all initialization files to 740 or lower   72033
for dir in /home/*/; do
    find $dir -type f -name ".*" |xargs chmod 740
done

#All logs must be readable to only root users
find /var/log -type f  | xargs chmod 600

#Create login banner 71863
echo "YOU ARE ACCESSING A US GOVERNMENT INFORMATION SYSTEM (IS) THAT IS PROVIDED FOR AUTHORIZED USE ONLY. By using this IS (which includes any device attached to this IS), you consent to the following conditions:  The US Government routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.  At any time, the US Government may inspect and seize data stored on this IS.  Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any US Government authorized purpose.  This IS includes security measures (e.g., authentication and access controls) to protect US Government interests--not for your personal benefit or privacy" > /etc/issue.net
echo "" > /etc/legal

#Create a distinct logout message
echo " " >> ~/.bash_logout
echo "_____________________" >> ~/.bash_logout
echo "|YOU HAVE LOGGED OUT|" >> ~/.bash_logout
echo "---------------------" >> ~/.bash_logout



#Remove NULLOK from PAM 
sed -i 's/auth     [success=1 default=ignore]      pam_unix.so nullok_secure/auth     [success=1 default=ignore]      pam_unix.so/' /etc/pam.d/common-auth

#Users logged out after 10 minutes of inactivity   72223
echo "export TMOUT" >> /etc/profile
echo "TMOUT=600" >> /etc/profile
echo "readonly TMOUT" >> /etc/profile

#Set all users bash histories to append only
for dir in /home/*/; do
    homedir="${dir%/}"
    chattr +a "$dir".bash_history
done

#Set all user .profiles files to immutable
for dir in /home/*/; do
    homedir="${dir%/}"
    chattr +i "$dir".profile
done

#Set bash history logging
echo "HISTFILE=~/.bash_history" >> /etc/profile
echo "HISTSIZE=10000" >> /etc/profile
echo "HISTFILESIZE=999999" >> /etc/profile
echo 'HISTIGNORE=""' >> /etc/profile
echo 'HISTCONTROL=""' >> /etc/profile
echo "readonly HISTFILE" >> /etc/profile
echo "readonly HISTIGNORE" >> /etc/profile
echo "export HISTFILE HISTSIZE HISTFILESIZE HISTIGNORE HISTCONTROL" >> /etc/profile

#
#Auditing configuration
#

#Install auditd
apt install auditd  -y -o Acquire::ForceIPv4=true

#Add shutdown on audit failure for auditd 72081
echo "-f 2" >> /etc/audit/rules.d/audit.rules
#Create auditd rules for all setguid/setgid files   72095
for file in $(find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null); do
        echo "-a always,exit -F path=\"$file\" -F perm=x -F auid>=1000 -F auid!=4294967295 -k setuid/setgid" >> /etc/audit/rules.d/audit.rules
done

#All uses of the chown command must be audited.  72097
echo "-a always,exit -F arch=b32 -S chown -F auid>=1000 -F auid!=4294967295  -F key=perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=4294967295  -F key=perm_mod" >> /etc/audit/rules.d/audit.rules
#All uses of the fchown command must be audited.  72099
echo "-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=4294967295  -F key=perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=4294967295  -F key=perm_mod" >> /etc/audit/rules.d/audit.rules
#All uses of the lchown command must be audited.  72101
echo "-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=4294967295  -F key=perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=4294967295  -F key=perm_mod" >> /etc/audit/rules.d/audit.rules
#All uses of the fchownat command must be audited.  72103
echo "-a always,exit -F arch=b32 -S fchownat -F auid>=1000 -F auid!=4294967295  -F key=perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=4294967295  -F key=perm_mod" >> /etc/audit/rules.d/audit.rules
#All uses of the chmod command must be audited.  72105
echo "-a always,exit -F arch=b32 -S chmod -F auid>=500 -F auid!=4294967295 -F key=perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S chmod -F auid>=500 -F auid!=4294967295 -F key=perm_mod" >> /etc/audit/rules.d/audit.rules
#All uses of the fchmod command must be audited.  72107
echo "-a always,exit -F arch=b32 -S fchmod -F auid>=500 -F auid!=4294967295 -F key=perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S fchmod -F auid>=500 -F auid!=4294967295 -F key=perm_mod" >> /etc/audit/rules.d/audit.rules
#All uses of the fchmodat command must be audited.  72109
echo "-a always,exit -F arch=b32 -S fchmodat -F auid>=500 -F auid!=4294967295 -F key=perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S fchmodat -F auid>=500 -F auid!=4294967295 -F key=perm_mod" >> /etc/audit/rules.d/audit.rules
#All uses of the setxattr command must be audited.  72111
echo "-a always,exit -F arch=b32 -S setxattr -F auid>=500 -F auid!=4294967295 -F key=perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S setxattr -F auid>=500 -F auid!=4294967295 -F key=perm_mod" >> /etc/audit/rules.d/audit.rules
#All uses of the fsetxattr command must be audited.  72113
echo "-a always,exit -F arch=b32 -S fsetxattr -F auid>=500 -F auid!=4294967295 -F key=perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S fsetxattr -F auid>=500 -F auid!=4294967295 -F key=perm_mod" >> /etc/audit/rules.d/audit.rules
#All uses of the lsetxattr command must be audited.  72115
echo "-a always,exit -F arch=b32 -S lsetxattr -F auid>=500 -F auid!=4294967295 -F key=perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S lsetxattr -F auid>=500 -F auid!=4294967295 -F key=perm_mod" >> /etc/audit/rules.d/audit.rules
#All uses of the removexattr command must be audited.  72117
echo "-a always,exit -F arch=b32 -S removexattr -F auid>=500 -F auid!=4294967295 -F key=perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S removexattr -F auid>=500 -F auid!=4294967295 -F key=perm_mod" >> /etc/audit/rules.d/audit.rules
#All uses of the fremoveattr command must be audited.  72119
echo "-a always,exit -F arch=b32 -S fremovexattr -F auid>=500 -F auid!=4294967295 -F key=perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S fremovexattr -F auid>=500 -F auid!=4294967295 -F key=perm_mod" >> /etc/audit/rules.d/audit.rules
#All uses of the lremovexattr command must be audited.  72121
echo "-a always,exit -F arch=b32 -S lremovexattr  -F auid>=500 -F auid!=4294967295 -F key=perm_mod" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S lremovexattr  -F auid>=500 -F auid!=4294967295 -F key=perm_mod" >> /etc/audit/rules.d/audit.rules
#All uses of the creat command must be audited.  72123
echo "-a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -F key=access" >> /etc/audit/rules.d/audit.rules
#All uses of the open command must be audited.  72125
echo "-a always,exit -F arch=b32 -S open -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -F key=access" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S open -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -F key=access" >> /etc/audit/rules.d/audit.rules
#All uses of the openat command must be audited.  72127
echo "-a always,exit -F arch=b32 -S openat -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -F key=access" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S openat -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -F key=access" >> /etc/audit/rules.d/audit.rules
#All uses of the open_by_handle_at command must be audited.  72129
echo "-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -F key=access" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -F key=access" >> /etc/audit/rules.d/audit.rules
#All uses of the truncate command must be audited.  72131
echo "-a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -F key=access" >> /etc/audit/rules.d/audit.rules
#All uses of the ftruncate command must be audited.  72133
echo "-a always,exit -F arch=b32 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295  -F key=access" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295  -F key=access" >> /etc/audit/rules.d/audit.rules
#All uses of the semanage command must be audited.  72135
echo "-a always,exit -F path=/usr/sbin/semanage -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change" >> /etc/audit/rules.d/audit.rules
#All uses of the setsebool command must be audited.  72137
echo "-a always,exit -F path=/usr/sbin/setsebool -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change" >> /etc/audit/rules.d/audit.rules
#All uses of the chcon command must be audited.  72139
echo "-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change" >> /etc/audit/rules.d/audit.rules
#All uses of the restorecon command must be audited.  72141
echo "-a always,exit -F path=/usr/sbin/setfiles -F perm=x -F auid>=1000 -F auid!=4294967295 -k -F privileged-priv_change" >> /etc/audit/rules.d/audit.rules
#Tallylog must be audited  72143
echo "-w /var/log/tallylog -p wa -k logins" >> /etc/audit/rules.d/audit.rules
#Faillock must be audited  72145
echo "-w /var/run/faillock -p wa -k logins" >> /etc/audit/rules.d/audit.rules
#lastlog must be audited  72147
echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/rules.d/audit.rules
#All uses of the passwd command must be audited.  72149
echo "-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-passwd" >> /etc/audit/rules.d/audit.rules
#All uses of the unix_chkpwd command must be audited.  72151
echo "-a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-passwd" >> /etc/audit/rules.d/audit.rules
#All uses of the gpasswd command must be audited.  72153
echo "-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-passwd" >> /etc/audit/rules.d/audit.rules
#All uses of the chage command must be audited.  72155
echo "-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-passwd" >> /etc/audit/rules.d/audit.rules
#All uses of userhelper must be audited.  72157
echo "-a always,exit -F path=/usr/sbin/userhelper -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-passwd" >> /etc/audit/rules.d/audit.rules
#All uses of the su command must be audited.  72159
echo "-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change" >> /etc/audit/rules.d/audit.rules
#All uses of the sudo command must be audited.  72161
echo "-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change" >> /etc/audit/rules.d/audit.rules
#All privileged function executions must be audited.  72163
echo "-w /etc/sudoers -p wa -k actions" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/sudoers.d/ -p wa -k actions" >> /etc/audit/rules.d/audit.rules
echo "-w /usr/sbin/visudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change" >> /etc/audit/rules.d/audit.rules
#All uses of the newgrp command must be audited.  72165
echo "-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change" >> /etc/audit/rules.d/audit.rules
#All uses of the chsh command must be audited.  72167
echo "-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change" >> /etc/audit/rules.d/audit.rules
#All uses of the sudoedit command must be audited.  72169
echo "-a always,exit -F path=/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change" >> /etc/audit/rules.d/audit.rules
#All uses of the mount command must be audited.  72171
echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k privileged-mount" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b32 -F path=/bin/mount -F auid>=1000 -F auid!=4294967295 -k privileged-mount" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b32 -F path=/usr/bin/mount -F auid>=1000 -F auid!=4294967295 -k privileged-mount" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k privileged-mount" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -F path=/bin/mount -F auid>=1000 -F auid!=4294967295 -k privileged-mount" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -F path=/usr/bin/mount -F auid>=1000 -F auid!=4294967295 -k privileged-mount" >> /etc/audit/rules.d/audit.rules
#All uses of the umount command must be audited.  72173
echo "-a always,exit -F path=/bin/umount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-mount" >> /etc/audit/rules.d/audit.rules
#All uses of the postdrop command must be audited.  72175
echo "-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-postfix" >> /etc/audit/rules.d/audit.rules
#All uses of the postqueue command must be audited.  72177
echo "-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-postfix" >> /etc/audit/rules.d/audit.rules
#All uses of the ssh-keysign command must be audited.  72179
echo "-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-ssh" >> /etc/audit/rules.d/audit.rules
#All uses of the crontab command must be audited.  72183
echo "-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-cron" >> /etc/audit/rules.d/audit.rules
#All uses of the pam_timestamp_check command must be audited  72185
echo "-a always,exit -F path=/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-pam" >> /etc/audit/rules.d/audit.rules
#All uses of the init_module command must be audited  72187
echo "-a always,exit -F arch=b32 -S init_module -k module-change" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S init_module -k module-change" >> /etc/audit/rules.d/audit.rules
#All uses of the delete_module command must be audited 72189
echo "-a always,exit -F arch=b32 -S delete_module -k module-change" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S delete_module -k module-change" >> /etc/audit/rules.d/audit.rules
#All uses of the insmod command must be audited.  72191
echo "-w /sbin/insmod -p x -F auid!=4294967295 -k module-change" >> /etc/audit/rules.d/audit.rules
#All uses of the rmmod command must be audited.  72193
echo "-w /sbin/rmmod-p x -F auid!=4294967295 -k module-change" >> /etc/audit/rules.d/audit.rules
#All uses of the modprobe command must be audited.  72195
echo "-w /sbin/modprobe -p x -F auid!=4294967295 -k module-change" >> /etc/audit/rules.d/audit.rules
#All uses of passwd will be audited.  72197
echo "-w /etc/passwd -p wa -k identity" >> /etc/audit/rules.d/audit.rules
#All uses of the rename command must be audited.  72199
echo "-a always,exit -F arch=b32 -S rename -F perm=x -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S rename -F perm=x -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
#All uses of the renameat command must be audited.  72201
echo "-a always,exit -F arch=b32 -S renameat -F perm=x -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S renameat -F perm=x -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
#All uses of the rmdir command must be audited.  72203
echo "-a always,exit -F arch=b32 -S rmdir -F perm=x -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S rmdir -F perm=x -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
#All uses of the unlink command must be audited.  72205
echo "-a always,exit -F arch=b32 -S unlink -F perm=x -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S unlink -F perm=x -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
#All uses of the unlinkat command must be audited.  72207
echo "-a always,exit -F arch=b32 -S unlinkat -F perm=x -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S unlinkat -F perm=x -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules
#All modifications of group must be audited.  73165
echo "-w /etc/group -p wa -k audit_rules_usergroup_modification" >> /etc/audit/rules.d/audit.rules
#All umodifications of gshadow must be audited.  73167
echo "-w /etc/gshadow -p wa -k identity" >> /etc/audit/rules.d/audit.rules
#All modifications of shadow must be audited.  73171
echo "-w /etc/shadow -p wa -k identity" >> /etc/audit/rules.d/audit.rules
#All modifications of opasswd must be audited.  73173
echo "-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/rules.d/audit.rules
#All uses of the create_module command must be audited  78999
echo "-a always,exit -F arch=b32 -S create_module -k module-change" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S create_module -k module-change" >> /etc/audit/rules.d/audit.rules
#All uses of the finit_module command must be audited  79001
echo "-a always,exit -F arch=b32 -S finit_module -k module-change" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S finit_module -k module-change" >> /etc/audit/rules.d/audit.rules

#Set action for when the storage volume is full  72087
sed -i 's/disk_full_action = SUSPEND/disk_full_action = HALT/' /etc/audit/auditd.conf
#Set log storage to ensure at least a weeks logs are maintained
sed -i 's/max_log_file = 6/max_log_file = 500/' /etc/audit/auditd.conf
sed -i 's/space_left = 75/space_left = 1000/' /etc/audit/auditd.conf
sed -i 's/space_left_action = SYSLOG/space_left_action = ROTATE/' /etc/audit/auditd.conf
sed -i 's/num_logs = 5/num_logs = 6/' /etc/audit/auditd.conf

#Restart auditd
chmod 600 /etc/audit/rules.d/audit.rules
#Ensure /var/log/audit is owned by root and set no more permissive than 750
chown root:root /var/log/audit  && chmod 0750 /var/log/audit
systemctl restart auditd


#Authentication data logging
sed -i 's/daemon.*;mail.*;\\/mail.*;\\/' /etc/rsyslog.d/50-default.conf
echo "daemon.notice /var/log/daemon.log" >> /etc/rsyslog.d/50-default.conf

#Logging of cron data  72051
sed -i 's/#cron.*\t\t\t\/var\/log\/cron.log/cron.*\t\t\t\t\/var\/log\/cron.log/' /etc/rsyslog.d/50-default.conf





#
#SSH Configuration
#

#SSH environment variables cannot be overridden  71957
echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config
#The SSH daemon must not allow compression or must only allow compression after successful authentication.  72267
echo "Compression delayed" >> /etc/ssh/sshd_config
#A FIPS 140-2 approved cryptographic algorithm must be used for SSH communications.  72221
echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr" >> /etc/ssh/sshd_config
#The SSH daemon must be configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms.  72253
echo "MACs hmac-sha2-256,hmac-sha2-512" >> /etc/ssh/sshd_config
#The system must not permit direct logons to the root account using remote access via SSH.  72247
sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
#The SSH daemon must not allow authentication using known hosts authentication.  72249
sed -i 's/#IgnoreUserKnownHosts yes/IgnoreUserKnownHosts yes/' /etc/ssh/sshd_config
#The SSH daemon must not permit Generic Security Service Application Program Interface (GSSAPI) authentication unless needed.  72259
sed -i 's/#GSSAPIAuthentication no/GSSAPIAuthentication no/' /etc/ssh/sshd_config
#The SSH daemon must not permit Kerberos authentication unless needed.  72261
sed -i 's/#KerberosAuthentication no/KerberosAuthentication no/' /etc/ssh/sshd_config
# The operating system must display the Standard Mandatory DoD Notice and Consent Banner until users acknowledge the usage conditions and take explicit actions to log on for further access.  72225
sed -i 's/#Banner \/etc\/issue.net/Banner \/etc\/issue.net/' /etc/ssh/sshd_config
#Timeout ssh sessions after 10 minutes inactivity  72237
echo "ClientAliveInterval 600" >> /etc/ssh/sshd_config
#Terminate session after timeout  72241
echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config

#Disable password based authentication   Left enabled for now.
#sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
#Restart SSH Daemon to enable changes
systemctl restart sshd

#Remove extra grub.cfg file per 72075
rm /usr/share/doc/grub-common/examples/grub.cfg

#Install AV solution 72213
apt install clamav -y -o Acquire::ForceIPv4=true

#Fail2Ban config
apt install fail2ban  -y -o Acquire::ForceIPv4=true
#Create the jail
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
#The operating system must enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period, banning for a week
sed -i 's/findtime  = 600/findtime  = 900/' /etc/fail2ban/jail.local
sed -i 's/maxretry = 5/maxretry = 3/' /etc/fail2ban/jail.local
sed -i 's/bantime  = 600/bantime  = 604800/' /etc/fail2ban/jail.local
 #Restart fail2ban to enable changes
systemctl restart fail2ban

#
#Apparmor installation
#

#apparmor is installed by default, this adds in extra profiles and tools to modify them
apt install apparmor-profiles apparmor-utils  -y -o Acquire::ForceIPv4=true

#
#AIDE (HIDS) installation
#

#Install AIDE  The first two lines assign variables for an uninterrupted install.
debconf-set-selections <<< "postfix postfix/mailname string $NEW_HOSTNAME"
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Local only'"
apt install aide -y -o Acquire::ForceIPv4=true


#Aide config, using more than NORMAL 72069-73
mv /etc/aide/aide.conf /etc/aide/aide.conf.default
touch /etc/aide/aide.conf
echo "# The location of the database to be read." >> /etc/aide/aide.conf
echo "database=file:/var/lib/aide/aide.db" >> /etc/aide/aide.conf
echo "" >> /etc/aide/aide.conf
echo "# The location of the database to be written." >> /etc/aide/aide.conf
echo "database_out=file:/var/lib/aide/aide.db.new" >> /etc/aide/aide.conf
echo "database_new=file:/var/lib/aide/aide.db.new" >> /etc/aide/aide.conf
echo "" >> /etc/aide/aide.conf
echo "gzip_dbout=no" >> /etc/aide/aide.conf
echo "" >> /etc/aide/aide.conf
echo "# Verbose level of message output - Default 5" >> /etc/aide/aide.conf
echo "verbose=5" >> /etc/aide/aide.conf
echo "#Output to a file" >> /etc/aide/aide.conf
echo "report_url=file:/var/log/aide/aide.log" >> /etc/aide/aide.conf
echo "# report_url=stdout" >> /etc/aide/aide.conf
echo "A= p+i+n+u+g+s+m+S+sha512+acl+xattrs" >>/etc/aide/aide.conf
echo "R=p+u+g+s+i+m+c+S+sha512" >> /etc/aide/aide.conf
echo "L=p+u+g" >> /etc/aide/aide.conf
echo ">=p+u+g+i+n+S" >> /etc/aide/aide.conf
echo "NORMAL = A" >> /etc/aide/aide.conf
echo "LOG = p+u+g+i+n+S" >> /etc/aide/aide.conf
echo "DIR = p+u+g+sha256" >> /etc/aide/aide.conf
echo "# Directories/files in the database." >> /etc/aide/aide.conf
echo "/etc	NORMAL" >> /etc/aide/aide.conf
echo "/boot   NORMAL" >> /etc/aide/aide.conf
echo "/bin    NORMAL" >> /etc/aide/aide.conf
echo "/sbin   NORMAL" >> /etc/aide/aide.conf
echo "/lib    NORMAL" >> /etc/aide/aide.conf
echo "/lib64  NORMAL" >> /etc/aide/aide.conf
echo "/opt    NORMAL" >> /etc/aide/aide.conf
echo "/usr    NORMAL" >> /etc/aide/aide.conf
echo "/root   NORMAL" >> /etc/aide/aide.conf
echo "/var    NORMAL" >> /etc/aide/aide.conf
echo "/var/log      LOG" >> /etc/aide/aide.conf
echo "/home   NORMAL" >> /etc/aide/aide.conf
echo "# IGNORE PATHS" >> /etc/aide/aide.conf
echo "!/dev" >> /etc/aide/aide.conf
echo "!/proc" >> /etc/aide/aide.conf
echo "!/var/lock" >> /etc/aide/aide.conf
echo "!/var/run" >> /etc/aide/aide.conf
echo "!/var/spool" >> /etc/aide/aide.conf

#Have AIDE run a report daily.   71975
mkdir /var/log/aide
echo "0 0 * * * /usr/sbin/aide --check > /var/log/aide/`date +%m-%d-%Y`.log" /var/spool/cron/crontabs/root

#
#PSAD installation if intrusion detection is desired
#

#Install PSAD
#apt install psad -y -o Acquire::ForceIPv4=true
#Configure PSAD to ignore IPV6, crash 
#sed -i 's/ALERTING_METHODS            ALL;/ALERTING_METHODS            noemail;/' /etc/psad/psad.conf
#sed -i 's/IPT_SYSLOG_FILE             \/var\/log\/messages;/IPT_SYSLOG_FILE             \/var\/log\/syslog;/' /etc/psad/psad.conf
#sed -i 's/ENABLE_IPV6_DETECTION       Y;/ENABLE_IPV6_DETECTION       N;/' /etc/psad/psad.conf
#sed -i 's/ENABLE_SNORT_SIG_STRICT     Y;/ENABLE_SNORT_SIG_STRICT     N;/' /etc/psad/psad.conf
#sed -i 's/HOSTNAME                    _CHANGEME_;/HOSTNAME                    '"$NEW_HOSTNAME"';/' /etc/psad/psad.conf
#Restart PSAD
#systemctl restart psad




 
#Re-read sysctl entries
sysctl -p
#Remove build essentials package and other unnecessary ones
#apt remove build-essentials wget -y
apt autoremove -o Acquire::ForceIPv4=true
apt autoclean -o Acquire::ForceIPv4=true

#Load the auditd file
auditctl -R /etc/audit/rules.d/audit.rules


#Load the firewall rules
echo "#!/bin/bash" >>  /etc/network/if-up.d/iptables
echo "bash /etc/iptables.rules" >> /etc/network/if-up.d/iptables
chmod +x /etc/network/if-up.d/iptables
bash /etc/iptables.rules

#Load the audit rules  72079
echo "#!/bin/bash" >>  /etc/network/if-up.d/audit
echo "auditctl -R /etc/audit/rules.d/audit.rules" >> /etc/network/if-up.d/audit
chmod +x /etc/network/if-up.d/audit
#Create the initial AIDE configuration
aide --init --config=/etc/aide/aide.conf



#Creating a GRUB password   Password1234
#grub-mkpasswd-pbkdf2
#     Enter in your password, then repeat it.
#The output will be "PBKDF2 hash of your password is grub.pbkdf2.sha512.10000.24C18744342E859F9BA096858347D06B0FC6......"
#vim /etc/grub.d/40_custom
#Insert the following :
#set superusers="root"
#password_pbkdf2 root grub.pbkdf2.sha512.10000.24C18744342E859F9BA096858347D06B0FC6869693A0D6.......
#Set these changes with the following command:
#grub-mkconfig -o /boot/grub/grub.cfg

#grub.pbkdf2.sha512.10000.F5B4D780AF5380386CF167DFD2CDB0256929E8CB076CA8D88D108BB69CC854DCEA2F31E020C4476EE3EE531A9CD0034F1E247C3ECFDAB61D7B42B....7BDD9A96FB471598845514CA

