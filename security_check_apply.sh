#!/usr/bin/env bash

echo "The sudo use_pty tag, when specified, will only execute sudo commands from users logged in to a real tty. This should be enabled by making sure that the use_pty tag exists in /etc/sudoers configuration file or any sudo configuration snippets in /etc/sudoers.d/."

youruser="max"
userlist=('git')

chmod 750 /root/
chmod 750 /home/*/

distroname=`cat /etc/lsb-release | tr -d '"' | tr -s '[:space:]' '\n' | grep -E --text 'DISTRIB_ID=[A-Za-z ]*' |  tr -d 'DISTRIB_ID='`

##############################################################################################################
# UBUNTU #####################################################################################################
##############################################################################################################
if [ $distroname == "Ubuntu" ]; then
    
    if [ -f "/etc/issue" ]; then
	sudo chgrp root /etc/issue
	sudo chown root /etc/issue
	sudo chmod 0644 /etc/issue
    fi

    if [ -f "/etc/issue.net" ]; then
	sudo chgrp root /etc/issue.net
	sudo chown root /etc/issue.net
	sudo chmod 0644 /etc/issue.net
    fi

    if [ -f "/etc/motd" ]; then
	sudo chgrp root /etc/motd
	sudo chown root /etc/motd
	sudo chmod 0644 /etc/motd
    fi

    if [ -f "/etc/pam.d/su" ]; then
	usermod -a -G wheel $youruser
	groupadd sugroup
	cat > /etc/pam.d/su <<-EOF
auth       sufficient pam_rootok.so
# auth       required   pam_wheel.so
# auth       sufficient pam_wheel.so trust
auth       required   pam_wheel.so deny group=nosu
auth       required   pam_wheel.so use_uid group=sugroup
# account    requisite  pam_time.so
session       required   pam_env.so readenv=1
session       required   pam_env.so readenv=1 envfile=/etc/default/locale
session    optional   pam_mail.so nopen
session    required   pam_limits.so
@include common-auth
@include common-account
@include common-session
EOF
    fi

    if [ -f "/etc/pam.d/common-password" ]; then
	cat > /etc/pam.d/common-password <<-EOF
password        requisite   	   	        pam_pwquality.so retry=3
password        required                        pam_pwhistory.so remember=5
password	[success=1 default=ignore]	pam_unix.so obscure sha512
password	requisite			pam_deny.so
password	required			pam_permit.so
EOF
    fi

    if [ -f "/etc/pam.d/common-auth" ]; then
	echo "auth required pam_tally2.so onerr=fail silent audit deny=5"
	cat > /etc/pam.d/common-auth <<-EOF
auth	[success=1 default=ignore]	pam_unix.so nullok
auth	requisite			pam_deny.so
auth	required			pam_permit.so
auth	optional			pam_cap.so 
auth required pam_tally2.so onerr=fail silent audit deny=5
EOF
    fi

    if [ -f "/etc/pam.d/common-account" ]; then
	echo "account required pam_tally2.so"
	cat > /etc/pam.d/common-account <<-EOF
account	[success=1 new_authtok_reqd=done default=ignore]	pam_unix.so 
account	requisite			pam_deny.so
account	required			pam_permit.so
account required                        pam_tally2.so
EOF
    fi

    if [ -f "/etc/default/useradd" ]; then
	cat > /etc/default/useradd <<-EOF
SHELL=/bin/sh
GROUP=100
INACTIVE=30
EXPIRE=
SKEL=/etc/skel
CREATE_MAIL_SPOOL=yes
EOF
    fi

    if [ -f "/etc/login.defs" ]; then
	cat > /etc/login.defs <<-EOF
# Modified for Linux.  --marekm
MAIL_DIR        /var/mail
#MAIL_FILE      .mail
FAILLOG_ENAB		yes
LOG_UNKFAIL_ENAB	no
LOG_OK_LOGINS		no
SYSLOG_SU_ENAB		yes
SYSLOG_SG_ENAB		yes
#SULOG_FILE	/var/log/sulog
#TTYTYPE_FILE	/etc/ttytype
FTMP_FILE	/var/log/btmp
SU_NAME		su
HUSHLOGIN_FILE	.hushlogin
#HUSHLOGIN_FILE	/etc/hushlogins
ENV_SUPATH	PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV_PATH	PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
TTYGROUP	tty
TTYPERM		0600
ERASECHAR	0177
KILLCHAR	025
UMASK		027
PASS_MAX_DAYS	365
PASS_MIN_DAYS	1
PASS_WARN_AGE	7
UID_MIN			 1000
UID_MAX			60000
#SYS_UID_MIN		  100
#SYS_UID_MAX		  999
GID_MIN			 1000
GID_MAX			60000
# System accounts
#SYS_GID_MIN		  100
#SYS_GID_MAX		  999
LOGIN_RETRIES		5
LOGIN_TIMEOUT		60
CHFN_RESTRICT		rwh
DEFAULT_HOME	yes
HOME_MODE	750
#USERDEL_CMD	/usr/sbin/userdel_local
USERGROUPS_ENAB yes
# FAKE_SHELL /bin/fakeshell
#CONSOLE	/etc/consoles
#CONSOLE	console:tty01:tty02:tty03:tty04
#CONSOLE_GROUPS		floppy:audio:cdrom
#MD5_CRYPT_ENAB	no
ENCRYPT_METHOD SHA512
# SHA_CRYPT_MIN_ROUNDS 5000
# SHA_CRYPT_MAX_ROUNDS 5000
#MOTD_FILE
#DIALUPS_CHECK_ENAB
#LASTLOG_ENAB
#MAIL_CHECK_ENAB
#OBSCURE_CHECKS_ENAB
#PORTTIME_CHECKS_ENAB
#SU_WHEEL_ONLY
#CRACKLIB_DICTPATH
#PASS_CHANGE_TRIES
#PASS_ALWAYS_WARN
#ENVIRON_FILE
#NOLOGINS_FILE
#ISSUE_FILE
#PASS_MIN_LEN
#PASS_MAX_LEN
#ULIMIT
#ENV_HZ
#CHFN_AUTH
#CHSH_AUTH
#FAIL_DELAY
# CLOSE_SESSIONS
# LOGIN_STRING
# NO_PASSWORD_CONSOLE
# QMAIL_DIR
EOF
    fi

    if [ -f "/etc/bash.bashrc" ] | [[ `grep -r 'umask 02[0-9]' /etc/bash.bashrc` == "" ]]; then
	echo 'umask 027' >> /etc/bash.bashrc
    fi

    if [ -f "/etc/csh.cshrc" ] | [[ `grep -r 'umask 02[0-9]' /etc/csh.cshrc` == "" ]]; then
	echo 'umask 027' >> /etc/csh.cshrc
    fi

    if [ -f "/etc/profile" ] | [[ `grep -r 'umask 02[0-9]' /etc/profile` == "umask 022" ]]; then
	sed -i 's/umask 022/umask 027/g' /etc/profile
    fi

    if [ -f "/etc/csh.cshrc" ]; then
       if [[ `grep -w 'TMOUT=600' /etc/csh.cshrc` == "" ]]; then
	   echo 'TMOUT=600' >> /etc/csh.cshrc
       fi
    fi

    if [ -f "/etc/csh.login" ]; then
	if [[ `grep -r 'umask 02[0-9]' /etc/csh.login` == "umask 022" ]]; then
	    sed -i 's/umask 022/umask 027/g' /etc/csh.login
	fi					  
    fi

    if [ -f "/etc/securetty" ]; then
	rm -rf /etc/securetty
	touch /etc/securetty
    else
	touch /etc/securetty
    fi

    if [ -d "/etc/apparmor.d/" ]; then
	aa-enforce /etc/apparmor.d/*
    fi

    chown root /boot/grub/grub.cfg
    chmod 0600 /boot/grub/grub.cfg

    if [ -f "/etc/systemd/journald.conf" ]; then
	cat > /etc/systemd/journald.conf <<-EOF
[Journal]
Storage=volatile
Compress=yes
#Seal=yes
#SplitMode=uid
#SyncIntervalSec=5m
#RateLimitIntervalSec=30s
#RateLimitBurst=10000
#SystemMaxUse=
#SystemKeepFree=
#SystemMaxFileSize=
#SystemMaxFiles=100
#RuntimeMaxUse=
#RuntimeKeepFree=
#RuntimeMaxFileSize=
#RuntimeMaxFiles=100
#MaxRetentionSec=
#MaxFileSec=1month
ForwardToSyslog=yes
#ForwardToKMsg=no
#ForwardToConsole=no
#ForwardToWall=yes
#TTYPath=/dev/console
#MaxLevelStore=debug
#MaxLevelSyslog=debug
#MaxLevelKMsg=notice
#MaxLevelConsole=info
#MaxLevelWall=emerg
#LineMax=48K
#ReadKMsg=yes
#Audit=yes
EOF
    fi

    for item in ${userlist[@]}; do
	if id -u $item >/dev/null 2>&1; then
	    sudo usermod -s /sbin/nologin $item
	fi
    done

    if [ -f "/etc/fstab" ] | [[ `grep -w '/tmp' /etc/fstab` == "/tmp" ]] || [[ `grep -w '/dev/shm' /etc/fstab` == "" ]] ; then
	sed -i '/\/tmp/d' /etc/fstab
	sed -i '/\/dev\/shm/d' /etc/fstab
	echo 'tmpfs /dev/shm tmpfs defaults,noatime,nodev,nosuid,mode=1777 0 0' >> /etc/fstab
	echo 'tmpfs /tmp tmpfs defaults,noatime,nodev,nosuid,mode=1777 0 0' >> /etc/fstab
    fi

    if [ -f "rm /etc/hosts.equiv" ]; then
	rm /etc/hosts.equiv
    fi

    chgrp root /etc/group- && chgrp root /etc/gshadow- && chgrp root /etc/passwd- && chgrp shadow /etc/shadow-
    chgrp root /etc/group && chgrp shadow /etc/gshadow && chgrp root /etc/passwd
    chgrp shadow /etc/shadow && chown root /etc/group- && chown root /etc/passwd-
    chown root /etc/shadow- && chown root /etc/group && chown root /etc/gshadow
    chown root /etc/passwd && chown root /etc/shadow && chmod 0644 /etc/group- && chmod 0640 /etc/gshadow-
    chmod 0644 /etc/passwd- && chmod 0640 /etc/shadow- && chmod 0644 /etc/passwd
    chmod 0640 /etc/gshadow && chmod 0644 /etc/passwd && chmod 0640 /etc/shadow
    touch /etc/at.allow && chgrp root /etc/at.allow && chown root /etc/at.allow
    touch /etc/cron.allow && chgrp root /etc/cron.allow && chown root /etc/cron.allow
    chmod 0640 /etc/at.allow && chmod 0640 /etc/cron.allow && chgrp root /etc/cron.d
    chgrp root /etc/cron.daily && chgrp root /etc/cron.hourly && chgrp root /etc/cron.monthly
    chgrp root /etc/cron.weekly && chgrp root /etc/crontab && chown root /etc/cron.d
    chown root /etc/cron.daily && chown root /etc/cron.hourly && chown root /etc/cron.monthly
    chown root /etc/cron.weekly && chown root /etc/crontab && chmod 0700 /etc/cron.d
    chmod 0700 /etc/cron.daily && chmod 0700 /etc/cron.hourly && chmod 0700 /etc/cron.monthly
    chmod 0700 /etc/cron.weekly && chmod 0600 /etc/crontab
    chmod 0600 /etc/ssh/* && chmod 0640 /etc/ssh/*_key && chmod 0644 /etc/ssh/*.pub


#######################

    if [ -f "$pwd/audit.rules" ]; then
	mkdir -p /etc/audit/rules.d/
	cp --remove-destination audit.rules /etc/audit/rules.d/rules.rules
	#   cp $pwd/audit.rules /etc/audit/rules.rules
    fi


##############################################################################################################
# ARCH #######################################################################################################
##############################################################################################################
elif [ $distroname == "Arch" ]; then
 
    if [ -f "/etc/pam.d/passwd" ]; then
	cat > /etc/pam.d/passwd <<-EOF
#%PAM-1.0
password	required	pam_cracklib.so difok=2 minlen=8 dcredit=2 ocredit=2 retry=3
password	required	pam_unix.so sha512 shadow use_authtok
password	required	pam_unix.so sha512 shadow nullok
password        required        pam_pwhistory.so remember=5
EOF
    fi

    if [ -f "/etc/pam.d/systemd-user" ]; then
	cat > /etc/pam.d/systemd-user <<-EOF
# Used by systemd --user instances.

account  include system-login
session  required pam_loginuid.so
session  include system-login
EOF
    fi

    if [ -f "/etc/pam.d/system-auth" ]; then
	cat > /etc/pam.d/system-auth <<-EOF
#%PAM-1.0

auth       required                    pam_faillock.so      preauth
-auth      [success=2 default=ignore]  pam_systemd_home.so
auth       [success=1 default=bad]     pam_unix.so          try_first_pass nullok
auth       [default=die]               pam_faillock.so      authfail
auth       optional                    pam_permit.so
auth       required                    pam_env.so
auth       required                    pam_faillock.so      authsucc
auth       optional                    pam_faillock.so      delay=4000000

-account   [success=1 default=ignore]  pam_systemd_home.so
account    required                    pam_unix.so
account    optional                    pam_permit.so
account    required                    pam_time.so

-password  [success=1 default=ignore]  pam_systemd_home.so
password   required                    pam_unix.so          try_first_pass nullok shadow sha512
password   optional                    pam_permit.so

-session   optional                    pam_systemd_home.so
session    required                    pam_limits.so
session    required                    pam_unix.so
session    optional                    pam_permit.so
EOF
    fi

    if [ -f "/etc/default/useradd" ]; then
	cat > /etc/default/useradd <<-EOF
GROUP=users
HOME=/home
INACTIVE=30
EXPIRE=
SHELL=/bin/sh
SKEL=/etc/skel
CREATE_MAIL_SPOOL=no
EOF
    fi

    if [ -f "/etc/login.defs" ]; then
	cat > /etc/login.defs <<-EOF
# Modified for Linux.  --marekm
FAIL_DELAY		3
LOG_UNKFAIL_ENAB	no
LOG_OK_LOGINS		no
SYSLOG_SU_ENAB	        yes
SYSLOG_SG_ENAB		yes
CONSOLE		/etc/securetty
#CONSOLE	console:tty01:tty02:tty03:tty04
#SULOG_FILE	/var/log/sulog
#TTYTYPE_FILE	/etc/ttytype
SU_NAME		su
#QMAIL_DIR	Maildir
MAIL_DIR	/var/spool/mail
HUSHLOGIN_FILE	.hushlogin
#HUSHLOGIN_FILE	/etc/hushlogins
ENV_SUPATH	PATH=/usr/local/sbin:/usr/local/bin:/usr/bin
ENV_PATH	PATH=/usr/local/sbin:/usr/local/bin:/usr/bin
TTYGROUP	tty
TTYPERM		0600
ERASECHAR	0177
KILLCHAR	025
UMASK		027
PASS_MAX_DAYS	365
PASS_MIN_DAYS	1
PASS_WARN_AGE	7
UID_MIN			 1000
UID_MAX			60000
# System accounts
SYS_UID_MIN		  500
SYS_UID_MAX		  999
GID_MIN			 1000
GID_MAX			60000
# System accounts
SYS_GID_MIN		  500
SYS_GID_MAX		  999
LOGIN_RETRIES		5
LOGIN_TIMEOUT		60
CHFN_RESTRICT		rwh
#CONSOLE_GROUPS		floppy:audio:cdrom
DEFAULT_HOME	yes
HOME_MODE	750
#USERDEL_CMD	/usr/sbin/userdel_local
USERGROUPS_ENAB yes
MOTD_FILE
ENCRYPT_METHOD SHA512
EOF
    fi

    for item in ${userlist[@]}; do
	if id -u $item >/dev/null 2>&1; then
	    sudo usermod -s /sbin/nologin $item
	fi
    done

    if [ -f "/etc/pam.d/su" ]; then
	usermod -a -G wheel $youruser
	groupadd sugroup
	cat > /etc/pam.d/su <<-EOF
#%PAM-1.0
auth            sufficient      pam_rootok.so
auth            required        pam_wheel.so use_uid group=sugroup
auth            required        pam_unix.so
account         required        pam_unix.so
session	        required        pam_unix.so
password        include         system-auth
EOF
    fi

    if [ -f "/etc/bash.bashrc" ] | [[ `grep -r 'umask 02[0-9]' /etc/bash.bashrc` == "" ]]; then
	echo 'umask 027' >> /etc/bash.bashrc
    fi

    if [ -f "/etc/csh.cshrc" ] | [[ `grep -r 'umask 02[0-9]' /etc/csh.cshrc` == "" ]]; then
	echo 'umask 027' >> /etc/csh.cshrc
    fi

    if [ -f "/etc/profile" ] | `grep -r 'umask 02[0-9]' /etc/profile` == "umask 022"; then
	sed -i 's/umask 022/umask 027/g' /etc/profile
    fi

    if [ -f "/etc/csh.cshrc" ] | [[ `grep -w 'TMOUT=600' /etc/profile` == "" ]]; then
	echo 'TMOUT=600' >> /etc/profile
    fi

    if [ -f "/etc/csh.login" ] | `grep -r 'umask 02[0-9]' /etc/csh.login` == "umask 022"; then
	sed -i 's/umask 022/umask 027/g' /etc/csh.login
    fi

    if [ -f "/etc/securetty" ]; then
	rm -rf /etc/securetty
	touch /etc/securetty
    else
	touch /etc/securetty
    fi

    apt update && apt install -y apparmor-notify apparmor-profiles apparmor-profiles-extra apparmor-utils
    
    if [ -d "/etc/apparmor.d/" ]; then
	aa-enforce /etc/apparmor.d/*
    fi

    chown root /boot/grub/grub.cfg
    chmod 0600 /boot/grub/grub.cfg

    if [ -f "/etc/systemd/journald.conf" ]; then
	cat > /etc/systemd/journald.conf <<-EOF
[Journal]
Storage=volatile
Compress=yes
#Seal=yes
#SplitMode=uid
#SyncIntervalSec=5m
#RateLimitIntervalSec=30s
#RateLimitBurst=10000
#SystemMaxUse=
#SystemKeepFree=
#SystemMaxFileSize=
#SystemMaxFiles=100
#RuntimeMaxUse=
#RuntimeKeepFree=
#RuntimeMaxFileSize=
#RuntimeMaxFiles=100
#MaxRetentionSec=
#MaxFileSec=1month
ForwardToSyslog=yes
#ForwardToKMsg=no
#ForwardToConsole=no
#ForwardToWall=yes
#TTYPath=/dev/console
#MaxLevelStore=debug
#MaxLevelSyslog=debug
#MaxLevelKMsg=notice
#MaxLevelConsole=info
#MaxLevelWall=emerg
#LineMax=48K
#ReadKMsg=yes
#Audit=yes
EOF
    fi

    if [ -f "/etc/modprobe.d/settings.conf" ] || [ `cat /etc/hostname` == "mksthinkpad" ]; then
	cat > /etc/modprobe.d/settings.conf <<-EOF
blacklist pcspkr
blacklist bluetooth
blacklist kvm
blacklist kvm_intel
blacklist kvm_amd

# options amdgpu reset_method=5
options snd_hda_intel power_save=1
options cfg80211 cfg80211_disable_40mhz_24ghz=1
options mac80211 minstrel_vht_only=1 ieee80211_default_rc_algo=minstrel_ht
options thinkpad_acpi fan_control=1

install dccp /bin/true
install rds /bin/true
install sctp /bin/true
install tipc /bin/true
install cramfs /bin/true
install freevxfs /bin/true
install hfs /bin/true
install hfsplus /bin/true
install jffs2 /bin/true
install udf /bin/true
EOF
    fi

    if [ -f "/etc/fstab" ] | [[ `grep -w '/tmp' /etc/fstab` == "/tmp" ]] || [[ `grep -w '/dev/shm' /etc/fstab` == "" ]] ; then
	sed -i '/\/tmp/d' /etc/fstab
	sed -i '/\/dev\/shm/d' /etc/fstab
	echo 'tmpfs /dev/shm tmpfs defaults,noatime,nodev,nosuid,mode=1777 0 0' >> /etc/fstab
	echo 'tmpfs /tmp tmpfs defaults,noatime,nodev,nosuid,mode=1777 0 0' >> /etc/fstab
    fi

    if [ -f "rm /etc/hosts.equiv" ]; then
	rm /etc/hosts.equiv
    fi

    chgrp root /etc/group- && chgrp root /etc/gshadow- && chgrp root /etc/passwd- && chgrp shadow /etc/shadow-
    chgrp root /etc/group && chgrp shadow /etc/gshadow && chgrp root /etc/passwd
    chgrp shadow /etc/shadow && chown root /etc/group- && chown root /etc/passwd-
    chown root /etc/shadow- && chown root /etc/group && chown root /etc/gshadow
    chown root /etc/passwd && chown root /etc/shadow && chmod 0644 /etc/group- && chmod 0640 /etc/gshadow-
    chmod 0644 /etc/passwd- && chmod 0640 /etc/shadow- && chmod 0644 /etc/passwd
    chmod 0640 /etc/gshadow && chmod 0644 /etc/passwd && chmod 0640 /etc/shadow
    touch /etc/at.allow && chgrp root /etc/at.allow && chown root /etc/at.allow
    touch /etc/cron.allow && chgrp root /etc/cron.allow && chown root /etc/cron.allow
    chmod 0640 /etc/at.allow && chmod 0640 /etc/cron.allow && chgrp root /etc/cron.d
    chgrp root /etc/cron.daily && chgrp root /etc/cron.hourly && chgrp root /etc/cron.monthly
    chgrp root /etc/cron.weekly && chgrp root /etc/crontab && chown root /etc/cron.d
    chown root /etc/cron.daily && chown root /etc/cron.hourly && chown root /etc/cron.monthly
    chown root /etc/cron.weekly && chown root /etc/crontab && chmod 0700 /etc/cron.d
    chmod 0700 /etc/cron.daily && chmod 0700 /etc/cron.hourly && chmod 0700 /etc/cron.monthly
    chmod 0700 /etc/cron.weekly && chmod 0600 /etc/crontab
    chmod 0600 /etc/ssh/* && chmod 0640 /etc/ssh/*_key && chmod 0644 /etc/ssh/*.pub


#######################

    if [ -f "$pwd/audit.rules" ]; then
	mkdir -p /etc/audit/rules.d/
	cp --remove-destination audit.rules /etc/audit/rules.d/rules.rules
	#   cp $pwd/audit.rules /etc/audit/rules.rules
    fi

else
    echo "Not supported by this script. But you can copy some commands"
fi
