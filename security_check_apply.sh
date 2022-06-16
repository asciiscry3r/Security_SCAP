#!/usr/bin/env bash

youruser="max"
userlist=('git')

echo "The sudo use_pty tag, when specified, will only execute sudo commands from users logged in to a real tty. This should be enabled by making sure that the use_pty tag exists in /etc/sudoers configuration file or any sudo configuration snippets in /etc/sudoers.d/."

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

if [ -f "/etc/pam.d/common-password" ]; then
    echo "password required pam_pwhistory.so ...existing_options... remember=5"
fi

if [ -f "/etc/pam.d/common-auth" ]; then
    echo "auth required pam_tally2.so onerr=fail silent audit deny=5"
fi

if [ -f "/etc/pam.d/common-account" ]; then
    echo "account required pam_tally2.so"
fi

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
account  required pam_tally2.so
session  required pam_loginuid.so
session  include system-login
EOF
fi

if [ -f "/etc/pam.d/system-auth" ]; then
    cat > /etc/pam.d/system-auth <<-EOF
#%PAM-1.0

auth       required                    pam_faillock.so      preauth
# Optionally use requisite above if you do not want to prompt for the password
# on locked accounts.
-auth      [success=2 default=ignore]  pam_systemd_home.so
auth       [success=1 default=bad]     pam_unix.so          try_first_pass nullok
auth       [default=die]               pam_faillock.so      authfail
auth       optional                    pam_permit.so
auth       required                    pam_env.so
auth       required                    pam_faillock.so      authsucc
auth       required                    pam_tally2.so onerr=fail silent audit deny=5
# If you drop the above call to pam_faillock.so the lock will be done also
# on non-consecutive authentication failures.

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
# useradd defaults file for ArchLinux
# original changes by TomK
GROUP=users
HOME=/home
INACTIVE=30
EXPIRE=
SHELL=/bin/bash
SKEL=/etc/skel
CREATE_MAIL_SPOOL=no
EOF
fi

if [ -f "/etc/login.defs" ]; then
    cat > /etc/login.defs <<-EOF
#
# /etc/login.defs - Configuration control definitions for the login package.
#
# Three items must be defined:  MAIL_DIR, ENV_SUPATH, and ENV_PATH.
# If unspecified, some arbitrary (and possibly incorrect) value will
# be assumed.  All other items are optional - if not specified then
# the described action or option will be inhibited.
#
# Comment lines (lines beginning with "#") and blank lines are ignored.
#
# Modified for Linux.  --marekm

#
# Delay in seconds before being allowed another attempt after a login failure
#
FAIL_DELAY		3

#
# Enable display of unknown usernames when login failures are recorded.
#
LOG_UNKFAIL_ENAB	no

#
# Enable logging of successful logins
#
LOG_OK_LOGINS		no

#
# Enable "syslog" logging of su activity - in addition to sulog file logging.
# SYSLOG_SG_ENAB does the same for newgrp and sg.
#
SYSLOG_SU_ENAB	        yes
SYSLOG_SG_ENAB		yes

#
# If defined, either full pathname of a file containing device names or
# a ":" delimited list of device names.  Root logins will be allowed only
# upon these devices.
#
CONSOLE		/etc/securetty
#CONSOLE	console:tty01:tty02:tty03:tty04

#
# If defined, all su activity is logged to this file.
#
#SULOG_FILE	/var/log/sulog

#
# If defined, file which maps tty line to TERM environment parameter.
# Each line of the file is in a format something like "vt100  tty01".
#
#TTYTYPE_FILE	/etc/ttytype

#
# If defined, the command name to display when running "su -".  For
# example, if this is defined as "su" then a "ps" will display the
# command is "-su".  If not defined, then "ps" would display the
# name of the shell actually being run, e.g. something like "-sh".
#
SU_NAME		su

#
# *REQUIRED*
#   Directory where mailboxes reside, _or_ name of file, relative to the
#   home directory.  If you _do_ define both, MAIL_DIR takes precedence.
#   QMAIL_DIR is for Qmail
#
#QMAIL_DIR	Maildir
MAIL_DIR	/var/spool/mail

#
# If defined, file which inhibits all the usual chatter during the login
# sequence.  If a full pathname, then hushed mode will be enabled if the
# user's name or shell are found in the file.  If not a full pathname, then
# hushed mode will be enabled if the file exists in the user's home directory.
#
HUSHLOGIN_FILE	.hushlogin
#HUSHLOGIN_FILE	/etc/hushlogins

#
# *REQUIRED*  The default PATH settings, for superuser and normal users.
#
# (they are minimal, add the rest in the shell startup files)
ENV_SUPATH	PATH=/usr/local/sbin:/usr/local/bin:/usr/bin
ENV_PATH	PATH=/usr/local/sbin:/usr/local/bin:/usr/bin

#
# Terminal permissions
#
#	TTYGROUP	Login tty will be assigned this group ownership.
#	TTYPERM		Login tty will be set to this permission.
#
# If you have a "write" program which is "setgid" to a special group
# which owns the terminals, define TTYGROUP to the group number and
# TTYPERM to 0620.  Otherwise leave TTYGROUP commented out and assign
# TTYPERM to either 622 or 600.
#
TTYGROUP	tty
TTYPERM		0600

#
# Login configuration initializations:
#
#	ERASECHAR	Terminal ERASE character ('\010' = backspace).
#	KILLCHAR	Terminal KILL character ('\025' = CTRL/U).
#	UMASK		Default "umask" value.
#
# The ERASECHAR and KILLCHAR are used only on System V machines.
# The ULIMIT is used only if the system supports it.
# (now it works with setrlimit too; ulimit is in 512-byte units)
#
# Prefix these values with "0" to get octal, "0x" to get hexadecimal.
#
ERASECHAR	0177
KILLCHAR	025
UMASK		027

#
# Password aging controls:
#
#	PASS_MAX_DAYS	Maximum number of days a password may be used.
#	PASS_MIN_DAYS	Minimum number of days allowed between password changes.
#	PASS_WARN_AGE	Number of days warning given before a password expires.
#
PASS_MAX_DAYS	365
PASS_MIN_DAYS	1
PASS_WARN_AGE	7

#
# Min/max values for automatic uid selection in useradd
#
UID_MIN			 1000
UID_MAX			60000
# System accounts
SYS_UID_MIN		  500
SYS_UID_MAX		  999

#
# Min/max values for automatic gid selection in groupadd
#
GID_MIN			 1000
GID_MAX			60000
# System accounts
SYS_GID_MIN		  500
SYS_GID_MAX		  999

#
# Max number of login retries if password is bad
#
LOGIN_RETRIES		5

#
# Max time in seconds for login
#
LOGIN_TIMEOUT		60

#
# Which fields may be changed by regular users using chfn - use
# any combination of letters "frwh" (full name, room number, work
# phone, home phone).  If not defined, no changes are allowed.
# For backward compatibility, "yes" = "rwh" and "no" = "frwh".
# 
CHFN_RESTRICT		rwh

#
# List of groups to add to the user's supplementary group set
# when logging in on the console (as determined by the CONSOLE
# setting).  Default is none.
#
# Use with caution - it is possible for users to gain permanent
# access to these groups, even when not logged in on the console.
# How to do it is left as an exercise for the reader...
#
#CONSOLE_GROUPS		floppy:audio:cdrom

#
# Should login be allowed if we can't cd to the home directory?
# Default in no.
#
DEFAULT_HOME	yes
HOME_MODE	750
#
# If defined, this command is run when removing a user.
# It should remove any at/cron/print jobs etc. owned by
# the user to be removed (passed as the first argument).
#
#USERDEL_CMD	/usr/sbin/userdel_local

#
# Enable setting of the umask group bits to be the same as owner bits
# (examples: 022 -> 002, 077 -> 007) for non-root users, if the uid is
# the same as gid, and username is the same as the primary group name.
#
# This also enables userdel to remove user groups if no members exist.
#
USERGROUPS_ENAB yes

#
# Controls display of the motd file. This is better handled by pam_motd.so
# so the declaration here is empty is suppress display by readers of this
# file.
#
MOTD_FILE

#
# Hash shadow passwords with SHA512.
#
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

chmod 750 /root/
chmod 750 /home/$youruser/

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

if [ -d "/etc/apparmor.d/" ]; then
    aa-enforce /etc/apparmor.d/*
fi

chown root /boot/grub/grub.cfg
cmod 600 /boot/grub/grub.cfg

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

# options amdgpu reset_method=5
options snd_hda_intel power_save=1
options cfg80211 cfg80211_disable_40mhz_24ghz=1
options mac80211 minstrel_vht_only=1 ieee80211_default_rc_algo=minstrel_ht
options thinkpad_acpi fan_control=1

install dccp /bin/true
install rds /bin/true
install sctp /bin/true
install tipc /bin/true
EOF
fi

chgrp root /etc/group-
chgrp root /etc/gshadow-
chgrp root /etc/passwd-
chgrp shadow /etc/shadow-
chgrp root /etc/group
chgrp shadow /etc/gshadow
chgrp root /etc/passwd
chgrp shadow /etc/shadow
chown root /etc/group-
chown root /etc/passwd-
chown root /etc/shadow-
chown root /etc/group
chown root /etc/gshadow
chown root /etc/passwd
chown root /etc/shadow
chmod 0644 /etc/group-
chmod 0640 /etc/gshadow-
chmod 0644 /etc/passwd-
chmod 0640 /etc/shadow-
chmod 0644 /etc/passwd
chmod 0640 /etc/gshadow
chmod 0644 /etc/passwd
chmod 0640 /etc/shadow
