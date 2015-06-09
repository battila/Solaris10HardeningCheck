#!/bin/bash

Solaris10Release=`awk '/Solaris/ {print $4}' /etc/release`

normal=$(tput sgr0)
red="\e[1;31m"
green="\e[1;32m"
gray="\e[1;30m"
blue="\e[1;34m"

checkService(){
        printf "\t%-70s" "$1"
        output=`svcs -Ho state $2 2>/dev/null`
        if [ -z "$output" ] || [ "$output" = "disabled" ]; then
                printf "\t\t\t${green}OK${normal}\n"
        else
                printf "\t\t\t${red}FAILED${normal}\n"
                printf "\t\tRemediation: ${blue}svcadm disable $2${normal}\n"
        fi
}


CheckUnnecessaryLocalServices() {
        printf "\n2 Restrict Services\n\n"
        printf "  2.1 Disable Unnecessary Local Services\n"

        checkService "2.1.1 Disable Local CDE ToolTalk Database Server" "svc:/network/rpc/cde-ttdbserver:tcp"
        checkService "2.1.2 Disable Local CDE Calendar Manager" "svc:/network/rpc/cde-calendar-manager:default"
        checkService "2.1.3 Disable Local Graphical Login Environment" "svc:/application/graphical-login/cde-login"
        checkService "2.1.4 Disable Local sendmail Service" "svc:/network/smtp:sendmail"
        checkService "2.1.5 Disable Local Web Console" "svc:/system/webconsole:console"
        checkService "2.1.6 Disable Local WBEM" "svc:/application/management/wbem"
        checkService "2.1.7 Disable Local BSD Print Protocol Adapter" "svc:/application/print/rfc1179"
        printf "  2.2 Disable Other Services\n"
        checkService "2.2.1 Disable RPC Encryption Key" "svc:/network/rpc/keyserv"
        checkService "2.2.2 Disable NIS Server Daemons: server" "svc:/network/nis/server"
        checkService "2.2.2 Disable NIS Server Daemons: passwd" "svc:/network/nis/passwd"
        checkService "2.2.2 Disable NIS Server Daemons: update" "svc:/network/nis/update"
        checkService "2.2.2 Disable NIS Server Daemons: xfr" "svc:/network/nis/xfr"
        checkService "2.2.3 Disable NIS Client Daemons" "svc:/network/nis/client"
        checkService "2.2.4 Disable NIS+ Daemons" "svc:/network/rpc/nisplus"
        checkService "2.2.5 Disable LDAP Cache Manager" "svc:/network/ldap/client"
        checkService "2.2.6 Disable Kerberos TGT Expiration Warning" "svc:/network/security/ktkt_warn"
        checkService "2.2.7 Disable Generic Security Services (GSS) Daemons" "svc:/network/rpc/gss"
        checkService "2.2.8 Disable Volume Manager: volfs" "svc:/system/filesystem/volfs"
        checkService "2.2.8 Disable Volume Manager: smserver" "svc:/network/rpc/smserver"

        # if version is < 11/06
        # # pgrep smbd # ls -l /etc/sfw/smb.conf /etc/sfw/smb.conf: No such file or directory
        # Remediation: # /etc/init.d/samba stop # mv /etc/sfw/smb.conf /etc/sfw/smb.conf.CIS
        # else:

        checkService "2.2.9 Disable Samba Support" "svc:/network/samba"
        checkService "2.2.10 Disable automount Daemon" "svc:/system/filesystem/autofs"
        checkService "2.2.11 Disable Apache Services" "svc:/network/http:apache2"
        checkService "2.2.12 Disable Solaris Volume Manager Services: metainit" "svc:/system/metainit"
        checkService "2.2.12 Disable Solaris Volume Manager Services: mdmonitor" "svc:/system/mdmonitor"

        # if version is < 11/06
        # checkService "Check Solaris Volume Manager Services: mpxio-upgrade" "svc:/platform/sun4u/mpxio-upgrade"
        # else: 
        checkService "2.2.12 Check Solaris Volume Manager Services: mpxio-upgrade" "svc:/system/device/mpxio-upgrade"

        checkService "2.2.13 Disable Solaris Volume Manager GUI: mdcomm" "svc:/network/rpc/mdcomm"
        checkService "2.2.13 Disable Solaris Volume Manager GUI: meta" "svc:/network/rpc/meta"
        checkService "2.2.13 Disable Solaris Volume Manager GUI: metamed" "svc:/network/rpc/metamed"
        checkService "2.2.13 Disable Solaris Volume Manager GUI: metamh" "svc:/network/rpc/metamh"
        

        # If you want to restrict access to this service, but not disable it completely, consider using a
        # host-based firewall such as ipfilter(5) to control what hosts are allowed to access this daemon.
        # Alternatively, TCP Wrappers support can be enabled in the daemon with the commands:
        # # svccfg -s svc:/network/rpc/bind setprop \ config/enable_tcpwrappers = true # svcadm refresh rpc/bind
        checkService "2.2.14 Disable Local RPC Port Mapping Service" "svc:/network/rpc/bind"

        printf "  2.3 Establish a Secure Baseline\n"
        printf "\t\t\t${gray}Missing${normal}\n"

}

CheckTCPWrappers() {
	printf "  2.4 Configure TCP Wrappers\n"
	printf "\t%-70s" "Verify TCP Wrappers default"
	output=`inetadm -p |awk -F= '/tcp_wrappers/ {print $2}'`
	if [ "$output" = "FALSE" ]; then
		printf "\t\t\t${red}FAILED${normal}\n"
		printf "\t\tRemediation: ${blue}svccfg -s svc:/network/rpc/bind setprop config/enable_tcpwrappers=true${normal}\n"
		printf "\t\tRemediation: ${blue}svcadm refresh rpc/bind${normal}\n"
	fi

	printf "\t%-70s" "Checking TCP Wrappers: /etc/hosts.allow"
	if [ -f /etc/hosts.allow ]; then
		printf "\t\t\t${green}OK${normal}\n"
	else
		printf "\t\t\t${red}FAILED${normal}\n"
		printf "\t\tRemediation: ${blue}echo \"ALL: <net>/<mask>, <net>/<mask>, ...\" > /etc/hosts.allow${normal}\n"
	fi

	printf "\t%-70s" "Checking TCP Wrappers: /etc/hosts.deny"
	if [ -f /etc/hosts.deny ]; then
		printf "\t\t\t${green}OK${normal}\n"
	else
		printf "\t\t\t${red}FAILED${normal}\n"
		printf "\t\tRemediation: ${blue}echo \"ALL: ALL\" >/etc/hosts.deny${normal}\n"
	fi
}

CheckNDD(){

	printf "\t%-70s" "$1"

	PROTO=${2:0:2}
	if [ $PROTO = "tc" ]; then
		DEVICE="/dev/tcp"
	elif [ $PROTO = "ip" ]; then
		DEVICE="/dev/ip"
	elif [ $PROTO = "ar" ]; then
		DEVICE="/dev/arp"
	else
		return -1
	fi

	if [ -z $4 ]; then
		REMEDIATION="Remediation: ${blue}ndd -set $DEVICE $2 $3${normal}"
	else
		REMEDIATION=$4
	fi

    output=`pfexec ndd -get $DEVICE $2 2>/dev/null`
    if [[ "${output}" -eq $3 ]]; then
            printf "\t\t\t${green}OK${normal}\n"
    else
            printf "\t\t\t${red}FAILED${normal}\n"
            printf "\t\t${gray}Expected: $3, got: ${output}${normal}\n"
            # printf "\t\tRemediation: ${blue}ndd -set $DEVICE $REMEDIATION $2${normal}\n"
            printf "\t\t$REMEDIATION\n"
            printf "\t\tAdd it to ${blue}/lib/svc/method/net-routing-setup${normal}\n"
            return -1
    fi

}


KernelTuning() {
	# Source Packet Forwarding
	CheckNDD "3.1.2 IPv4 Source Packet Forwarding" "ip_forward_src_routed" 0
	CheckNDD "3.1.2 IPv6 Source Packet Forwarding" "ip6_forward_src_routed" 0
	CheckNDD "3.1.3 Broadcast Packet Forwarding" "ip_forward_directed_broadcasts" 0
	CheckNDD "3.1.4 Response to ICMP Timestamp Requests" "ip_respond_to_timestamp" 0
	CheckNDD "3.1.5 Response to ICMP Broadcast Timestamp Requests" "ip_respond_to_timestamp_broadcast" 0
	CheckNDD "3.1.6 Response to ICMP Netmask Requests" "ip_respond_to_address_mask_broadcast" 0
	CheckNDD "3.1.7 ICMPv6 Redirect Messages" "ip6_send_redirects" 0
	CheckNDD "3.1.8 Response to Broadcast ICMPv4 Echo Request" "ip_respond_to_echo_broadcast" 0
	CheckNDD "3.1.9 IPv4 Response to Multicast Echo Request" "ip_respond_to_echo_multicast" 0
	CheckNDD "3.1.9 IPv6 Response to Multicast Echo Request" "ip6_respond_to_echo_multicast" 0
	CheckNDD "3.1.10 Interval for Scanning IRE_CACHE" "ip_ire_arp_interval" 60000
	CheckNDD "3.1.11 IPv4 Ignore ICMP Redirect Messages" "ip_ignore_redirect" 1
	CheckNDD "3.1.11 IPv6 Ignore ICMP Redirect Messages" "ip6_ignore_redirect" 1
	CheckNDD "3.1.12 IPv4 Strict Multihoming" "ip_strict_dst_multihoming" 1
	CheckNDD "3.1.12 IPv6 Strict Multihoming" "ip6_strict_dst_multihoming" 1
	CheckNDD "3.1.13 ICMPv4 Redirect Messages" "ip_send_redirects" 0
	CheckNDD "3.1.14 ARP Cleanup Interval" "arp_cleanup_interval" 60000
	CheckNDD "3.1.15 TCP Reverse IP Source Routing" "tcp_rev_src_routes" 0
	CheckNDD "3.1.16 Maximum Number of Half-open TCP Connections" "tcp_conn_req_max_q0" 4096
	CheckNDD "3.1.17 Maximum Number of Incoming Connections" "tcp_conn_req_max_q" 1024
	
	printf "\t%-70s" "3.1.18 Lock down dtspcd" 
	printf "\t\t\t${gray}Not Implemented${normal}\n"
	# Lock down dtspcd(8)
	# CheckNDD "tcp_extra_priv_ports" 6112 "tcp_extra_priv_ports_add"
}

CheckCoreDump() {
	printf "\n  %-70s" "3.2 Restrict Core Dumps to Protected Directory"
	# printf  "Restrict Core Dumps to Protected Directory"
	output=`pfexec coreadm | awk -F: '/global core file pattern/ {print $2}'`

	# remove white space
	output="$(echo -e "${output}" | tr -d '[[:space:]]')"

    if [ -z "$output" ]; then
        printf "\t\t\t${red}FAILED${normal}\n"
        printf "\tRemediation:\n\t\t${blue}mkdir -p /var/cores && chown root:root /var/cores && chmod 700 /var/cores\n\t\t"
cat <<EOF
coreadm -g /var/cores/core_%n_%f_%u_%g_%t_%p -e log -e global -e global-setid -d process -d proc-setid
EOF
		printf "${normal}\n"
    else
    	printf "\t\t\t${green}OK${normal}\n"    
    fi
}

StackProtection() {
	printf "  %-70s" "3.3 Check Stack Protection"
	output=`grep "^set noexec_user_stack=1" /etc/system`
	if [ -z "$output" ]; then
		printf "\t\t\t${red}FAILED${normal}\n"
		printf "\tRemediation:\n\t\tAdd ${blue}set noexec_user_stack=1${normal} to the /etc/system\n"
	fi
	output=`grep "^set noexec_user_stack_log=1" /etc/system`
	if [ -z "$output" ]; then
		printf "\t\tAdd ${blue}set noexec_user_stack_log=1${normal} to the /etc/system\n"
	fi
}

CheckTCPSequenceNumbergeneration() {
	printf "\n  %-70s" "3.4 Check Strong TCP Sequence Number Generation"
	output=`pfexec ndd -get /dev/tcp tcp_strong_iss 2>/dev/null`
    if [[ "${output}" -eq 2 ]]; then
        printf "\t\t\t${green}OK${normal}\n"
    else
        printf "\t\t\t${red}FAILED${normal}\n"
        printf "\t${gray}Expected: 2, got: ${output}${normal}\n"
        # printf "\t\tRemediation: ${blue}ndd -set $DEVICE $REMEDIATION $2${normal}\n"
        printf "\tREMEDIATION\n"
        printf "\t\t${blue}perl -pi -e  's/TCP_STRONG_ISS=.*/TCP_STRONG_ISS=2/' /etc/default/inetinit${normal}\n"
    fi
# CheckNDD "3.4 Check Strong TCP Sequence Number Generation" "tcp_strong_iss" 2
}

CheckRouting() {
	printf "\n  %-70s" "3.5 Network Routing"
	output=`routeadm -p | egrep "^ipv[46]-routing |^ipv[46]-forwarding" |grep enabled|awk '{ printf("%s %s\n", $1, $NF); }'`
	if [ -z "$output" ]; then
		printf "\t\t\t${green}OK${normal}\n"
	else
        printf "\t\t\t${red}FAILED${normal}\n"
        printf "\t\t${gray}Got: ${output}${normal}\n"
        # printf "\t\tRemediation: ${blue}ndd -set $DEVICE $REMEDIATION $2${normal}\n"
        printf "\t\t$REMEDIATION\n"
        printf "\t\t${blue}routeadm -d ipv4-forwarding -d ipv6-forwarding${normal}\n"
        printf "\t\t${blue}routeadm -d ipv4-routing -d ipv6-routing${normal}\n"
        printf "\t\t${blue}routeadm -u${normal}\n"
    fi
}

CheckInetdConnectionLogging() {
	
	printf "  %-70s" "4.1 Check inetd Connection Logging"
	output=`svcprop -p defaults/tcp_trace svc:/network/inetd:default`

	if [ "$output" = "false" ]; then
		printf "\t\t\t${red}FAILED${normal}\n"
        printf "\tREMEDIATION\n"
        printf "\t\t${blue}inetadm -M tcp_trace=true${normal}\n"
        printf "\t\t${blue}svcadm refresh svc:/network/inetd${normal}\n"
	else
		printf "\t\t\t${green}OK${normal}\n"
	fi

}

CheckFTPdaemonLogging() {
	# We have no FTP service
	printf "  %-70s" "4.2 FTP daemon Logging"
	printf "\t\t\t${gray}OK${normal}\n"
}

CheckDebugLevelDaemonLogging() {
	printf "  %-70s" "4.3 Check Debug Level Daemon Logging"

	output=`svcs -Ho state svc:/system/system-log`
	if [ "$output" = "onlie" ]; then
		output=`grep -v "^#" /etc/syslog.conf | grep /var/log/connlog`
		if [ -z "$output" ]; then
			printf "\t\t\t${red}FAILED${normal}\n"
		else
			printf "\t\t\t${green}OK${normal}\n"
		fi
	else
		printf "\t\t\t${red}FAILED${normal}\n"
	fi

}

CapturesyslogAUTHMessages() {
	printf "  %-70s" "4.4 Capture syslog AUTH Messages"
	output=`svcs -Ho state svc:/system/system-log`
	if [ "$output" = "onlie" ]; then
		output=`grep -v "^#" /etc/syslog.conf | grep /var/log/authlog`
		if [ -z "$output" ]; then
			printf "\t\t\t${red}FAILED${normal}\n"
		else
			printf "\t\t\t${green}OK${normal}\n"
		fi
	else
		printf "\t\t\t${red}FAILED${normal}\n"
	fi
}



EnableLoginRecords() {
	printf "  %-70s" "4.5 Enable Login Records"
	if [ -f  "/var/adm/loginlog" ]; then
		grep loginlog /etc/logadm.conf >/dev/null
		if [ $? -eq 0]; then
			printf "\t\t\t${green}OK${normal}\n"
		else
			printf "\t\t\t${red}FAILED${normal}\n"
			printf "\tREMEDIATION\n"
        	printf "\t\t${blue}logadm -w loginlog -C 13 /var/adm/loginlog${normal}\n"
		fi	
	else
		printf "\t\t\t${red}FAILED${normal}\n"
		printf "\tREMEDIATION\n"
		printf "\t\t${blue}touch /var/adm/loginlog${normal}\n"
		printf "\t\t${blue}chown root:sys /var/adm/loginlog${normal}\n"
		printf "\t\t${blue}chmod 600 /var/adm/loginlog${normal}\n"
    	printf "\t\t${blue}logadm -w loginlog -C 13 /var/adm/loginlog${normal}\n"
	fi

}

CaptureAllFailedLoginAttempts() {
	printf "  %-70s" "4.6 Capture All Failed Login Attempts"
	grep "^SYSLOG_FAILED_LOGINS=0" /etc/default/login >/dev/null
	if [ $? -eq 0 ]; then
		printf "\t\t\t${green}OK${normal}\n"
	else
		printf "\t\t\t${red}FAILED${normal}\n"
		printf "\tREMEDIATION\n"
		printf "\t\t${blue}perl -pi -e 's/.*SYSLOG_FAILED_LOGINS=.*/SYSLOG_FAILED_LOGINS=0/' /etc/default/login${normal}\n"
		# printf "\t\t${blue}echo \"SYSLOG_FAILED_LOGINS=0\" >> /etc/default/login${normal}\n"
	fi

}

EnableCronLogging() {
	printf "  %-70s" "4.7 Enable cron Logging"
	if [ -f  "/var/cron/log" ]; then
		grep "^CRONLOG=YES" /etc/default/cron >/dev/null
		if [ $? -eq 0 ]; then
			printf "\t\t\t${green}OK${normal}\n"
		else
			printf "\t\t\t${red}FAILED${normal}\n"
			printf "\tREMEDIATION\n"
        	printf "\t\t${blue}perl -pi -e 's/.*CRONLOG=.*/CRONLOG=YES/' /etc/default/cron${normal}\n"
		fi	
	else
		printf "\t\t\t${red}FAILED${normal}\n"
		printf "\tREMEDIATION\n"
		printf "\t\t${blue}touch /var/cron/log && chown root:root /var/cron/log && chmod go-rwx /var/cron/log${normal}\n"
    	printf "\t\t${blue}perl -pi -e 's/.*CRONLOG=.*/CRONLOG=YES/' /etc/default/cron${normal}\n"
    	printf "\t\t${blue}pkgchk -f -n -p /etc/default/cron${normal}\n"
	fi
}

EnableSystemAccounting() {
	printf "  %-70s" "4.8 Enable System Accounting"
	output=`svcs -Ho state svc:/system/sar 2>/dev/null`
	if [ "$output" = "onlie" ]; then
		if [ find /var/adm/sa -type f -mmin -$((60)) ]; then
		# if [ "$(ls -A /var/adm/sa)" ]; then
			printf "\t\t\t${green}OK${normal}\n"
		else
    		printf "\t\t\t${red}FAILED${normal}\n"
		fi
	else
		printf "\t\t\t${red}FAILED${normal}\n"
	fi
}

EnableKernelLevelAuditing() {
	printf "  %-70s" "4.9 Check Enable Kernel Level Auditing"
  output=`modinfo | grep c2audit`
  if [ "$output" = "" ]; then
    printf "\t\t\t${red}FAILED${normal}\n"
  else
    printf "\t\t\t${green}OK${normal}\n"
  fi
}

CheckCMASK() {
  printf "  %-70s" "5.1 Check Set daemon umask"
  output=`grep "^CMASK=022" /etc/default/init`
  if [ "$output" = "CMASK=022" ]; then
    printf "\t\t\t${green}OK${normal}\n"
  else
    printf "\t\t\t${red}FAILED${normal}\n"
  fi
}

CheckUserMountedDevices() {
  printf "  %-70s" "5.2 Check Restrict Set-UID on User Mounted Devices (Scored)"
  output=`grep -v "^#" /etc/rmmount.conf | grep -- "-o nosuid"`
  if [ "$output" = "mount * hsfs udfs ufs -o nosuid" ]; then
    printf "\t\t\t${green}OK${normal}\n"
  else
    printf "\t\t\t${red}FAILED${normal}\n"
  fi
}

CheckStickyBit() {
  printf "  %-70s" "5.3 Check Set Sticky Bit on World Writable Directories (Not Scored)"
  output=`pfexec find / \( -fstype nfs -o -fstype cachefs -o -fstype autofs -o -fstype ctfs -o -fstype mntfs -o -fstype objfs -o -fstype proc \) -prune -o -type d  \( -perm -0002 -a ! -perm -1000 \) -print`
  if [ "$output" = "" ]; then
    printf "\t\t\t${green}OK${normal}\n"
  else
    printf "\t\t\t${red}FAILED${normal}\n"
  fi
}

CheckConfigureSSH() {
  printf "  %-70s\n" "6.1 Configure SSH (Not Scored)"
  printf "  \t%-70s" "6.1.1 Configure SSH (Not Scored)"
  printf "\t\t\t${gray}Not Implemented${normal}\n"
}

CheckConfigureSSHProto2() {
  printf "  \t%-70s" "6.1.2 Check Set SSH Protocol to 2 (Scored)"
  output=`grep -v "^#" /etc/ssh/sshd_config | grep "^Protocol"`
  if [ "$output" = "Protocol 2" ]; then
    printf "\t\t\t${green}OK${normal}\n"
  else
    printf "\t\t\t${red}FAILED${normal}\n"
  fi
}

CheckConfigureSSHDisX() {
  printf "  \t%-70s" "6.1.3 Check Disable SSH X11Forwarding (Scored)"
  output=`grep -v "^#" /etc/ssh/sshd_config | grep "^X11Forwarding"`
  if [ "$output" = "X11Forwarding no" ]; then
    printf "\t\t\t${green}OK${normal}\n"
  else
    printf "\t\t\t${red}FAILED${normal}\n"
  fi
}

CheckConfigureSSHMaxAuthTry() {
  printf "  \t%-70s" "6.1.4 Check Set SSH MaxAuthTries to 3 (Scored)"
  output=`grep -v "^#" /etc/ssh/sshd_config | grep "^MaxAuthTries"`
  if [ "$output" = "MaxAuthTries 3" ]; then
    printf "\t\t\t${green}OK${normal}\n"
  else
    printf "\t\t\t${red}FAILED${normal}\n"
  fi
}

CheckConfigureSSHMaxAuthTryLog() {
  printf "  \t%-70s" "6.1.5 Check Set SSH MaxAuthTriesLog to 0 (Scored)"
  output=`grep -v "^#" /etc/ssh/sshd_config | grep "^MaxAuthTriesLog"`
  if [ "$output" = "MaxAuthTriesLog 0" ]; then
    printf "\t\t\t${green}OK${normal}\n"
  else
    printf "\t\t\t${red}FAILED${normal}\n"
  fi
}

CheckConfigureSSHIgnoreRhosts() {
  printf "  \t%-70s" "6.1.6 Check Set SSH IgnoreRhosts to yes (Scored)"
  output=`grep -v "^#" /etc/ssh/sshd_config | grep "^IgnoreRhosts"`
  if [ "$output" = "IgnoreRhosts yes" ]; then
    printf "\t\t\t${green}OK${normal}\n"
  else
    printf "\t\t\t${red}FAILED${normal}\n"
  fi
}

CheckConfigureSSHRhostsAuthentication() {
  printf "  \t%-70s" "6.1.7 Check Set SSH RhostsAuthentication to no (Scored)"
  output=`grep -v "^#" /etc/ssh/sshd_config | grep "^RhostsAuthentication"`
  if [ "$output" = "RhostsAuthentication no" ]; then
    printf "\t\t\t${green}OK${normal}\n"
  else
    printf "\t\t\t${red}FAILED${normal}\n"
  fi
}

CheckConfigureSSHRhostsRSAAuthentication() {
  printf "  \t%-70s" "6.1.8 Check Set SSH RhostsRSAAuthentication to no (Scored)"
  output=`grep -v "^#" /etc/ssh/sshd_config | grep "^RhostsRSAAuthentication"`
  if [ "$output" = "RhostsRSAAuthentication no" ]; then
    printf "\t\t\t${green}OK${normal}\n"
  else
    printf "\t\t\t${red}FAILED${normal}\n"
  fi
}

CheckConfigureSSHrootLogin() {
  printf "  \t%-70s" "6.1.9 Check Disable SSH root login (Scored)"
  output=`grep -v "^#" /etc/ssh/sshd_config | grep "^PermitRootLogin"`
  if [ "$output" = "PermitRootLogin no" ]; then
    printf "\t\t\t${green}OK${normal}\n"
  else
    printf "\t\t\t${red}FAILED${normal}\n"
  fi
}

CheckConfigureSSHPermitEmptyPasswords() {
  printf "  \t%-70s" "6.1.10 Check Set SSH PermitEmptyPasswords to no (Scored)"
  output=`grep -v "^#" /etc/ssh/sshd_config | grep "^PermitEmptyPasswords"`
  if [ "$output" = "PermitEmptyPasswords no" ]; then
    printf "\t\t\t${green}OK${normal}\n"
  else
    printf "\t\t\t${red}FAILED${normal}\n"
  fi
}

CheckConfigureSSHBanner() {
  printf "  \t%-70s" "6.1.11 Set SSH Banner (Scored)"
  output=`grep -v "^#" /etc/ssh/sshd_config | grep "^Banner"`
  if [ "$output" = "Banner /etc/issue" ]; then
    printf "\t\t\t${green}OK${normal}\n"
  else
    printf "\t\t\t${red}FAILED${normal}\n"
  fi
}

CheckDisableLogin() {
  printf "  %-70s" "6.2 Check Disable login: Prompts on Serial Ports (Scored)"
  output=`pmadm -L | awk -F: '($4 == "ux") { print $3 }'`
  if [ "$output" = "ttya" ]; then
    printf "\t\t\t${green}OK${normal}\n"
  else
    printf "\t\t\t${red}FAILED${normal}\n"
  fi
}

CheckDisablenobodyAccess4RPCEncKeys() {
  printf "  %-70s" "6.3 Disable \"nobody\" Access for RPC Encryption Key Storage Service (Scored)"
  output=`grep "^ENABLE_NOBODY_KEYS=NO" /etc/default/keyserv`
  if [ "$output" = "ENABLE_NOBODY_KEYS=NO" ]; then
    printf "\t\t\t${green}OK${normal}\n"
  else
    printf "\t\t\t${red}FAILED${normal}\n"
  fi
}

CheckDisableRhostsSupportInPam() {
  printf "  %-70s" "6.4 Check Disable .rhosts Support in /etc/pam.conf (Scored)"
  output=`grep "pam_rhosts_auth" /etc/pam.conf |grep -v "^#"`
  if [ "$output" = "" ]; then
    printf "\t\t\t${green}OK${normal}\n"
  else
    printf "\t\t\t${red}FAILED${normal}\n"
  fi
}

CheckRestrcikFTPUse() {
  printf "  %-70s" "6.5 Check Restrict FTP Use (Scored)"
  for user in `getent passwd |awk -F: '{ print $1 }'`; do
    grep -w \"${user}\" /etc/ftpd/ftpusers >/dev/null 2>&1;
    if [ $? != 0 ]; then
      printf "\t\t\t${red}FAILED${normal}\n"
      return
    fi;
  done
  printf "\t\t\t${green}OK${normal}\n"
}

CheckSetDelaybwFailedLoginAttempts() {
  printf "  %-70s" "6.6 Set Delay between Failed Login Attempts to 4 (Scored)"
  output=`grep "^SLEEPTIME=4" /etc/default/login`
  if [ "$output" = "SLEEPTIME=4" ]; then
    printf "\t\t\t${green}OK${normal}\n"
  else
    printf "\t\t\t${red}FAILED${normal}\n"
  fi
}

CheckSetDefaulCDESL() {
  printf "  %-70s" "6.7 Set Default Screen Lock for CDE Users (Scored)"
  printf "\t\t\t${gray}Not Implemented${normal}\n"
}

CheckSetDefaulGnomeSL() {
  printf "  %-70s" "6.8 Set Default Screen Lock for GNOME Users (Scored)"
  printf "\t\t\t${gray}Not Implemented${normal}\n"
}

CheckRestrcikCronAtToAuthUsers() {
  printf "  %-70s" "6.9 Restrict at/cron to Authorized Users (Scored)"
  if [ -e "/etc/cron.d/cron.deny" ] || [ -e "/etc/cron.d/at.deny"]; then
    printf "\t\t\t${red}FAILED${normal}\n"
  else
    if [ -e "/etc/cron.d/cron.allow" ] && [ `cat /etc/cron.d/cron.allow` = "root"] && [ -s "/etc/cron.d/at.allow" ]; then
      printf "\t\t\t${green}OK${normal}\n"
    fi
  fi
}

CheckRestrictRootLoginToSystemConsole() {
  printf "  %-70s" "6.10 Restrict root Login to System Console (Scored)"
  output=`grep "^CONSOLE=/dev/console" /etc/default/login`
  if [ "$output" = "CONSOLE=/dev/console" ]; then
    printf "\t\t\t${green}OK${normal}\n"
  else
    printf "\t\t\t${red}FAILED${normal}\n"
  fi
}

CheckRetryLimit4AccountLockout() {
  printf "  %-70s" "6.11 Set Retry Limit for Account Lockout (Scored)"
  output=`grep "^RETRIES=3" /etc/default/login`
  if [ "$output" = "RETRIES=3" ]; then
    output=`grep "^LOCK_AFTER_RETRIES=YES" /etc/security/policy.conf`
    if [ "$output" = "LOCK_AFTER_RETRIES=YES" ]; then
      printf "\t\t\t${green}OK${normal}\n"
    else
      printf "\t\t\t${red}FAILED${normal}\n"
    fi
  else
    printf "\t\t\t${red}FAILED${normal}\n"
  fi
}

CheckSetEEPROMSecurityModeandLogFailedAccess() {
  printf "  %-70s" "6.12 Set EEPROM Security Mode and Log Failed Access (Not Scored)"
  output=`eeprom security-mode | awk -F= '{ print $2 }'`
  if [ -z "$output" ]; then
    printf "\t\t\t${green}OK${normal}\n"
  else
    printf "\t\t\t${red}FAILED${normal}\n"
  fi
}

CheckSecureGRUBMenu() {
  printf "  %-70s" "6.13 Secure the GRUB Menu (Not Scored)"
  output=`grep "^password -md5" /boot/grub/menu.lst`
  if [ -z "$output" ]; then
    printf "\t\t\t${red}FAILED${normal}\n"
  else
    printf "\t\t\t${green}OK${normal}\n"
  fi
}

CheckDisableSystemAccounts() {
  printf "  %-70s" "7.1 Disable System Accounts (Scored)"

  for user in daemon bin nuucp smmsp listen gdm webservd nobody noaccess nobody4 svctag sys adm lp uucp postgres
  do
    /usr/bin/getent passwd $user > /dev/null 2>/dev/null
    if [ $? -eq 0 ]; then
      stat=`pfexec passwd -s ${user} | awk '{ print $2 }'`
      if [ "${stat}" != "LK" ]; then
        # echo "Account ${user} is not locked."
        printf "\t\t\t${red}FAILED${normal}\n"
        return
      fi
    fi
  done
  printf "\t\t\t${green}OK${normal}\n"
}

CheckSetPasswordExpiration() {
  printf "  %-70s" "7.2 Set Password Expiration Parameters on Active Accounts (Scored)"
  output=`pfexec /usr/bin/logins -ox | awk -F: '( $1 != "root" && $8 != "LK" && $8 != "NL") && ( $10 != "7" || $11 != "91" || $12 != "28") { print }'`
  if [ -z "$output" ]; then
    output=`/usr/bin/grep "MAXWEEKS=" /etc/default/passwd | awk -F= '($2 <= 13 && $2 != "") { print $0 }'`
    if [ "$output" = "MAXWEEKS=13" ]; then
      output=`/usr/bin/grep "MINWEEKS=" /etc/default/passwd | awk -F= '($2 >= 1 && $2 != "") { print $0 }'`
      if [ "$output" = "MINWEEKS=1" ]; then
        output=`/usr/bin/grep "WARNWEEKS=" /etc/default/passwd | awk -F= '($2 >= 4 && $2 != "") { print $0 }'`
        if [ "$output" = "WARNWEEKS=4" ]; then
          printf "\t\t\t${green}OK${normal}\n"
          return
        fi
      fi
    fi
  fi
  printf "\t\t\t${red}FAILED${normal}\n"
}

CheckStrongPasswordCreationiPolicies() {
  printf "  %-70s" "7.3 Set Strong Password Creation Policies (Scored)"
  output=`grep "^PASSLENGTH=" /etc/default/passwd | awk -F= '($2 >= 8 && $2 != "") { print $0 }'`
  if [ "$output" = "PASSLENGTH=8" ]; then
    output=`grep "^NAMECHECK=YES" /etc/default/passwd`
    if [ "$output" = "NAMECHECK=YES" ]; then
      output=`grep "^HISTORY=" /etc/default/passwd | awk -F= '($2 >= 10 && $2 != "") { print $0 }'`
      if [ "$output" = "HISTORY=10" ]; then
        output=`grep "^MINDIFF=" /etc/default/passwd | awk -F= '($2 >= 3 && $2 != "") { print $0 }'`
        if [ "$output" = "MINDIFF=3" ]; then
          output=`grep "^MINALPHA=" /etc/default/passwd | awk -F= '($2 >= 2 && $2 != "") { print $0 }'`
          if [ "$output" = "MINALPHA=2" ]; then
            output=`grep "^MINUPPER=" /etc/default/passwd | awk -F= '($2 >= 1 && $2 != "") { print $0 }'`
            if [ "$output" = "MINUPPER=1" ]; then
              output=`grep "^MINLOWER=" /etc/default/passwd | awk -F= '($2 >= 1 && $2 != "") { print $0 }'`
              if [ "$output" = "MINLOWER=1" ]; then
                output=`grep "^MINNONALPHA=" /etc/default/passwd | awk -F= '($2 >= 1 && $2 != "") { print $0 }'`
                if [ "$output" = "MINNONALPHA=1" ]; then
                  output=`grep "^MAXREPEATS=0" /etc/default/passwd`
                  if [ "$output" = "MAXREPEATS=0" ]; then
                    output=`grep "^WHITESPACE=YES" /etc/default/passwd`
                    if [ "$output" = "WHITESPACE=YES" ]; then
                      output=`grep "^DICTIONDBDIR=/var/passwd" /etc/default/passwd`
                      if [ "$output" = "DICTIONDBDIR=/var/passwd" ]; then
                        output=`grep "^DICTIONLIST=/usr/share/lib/dict/words" /etc/default/passwd`
                        if [ "$output" = "DICTIONLIST=/usr/share/lib/dict/words" ]; then
                          printf "\t\t\t${green}OK${normal}\n"
                          return
                        fi
                      fi
                    fi
                  fi
                fi
              fi
            fi
          fi
        fi
      fi
    fi
  fi
  printf "\t\t\t${red}FAILED${normal}\n"
}

CheckDefaultGroup4RootAccount() {
  printf "  %-70s" "7.4 Set Default Group for root Account (Scored)"
  output=`grep root /etc/passwd | cut -f4 -d:`
  if [ "$output" = "0" ]; then
    printf "\t\t\t${green}OK${normal}\n"
  else
    printf "\t\t\t${red}FAILED${normal}\n"
  fi
}

CheckRoothomeDirectory() {
  printf "  %-70s" "7.5 Change Home Directory for root Account (Scored)"
  output=`grep root /etc/passwd | cut -f6 -d:`
  if [ "$output" = "/root" ]; then
    printf "\t\t\t${green}OK${normal}\n"
  else
    printf "\t\t\t${red}FAILED${normal}\n"
  fi
}

CheckUsersDefaultUmask() {
  printf "  %-70s" "7.6 Set Default umask for Users (Scored)"
  output=`grep "^UMASK=077" /etc/default/login`
  if [ "$output" = "UMASK=077" ]; then
    output=`grep "^umask 077" /etc/.login`
    if [ "$output" = "umask 077" ]; then
      output=`grep "^umask 077" /etc/profile`
      if [ "$output" = "umask 077" ]; then
        printf "\t\t\t${green}OK${normal}\n"
        return
      fi
    fi
  fi
  printf "\t\t\t${red}FAILED${normal}\n"
}

CheckDefaultUmask4FTPUsers() {
  printf "  %-70s" "7.7 Set Default umask for FTP Users (Scored)"
  output=`grep "^defumask 077" /etc/ftpd/ftpaccess`
  if [ "$output" = "defumask 077" ]; then
    printf "\t\t\t${green}OK${normal}\n"
  else
    printf "\t\t\t${red}FAILED${normal}\n"
  fi
}

CheckMesgNasDefaultForAll() {
  printf "  %-70s" "7.8 Set \"mesg n\" as Default for All Users (Scored)"
  output=`grep "^mesg n" /etc/.login`
  if [ "$output" = "mesg n" ]; then
    output=`grep "^mesg n" /etc/profile`
    if [ "$output" = "mesg n" ]; then
      printf "\t\t\t${green}OK${normal}\n"
      return
    fi
  fi

  printf "\t\t\t${red}FAILED${normal}\n"
}

CheckLockInactiveUserAccounts() {
  printf "  %-70s" "7.9 Lock Inactive User Accounts (Scored)"
  if [ -e /usr/sadm/defadduser ]; then
    output=`grep definact /usr/sadm/defadduser`
    if [ "$output" = "definact=35" ]; then
      printf "\t\t\t${green}OK${normal}\n"
    else
      printf "\t\t\t${red}FAILED${normal}\n"
    fi
  else
    printf "\t\t\t${red}FAILED${normal}\n"
  fi
}

CheckWarnings4StandardLoginServices() {
  printf "  %-70s" "8.1 Create Warnings for Standard Login Services (Scored)"
  if [ -e "/etc/motd" -a -e "/etc/issue" ]; then
    printf "\t\t\t${green}OK${normal}\n"
  else
    printf "\t\t\t${red}FAILED${normal}\n"
  fi
}

CheckWarnings4CDEUsers() {
  printf "  %-70s" "8.2 Create Warning Banner for CDE Users (Scored)"
  printf "\t\t\t${gray}Not Implemented${normal}\n"
}

CheckWarnings4GnomeUsers() {
  printf "  %-70s" "8.3 Create Warning Banner for GNOME Users (Scored)"
  printf "\t\t\t${gray}Not Implemented${normal}\n"
}

CheckWarnings4FTPUsers() {
  printf "  %-70s" "8.4 Create Warning Banner for FTP daemon (Scored)"
  output=`grep "Authorized uses only. All activity may be monitored and reported." /etc/ftpd/banner.msg 2>/dev/null`
  if [ "$output" = "Authorized uses only. All activity may be monitored and reported." ]; then
    printf "\t\t\t${green}OK${normal}\n"
  else
    printf "\t\t\t${red}FAILED${normal}\n"
  fi
}

CheckWarnings4TelnetUsers() {
  printf "  %-70s" "8.5 Check Banner Setting for telnet is Null (Scored)"
  printf "\t\t\t${gray}Not Implemented${normal}\n"
}

Check4RemoteConsoles() {
  printf "  %-70s" "9.1 Check for Remote Consoles (Scored)"
  output=`pfexec /usr/sbin/consadm -p`
  if [ -z "$output" ]; then
    printf "\t\t\t${green}OK${normal}\n"
  else
    printf "\t\t\t${red}FAILED${normal}\n"
  fi
}

VerifySystemFilePermissioins() {
  printf "  %-70s" "9.2 Verify System File Permissions (Not Scored)"
  output=`pfexec pkgchk -n 2>&1`
  if [ -z "$output" ]; then
    printf "\t\t\t${green}OK${normal}\n"
  else
    printf "\t\t\t${red}FAILED${normal}\n"
  fi
}

EnsurePasswordFieldsareNotEmpty() {
  printf "  %-70s" "9.3 Ensure Password Fields are Not Empty (Scored)"
  output=`pfexec /usr/bin/logins -p`
  if [ -z "$output" ]; then
    printf "\t\t\t${green}OK${normal}\n"
  else
    printf "\t\t\t${red}FAILED${normal}\n"
  fi
}

VerifyNoLegacyPlus() {
  printf "  %-70s" "9.4 Verify No Legacy "+" Entries Exist in passwd, shadow, and group Files"
  output=`pfexec grep '^+' /etc/passwd /etc/shadow /etc/group`
  if [ -z "$output" ]; then
    printf "\t\t\t${green}OK${normal}\n"
  else
    printf "\t\t\t${red}FAILED${normal}\n"
  fi
}

VerifyNoUID0AccountsExistsOtherThenRoot() {
  printf "  %-70s" "9.5 Verify No UID 0 Accounts Exist Other than root (Scored)"
  output=`pfexec /usr/bin/logins -o | awk -F: '($2 == 0) { print $1 }'`
  if [ "$output" = "root" ]; then
    printf "\t\t\t${green}OK${normal}\n"
  else
    printf "\t\t\t${red}FAILED${normal}\n"
  fi
}

EnsureRootPATHIntegrity() {
  printf "  %-70s" "9.6 Ensure root PATH Integrity (Scored)"

  if [ "`echo $PATH | grep :: `" != "" ]; then
    echo "Empty Directory in PATH (::)"
  fi
  if [ "`echo $PATH | grep :$`" != "" ]; then
    echo "Trailing : in PATH"
  fi
  p=`echo $PATH | sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'`
  set -- $p
  while [ "$1" != "" ]; do
    if [ "$1" = "." ]; then
      echo "PATH contains ."
      shift
      continue
    fi
    if [ -d $1 ]; then
      dirperm=`ls -ld $1 | cut -f1 -d" "`
      if [ `echo $dirperm | cut -c6 ` != "-" ]; then
        # echo "Group Write permission set on directory $1"
        printf "\t\t\t${red}FAILED${normal}\n"
        return
      fi
      if [ `echo $dirperm | cut -c9 ` != "-" ]; then
        # echo "Other Write permission set on directory $1"
        printf "\t\t\t${red}FAILED${normal}\n"
        return
      fi
    fi
    shift
  done
  printf "\t\t\t${green}OK${normal}\n"

}

CheckPermissionsOnUserHomeDirectories() {
  printf "  %-70s" "9.7 Check Permissions on User Home Directories (Scored)"

  for dir in `pfexec /usr/bin/logins -ox | awk -F: '($8 == "PS" && $1 != "root") { print $6 }'`; do
    dirperm=`ls -ld $dir | cut -f1 -d" "`
    if [ `echo $dirperm | cut -c6 ` != "-" ]; then
      # echo "Group Write permission set on directory $dir"
      printf "\t\t\t${red}FAILED${normal}\n"
      return
    fi
    # if [ `echo $dirperm | cut -c8 ` != "-" ]; then
    #   echo "Other Read permission set on directory $dir"
    # fi
    if [ `echo $dirperm | cut -c9 ` != "-" ]; then
      # echo "Other Write permission set on directory $dir"
      printf "\t\t\t${red}FAILED${normal}\n"
      return
    fi
    # if [ `echo $dirperm | cut -c10 ` != "-" ]; then
    #   echo "Other Execute permission set on directory $dir"
    # fi
  done
  printf "\t\t\t${green}OK${normal}\n"
}

CheckUserDorFilePermissions() {
  printf "  %-70s" "9.8 Check User Dot File Permissions (Scored)"

  for dir in `pfexec /usr/bin/logins -ox | awk -F: '($8 == "PS") { print $6 }'`; do 
    for file in $dir/.[A-Za-z0-9]*; do 
    if [ ! -h "$file" -a -f "$file" ]; then
      fileperm=`ls -ld $file | cut -f1 -d" "` 
      if [ `echo $fileperm | cut -c6 ` != "-" ]; then 
        # echo "Group Write permission set on file $file" 
        printf "\t\t\t${red}FAILED${normal}\n"
        return
      fi     
      if [ `echo $fileperm | cut -c9 ` != "-" ]; then 
        # echo "Other Write permission set on file $file"
        printf "\t\t\t${red}FAILED${normal}\n"
        return
      fi 
    fi 
    done 
  done
  printf "\t\t\t${green}OK${normal}\n"

}

CheckPermissionsOnIUserDotNetrcFiles() {
  printf "  %-70s" "9.9 Check Permissions on User .netrc Files (Scored)"

  for dir in `pfexec /usr/bin/logins -ox | awk -F: '($8 == "PS") { print $6 }'`; do
    for file in $dir/.netrc; do 
    if [ ! -h "$file" -a -f "$file" ]; then 
      fileperm=`ls -ld $file | cut -f1 -d" "` 
      # if [ `echo $fileperm | cut -c5 ` != "-" ]; then
      #   echo "Group Read set on $file" 
      # fi
      # if [ `echo $fileperm | cut -c6 ` != "-" ]; then 
      #   echo "Group Write set on $file" 
      # fi 
      # if [ `echo $fileperm | cut -c7 ` != "-" ]; then 
      #   echo "Group Execute set on $file" 
      # fi
      if [ `echo $fileperm | cut -c8 ` != "-" ]; then
        # echo "Other Read set on $file"
        printf "\t\t\t${red}FAILED${normal}\n"
        return
      fi 
      if [ `echo $fileperm | cut -c9 ` != "-" ]; then 
        # echo "Other Write set on $file"
        printf "\t\t\t${red}FAILED${normal}\n"
        return
      fi 
      if [ `echo $fileperm | cut -c10 ` != "-" ]; then
        # echo "Other Execute set on $file"
        printf "\t\t\t${red}FAILED${normal}\n"
        return
      fi
    fi
    done
  done
  printf "\t\t\t${green}OK${normal}\n"
}

Check4PresenceOfUsersRhostFiles() {
  printf "  %-70s" "9.10 Check for Presence of User .rhosts Files (Scored)"

  for dir in `pfexec /usr/bin/logins -ox | awk -F: '($8 == "PS") { print $6 }'`; do
    for file in $dir/.rhosts; do
      if [ ! -h "$file" -a -f "$file" ]; then
        # echo ".rhosts file in $dir"
        printf "\t\t\t${red}FAILED${normal}\n"
        return
      fi
    done
  done
  printf "\t\t\t${green}OK${normal}\n"
}


CheckGroupsInEtcPasswd() {
  printf "  %-70s" "9.11 Check Groups in /etc/passwd (Scored)"
  storeIFS=${IFS}
  IFS=$'\n'
  failed=0
  defUsers="root daemon bin sys adm lp uucp nuucp smmsp listen gdm webservd postgres svctag nobody noaccess nobody4 unknown"
  declare -a p_array=(`getent passwd`)
  declare -a g_array=(`getent group`)

  for x in ${p_array[@]}; do
    if [ "$x" = "" ]; then
      break 
    fi
    userid=`echo "$x" | cut -f1 -d':'`
    if [ "$defUsers" != "${defUsers/$userid/}" ]; then
        continue
    fi
    groupid=`echo "$x" | cut -f4 -d':'`
    found_group=0
    for x in ${g_array[@]}; do
      gid=`echo $x | cut -f3 -d":"`
      if [ $gid -eq $groupid ]; then
        found_group=1
        break
      fi
    done
    if [ $found_group -eq 0 ]; then
      printf "\t\t\t${red}FAILED${normal}\n"
      IFS=${storeIFS}
      return
      # echo "Groupid $groupid does not exist in /etc/group, but is used by $userid" 
    fi
  done
  IFS=${storeIFS}
  printf "\t\t\t${green}OK${normal}\n"
}


CheckThatUsersAreAssignedHomeDirectories() {
  printf "  %-70s" "9.12 Check That Users Are Assigned Home Directories (Scored)"

  storeIFS=${IFS}
  IFS=$'\n'
  defUsers="root daemon bin sys adm lp uucp nuucp smmsp listen gdm webservd postgres svctag nobody noaccess nobody4 unknown"
  declare -a p_array=(`getent passwd`)
  for x in ${p_array[@]}; do
    user=`echo $x | awk -F: '{ print $1}'`
    dir=`echo $x | awk -F: '{ print $6}'`
    if [ "$defUsers" != "${defUsers/$user/}" ]; then
        continue
    fi    
    if ([ -z "${dir}" ] || [ "$dir" = "/" ]); then 
      printf "\t\t\t${red}FAILED${normal}\n"
      exit
    fi
  done
  IFS=${storeIFS}
  printf "\t\t\t${green}OK${normal}\n"
}

CheckUnnecessaryLocalServices
CheckTCPWrappers
printf "\n3 Kernel Tuning\n\n"
printf "  3.1 Modify Network Parameters\n"
KernelTuning
CheckCoreDump
StackProtection
CheckTCPSequenceNumbergeneration
CheckRouting

printf "\n4.0 Logging\n"
CheckInetdConnectionLogging
CheckFTPdaemonLogging
CheckDebugLevelDaemonLogging
CapturesyslogAUTHMessages
EnableLoginRecords
CaptureAllFailedLoginAttempts
EnableCronLogging
EnableSystemAccounting
EnableKernelLevelAuditing

printf "\n5 File/Directory Permissions/Access\n"
CheckCMASK
CheckUserMountedDevices
CheckStickyBit


printf "\n6 System Access, Authentication, and Authorization\n"
CheckConfigureSSH
CheckConfigureSSHProto2
CheckConfigureSSHDisX
CheckConfigureSSHMaxAuthTry
CheckConfigureSSHMaxAuthTryLog
CheckConfigureSSHIgnoreRhosts
CheckConfigureSSHRhostsAuthentication
CheckConfigureSSHRhostsRSAAuthentication
CheckConfigureSSHrootLogin
CheckConfigureSSHPermitEmptyPasswords
CheckConfigureSSHBanner
CheckDisableLogin
CheckDisablenobodyAccess4RPCEncKeys
CheckDisableRhostsSupportInPam
CheckRestrcikFTPUse
CheckSetDelaybwFailedLoginAttempts
CheckSetDefaulCDESL
CheckSetDefaulGnomeSL
CheckRestrcikCronAtToAuthUsers
CheckRestrictRootLoginToSystemConsole
CheckRetryLimit4AccountLockout
CheckSetEEPROMSecurityModeandLogFailedAccess
CheckSecureGRUBMenu

printf "\n7 User Accounts and Environment\n"
CheckDisableSystemAccounts
CheckSetPasswordExpiration
CheckStrongPasswordCreationiPolicies
CheckDefaultGroup4RootAccount
CheckRoothomeDirectory
CheckUsersDefaultUmask
CheckDefaultUmask4FTPUsers
CheckMesgNasDefaultForAll
CheckLockInactiveUserAccounts


printf "\n8 Warning Banners\n"
CheckWarnings4StandardLoginServices
CheckWarnings4CDEUsers
CheckWarnings4GnomeUsers
CheckWarnings4FTPUsers
CheckWarnings4TelnetUsers

printf "\n9 System Maintenance\n"
Check4RemoteConsoles
VerifySystemFilePermissioins
EnsurePasswordFieldsareNotEmpty
VerifyNoLegacyPlus
VerifyNoUID0AccountsExistsOtherThenRoot
EnsureRootPATHIntegrity
CheckPermissionsOnUserHomeDirectories
CheckUserDorFilePermissions
CheckPermissionsOnIUserDotNetrcFiles
Check4PresenceOfUsersRhostFiles
CheckGroupsInEtcPasswd
CheckThatUsersAreAssignedHomeDirectories

printf "\n10 Appendix: Additional Security Notes\n"
checkService "10.6 Check Support for Internet Services (inetd)" "svc:/network/inetd"

