#!/bin/bash
##########################################################
# Name: oracle-rdbms-server-12c-preinstall
#
# Description: A script to linux 6.x && 7.x version 
# for oracle database preinstall configureation
#
# Author: Falkon
##########################################################

USERID="1001"
GROUPID="1001"
BACKUPS_DIR="/var/log/oracle-validated/backup/`date "+%b-%d-%Y-%H-%M-%S"`"

CUT=/bin/cut
RPM=/bin/rpm
SED=/bin/sed

# Setting hostname
f_sethostname(){

        current_hostname=`/bin/hostname`

        if [[ ! "$current_hostname" = "localhost" ]]; then
                echo "Hostname has been changed! If you need to change it again, configure it manually ..."
                return 2
        else
                while [[ ! "$hostname" =~ ^[a-z][a-z0-9-]{1,}$ ]]
                do
                        printf "Please enter your hostname [example-db12c]:"
                        read hostname
                        if [[ ! "$hostname" =~ ^[a-z][a-z0-9-]{1,}$ ]]; then
                                echo "The hostname entered is invalid, Please re-enter."
                        fi
                done
        fi
}


# Setting hosts
f_sethosts(){
	
		HOSTSFILE="/etc/hosts"
		
		/bin/cp ${HOSTSFILE} ${BACKUPS_DIR}
		if [[ $? -ne 0 ]]; then
				echo "Failed to copy ${HOSTSFILE} to ${BACKUPS_DIR}..."
				return 1		
		else
				ipaddr=$(ip -f inet -4 -br addr | grep ^e | awk '{print $3}' | cut -d "/" -f1)
				echo -e >> $HOSTSFILE
				echo "# Oracle database hostname resolution" >> $HOSTSFILE
				echo "${ipaddr} ${current_hostname}" >>  $HOSTSFILE
		fi
}

# Close selinux
f_shutselinux(){
	
		SELINUXFILE="/etc/sysconfig/selinux"
		
		/bin/cp ${SELINUXFILE} ${BACKUPS_DIR}
		if [[ $? -ne 0 ]]; then
				echo "Failed to copy ${SELINUXFILE} to ${BACKUPS_DIR}..."
				return 1		
		else
				$SED -i '7s/enforcing/disabled/' $SELINUXFILE
		fi
}

# Create oracle database groups and user
f_createuser(){
		groupnum=`cat /etc/group | sort -t : -g +2 -3 | grep -v nfsnobody | cut -d ":" -f3 | tail -1`
		if [[ $groupnum -eq $GROUPID ]]; then
				GROUPID = `expr + 1`
		fi

		usernum=`cat /etc/group | sort -t : -g +2 -3 | grep -v nfsnobody | cut -d ":" -f3 | tail -1`
		if [[ $usernum -eq $USERID ]]; then
				USERID = `expr + 1`
		fi

		echo "Adding group 'oinstall' with gid '$GROUPID'..."
		/usr/sbin/groupadd -g  ${GROUPID} oinstall
		echo "Adding group dba"
		/usr/sbin/groupadd dba
		echo "Adding group oper"
		/usr/sbin/groupadd oper

		echo "Adding user 'oracle' with uid '$USERID'..."
		/bin/id oracle > /dev/null 2>&1
		if [[ $? -ne 0 ]]; then
				# Add user
				/usr/sbin/useradd -u ${USERID} -g oinstall -G dba,oper oracle
		else
				echo "User 'oracle' already exist ..."
				oracle_info=$(/bin/id oracle)
				echo "[INFO] ${oracle_info}"
		fi	 
}

# Create oracle database base directory
f_createdir(){
	
		ORACLE_BASE="/u01/app/oracle"
		
		if [[ ! -d $ORACLE_BASE ]]; then
				echo "Creating directory for oracle base ..."
				/bin/mkdir -p $ORACLE_BASE
				if [[ $? -ne 0 ]]; then
						echo "Failed to creating oracle base directory ..."
						return 1
				else
						echo "Creating directory for oracle base seccussed ..."
				fi
		fi
}

# Setting oracle database resource limits
f_setlimits(){
	
		LIMITS_CONF="/etc/security/limits.conf"
		
		if [[ -f $LIMITS_CONF ]]; then
				/bin/cp ${LIMITS_CONF} ${BACKUPS_DIR}
				if [[ $? -eq 0 ]]; then
						$SED -i '$a # Oracle database resource limits' $LIMITS_CONF
						$SED -i '$a oracle 	soft 	nofile 	131072' $LIMITS_CONF
						$SED -i '$a oracle 	hard 	nofile 	131072' $LIMITS_CONF
						$SED -i '$a oracle 	hard 	nproc 	131072' $LIMITS_CONF
						$SED -i '$a oracle 	soft 	core 	unlimited' $LIMITS_CONF
						$SED -i '$a oracle 	hard 	core 	unlimited' $LIMITS_CONF
						$SED -i '$a oracle 	soft 	stack 	10240' $LIMITS_CONF
						$SED -i '$a oracle 	hard 	stack 	32768' $LIMITS_CONF
				else
						echo "Failed to copy ${LIMITS_CONF} to ${BACKUPS_DIR}..."
						return 1
				fi
			 
		fi
}

# Define oracle database kernel parameter
f_params(){
		array_params[0]="# Oracle database kernel parameters"
	   	array_params[1]="fs.aio-max-nr = 1048576"
	    array_params[2]="kernel.shmmni = 4096"
	    array_params[3]="kernel.sem = 32000 1024000000 500 32000"
	    array_params[4]="net.ipv4.ip_local_port_range = 9000 65500"
	    array_params[5]="net.core.rmem_default = 4194304"
	    array_params[6]="net.core.rmem_max = 4194304"
	    array_params[7]="net.core.wmem_default = 4194304"
	    array_params[8]="net.core.wmem_max = 4194304"
}

# Setting EL7 oracle database kernel parameter
f_el7setparams(){
	
		SYSCTL_CONF="/etc/sysctl.d/97-oracle-database-sysctl.conf"

		if [[ ! -f  $SYSCTL_CONF ]]; then
				/bin/touch ${SYSCTL_CONF}
				if [[ $? -ne 0 ]]; then
						echo "Failed to creating to $SYSCTL_CONF ..."
						return 1
				else
						/bin/cp ${SYSCTL_CONF} ${BACKUPS_DIR}
						if [[ $? -ne 0 ]]; then
								echo "Failed to copy ${SYSCTL_CONF} to ${BACKUPS_DIR} ..."
								return 1
						else
								f_params;
								echo "Adding oracle database kerenl parameters ..."
								OLD_IFS=$IFS
								IFS=$'\n'
								for arg in ${array_params[@]}; do
									echo $arg >> ${SYSCTL_CONF}
								done
								IFS=$OLD_IFS
								sysctl --system
						fi
				fi
		else
				/bin/cp ${SYSCTL_CONF} ${BACKUPS_DIR}
				if [[ $? -ne 0 ]]; then
						echo "Failed to copy ${SYSCTL_CONF} to ${BACKUPS_DIR} ..."
						return 1
				else
						f_params;
						echo "Adding oracle database kerenl parameters ..."
						OLD_IFS=$IFS
						IFS=$'\n'
						for arg in ${array_params[@]}; do
								echo $arg >> ${SYSCTL_CONF}
						done 
						IFS=$OLD_IFS
						sysctl --system
				fi
		fi
}

# Setting EL6 oracle database kernel parameter
f_el6setparams(){

		SYSCTL_CONF="/etc/sysctl.conf"
		
		if [[ ! -f $SYSCTL_CONF ]]; then
				/bin/cp ${SYSCTL_CONF} ${BACKUPS_DIR}
				if [[ $? -ne 0 ]]; then
						echo "Failed to copy ${SYSCTL_CONF} to ${BACKUPS_DIR} ..."
						return 1
				else
						f_params;
						echo "Adding oracle database kerenl parameters ..."
						OLD_IFS=$IFS
						IFS=$'\n'
						for arg in ${array_params[@]}; do
								echo $arg >> ${SYSCTL_CONF}
						done
						IFS=$OLD_IFS
						sysctl -p
				fi
		fi
}

# Checking oracle database requires install packages
f_checkrpm(){
		array_list_rpm[0]="bc"
		array_list_rpm[1]="binutils"
		array_list_rpm[2]="compat-libcap1"
		array_list_rpm[3]="compat-libstdc++-33"
		array_list_rpm[4]="glibc"
		array_list_rpm[5]="glibc-devel"
		array_list_rpm[6]="ksh"
		array_list_rpm[7]="libaio"
		array_list_rpm[8]="libaio-devel"
		array_list_rpm[9]="libgcc"
		array_list_rpm[10]="libstdc++"
		array_list_rpm[11]="libstdc++-devel"
		array_list_rpm[12]="libxcb"
		array_list_rpm[13]="libX11"
		array_list_rpm[14]="libXau"
		array_list_rpm[15]="libXi"
		array_list_rpm[16]="libXtst"
		array_list_rpm[17]="libXrender"
		array_list_rpm[18]="libXrender-devel"
		array_list_rpm[19]="make"
		array_list_rpm[20]="nfs-utils"
		array_list_rpm[21]="smartmontools"
		array_list_rpm[22]="sysstat"
		array_list_rpm[23]="net-tools"

		# Find required install RPM
		echo -e "\033[31;49;1mYou need to configure repo and manually install the following dependency packages ...\033[39;49;0m"
		
		for listrpm in ${array_list_rpm[@]};
		do
				check_installed=$($RPM -qa | grep ^$listrpm | $CUT -d "-" -f1)
				if [[ ! $check_installed ]]; then
						echo "yum -y insstall ${listrpm}"
				fi
		done
}

# Close services firewall or iptables
v=$(uname -r | cut -d l -f2 | cut -c 1)
if [[ $v -eq 7 ]]; then
		version=7
		fw=$(systemctl status firewalld | grep -c "inactive")
		if [[ $fw -eq 0 ]]; then
				systemctl disable firewalld > /dev/null 2&>1
				systemctl stop firewalld
				echo "Services firewalld status: stop"
		fi
elif [[ $v -eq 6 ]]; then
		version=6
		fw=$(service iptables status | grep "is not running")
		if [[ $fw = '' ]]; then
				service iptables stop
				chkconfig --level 2345 iptables off
				echo "Services iptables status: stop"
		fi
fi

# Creating backup  dirctory
/bin/mkdir --mode 0700 -p ${BACKUPS_DIR}

f_sethostname;
# Set EL7 hostname
if [[ $? -ne 2 ]] && [[ $version -eq 7 ]]; then
        hostnamectl set-hostname $hostname
        if [[ $? -ne 0 ]]; then
                echo "Setting hostname failed ... "
        else
                echo "Setting hostname succeeded ... "
        fi
fi

# Set EL6 hostname
if [[ $? -ne 2 ]] && [[ $version -eq 6 ]]; then
        
        HOSTNAMEFILE="/etc/sysconfig/network"
        
        /bin/cp ${HOSTNAMEFILE} ${BACKUPS_DIR}
        if [[ $? -ne 0 ]]; then
                echo "Failed to copy ${HOSTNAMEFILE} to ${BACKUPS_DIR}"
        else
                $SED -i 's/localhost/${hostname}/' $HOSTNAMEFILE
                if [[ $? -ne 0 ]]; then
                        echo "Setting hostname failed ..."
                else
                        echo "Setting hostname succeeded ... "
                fi
        fi
fi


f_sethosts;
if [[ $? -ne 0 ]]; then
		echo "Oracle database hosts setting failed ..."
else
		echo "Oracle database hosts setting succeeded ..."
fi

f_shutselinux;
if [[ $? -ne 0 ]]; then
		echo "SELINUX closed failed ..."
else
		echo "SELINUX closed succeeded ..."
fi


f_createuser;
if [[ $? -ne 0 ]]; then
		echo "Creating user 'oracle' failed ..."
else
		echo "Creating user 'oracle' succeeded ..."
		echo -e "\033[31;49;1mFor security reasons, no default password was set for user 'oracle'. If you wish to login as the 'oracle' user, you will need to set a password for this account.\033[39;49;0m"
fi


f_createdir;
if [[ -d /u01/app/oracle ]]; then
		echo "Changing ownership 'oracle:oinstall' to '/u01'"
	        	chown -R oracle:oinstall /u01
		if [[ $? -eq 0 ]]; then
				echo "Changing permission '755' to '/u01'"
				chmod -R 775 /u01
				if [[ $? -ne 0 ]]; then
						echo "Changing ownership and permission failed ..."
				else
						echo "Changing ownership and permission succeeded ..."
				fi
		fi
fi


f_setlimits;
if [[ $? -ne 0 ]]; then
		echo "Verifying oracle user limits failed ..."
else
		echo "Verifying && setting oracle user limits succeeded ..."
fi


if [[ $version = 7 ]]; then
		f_el7setparams;
		if [[ $? -ne 0 ]]; then
				echo "Adding oracle database kernel parameters failed ..."
		else
				echo "Adding oracle database kernel parameters succeeded ..."
		fi
fi


if [[ $version = 6 ]]; then
		f_el6setparams;
		if [[ $? -ne 0 ]]; then
				echo "Adding oracle database kernel parameters failed ..."
		else
				echo "Adding oracle database kernel parameters succeeded ..."
		fi
fi

f_checkrpm;

echo "The oracle database preinstall configureation is complete."