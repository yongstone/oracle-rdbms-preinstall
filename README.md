- Script name: oracle-rdbms-server-12c-preinstall
- Description: A script to linux 6.x && 7.x version for oracle database 11g 12c preinstall configureation
- Sample:
```sh
[root@localhost ~]# ./oracle-rdbms-server-12c-silent-preinstall.sh 
Services firewalld status: stop
Please enter your hostname [example-db12c]:example-db12c
Setting hostname succeeded ... 
Oracle database hosts setting succeeded ...
SELINUX closed succeeded ...
Adding group 'oinstall' with gid '1001'...
Adding group dba
Adding group oper
Adding user 'oracle' with uid '1001'...
Creating user 'oracle' succeeded ...
For security reasons, no default password was set for user 'oracle'. If you wish to login as the 'oracle' user, you will need to set a password for this account.
Creating directory for oracle base ...
Creating directory for oracle base seccussed ...
Changing ownership 'oracle:oinstall' to '/u01'
Changing permission '755' to '/u01'
Changing ownership and permission succeeded ...
Verifying && setting oracle user limits succeeded ...
Adding oracle database kerenl parameters ...
* Applying /usr/lib/sysctl.d/00-system.conf ...
* Applying /usr/lib/sysctl.d/10-default-yama-scope.conf ...
kernel.yama.ptrace_scope = 0
* Applying /usr/lib/sysctl.d/50-default.conf ...
kernel.sysrq = 16
kernel.core_uses_pid = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.promote_secondaries = 1
net.ipv4.conf.all.promote_secondaries = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
* Applying /etc/sysctl.d/97-oracle-database-sysctl.conf ...
fs.aio-max-nr = 1048576
kernel.shmmni = 4096
kernel.sem = 32000 1024000000 500 32000
net.ipv4.ip_local_port_range = 9000 65500
net.core.rmem_default = 4194304
net.core.rmem_max = 4194304
net.core.wmem_default = 4194304
net.core.wmem_max = 4194304
* Applying /etc/sysctl.d/99-sysctl.conf ...
* Applying /etc/sysctl.conf ...
Adding oracle database kernel parameters succeeded ...
You need to configure repo and manually install the following dependency packages ...
yum -y insstall bc
yum -y insstall compat-libcap1
yum -y insstall compat-libstdc++-33
yum -y insstall glibc-devel
yum -y insstall ksh
yum -y insstall libaio-devel
yum -y insstall libstdc++-devel
yum -y insstall libxcb
yum -y insstall libX11
yum -y insstall libXau
yum -y insstall libXi
yum -y insstall libXtst
yum -y insstall libXrender
yum -y insstall libXrender-devel
yum -y insstall nfs-utils
yum -y insstall smartmontools
yum -y insstall sysstat
yum -y insstall net-tools
The oracle database preinstall configureation is complete.
```