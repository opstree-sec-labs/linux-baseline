
control "linux-Servie-DHCP " do
  title "Ensure DHCP Server is not enabled"
  desc "The Dynamic Host Configuration Protocol (DHCP) is a service that allows machines to be
  dynamically assigned IP addresses.
  Unless a system is specifically set up to act as a DHCP server, it is recommended that this
  service be deleted to reduce the potential attack surface."
  impact 0.5
  tag Vulnerability: 'Low'
  tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
  tag Remedy:"Run one of the following commands to disable dhcpd :
  chkconfig dhcpd off
  systemctl disable dhcpd
  update-rc.d dhcpd disable"
  ref 'About DHCP Server', url: 'https://www.infoblox.com/glossary/dhcp-server/#:~:text=A%20DHCP%20Server%20is%20a,to%20broadcast%20queries%20by%20clients.'
  describe command('systemctl is-enabled dhcpd') do
    its('stderr') { should match /Failed to get unit file state for dhcpd.service/ }
  end
end

control "linux-Servie-LDAP " do
  title "Ensure LDAP server is not enabled"
  desc "The Lightweight Directory Access Protocol (LDAP) was introduced as a replacement for
  NIS/YP. It is a service that provides a method for looking up information from a central
  database. If the system will not need to act as an LDAP server, it is recommended that the software be
  disabled to reduce the potential attack surface."
  impact 0.5
  tag Vulnerability: 'Low'
  tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
  tag Remedy:"Run one of the following commands to disable slapd :
  chkconfig slapd off
  systemctl disable slapd
  update-rc.d slapd disable"
  ref 'About LDAP Server', url: 'https://tldp.org/HOWTO/LDAP-HOWTO/whatisldap.html#:~:text=LDAP%20stands%20for%20Lightweight%20Directory,other%20connection%20oriented%20transfer%20services.'
  describe command('systemctl is-enabled slapd') do
    its('stderr') { should match /Failed to get unit file state for slapd.service/ }
  end
end

control "linux-Servie-NFS-RPC " do
  title "Ensure NFS and RPC are not enabled"
  desc "The Network File System (NFS) is one of the first and most widely distributed file systems
  in the UNIX environment. It provides the ability for systems to mount file systems of other
  servers through the network.
  If the system does not export NFS shares or act as an NFS client, it is recommended that
  these services be disabled to reduce the remote attack surface."
  impact 0.5
  tag Vulnerability: 'Medium'
  tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
  tag Remedy:"Run one of the following commands to disable nfs and rpcbind :
  chkconfig nfs off
  chkconfig rpcbind off
  systemctl disable nfs
  systemctl disable rpcbind
  update-rc.d nfs disable
  update-rc.d rpcbind disable"
  ref 'About Network Filesystem', url: 'https://www.geeksforgeeks.org/network-file-system-nfs/'
  describe command('systemctl is-enabled nfs') do
    its('stderr') { should match /Failed to get unit file state for nfs.service/ }
  end
end

control "linux-Servie-DNS " do
  title "Ensure DNS Server is not enabled"
  desc "The Domain Name System (DNS) is a hierarchical naming system that maps names to IP
  addresses for computers, services and other resources connected to a network.
  Unless a system is specifically designated to act as a DNS server, it is recommended that the
  package be deleted to reduce the potential attack surface."
  impact 0.5
  tag Vulnerability: 'Medium'
  tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
  tag Remedy:"Run one of the following commands to disable named :
  chkconfig named off
  systemctl disable named
  update-rc.d named disable"
  ref 'About DNS Server', url: 'https://www.cloudflare.com/learning/dns/what-is-a-dns-server/'
  describe command('systemctl is-enabled named') do
    its('stderr') { should match /Failed to get unit file state for named.service/ }
  end
end

control "linux-Servie-FTP " do
  title "Ensure FTP Server is not enabled"
  desc "The File Transfer Protocol (FTP) provides networked computers with the ability to transfer
  files.FTP does not protect the confidentiality of data or authentication credentials. It is
  recommended SFTP be used if file transfer is required. Unless there is a need to run the
  system as a FTP server (for example, to allow anonymous downloads), it is recommended
  that the package be deleted to reduce the potential attack surface."
  impact 0.5
  tag Vulnerability: 'High'
  tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
  tag Remedy:"Run one of the following commands to disable vsftpd :
  chkconfig vsftpd off
  systemctl disable vsftpd
  update-rc.d vsftpd disable"
  ref 'About vsftpd Server', url: 'https://security.appspot.com/vsftpd.html'
  describe command('systemctl is-enabled vsftpd') do
    its('stderr') { should match /Failed to get unit file state for vsftpd.service/ }
  end
end

control "linux-Servie-HTTPD " do
  title "Ensure HTTPD Server is not enabled"
  desc "HTTP or web servers provide the ability to host web site content.
  Unless there is a need to run the system as a web server, it is recommended that the
  package be deleted to reduce the potential attack surface."
  impact 0.5
  tag Vulnerability: 'Medium'
  tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
  tag Remedy:"Run one of the following commands to disable httpd :
  chkconfig httpd off
  systemctl disable httpd
  update-rc.d httpd disable"
  ref 'About httpd Server', url: 'https://httpd.apache.org/'
  describe command('systemctl is-enabled httpd') do
    its('stderr') { should match /Failed to get unit file state for httpd.service/ }
  end
end

control "linux-Servie-Samba" do
  title "Ensure Samba is not enabled"
  desc "The Samba daemon allows system administrators to configure their Linux systems to share
  file systems and directories with Windows desktops. Samba will advertise the file systems
  and directories via the Server Message Block (SMB) protocol. Windows desktop users will
  be able to mount these directories and file systems as letter drives on their systems."
  impact 0.5
  tag Vulnerability: 'High'
  tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
  tag Remedy:"Run one of the following commands to disable smb :
  chkconfig smb off
  systemctl disable smb
  update-rc.d smb disable"
  ref 'About Samba Server', url: 'https://www.samba.org/'
  describe command('systemctl is-enabled smb') do
    its('stderr') { should match /Failed to get unit file state for smb.service/ }
  end
end

control "linux-Servie-SNMP" do
  title "Ensure SNMP Server is not enabled"
  desc "The Simple Network Management Protocol (SNMP) server is used to listen for SNMP commands from an SNMP management system, execute the commands or collect the information and then send results back to the requesting system.
  The SNMP server can communicate using SNMP v1, which transmits data in the clear and
  does not require authentication to execute commands. Unless absolutely necessary, it is
  recommended that the SNMP service not be used. If SNMP is required the server should be
  configured to disallow SNMP v1."
  impact 0.5
  tag Vulnerability: 'Medium'
  tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
  tag Remedy:"Run one of the following commands to disable snmpd :
  chkconfig snmpd off
  systemctl disable snmpd
  update-rc.d snmpd disable"
  ref 'About SNMP Server', url: 'https://docs.oracle.com/cd/E19121-01/sf.v40z/817-5249-17/chapter3.html#:~:text=Simple%20Network%20Management%20Protocol%20(SNMP)%20is%20a%20network%2Dmanagement,and%20security%20on%20a%20network.'
  describe command('systemctl is-enabled snmpd') do
    its('stderr') { should match /Failed to get unit file state for snmpd.service/ }
  end
end

control "linux-Servie-rsync" do
  title "Ensure rsync service is not enabled"
  desc "The rsyncd service can be used to synchronize files between systems over network links.
  The rsyncd service presents a security risk as it uses unencrypted protocols for
  communication"
  impact 0.5
  tag Vulnerability: 'Medium'
  tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
  tag Remedy:"Run one of the following commands to disable rsyncd :
  # chkconfig rsyncd off
  # systemctl disable rsyncd
  # update-rc.d rsyncd disable"
  ref 'About Rsync daemon', url: 'https://www.atlantic.net/vps-hosting/how-to-setup-rsync-daemon-linux-server/'
  describe command('systemctl is-enabled rsyncd') do
    its('stderr') { should match /Failed to get unit file state for rsync.service/ }
  end
end

control "linux-Servie-NIS" do
  title "Ensure NIS Server is not enabled"
  desc "The Network Information Service (NIS) (formally known as Yellow Pages) is a client-server
  directory service protocol for distributing system configuration files. The NIS server is a
  collection of programs that allow for the distribution of configuration files.
  The NIS service is inherently an insecure system that has been vulnerable to DOS attacks,
  buffer overflows and has poor authentication for querying NIS maps. NIS generally has
  been replaced by such protocols as Lightweight Directory Access Protocol (LDAP). It is
  recommended that the service be disabled and other, more secure services be used"
  impact 0.5
  tag Vulnerability: 'High'
  tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
  tag Remedy:"Run one of the following commands to disable ypserv :
  # chkconfig ypserv off
  # systemctl disable ypserv
  # update-rc.d ypserv disable"
  ref 'About NIS Server', url: 'https://likegeeks.com/linux-nis-server/'
  describe command('systemctl is-enabled ypserv') do
    its('stderr') { should match /Failed to get unit file state for ypserv.service/ }
  end
end
