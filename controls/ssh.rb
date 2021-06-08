ssh_config_directory  = attribute('sshConfig', default: '/etc/ssh', description: 'Path to the ssh config directory')

control "linux-sshd-permission " do
    title "Ensure permissions on /etc/ssh/sshd_config are configured"
    desc "The /etc/ssh/sshd_config file contains configuration specifications for sshd. The command below sets the owner and group of the file to root.
    It should not allow others to read and write permission
    "
    impact 0.5
    tag Vulnerability: 'Critical'
    tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
    tag Remedy:"Run the following commands to set ownership and permissions on /etc/ssh/sshd_config : 
    # chown root:root /etc/ssh/sshd_config 
    # chmod og-rwx /etc/ssh/sshd_config"
    ref 'About SSHD config', url: 'https://www.ssh.com/ssh/sshd_config/'
    describe file("#{ssh_config_directory}/sshd_config") do
        it { should exist }
        its('group') { should eq 'root' }
        its('owner') { should eq 'root' }
        it { should_not  be_writable.by('group') }
        it { should_not be_writable.by('other') }
        it { should_not be_readable.by('other') }
    end
end

control "linux-ssh-protocol-version " do
    title "Ensure SSH Protocol is set to 2"
    desc "Older versions of SSH support two different and incompatible protocols: SSH1 and SSH2.
    SSH1 was the original protocol and was subject to security issues. SSH2 is more advanced
    and secure.
    "
    impact 0.5
    tag Vulnerability: 'High'
    tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
    tag Remedy:"Edit the /etc/ssh/sshd_config file to set the parameter as follows:
    Protocol 2"
    ref 'Problem with Version 1', url: 'https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_ssh/configuration/15-s/sec-usr-ssh-15-s-book/sec-secure-shell-v2.html#:~:text=Secure%20Shell%20Version%202%20Support,-The%20Secure%20Shell&text=The%20only%20reliable%20transport%20that,the%20secure%20transfer%20of%20files.'
    ref 'Bleichenbacher Attack', url: 'https://medium.com/@c0D3M/bleichenbacher-attack-explained-bc630f88ff25'
    describe command('timeout 2s telnet 127.0.0.1 22 | grep SSH') do
        its('stdout') { should match /SSH-2.0/ }
    end
end

control "linux-ssh-loglevel " do
    title "Ensure SSH LogLevel is appropriate"
    desc "INFO level is the basic level that only records login activity of SSH users. In many situations,
    such as Incident Response, it is important to determine when a particular user was active
    on a system. The logout record can eliminate those users who disconnected, which helps
    narrow the field.
    VERBOSE level specifies that login and logout activity as well as the key fingerprint for any
    SSH key used for login will be logged. This information is important for SSH key
    management, especially in legacy environments.
    "
    impact 0.5
    tag Vulnerability: 'High'
    tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
    tag Remedy:"Edit the /etc/ssh/sshd_config file to set the parameter as follows:
    LogLevel VERBOSE or INFO"
    ref 'About SSHD', url: 'https://www.ssh.com/ssh/sshd_config/'
    describe command('sshd -T 2> /dev/null | grep loglevel ') do
        its('stdout') { should match /INFO|VERBOSE/ }
    end
end

control "linux-ssh-x11-forwarding " do
    title "Ensure SSH X11 forwarding is disabled"
    desc "The X11Forwarding parameter provides the ability to tunnel X11 traffic through the
    connection to enable remote graphic connections.
    Disable X11 forwarding unless there is an operational requirement to use X11 applications
    directly. There is a small risk that the remote X11 servers of users who are logged in via
    SSH with X11 forwarding could be compromised by other users on the X11 server. Note
    that even if X11 forwarding is disabled, users can always install their own forwarders.
    "
    impact 0.5
    tag Vulnerability: 'Medium'
    tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
    tag Remedy:"Edit the /etc/ssh/sshd_config file to set the parameter as follows:
    X11Forwarding no"
    ref 'About SSHD', url: 'https://www.ssh.com/ssh/sshd_config/'
    describe command('sshd -T 2> /dev/null | grep x11forwarding ') do
        its('stdout') { should match /yes/ }
    end
end

control "linux-ssh-max-auth " do
    title "Ensure SSH MaxAuthTries is set to 4 or less"
    desc "The MaxAuthTries parameter specifies the maximum number of authentication attempts
    permitted per connection. When the login failure count reaches half the number, error
    messages will be written to the syslog file detailing the login failure.
    Setting the MaxAuthTries parameter to a low number will minimize the risk of successful
    brute force attacks to the SSH server. While the recommended setting is 4, set the number
    based on site policy.
    "
    impact 0.5
    tag Vulnerability: 'High'
    tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
    tag Remedy:"Edit the /etc/ssh/sshd_config file to set the parameter as follows:
    MaxAuthTries 4"
    ref 'About Max Auth Tries', url: 'https://unix.stackexchange.com/questions/418582/in-sshd-config-maxauthtries-limits-the-number-of-auth-failures-per-connection'
    describe command('sshd -T 2> /dev/null | grep maxauthtries ') do
        its('stdout') { should match /4/ }
    end
end

control "linux-ssh-rhost " do
    title "Ensure SSH IgnoreRhosts is enabled"
    desc "The IgnoreRhosts parameter specifies that .rhosts and .shosts files will not be used in
    RhostsRSAAuthentication or HostbasedAuthentication .
    "
    impact 0.5
    tag Vulnerability: 'Medium'
    tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
    tag Remedy:"Edit the /etc/ssh/sshd_config file to set the parameter as follows:
    IgnoreRhosts yes"
    ref 'About SSHD', url: 'https://www.ssh.com/ssh/sshd_config/'
    describe command('sshd -T 2> /dev/null | grep ignorerhosts') do
        its('stdout') { should match /yes/ }
    end
end

control "linux-ssh-hostbased-authentication " do
    title "Ensure SSH HostbasedAuthentication is disabled"
    desc "The HostbasedAuthentication parameter specifies if authentication is allowed through
    trusted hosts via the user of .rhosts , or /etc/hosts.equiv , along with successful public
    key client host authentication. This option only applies to SSH Protocol Version 2.
    Even though the .rhosts files are ineffective if support is disabled in /etc/pam.conf ,
    disabling the ability to use .rhosts files in SSH provides an additional layer of protection.
    "
    impact 0.5
    tag Vulnerability: 'Medium'
    tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
    tag Remedy:"Edit the /etc/ssh/sshd_config file to set the parameter as follows:
    HostbasedAuthentication no"
    ref 'About SSHD', url: 'https://www.ssh.com/ssh/sshd_config/'
    describe command('sshd -T 2> /dev/null | grep hostbasedauthentication') do
        its('stdout') { should match /no/ }
    end
end

control "linux-ssh-root-login " do
    title "Ensure SSH root login is disabled"
    desc "The PermitRootLogin parameter specifies if the root user can log in using ssh. The default
    is no.
    Disallowing root logins over SSH requires system admins to authenticate using their own
    individual account, then escalating to root via sudo or su . This in turn limits opportunity for
    non-repudiation and provides a clear audit trail in the event of a security incident
    "
    impact 0.5
    tag Vulnerability: 'High'
    tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
    tag Remedy:"Edit the /etc/ssh/sshd_config file to set the parameter as follows:
    PermitRootLogin no "
    ref 'About SSHD', url: 'https://www.ssh.com/ssh/sshd_config/'
    describe command('sshd -T 2> /dev/null | grep permitrootlogin') do
        its('stdout') { should match /no/ }
    end
end


control "linux-ssh-permit-empty-password " do
    title "Ensure SSH PermitEmptyPasswords is disabled"
    desc "The PermitEmptyPasswords parameter specifies if the SSH server allows login to accounts
    with empty password strings.
    Disallowing remote shell access to accounts that have an empty password reduces the
    probability of unauthorized access to the system
    "
    impact 0.5
    tag Vulnerability: 'Critical'
    tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
    tag Remedy:"Edit the /etc/ssh/sshd_config file to set the parameter as follows:
    PermitEmptyPasswords no "
    ref 'About SSHD', url: 'https://www.ssh.com/ssh/sshd_config/'
    describe command('sshd -T 2> /dev/null | grep permitemptypasswords') do
        its('stdout') { should match /no/ }
    end
end

control "linux-ssh-PermitUserEnvironment" do
    title "Ensure SSH PermitUserEnvironment is disabled"
    desc "The PermitUserEnvironment option allows users to present environment options to the
    ssh daemon.
    Permitting users the ability to set environment variables through the SSH daemon could
    potentially allow users to bypass security controls (e.g. setting an execution path that has
    ssh executing trojan'd programs)
    "
    impact 0.5
    tag Vulnerability: 'High'
    tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
    tag Remedy:"Edit the /etc/ssh/sshd_config file to set the parameter as follows:
    PermitUserEnvironment no "
    ref 'About SSHD', url: 'https://www.ssh.com/ssh/sshd_config/'
    describe command('sshd -T 2> /dev/null | grep permituserenvironment') do
        its('stdout') { should match /no/ }
    end
end

control "linux-ssh-PermitUserEnvironment" do
    title "Ensure SSH PermitUserEnvironment is disabled"
    desc "The PermitUserEnvironment option allows users to present environment options to the
    ssh daemon.
    Permitting users the ability to set environment variables through the SSH daemon could
    potentially allow users to bypass security controls (e.g. setting an execution path that has
    ssh executing trojan'd programs)
    "
    impact 0.5
    tag Vulnerability: 'High'
    tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
    tag Remedy:"Edit the /etc/ssh/sshd_config file to set the parameter as follows:
    PermitUserEnvironment no "
    ref 'About SSHD', url: 'https://www.ssh.com/ssh/sshd_config/'
    describe command('sshd -T 2> /dev/null | grep permituserenvironment') do
        its('stdout') { should match /no/ }
    end
end

control "linux-ssh-ciphers" do
    title "Ensure only strong Ciphers are used"
    desc "Weak ciphers that are used for authentication to the cryptographic module cannot be relied
    upon to provide confidentiality or integrity, and system data may be compromised.

    "
    impact 0.5
    tag Vulnerability: 'High'
    tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
    tag Remedy:"Edit the /etc/ssh/sshd_config file add/modify the Ciphers line to contain a comma
    separated list of the site approved ciphers
    Example:
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
    ref 'About SSHD', url: 'https://www.ssh.com/ssh/sshd_config/'
    describe command('sshd -T 2> /dev/null | grep ciphers') do
        its('stdout') { should_not match /3des-cbc|aes128-cbc|aes192-cbc|aes256-cbc|arcfour|arcfour128|arcfour256|blowfish-cbc|cast128-cbc|rijndael-cbc@lysator.liu.se/ }
    end
end

control "linux-ssh-Mac-algorithms" do
    title "Ensure only strong MAC algorithms are used"
    desc "MD5 and 96-bit MAC algorithms are considered weak and have been shown to increase
    exploitability in SSH downgrade attacks. Weak algorithms continue to have a great deal of
    attention as a weak spot that can be exploited with expanded computing power. An
    attacker that breaks the algorithm could take advantage of a MiTM position to decrypt the
    SSH tunnel and capture credentials and information
    "
    impact 0.5
    tag Vulnerability: 'High'
    tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
    tag Remedy:"Edit the /etc/ssh/sshd_config file and add/modify the MACs line to contain a comma
    separated list of the site approved MACs
    Example:
    MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"
    ref 'About SSHD', url: 'https://www.ssh.com/ssh/sshd_config/'
    describe command('sshd -T 2> /dev/null | grep -i "MACs"') do
        its('stdout') { should_not match /hmac-md5|hmac-md5-96|hmac-ripemd160|hmac-sha1|hmac-sha1-96|umac-64@openssh.com|umac-128@openssh.com|hmac-md5-etm@openssh.com|hmac-md5-96-etm@openssh.com|hmac-ripemd160-etm@openssh.com|hmac-sha1-etm@openssh.com|hmac-sha1-96-etm@openssh.com|umac-64-etm@openssh.com|umac-128-etm@openssh.com/ }
    end
end

control "linux-ssh-key-exchange" do
    title "Ensure only strong Key Exchange algorithms are used"
    desc "Key exchange is any method in cryptography by which cryptographic keys are exchanged between two parties,
    allowing use of a cryptographic algorithm. If the sender and receiver wish to exchange encrypted messages,
    each must be equipped to encrypt messages to be sent and decrypt messages received.
    Key exchange methods that are considered weak should be removed. 
    A key exchange method may be weak because too few bits are used, or the hashing algorithm is considered too weak. 
    Using weak algorithms could expose connections to man-in-the-middle attacks
    "
    impact 0.5
    tag Vulnerability: 'High'
    tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
    tag Remedy:"Edit the /etc/ssh/sshd_config file add/modify the KexAlgorithms line to contain a comma
    separated list of the site approved key exchange algorithms
    Example:
    KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-
    group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-
    sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-
    hellman-group-exchange-sha256"
    ref 'About SSHD', url: 'https://www.ssh.com/ssh/sshd_config/'
    describe command('sshd -T 2> /dev/null | grep  kexalgorithms') do
        its('stdout') { should_not match /diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1/ }
    end
end

control "linux-ssh-idle-timeout" do
    title "Ensure SSH Idle Timeout Interval is configured"
    desc "The two options ClientAliveInterval and ClientAliveCountMax control the timeout of
    ssh sessions. When the ClientAliveInterval variable is set, ssh sessions that have no
    activity for the specified length of time are terminated. When the ClientAliveCountMax
    variable is set, sshd will send client alive messages at every ClientAliveInterval interval.
    When the number of consecutive client alive messages are sent with no response from the
    client, the ssh session is terminated. For example, if the ClientAliveInterval is set to 15
    seconds and the ClientAliveCountMax is set to 3, the client ssh session will be terminated
    after 45 seconds of idle time.
    "
    impact 0.5
    tag Vulnerability: 'High'
    tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
    tag Remedy:"Edit the /etc/ssh/sshd_config file to set the parameters according to site policy:
    ClientAliveInterval 300
    ClientAliveCountMax 0"
    ref 'About SSHD', url: 'https://www.ssh.com/ssh/sshd_config/'
    describe command('sshd -T 2> /dev/null | grep  clientaliveinterval') do
        its('stdout') { should match /300/ }
    end
    describe command('sshd -T 2> /dev/null | grep  clientalivecountmax') do
        its('stdout') { should match /0/ }
    end
end

control "linux-ssh-login-grace-time" do
    title "Ensure SSH LoginGraceTime is set to one minute or less"
    desc "The LoginGraceTime parameter specifies the time allowed for successful authentication to
    the SSH server. The longer the Grace period is the more open unauthenticated connections
    can exist. Like other session controls in this session the Grace Period should be limited to
    appropriate organizational limits to ensure the service is available for needed access.
    "
    impact 0.5
    tag Vulnerability: 'Medium'
    tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
    tag Remedy:"Edit the /etc/ssh/sshd_config file to set the parameters according to site policy:
    LoginGraceTime 60 "
    ref 'About SSHD', url: 'https://www.ssh.com/ssh/sshd_config/'
    describe command('sshd -T 2> /dev/null | grep  logingracetime') do
        its('stdout') { should match /60/ }
    end
end

control "linux-ssh-access-limited" do
    title "Ensure SSH access is limited"
    desc "There are several options available to limit which users and group can access the system
    via SSH. It is recommended that at least one of the following options be leveraged:
    AllowUsers
    The AllowUsers variable gives the system administrator the option of allowing specific
    users to ssh into the system. The list consists of space separated user names. Numeric user
    IDs are not recognized with this variable. If a system administrator wants to restrict user
    access further by only allowing the allowed users to log in from a particular host, the entry
    can be specified in the form of user@host.
    Similarly for 
    AllowGroups, DenyUsers, DenyGroups
    
    "
    impact 0.5
    tag Vulnerability: 'High'
    tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
    tag Remedy:"Edit the /etc/ssh/sshd_config file to set one or more of the parameter as follows:
    AllowUsers <userlist>
    DenyUsers <userlist>
    AllowGroups <grouplist>
    DenyGroups <grouplist>"
    ref 'About SSHD', url: 'https://www.ssh.com/ssh/sshd_config/'
    describe command('sshd -T 2> /dev/null | grep  allowusers') do
        its('stdout') { should_not match // }
    end
    describe command('sshd -T 2> /dev/null | grep  denyusers') do
        its('stdout') { should_not match // }
    end
    describe command('sshd -T 2> /dev/null | grep  allowgroups') do
        its('stdout') { should_not match // }
    end
    describe command('sshd -T 2> /dev/null | grep  denygroups') do
        its('stdout') { should_not match // }
    end
end

control "linux-ssh-warning-banner" do
    title "Ensure SSH warning banner is configured"
    desc "The Banner parameter specifies a file whose contents must be sent to the remote user
    before authentication is permitted. By default, no banner is displayed.
    Banners are used to warn connecting users of the particular site's policy regarding
    connection. Presenting a warning message prior to the normal user login may assist the
    prosecution of trespassers on the computer system."
    impact 0.5
    tag Vulnerability: 'Medium'
    tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
    tag Remedy:"Edit the /etc/ssh/sshd_config file to set one or more of the parameter as follows:
    Banner /etc/issue.net"
    ref 'About SSHD', url: 'https://www.ssh.com/ssh/sshd_config/'
    describe command('sshd -T 2> /dev/null | grep banner') do
        its('stdout') { should_not match /none/ }
    end   
end

control "linux-ssh-pam" do
    title "Ensure SSH PAM is enabled"
    desc "UsePAM Enables the Pluggable Authentication Module interface. If set to “yes” this will
    enable PAM authentication using ChallengeResponseAuthentication and
    PasswordAuthentication in addition to PAM account and session module processing for all
    authentication types
    When usePAM is set to yes, PAM runs through account and session types properly. This is
    important if you want to restrict access to services based off of IP, time or other factors of
    the account. Additionally, you can make sure users inherit certain environment variables
    on login or disallow access to the server"
    impact 0.5
    tag Vulnerability: 'High'
    tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
    tag Remedy:"Edit the /etc/ssh/sshd_config file to set one or more of the parameter as follows:
    UsePAM yes"
    ref 'About SSHD', url: 'https://www.ssh.com/ssh/sshd_config/'
    describe command('sshd -T 2> /dev/null | grep usepam') do
        its('stdout') { should match /yes/ }
    end
end

control "linux-ssh-tcp-forward" do
    title "Ensure SSH AllowTcpForwarding is disabled"
    desc "SSH port forwarding is a mechanism in SSH for tunneling application ports from the client to the server,
    or servers to clients. It can be used for adding encryption to legacy applications, going through firewalls, 
    and some system administrators and IT professionals use it for opening backdoors into the internal network from their 
    home machines. Leaving port forwarding enabled can expose the organization to security risks and back-
    doors. 
    SSH connections are protected with strong encryption. This makes their contents invisible 
    to most deployed network monitoring and traffic filtering solutions. This invisibility carries 
    considerable risk potential if it is used for malicious purposes such as data exfiltration. 
    Cybercriminals or malware could exploit SSH to hide their unauthorized communications, or to exfiltrate stolen data from the target network"
    impact 0.5
    tag Vulnerability: 'High'
    tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
    tag Remedy:"Edit the /etc/ssh/sshd_config file to set the parameter as follows: AllowTcpForwarding no"
    ref 'About SSHD', url: 'https://www.ssh.com/ssh/sshd_config/'
    describe command('sshd -T 2> /dev/null | grep allowtcpforwarding') do
        its('stdout') { should match /no/ }
    end 
end

control "linux-ssh-maxstartup" do
    title "Ensure SSH MaxStartups is configured"
    desc "The MaxStartups parameter specifies the maximum number of concurrent unauthenticated connections to the SSH daemon. 
    To protect a system from denial of service due to a large number of pending authentication 
    connection attempts, use the rate limiting function of MaxStartups to protect availability of 
    sshd logins and prevent overwhelming the daemon."
    impact 0.5
    tag Vulnerability: 'Medium'
    tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
    tag Remedy:"Edit the /etc/ssh/sshd_config file to set the parameter as follows: maxstartups 10:30:60"
    ref 'About SSHD', url: 'https://www.ssh.com/ssh/sshd_config/'
    describe command('sshd -T 2> /dev/null | grep maxstartups') do
        its('stdout') { should match /10:30:60/ }
    end 
end

control "linux-ssh-max-session" do
    title "Ensure SSH MaxSessions is set to 4 or less"
    desc "
    The MaxSessions parameter specifies the maximum number of open sessions permitted from a given connection. 
    To protect a system from denial of service due to a large number of concurrent sessions, use the rate limiting function of MaxSessions to protect availability of sshd logins and prevent overwhelming the daemon.
    "
    impact 0.5
    tag Vulnerability: 'High'
    tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
    tag Remedy:"Edit the /etc/ssh/sshd_config file to set the parameter as follows: MaxSessions 4"
    ref 'About SSHD', url: 'https://www.ssh.com/ssh/sshd_config/'
    describe command('sshd -T 2> /dev/null | grep maxsessions') do
        its('stdout') { should match /4/ }
    end 
end
