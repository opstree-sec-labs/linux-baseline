# This block mainly contains checks related to 
# Passwd
control "linux-system-/etc/passwd-owners" do
    title "Ensure permissions on /etc/passwd are configured"
    desc "The /etc/passwd file contains user account information that is used by many system
    utilities and therefore must be readable for these utilities to operate.
    It is critical to ensure that the /etc/passwd file is protected from unauthorized write
    access. Although it is protected by default, the file permissions could be changed either
    inadvertently or through malicious actions.
    It's owner and group should be root"

    impact 1.0
    tag Vulnerability: 'Critical'
    tag Version: 'passwdCIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
    tag Remedy:"Execute following commands to change owner
                chown root:root /etc/passwd"
    ref 'About /etc/passwd', url: 'https://linuxize.com/post/etc-passwd-file/#:~:text=%2Fetc%2Fpasswd%20is%20a%20plain,readable%20by%20all%20system%20users.'
    describe file("/etc/passwd") do
        it { should exist }
        its('group') { should eq 'root' }
        its('owner') { should eq 'root' }
      end
    end


control "linux-system-/etc/passwd-file-permission" do
    title "Ensure permissions on /etc/passwd are configured"
    desc "The /etc/passwd file contains user account information that is used by many system
    utilities and therefore must be readable for these utilities to operate.
    It is critical to ensure that the /etc/passwd file is protected from unauthorized write
    access. Although it is protected by default, the file permissions could be changed either
    inadvertently or through malicious actions.
    It should not be writable by others"

    impact 1.0
    tag Vulnerability: 'Critical'
    tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
    tag Remedy:"Execute following commands to change permission
                chmod 644 /etc/passwd"
    ref 'About /etc/passwd', url: 'https://linuxize.com/post/etc-passwd-file/#:~:text=%2Fetc%2Fpasswd%20is%20a%20plain,readable%20by%20all%20system%20users.'
    describe file("/etc/passwd") do
        it { should exist }
        its('mode') { should cmp '0644' }
        it { should_not  be_writable.by('group') }
        it { should_not be_writable.by('other') }
      end
    end

# End of Passwd 
# Start of Shadow

control "linux-system-/etc/shadow-owners" do
    title "Ensure permissions on /etc/shadow are configured"
    desc "The /etc/shadow file is used to store the information about user accounts that is critical to
    the security of those accounts, such as the hashed password and other security
    information.
    If attackers can gain read access to the /etc/shadow file, they can easily run a password
    cracking program against the hashed password to break it. Other security information that
    is stored in the /etc/shadow file (such as expiration) could also be useful to subvert the
    user accounts
    It's owner should be root and group should be shadow.
    "
    impact 1.0
    tag Vulnerability: 'Critical'
    tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
    tag Remedy:"Execute following commands to change owner
                chown root:shadow /etc/shadow"
    ref 'About /etc/shadow', url: 'https://www.cyberciti.biz/faq/understanding-etcshadow-file/'
    describe file("/etc/shadow") do
        it { should exist }
        its('group') { should eq 'shadow' }
        its('owner') { should eq 'root' }
      end
    end

control "linux-system-/etc/shadow-file-permission" do
    title "Ensure permissions on /etc/shadow are configured"
    desc "The /etc/shadow file is used to store the information about user accounts that is critical to
    the security of those accounts, such as the hashed password and other security
    information.
    If attackers can gain read access to the /etc/shadow file, they can easily run a password
    cracking program against the hashed password to break it. Other security information that
    is stored in the /etc/shadow file (such as expiration) could also be useful to subvert the
    user accounts
    It's permission should be 640.
    "
    impact 1.0
    tag Vulnerability: 'Critical'
    tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
    tag Remedy:"Execute following commands to change permission
                chmod 640 /etc/shadow"
    ref 'About /etc/shadow', url: 'https://www.cyberciti.biz/faq/understanding-etcshadow-file/'
    describe file("/etc/shadow") do
        it { should exist }
        its('mode') { should cmp '0640' }
        it { should_not  be_writable.by('group') }
        it { should_not be_writable.by('other') }
        it { should_not be_readable.by('other') }
      end
    end

# End of Shadow

# Start of /etc/group

control "linux-system-/etc/group-owners" do
  title "Ensure permissions on /etc/group are configured"
  desc "The /etc/group file contains a list of all the valid groups defined in the system.
  The /etc/group file needs to be protected from unauthorized changes by non-privileged
  users, but needs to be readable as this information is used with many non-privileged
  programs.
  It's owner and group should be root.
  "
  impact 1.0
  tag Vulnerability: 'Critical'
  tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
  tag Remedy:"Execute following commands to change owner
              chown root:root /etc/group"
  ref 'About /etc/groups', url: 'https://www.cyberciti.biz/faq/understanding-etcgroup-file/'
  describe file("/etc/group") do
      it { should exist }
      its('group') { should eq 'root' }
      its('owner') { should eq 'root' }
    end
  end

control "linux-system-/etc/group-permission" do
  title "Ensure permissions on /etc/group are configured"
  desc "The /etc/group file contains a list of all the valid groups defined in the system.
  The /etc/group file needs to be protected from unauthorized changes by non-privileged
  users, but needs to be readable as this information is used with many non-privileged
  programs.
  It's permission should be 644.
  "
  impact 1.0
  tag Vulnerability: 'Critical'
  tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
  tag Remedy:"Execute following commands to change permission
              chmod 644 /etc/group"
  ref 'About /etc/group', url: 'https://www.cyberciti.biz/faq/understanding-etcgroup-file/'
  describe file("/etc/group") do
      it { should exist }
      its('mode') { should cmp '0644' }
      it { should_not  be_writable.by('group') }
      it { should_not be_writable.by('other') }
    end
  end

# End of /etc/group

# Start of /etc/gshadow

control "linux-system-/etc/gshadow-owners" do
  title "Ensure permissions on /etc/gshadow are configured"
  desc "The /etc/gshadow file is used to store the information about groups that is critical to the
  security of those accounts, such as the hashed password and other security information.
  It's owner should be root and group should be shadow.
  "
  impact 1.0
  tag Vulnerability: 'Critical'
  tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
  tag Remedy:"Execute following commands to change owner
              chown root:shadow /etc/gshadow"
  ref 'About /etc/gshadow', url: 'https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/4/html/introduction_to_system_administration/s3-acctsgrps-gshadow'
  describe file("/etc/gshadow") do
      it { should exist }
      its('group') { should eq 'shadow' }
      its('owner') { should eq 'root' }
    end
  end

control "linux-system-/etc/gshadow-permission" do
  title "Ensure permissions on /etc/gshadow are configured"
  desc "The /etc/gshadow file is used to store the information about groups that is critical to the
  security of those accounts, such as the hashed password and other security information.
  It's permission should be 644.
  "
  impact 1.0
  tag Vulnerability: 'Critical'
  tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
  tag Remedy:"Execute following commands to change permission
              chmod 640 /etc/gshadow"
  ref 'About /etc/gshadow', url: 'https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/4/html/introduction_to_system_administration/s3-acctsgrps-gshadow'
  describe file("/etc/gshadow") do
      it { should exist }
      its('mode') { should cmp '0640' }
      it { should_not  be_writable.by('group') }
      it { should_not  be_readable.by('other') }
      it { should_not  be_writable.by('other') }
    end
  end

# End of /etc/gshadow

## backup files
# Passwd -
control "linux-system-(/etc/passwd-)-owners" do
  title "Ensure permissions on /etc/passwd- are configured"
  desc "The /etc/passwd- is a backup file maintained by several utility which uses /etc/passwd.
  Like /etc/passwd it contain several sensitive information.
  It's owner and group should be root"

  impact 1.0
  tag Vulnerability: 'Critical'
  tag Version: 'passwdCIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
  tag Remedy:"Execute following commands to change owner
              chown root:root /etc/passwd-"
  ref 'About /etc/passwd', url: 'https://linuxize.com/post/etc-passwd-file/#:~:text=%2Fetc%2Fpasswd%20is%20a%20plain,readable%20by%20all%20system%20users.'
  describe file("/etc/passwd-") do
      it { should exist }
      its('group') { should eq 'root' }
      its('owner') { should eq 'root' }
    end
  end


control "linux-system-(/etc/passwd-)-file-permission" do
  title "Ensure permissions on /etc/passwd are configured"
  desc "The /etc/passwd- is a backup file maintained by several utility which uses /etc/passwd.
  Like /etc/passwd it contain several sensitive information.
  It should not be writable by others"

  impact 1.0
  tag Vulnerability: 'Critical'
  tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
  tag Remedy:"Execute following commands to change permission
              chmod 644 /etc/passwd-"
  ref 'About /etc/passwd', url: 'https://linuxize.com/post/etc-passwd-file/#:~:text=%2Fetc%2Fpasswd%20is%20a%20plain,readable%20by%20all%20system%20users.'
  describe file("/etc/passwd-") do
      it { should exist }
      its('mode') { should cmp '0644' }
      it { should_not  be_writable.by('group') }
      it { should_not be_writable.by('other') }
    end
  end

# End of Passwd-
# Start of Shadow-

control "linux-system-(/etc/shadow-)-owners" do
  title "Ensure permissions on /etc/shadow are configured"
  desc "The /etc/shadow- is a backup file maintained by several utility which uses /etc/shadow.
  Like /etc/shadow it contain several sensitive information.
  It's owner should be root and group should be shadow.
  "
  impact 1.0
  tag Vulnerability: 'Critical'
  tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
  tag Remedy:"Execute following commands to change owner
              chown root:shadow /etc/shadow-"
  ref 'About /etc/shadow', url: 'https://www.cyberciti.biz/faq/understanding-etcshadow-file/'
  describe file("/etc/shadow-") do
      it { should exist }
      its('group') { should eq 'shadow' }
      its('owner') { should eq 'root' }
    end
  end

control "linux-system-(/etc/shadow-)-file-permission" do
  title "Ensure permissions on /etc/shadow are configured"
  desc "The /etc/shadow- is a backup file maintained by several utility which uses /etc/shadow.
  Like /etc/shadow it contain several sensitive information.
  It's permission should be 640.
  "
  impact 1.0
  tag Vulnerability: 'Critical'
  tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
  tag Remedy:"Execute following commands to change permission
              chmod 640 /etc/shadow-"
  ref 'About /etc/shadow', url: 'https://www.cyberciti.biz/faq/understanding-etcshadow-file/'
  describe file("/etc/shadow-") do
      it { should exist }
      its('mode') { should cmp '0640' }
      it { should_not  be_writable.by('group') }
      it { should_not be_writable.by('other') }
      it { should_not be_readable.by('other') }
    end
  end

# End of Shadow
# Start of /etc/group

control "linux-system-(/etc/group-)-owners" do
title "Ensure permissions on /etc/group are configured"
desc "The /etc/group- is a backup file maintained by several utility which uses /etc/group.
Like /etc/group it contain several sensitive information.
It's owner and group should be root.
"
impact 1.0
tag Vulnerability: 'Critical'
tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
tag Remedy:"Execute following commands to change owner
            chown root:root /etc/group-"
ref 'About /etc/groups', url: 'https://www.cyberciti.biz/faq/understanding-etcgroup-file/'
describe file("/etc/group-") do
    it { should exist }
    its('group') { should eq 'root' }
    its('owner') { should eq 'root' }
  end
end

control "linux-system-(/etc/group-)-permission" do
title "Ensure permissions on /etc/group are configured"
desc "The /etc/group- is a backup file maintained by several utility which uses /etc/group.
Like /etc/group it contain several sensitive information.
It's permission should be 644.
"
impact 1.0
tag Vulnerability: 'Critical'
tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
tag Remedy:"Execute following commands to change permission
            chmod 644 /etc/group-"
ref 'About /etc/group', url: 'https://www.cyberciti.biz/faq/understanding-etcgroup-file/'
describe file("/etc/group-") do
    it { should exist }
    its('mode') { should cmp '0644' }
    it { should_not  be_writable.by('group') }
    it { should_not be_writable.by('other') }
  end
end

# End of /etc/group
# Start of /etc/gshadow

control "linux-system-(/etc/gshadow-)-owners" do
title "Ensure permissions on /etc/gshadow are configured"
desc "The /etc/gshadow- is a backup file maintained by several utility which uses /etc/gshadow.
Like /etc/gshadow it contain several sensitive information.
It's owner should be root and group should be shadow.
"
impact 1.0
tag Vulnerability: 'Critical'
tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
tag Remedy:"Execute following commands to change owner
            chown root:shadow /etc/gshadow-"
ref 'About /etc/gshadow', url: 'https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/4/html/introduction_to_system_administration/s3-acctsgrps-gshadow'
describe file("/etc/gshadow-") do
    it { should exist }
    its('group') { should eq 'shadow' }
    its('owner') { should eq 'root' }
  end
end

control "linux-system-(/etc/gshadow-)-permission" do
title "Ensure permissions on /etc/gshadow are configured"
desc "The /etc/gshadow- is a backup file maintained by several utility which uses /etc/gshadow.
Like /etc/gshadow it contain several sensitive information.
It's permission should be 640.
"
impact 1.0
tag Vulnerability: 'Critical'
tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
tag Remedy:"Execute following commands to change permission
            chmod 640 /etc/gshadow-"
ref 'About /etc/gshadow', url: 'https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/4/html/introduction_to_system_administration/s3-acctsgrps-gshadow'
describe file("/etc/gshadow-") do
    it { should exist }
    its('mode') { should cmp '0640' }
    it { should_not  be_writable.by('group') }
    it { should_not  be_readable.by('other') }
    it { should_not  be_writable.by('other') }
  end
end
# End of /etc/gshadow

# Nobody
control "linux-system-files-with-no-owner" do
  title "Ensure no unowned files or directories exist"
  desc "Sometimes when administrators delete users they neglect to
  remove all files owned by those users from the system.
  A new user who is assigned the deleted user's user ID or group ID may then end up
  owning these files, and thus have more access on the system than was intended.
  "
  impact 1.0
  tag Vulnerability: 'Critical'
  tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
  tag Remedy:"Reset the owners of these files."
  ref 'What happens to file owned by deleted user', url: 'https://serverfault.com/questions/397982/what-happens-to-a-users-files-when-i-delete-the-user-in-linux#:~:text=So%20by%20default%2C%20nothing%20happens,group%20IDs%20as%20they%20are.&text=userdel%20(and%20deluser%20)%20do%20have,search%2Dand%2Ddestroy%20operation.'
  describe command("df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser") do
    its(:stdout) { should match /''/ }
  end
end

#nogroup
control "linux-system-files-with-no-group" do
  title "Ensure no ungrouped files or directories exist"
  desc "Sometimes when administrators delete users or groups from the system they neglect to
  remove all files owned by those users or groups.
  A new group who is assigned the deleted  group ID may then end up
  owning these files, and thus have more access on the system than was intended.
  "
  impact 1.0
  tag Vulnerability: 'Critical'
  tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
  tag Remedy:"Reset the group of these files."
  ref 'What happens to file owned by deleted group', url: 'https://serverfault.com/questions/397982/what-happens-to-a-users-files-when-i-delete-the-user-in-linux#:~:text=So%20by%20default%2C%20nothing%20happens,group%20IDs%20as%20they%20are.&text=userdel%20(and%20deluser%20)%20do%20have,search%2Dand%2Ddestroy%20operation.'
  describe command("df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup") do
    its(:stdout) { should match /''/ }
  end
end
