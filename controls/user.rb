

control "linux-user-password-expiration-maximum-days" do
    title "Ensure password expiration is 365 days or less"
    desc "The PASS_MAX_DAYS parameter in /etc/login.defs allows an administrator to force
    passwords to expire once they reach a defined age. It is recommended that the
    PASS_MAX_DAYS parameter be set to less than or equal to 365 days.
    The window of opportunity for an attacker to leverage compromised credentials or
    successfully compromise credentials via an online brute force attack is limited by the age of
    the password. Therefore, reducing the maximum age of a password also reduces an
    attacker's window of opportunity."
    impact 0.5
    tag Vulnerability: 'High'
    tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
    tag Remedy:"Set the PASS_MAX_DAYS parameter to conform to site policy in /etc/login.defs :
    PASS_MAX_DAYS 365"
    ref 'About login.defs', url: 'https://www.thegeekdiary.com/understanding-etclogin-defs-file/#:~:text=The%20%2Fetc%2Flogin.,directive%20name%20and%20associated%20value.'
    describe command('grep "PASS_MAX_DAYS.*.[0-9]" /etc/login.defs') do
      its('stdout') { should match /365/ }
    end
  end

control "linux-user-password-expiration-minimum-days" do
    title "Ensure minimum days between password changes is 7 or more"
    desc "The PASS_MIN_DAYS parameter in /etc/login.defs allows an administrator to prevent
    users from changing their password until a minimum number of days have passed since the
    last time the user changed their password. It is recommended that PASS_MIN_DAYS
    parameter be set to 7 or more days.
    By restricting the frequency of password changes, an administrator can prevent users from
    repeatedly changing their password in an attempt to circumvent password reuse controls.
    "
    impact 0.5
    tag Vulnerability: 'Medium'
    tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
    tag Remedy:"Set the PASS_MIN_DAYS parameter to 7 in /etc/login.defs :
    PASS_MIN_DAYS 7"
    ref 'About login.defs', url: 'https://www.thegeekdiary.com/understanding-etclogin-defs-file/#:~:text=The%20%2Fetc%2Flogin.,directive%20name%20and%20associated%20value.'
    describe command('grep "PASS_MIN_DAYS.*[0-9]" /etc/login.defs') do
      its('stdout') { should match /7/ }
    end
  end

control "linux-user-password-expiration-warning" do
    title "Ensure password expiration warning days is 7 or more"
    desc "The PASS_WARN_AGE parameter in /etc/login.defs allows an administrator to notify users
    that their password will expire in a defined number of days. It is recommended that the
    PASS_WARN_AGE parameter be set to 7 or more days.
    Providing an advance warning that a password will be expiring gives users time to think of
    a secure password. Users caught unaware may choose a simple password or write it down
    where it may be discovered.
    "
    impact 0.5
    tag Vulnerability: 'Medium'
    tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
    tag Remedy:"Set the PASS_WARN_AGE parameter to 7 in /etc/login.defs :
    PASS_WARN_AGE 7"
    ref 'About login.defs', url: 'https://www.thegeekdiary.com/understanding-etclogin-defs-file/#:~:text=The%20%2Fetc%2Flogin.,directive%20name%20and%20associated%20value.'
    describe command('grep "PASS_WARN_AGE.*[0-9]" /etc/login.defs') do
      its('stdout') { should match /7/ }
    end
  end

control "linux-user-password-expiration-warning" do
    title "Ensure password expiration warning days is 7 or more"
    desc "The PASS_WARN_AGE parameter in /etc/login.defs allows an administrator to notify users
    that their password will expire in a defined number of days. It is recommended that the
    PASS_WARN_AGE parameter be set to 7 or more days.
    Providing an advance warning that a password will be expiring gives users time to think of
    a secure password. Users caught unaware may choose a simple password or write it down
    where it may be discovered.
    "
    impact 0.5
    tag Vulnerability: 'Medium'
    tag Version: 'CIS_Distribution_Independent_Linux_Benchmark_v2.0.0'
    tag Remedy:"Set the PASS_WARN_AGE parameter to 7 in /etc/login.defs :
    PASS_WARN_AGE 7"
    ref 'About login.defs', url: 'https://www.thegeekdiary.com/understanding-etclogin-defs-file/#:~:text=The%20%2Fetc%2Flogin.,directive%20name%20and%20associated%20value.'
    describe command('grep "PASS_WARN_AGE.*[0-9]" /etc/login.defs') do
      its('stdout') { should match /7/ }
    end
  end