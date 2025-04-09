logical_impact_definition = """
Logical Impact describes the potential impacts that an exploit can create on a target system. 
It focuses on the outcomes of unauthorized actions, such as data modification, information disclosure, service interruptions, and privilege escalation, resulting from exploiting system vulnerabilities.
"""

logical_impact_desc = """
Logical Impact:
________________________________________
1. Read
•	Definition: Indicates whether the attacker is able to gain unauthorized access to data.
•	Examples:
o	Reading sensitive database records without authorization.
o	Extracting data from memory through unintended leaks.
•	Common Methods:
o	Abusing weak access controls on files or databases.
o	Exploiting directory traversal vulnerabilities to access restricted files.

2. Write
•	Definition: A vulnerability is characterized by Write if an attacker can perform unauthorized modifications on the data.
•	Examples:
o	Changing configuration files to disrupt operations.
o	Altering database entries to manipulate stored information.
•	Common Methods:
o	Exploiting injection vulnerabilities to modify data.
o	Leveraging API misconfigurations to overwrite sensitive files.

________________________________________
3. Resource Removal
•	Definition: Represents an unauthorized removal (deletion) of data by an attacker.
•	Examples:
o	Deleting critical system logs to cover malicious activity.
o	Removing user data or backups to disrupt operations.
•	Common Methods:
o	Executing SQL injection to drop database tables.
o	Using malware to wipe storage devices.

________________________________________
4. Service Interrupt
•	Definition: An attacker causes a loss in the availability of a target system.
•	Examples:
o	Launching Distributed Denial of Service (DDoS) attacks.
o	Exploiting resource exhaustion vulnerabilities to crash services.
•	Common Methods:
o	Flooding network traffic to overwhelm the system.
o	Abusing poorly implemented resource management to force downtime.

________________________________________
5. Indirect Disclosure
•	Definition: An attacker can learn information about the target, not through a direct read operation, but through indirect methods like side-channel attacks or traffic analysis.
•	Examples:
o	Using timing analysis to deduce encryption keys.
o	Monitoring network traffic patterns to infer user behavior.
•	Common Methods:
o	Performing cache-based side-channel attacks.
o	Analyzing packet metadata to infer sensitive information.

________________________________________
6. Privilege Escalation
•	Definition: An adversary gains a level of privilege that is not intended for them.
•	Examples:
o	Gaining administrative access to a system through privilege escalation exploits.
o	Manipulating a vulnerability to perform unauthorized actions as a higher-privileged user.
•	Common Methods:
o	Abusing buffer overflow vulnerabilities to gain root privileges.
o	Exploiting misconfigured file permissions to elevate access levels.
"""


example_logical_impact_with_labels = """
This first example would fall under both 'Read' and 'Resource Removal':
    A vulnerability in the one-X Portal component of Avaya IP Office allows an authenticated attacker to read and delete arbitrary files on the system. Affected versions of Avaya IP Office include 9.1 through 9.1 SP12 10.0 through 10.0 SP7 and 10.1 through 10.1 SP2.
This next example would only fall under 'Resource Removal':
    A Directory Traversal issue was discovered in RubyGems 2.7.6 and later through 3.0.2. Before making new directories or touching files (which now include path-checking code for symlinks) it would delete the target destination. If that destination was hidden behind a symlink a malicious gem could delete arbitrary files on the users machine presuming the attacker could guess at paths. Given how frequently gem is run as sudo and how predictable paths are on modern systems (/tmp /usr etc.) this could likely lead to data loss or an unusable system.
This next example would fall under 'Service Interupt' only:
    A user authorized to perform database queries may cause denial of service by issuing specially crafted queries which violate an invariant in the query subsystems support for geoNear. This issue affects: MongoDB Inc. MongoDB Server v4.5 versions prior to 4.5.1; v4.4 versions prior to 4.4.0-rc7; v4.2 versions prior to 4.2.8; v4.0 versions prior to 4.0.19.
This next example falls under 'write':
    In generate_jsimd_ycc_rgb_convert_neon of jsimd_arm64_neon.S there is a possible out of bounds write due to a missing bounds check. This could lead to remote code execution in an unprivileged process with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-8.0 Android-8.1 Android-9 Android-10Android ID: A-120551338
This next example could fall under both 'Read' and 'Write':
    Memory access out of buffer boundaries issues was discovered in Contiki-NG 4.4 through 4.5 in the SNMP BER encoder/decoder. The length of provided input/output buffers is insufficiently verified during the encoding and decoding of data. This may lead to out-of-bounds buffer read or write access in BER decoding and encoding functions.
This next example would fall under 'Priviledge escalation':
    Huawei FusionComput 8.0.0 have an improper authorization vulnerability. A module does not verify some input correctly and authorizes files with incorrect access. Attackers can exploit this vulnerability to launch privilege escalation attack. This can compromise normal service.
This next example would fall under 'Read', 'Write', and 'Resource Removal':
    A command injection vulnerability is present that permits an unauthenticated user with access to the Aruba Instant web interface to execute arbitrary system commands within the underlying operating system. An attacker could use this ability to copy files read configuration write files delete files or reboot the device. Workaround: Block access to the Aruba Instant web interface from all untrusted users. Resolution: Fixed in Aruba Instant 4.2.4.12 6.5.4.11 8.3.0.6 and 8.4.0.1
This example would fall under 'Indirect Disclosure':
    In postNotification of ServiceRecord.java there is a possible bypass of foreground process restrictions due to an uncaught exception. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-8.1 Android-9Android ID: A-140108616
"""

# Logical Impact Prompts
one_shot_logical_impact_example = """
1. Read, Write, and Resource Removal example (occasionally descriptions might fall under more than one label like this one):
A command injection vulnerability is present that permits an unauthenticated user with access to the Aruba Instant web interface to execute arbitrary system commands within the underlying operating system. An attacker could use this ability to copy files read configuration write files delete files or reboot the device. Workaround: Block access to the Aruba Instant web interface from all untrusted users. Resolution: Fixed in Aruba Instant 4.2.4.12 6.5.4.11 8.3.0.6 and 8.4.0.1

2. Service Interrupt Examples:
A buffer overflow vulnerability in tiff12_print_page() in devices/gdevtfnx.c of Artifex Software GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is fixed in v9.51.

3. Indirect Disclosure
An information disclosure vulnerability exists when Microsoft SharePoint Server fails to properly handle objects in memory aka Microsoft SharePoint Information Disclosure Vulnerability.

4. Privilege Escalation Examples:
Buffer overflow in a subsystem for some Intel(R) Server Boards Server Systems and Compute Modules before version 1.59 may allow a privileged user to potentially enable escalation of privilege via local access.

"""

five_shot_logical_impact_example = """
1. Read, Write, and Resource Removal example (occasionally descriptions might fall under more than one label like this one):
    a. A command injection vulnerability is present that permits an unauthenticated user with access to the Aruba Instant web interface to execute arbitrary system commands within the underlying operating system. An attacker could use this ability to copy files read configuration write files delete files or reboot the device. Workaround: Block access to the Aruba Instant web interface from all untrusted users. Resolution: Fixed in Aruba Instant 4.2.4.12 6.5.4.11 8.3.0.6 and 8.4.0.1

2. Service Interrupt Examples:
    a. A buffer overflow vulnerability in tiff12_print_page() in devices/gdevtfnx.c of Artifex Software GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is fixed in v9.51.
    b. A vulnerability in the IPv6 implementation of Cisco StarOS could allow an unauthenticated remote attacker to cause a denial of service (DoS) condition on an affected device. The vulnerability is due to insufficient validation of incoming IPv6 traffic. An attacker could exploit this vulnerability by sending a crafted IPv6 packet to an affected device with the goal of reaching the vulnerable section of the input buffer. A successful exploit could allow the attacker to cause the device to reload resulting in a DoS condition. This vulnerability is specific to IPv6 traffic. IPv4 traffic is not affected.
    c. A vulnerability in the IPv6 packet processing engine of Cisco Small Business Smart and Managed Switches could allow an unauthenticated remote attacker to cause a denial of service (DoS) condition on an affected device. The vulnerability is due to insufficient validation of incoming IPv6 traffic. An attacker could exploit this vulnerability by sending a crafted IPv6 packet through an affected device. A successful exploit could allow the attacker to cause an unexpected reboot of the switch leading to a DoS condition. This vulnerability is specific to IPv6 traffic. IPv4 traffic is not affected.
    d. A buffer overflow vulnerability in pcx_write_rle() in contrib/japanese/gdev10v.c of Artifex Software GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is fixed in v9.51.

3. Indirect Disclosure
    a. An information disclosure vulnerability exists when Microsoft SharePoint Server fails to properly handle objects in memory aka Microsoft SharePoint Information Disclosure Vulnerability.
    b. An information disclosure vulnerability exists when the Windows kernel fails to properly initialize a memory address aka Windows Kernel Information Disclosure Vulnerability. This CVE ID is unique from CVE-2020-1367 CVE-2020-1389 CVE-2020-1426.
    c. An information disclosure vulnerability exists when the Windows kernel fails to properly initialize a memory address aka Windows Kernel Information Disclosure Vulnerability. This CVE ID is unique from CVE-2020-1367 CVE-2020-1419 CVE-2020-1426.
    d. An information disclosure vulnerability exists when the Windows kernel improperly handles objects in memory aka Windows Kernel Information Disclosure Vulnerability. This CVE ID is unique from CVE-2020-1367 CVE-2020-1389 CVE-2020-1419.
    e. An information disclosure vulnerability exists when the Windows kernel improperly handles objects in memory aka Windows Kernel Information Disclosure Vulnerability. This CVE ID is unique from CVE-2020-1389 CVE-2020-1419 CVE-2020-1426.

4. Privilege Escalation Examples:
    a. Buffer overflow in a subsystem for some Intel(R) Server Boards Server Systems and Compute Modules before version 1.59 may allow a privileged user to potentially enable escalation of privilege via local access.
    b. Improper permissions in the installer for the Intel(R) Mailbox Interface driver all versions may allow an authenticated user to potentially enable escalation of privilege via local access.
    c. Improper permissions in the installer for the Intel(R) RealSense(TM) D400 Series UWP driver for Windows* 10 may allow an authenticated user to potentially enable escalation of privilege via local access.
    d. In reset of NuPlayerDriver.cpp there is a possible use-after-free due to improper locking. This could lead to local escalation of privilege in the media server with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-8.0 Android-8.1 Android-9 Android-10Android ID: A-151643722

5. Service Interrupt and Write Example:
    a. An issue was discovered in Avast Antivirus before 20. An Arbitrary Memory Address Overwrite vulnerability in the aswAvLog Log Library results in Denial of Service of the Avast Service (AvastSvc.exe).

6. Read and Write Examples:
    a. An issue was discovered on Samsung mobile devices with P(9.0) (Exynos chipsets) software. Kernel Wi-Fi drivers allow out-of-bounds Read or Write operations (e.g. a buffer overflow). The Samsung IDs are SVE-2019-16125 SVE-2019-16134 SVE-2019-16158 SVE-2019-16159 SVE-2019-16319 SVE-2019-16320 SVE-2019-16337 SVE-2019-16464 SVE-2019-16465 SVE-2019-16467 (March 2020).
    b. XSS exists in PRTG Network Monitor 20.1.56.1574 via crafted map properties. An attacker with Read/Write privileges can create a map and then use the Map Designer Properties screen to insert JavaScript code. This can be exploited against any user with View Maps or Edit Maps access.

7. Read and Resource Removal Example:
    a. An issue was discovered in ProjectSend r1053. upload-process-form.php allows finished_files[]=../ directory traversal. It is possible for users to read arbitrary files and (potentially) access the supporting database delete arbitrary files access user passwords or run arbitrary code.

8. Resource Removal Example:
    a. TYPO3 before 4.3.12 4.4.x before 4.4.9 and 4.5.x before 4.5.4 allows remote attackers to delete arbitrary files on the webserver.
    b. SmarterTools SmarterMail 16.x before build 6985 allows directory traversal. An authenticated user could delete arbitrary files or could create files in new folders in arbitrary locations on the mail server. This could lead to command execution on the server for instance by putting files inside the web directories.
    c. PEAR Archive_Tar version 1.4.3 and earlier contains a CWE-502 CWE-915 vulnerability in the Archive_Tar class. There are several file operations with $v_header[filename] as parameter (such as file_exists is_file is_dir etc). When extract is called without a specific prefix path we can trigger unserialization by crafting a tar file with phar://[path_to_malicious_phar_file] as path. Object injection can be used to trigger destruct in the loaded PHP classes e.g. the Archive_Tar class itself. With Archive_Tar object injection arbitrary file deletion can occur because @unlink($this->_temp_tarname) is called. If another class with useful gadget is loaded it may possible to cause remote code execution that can result in files being deleted or possibly modified. This vulnerability appears to have been fixed in 1.4.4.

9. Privilege Escalation and Write Example:
    a. In addListener of RegionSamplingThread.cpp there is a possible out of bounds write due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-10Android ID: A-150904694

"""

ten_shot_logical_impact_example = """
1. Read, Write, and Resource Removal example (occasionally descriptions might fall under more than one label like this one):
    a. A command injection vulnerability is present that permits an unauthenticated user with access to the Aruba Instant web interface to execute arbitrary system commands within the underlying operating system. An attacker could use this ability to copy files read configuration write files delete files or reboot the device. Workaround: Block access to the Aruba Instant web interface from all untrusted users. Resolution: Fixed in Aruba Instant 4.2.4.12 6.5.4.11 8.3.0.6 and 8.4.0.1

2. Service Interrupt Examples:
    a. A buffer overflow vulnerability in tiff12_print_page() in devices/gdevtfnx.c of Artifex Software GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is fixed in v9.51.
    b. A vulnerability in the IPv6 implementation of Cisco StarOS could allow an unauthenticated remote attacker to cause a denial of service (DoS) condition on an affected device. The vulnerability is due to insufficient validation of incoming IPv6 traffic. An attacker could exploit this vulnerability by sending a crafted IPv6 packet to an affected device with the goal of reaching the vulnerable section of the input buffer. A successful exploit could allow the attacker to cause the device to reload resulting in a DoS condition. This vulnerability is specific to IPv6 traffic. IPv4 traffic is not affected.
    c. A vulnerability in the IPv6 packet processing engine of Cisco Small Business Smart and Managed Switches could allow an unauthenticated remote attacker to cause a denial of service (DoS) condition on an affected device. The vulnerability is due to insufficient validation of incoming IPv6 traffic. An attacker could exploit this vulnerability by sending a crafted IPv6 packet through an affected device. A successful exploit could allow the attacker to cause an unexpected reboot of the switch leading to a DoS condition. This vulnerability is specific to IPv6 traffic. IPv4 traffic is not affected.
    d. A buffer overflow vulnerability in pcx_write_rle() in contrib/japanese/gdev10v.c of Artifex Software GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is fixed in v9.51.
    e. A buffer overflow vulnerability in lxm5700m_print_page() in devices/gdevlxm.c of Artifex Software GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted eps file. This is fixed in v9.51.
    f. A buffer overflow vulnerability in mj_color_correct() in contrib/japanese/gdevmjc.c of Artifex Software GhostScript v9.50 allows a remote attacker to cause a denial of service via a crafted PDF file. This is fixed in v9.51.
    g. IBM Spectrum Scale for IBM Elastic Storage Server 5.3.0 through 5.3.6 could allow an authenticated user to cause a denial of service during deployment or upgrade if GUI specific services are enabled. IBM X-Force ID: 179162.
    h. Improper access control for some Intel(R) Server Boards Server Systems and Compute Modules before version 1.59 may allow an authenticated user to potentially enable denial of service via local access.
    i. Improper authentication in subsystem for Intel (R) LED Manager for NUC before version 1.2.3 may allow privileged user to potentially enable denial of service via local access.

3. Indirect Disclosure
    a. An information disclosure vulnerability exists when Microsoft SharePoint Server fails to properly handle objects in memory aka Microsoft SharePoint Information Disclosure Vulnerability.
    b. An information disclosure vulnerability exists when the Windows kernel fails to properly initialize a memory address aka Windows Kernel Information Disclosure Vulnerability. This CVE ID is unique from CVE-2020-1367 CVE-2020-1389 CVE-2020-1426.
    c. An information disclosure vulnerability exists when the Windows kernel fails to properly initialize a memory address aka Windows Kernel Information Disclosure Vulnerability. This CVE ID is unique from CVE-2020-1367 CVE-2020-1419 CVE-2020-1426.
    d. An information disclosure vulnerability exists when the Windows kernel improperly handles objects in memory aka Windows Kernel Information Disclosure Vulnerability. This CVE ID is unique from CVE-2020-1367 CVE-2020-1389 CVE-2020-1419.
    e. An information disclosure vulnerability exists when the Windows kernel improperly handles objects in memory aka Windows Kernel Information Disclosure Vulnerability. This CVE ID is unique from CVE-2020-1389 CVE-2020-1419 CVE-2020-1426.
    f. An information disclosure vulnerability exists when Skype for Business is accessed via Internet Explorer aka Skype for Business via Internet Explorer Information Disclosure Vulnerability.
    g. An information disclosure vulnerability exists when Skype for Business is accessed via Microsoft Edge (EdgeHTML-based) aka Skype for Business via Microsoft Edge (EdgeHTML-based) Information Disclosure Vulnerability.
    h. An information vulnerability exists when Windows Connected User Experiences and Telemetry Service improperly discloses file information aka Connected User Experiences and Telemetry Service Information Disclosure Vulnerability.
    i. FusionCompute 8.0.0 has an information disclosure vulnerability. Due to the properly protection of certain information attackers may exploit this vulnerability to obtain certain information.
    j. Huawei Honor V30 smartphones with versions earlier than 10.1.0.212(C00E210R5P1) have an improper authentication vulnerability. The system does not sufficiently validate certain parameter passed from the bottom level the attacker should trick the user into installing a malicious application and control the bottom level successful exploit could cause information disclosure.

4. Privilege Escalation Examples:
    a. Buffer overflow in a subsystem for some Intel(R) Server Boards Server Systems and Compute Modules before version 1.59 may allow a privileged user to potentially enable escalation of privilege via local access.
    b. Improper permissions in the installer for the Intel(R) Mailbox Interface driver all versions may allow an authenticated user to potentially enable escalation of privilege via local access.
    c. Improper permissions in the installer for the Intel(R) RealSense(TM) D400 Series UWP driver for Windows* 10 may allow an authenticated user to potentially enable escalation of privilege via local access.
    d. In reset of NuPlayerDriver.cpp there is a possible use-after-free due to improper locking. This could lead to local escalation of privilege in the media server with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-8.0 Android-8.1 Android-9 Android-10Android ID: A-151643722
    e. Improper input validation for some Intel(R) Server Boards Server Systems and Compute Modules before version 1.59 may allow a privileged user to potentially enable escalation of privilege via local access.
    f. Improper input validation for some Intel(R) Wireless Bluetooth(R) products may allow an authenticated user to potentially enable escalation of privilege via local access.

5. Service Interrupt and Write Example:
    a. An issue was discovered in Avast Antivirus before 20. An Arbitrary Memory Address Overwrite vulnerability in the aswAvLog Log Library results in Denial of Service of the Avast Service (AvastSvc.exe).

6. Read Example:
    a. Adobe Acrobat and Reader versions 2020.009.20074 and earlier 2020.001.30002 2017.011.30171 and earlier and 2015.006.30523 and earlier have a stack exhaustion vulnerability. Successful exploitation could lead to application denial-of-service.
    b. An information disclosure vulnerability exists when Microsoft Office software reads out of bound memory due to an uninitialized variable which could disclose the contents of memory aka Microsoft Office Information Disclosure Vulnerability. This CVE ID is unique from CVE-2020-1445.
    c. ** DISPUTED ** An issue was discovered in the Linux kernel through 5.6.2. mpol_parse_str in mm/mempolicy.c has a stack-based out-of-bounds write because an empty nodelist is mishandled during mount option parsing aka CID-aa9f7d5172fa. NOTE: Someone in the security community disagrees that this is a vulnerability because the issue  is a bug in parsing mount options which can only be specified by a privileged user so triggering the bug does not grant any powers not already held. .
    d. ** DISPUTED ** In LuaJIT through 2.0.5 as used in Moonjit before 2.1.2 and other products debug.getinfo has a type confusion issue that leads to arbitrary memory write or read operations because certain cases involving valid stack levels and > options are mishandled. NOTE: The LuaJIT project owner states that the debug libary is unsafe by definition and that this is not a vulnerability. When LuaJIT was originally developed the expectation was that the entire debug library had no security guarantees and thus it made no sense to assign CVEs. However not all users of later LuaJIT derivatives share this perspective.


7. Read and Resource Removal Example:
    a. An issue was discovered in ProjectSend r1053. upload-process-form.php allows finished_files[]=../ directory traversal. It is possible for users to read arbitrary files and (potentially) access the supporting database delete arbitrary files access user passwords or run arbitrary code.

8. Resource Removal Example:
    a. TYPO3 before 4.3.12 4.4.x before 4.4.9 and 4.5.x before 4.5.4 allows remote attackers to delete arbitrary files on the webserver.
    b. SmarterTools SmarterMail 16.x before build 6985 allows directory traversal. An authenticated user could delete arbitrary files or could create files in new folders in arbitrary locations on the mail server. This could lead to command execution on the server for instance by putting files inside the web directories.
    c. PEAR Archive_Tar version 1.4.3 and earlier contains a CWE-502 CWE-915 vulnerability in the Archive_Tar class. There are several file operations with $v_header[filename] as parameter (such as file_exists is_file is_dir etc). When extract is called without a specific prefix path we can trigger unserialization by crafting a tar file with phar://[path_to_malicious_phar_file] as path. Object injection can be used to trigger destruct in the loaded PHP classes e.g. the Archive_Tar class itself. With Archive_Tar object injection arbitrary file deletion can occur because @unlink($this->_temp_tarname) is called. If another class with useful gadget is loaded it may possible to cause remote code execution that can result in files being deleted or possibly modified. This vulnerability appears to have been fixed in 1.4.4.
    d. This vulnerability allows remote attackers to delete arbitrary files on vulnerable installations of NetGain Systems Enterprise Manager 7.2.730 build 1034. Although authentication is required to exploit this vulnerability the existing authentication mechanism can be bypassed. The specific flaw exists within the org.apache.jsp.u.jsp.reports.templates.misc.sample_jsp servlet which listens on TCP port 8081 by default. When parsing the type parameter the process does not properly validate a user-supplied path prior to using it in file operations. An attacker can leverage this in conjunction with other vulnerabilities to execute code in the context of Administrator. Was ZDI-CAN-5190.
    e. Zikula Application Framework before 1.3.7 build 11 allows remote attackers to conduct PHP object injection attacks and delete arbitrary files or execute arbitrary PHP code via crafted serialized data in the (1) authentication_method_ser or (2) authentication_info_ser parameter to index.php or (3) zikulaMobileTheme parameter to index.php.
    f. zxpdf in xpdf before 3.02-19 as packaged in Debian unstable and 3.02-12+squeeze1 as packaged in Debian squeeze deletes temporary files insecurely which allows remote attackers to delete arbitrary files via a crafted .pdf.gz file name.
    g. An issue was discovered in zzcms 8.3. user/ztconfig.php allows remote attackers to delete arbitrary files via an absolute pathname in the oldimg parameter in an action=modify request. This can be leveraged for database access by deleting install.lock.

9. Privilege Escalation and Write Example:
    a. In addListener of RegionSamplingThread.cpp there is a possible out of bounds write due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-10Android ID: A-150904694
    b. In LoadPartitionTable of gpt.cc there is a possible out of bounds write due to a missing bounds check. This could lead to local escalation of privilege when inserting a malicious USB device with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-8.1 Android-9 Android-10 Android-8.0Android ID: A-152874864
    c. Out of bounds write in system driver for some Intel(R) Graphics Drivers before version 15.33.50.5129 may allow an authenticated user to potentially enable escalation of privilege via local access.

10. Privilege Escalation and Read Example:
    a. Out of bounds read in some Intel(R) Graphics Drivers before versions 15.45.31.5127 and 15.40.45.5126 may allow an authenticated user to potentially enable escalation of privilege via local access.

11. Write and Resource Removal Example:
    a. IBM QRadar 7.2.0 thorugh 7.2.9 could allow an authenticated user to overwrite or delete arbitrary files due to a flaw after WinCollect installation. IBM X-Force ID: 181861.

12. Read and Write Examples:
    a. An issue was discovered on Samsung mobile devices with P(9.0) (Exynos chipsets) software. Kernel Wi-Fi drivers allow out-of-bounds Read or Write operations (e.g. a buffer overflow). The Samsung IDs are SVE-2019-16125 SVE-2019-16134 SVE-2019-16158 SVE-2019-16159 SVE-2019-16319 SVE-2019-16320 SVE-2019-16337 SVE-2019-16464 SVE-2019-16465 SVE-2019-16467 (March 2020).
    b. XSS exists in PRTG Network Monitor 20.1.56.1574 via crafted map properties. An attacker with Read/Write privileges can create a map and then use the Map Designer Properties screen to insert JavaScript code. This can be exploited against any user with View Maps or Edit Maps access.
    c. The SDDisk2k.sys driver of WinMagic SecureDoc v8.5 and earlier allows local users to read or write to physical disc sectors via a \.SecureDocDevice handle. Exploiting this vulnerability results in privileged code execution.
    d. The SDDisk2k.sys driver of WinMagic SecureDoc v8.5 and earlier allows local users to read or write to physical disc sectors via a \.SecureDocDevice handle. Exploiting this vulnerability results in privileged code execution.

"""
# 1. Read 10
# 2. Write 10
# 3. Resource Removal 10
# 4. Service Interrupt Examples: 10
# 5. Indirect Disclosure 10
# 6. Privilege Escalation 10