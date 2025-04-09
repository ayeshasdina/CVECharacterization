impact_method_definition = """
Impact Methods describe the approaches or techniques used to exploit a software vulnerability, focusing on how attackers leverage specific weaknesses in a system to achieve malicious objectives. 
These methods encompass various tactics such as exploiting trust relationships, bypassing authentication mechanisms, or executing unauthorized code to compromise a system.
"""

impact_method_desc = """
Impact Methods:
1. Trust Failure
•	Definition: A vulnerability is exploited when an assumed trust relationship between two parties leads to unexpected impacts.
•	Examples:
o	Exploitation of implicit trust between two interconnected systems.
o	Leveraging trust relationships in federated authentication systems.
•	Common Methods:
o	Forging credentials or certificates to manipulate trust.
o	Abusing overly permissive trust configurations.

________________________________________
2. Context Escape
•	Definition: Attackers exploit a trust mechanism by breaking out of a sandbox or isolation environment intended to limit their actions.
•	Examples:
o	Escape from virtualized environments like containers or hypervisors.
o	Breaching browser sandboxes to access host systems.
•	Common Methods:
o	Executing malicious payloads that exploit sandbox vulnerabilities.
o	Chaining exploits to bypass isolation boundaries.

________________________________________
3. Authentication Bypass
•	Definition: A failure to identify the adversary properly, enabling unauthorized access to a system.
•	Examples:
o	Exploiting weak password policies.
o	Manipulating login flows to bypass authentication.
•	Common Methods:
o	Session hijacking through intercepted tokens.
o	Replay attacks using captured authentication credentials.

________________________________________
4. Man-in-the-Middle
•	Definition: Attackers gain unauthorized access to a communication channel, potentially leading to sensitive data disclosure, impersonation, data modification, or denial of communication.
•	Examples:
o	Intercepting traffic on unencrypted networks.
o	Performing SSL/TLS stripping to downgrade secure connections.
•	Common Methods:
o	Using rogue access points to eavesdrop on traffic.
o	Injecting malicious content into intercepted communications.

________________________________________
5. Code Execution
•	Definition: A vulnerability exploit that allows an attacker to execute unauthorized code within a target system.
•	Examples:
o	Exploiting a buffer overflow to inject malicious code.
o	Abusing deserialization flaws to run arbitrary scripts.
•	Common Methods:
o	Leveraging stack or heap-based overflows.
o	Exploiting command injection vulnerabilities in applications.
"""


example_impact_method_with_labels = """
1. Trust Failure
Zoom Client for Meetings through 4.6.9 uses the ECB mode of AES for video and audio encryption. Within a meeting  all participants use a single 128-bit key.

2. Context Escape
Using an ID that can be controlled by a compromised renderer which allows any frame to overwrite the page_state of any other frame in the same process in Navigation in Google Chrome on Chrome OS prior to 62.0.3202.74 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.

3. Authentication Bypass
Zoho ManageEngine DataSecurity Plus prior to 6.0.1 uses default admin credentials to communicate with a DataEngine Xnode server. This allows an attacker to bypass authentication for this server and execute all operations in the context of admin user.

4. Man in the Middle
When the pre-logon feature is enabled  a missing certification validation in Palo Alto Networks GlobalProtect app can disclose the pre-logon authentication cookie to a man-in-the-middle attacker on the same local area network segment with the ability to manipulate ARP or to conduct ARP spoofing attacks. This allows the attacker to access the GlobalProtect Server as allowed by configured Security rules for the pre-login user. This access may be limited compared to the network access of regular users. This issue affects: GlobalProtect app 5.0 versions earlier than GlobalProtect app 5.0.10 when the prelogon feature is enabled; GlobalProtect app 5.1 versions earlier than GlobalProtect app 5.1.4 when the prelogon feature is enabled.

5. Code Execution
When configured to enable default typing  Jackson contained a deserialization vulnerability that could lead to arbitrary code execution. Jackson fixed this vulnerability by blacklisting known deserialization gadgets. Spring Batch configures Jackson with global default typing enabled which means that through the previous exploit  arbitrary code could be executed if all of the following is true: * Spring Batchs Jackson support is being leveraged to serialize a jobs ExecutionContext. * A malicious user gains write access to the data store used by the JobRepository (where the data to be deserialized is stored). In order to protect against this type of attack  Jackson prevents a set of untrusted gadget classes from being deserialized. Spring Batch should be proactive against blocking unknown deserialization gadgets when enabling default typing.

"""

# Impact Method Prompts
one_shot_impact_method_example = """
1. Trust Failure
Zoom Client for Meetings through 4.6.9 uses the ECB mode of AES for video and audio encryption. Within a meeting  all participants use a single 128-bit key.

2. Context Escape
Using an ID that can be controlled by a compromised renderer which allows any frame to overwrite the page_state of any other frame in the same process in Navigation in Google Chrome on Chrome OS prior to 62.0.3202.74 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.

3. Authentication Bypass
Zoho ManageEngine DataSecurity Plus prior to 6.0.1 uses default admin credentials to communicate with a DataEngine Xnode server. This allows an attacker to bypass authentication for this server and execute all operations in the context of admin user.

4. Man in the Middle
When the pre-logon feature is enabled  a missing certification validation in Palo Alto Networks GlobalProtect app can disclose the pre-logon authentication cookie to a man-in-the-middle attacker on the same local area network segment with the ability to manipulate ARP or to conduct ARP spoofing attacks. This allows the attacker to access the GlobalProtect Server as allowed by configured Security rules for the pre-login user. This access may be limited compared to the network access of regular users. This issue affects: GlobalProtect app 5.0 versions earlier than GlobalProtect app 5.0.10 when the prelogon feature is enabled; GlobalProtect app 5.1 versions earlier than GlobalProtect app 5.1.4 when the prelogon feature is enabled.

5. Code Execution
When configured to enable default typing  Jackson contained a deserialization vulnerability that could lead to arbitrary code execution. Jackson fixed this vulnerability by blacklisting known deserialization gadgets. Spring Batch configures Jackson with global default typing enabled which means that through the previous exploit  arbitrary code could be executed if all of the following is true: * Spring Batchs Jackson support is being leveraged to serialize a jobs ExecutionContext. * A malicious user gains write access to the data store used by the JobRepository (where the data to be deserialized is stored). In order to protect against this type of attack  Jackson prevents a set of untrusted gadget classes from being deserialized. Spring Batch should be proactive against blocking unknown deserialization gadgets when enabling default typing.

"""

five_shot_impact_method_example = """
Trust Failure Examples:
1. Zoom Client for Meetings through 4.6.9 uses the ECB mode of AES for video and audio encryption. Within a meeting  all participants use a single 128-bit key.
2. vulnerability in the Trusted Platform Module (TPM) functionality of software for Cisco Nexus 9000 Series Fabric Switches in Application Centric Infrastructure (ACI) mode could allow an unauthenticated  local attacker with physical access to view sensitive information on an affected device. The vulnerability is due to a lack of proper data-protection mechanisms for disk encryption keys that are used within the partitions on an affected device hard drive. An attacker could exploit this vulnerability by obtaining physical access to the affected device to view certain cleartext keys. A successful exploit could allow the attacker to execute a custom boot process or conduct further attacks on an affected device.
3. An information disclosure vulnerability was reported in Lenovo XClarity Administrator (LXCA) versions prior to 2.6.6 that could allow unauthenticated access to some configuration files which may contain usernames  license keys  IP addresses  and encrypted password hashes.
4. An issue was detected in ONAP Portal through Dublin. By executing a padding oracle attack using the ONAPPORTAL/processSingleSignOn UserId field  an attacker is able to decrypt arbitrary information encrypted with the same symmetric key as UserId. All Portal setups are affected.
5. An issue was discovered in Digital Persona U.are.U 4500 Fingerprint Reader v24. The key and salt used for obfuscating the fingerprint image exhibit cleartext when the fingerprint scanner device transfers a fingerprint image to the driver. An attacker who sniffs an encrypted fingerprint image can easily decrypt that image using the key and salt.

Context Escape  Examples:
1. Using an ID that can be controlled by a compromised renderer which allows any frame to overwrite the page_state of any other frame in the same process in Navigation in Google Chrome on Chrome OS prior to 62.0.3202.74 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
2. A vulnerability in the Python scripting subsystem of Cisco NX-OS Software could allow an authenticated  local attacker to escape the Python parser and issue arbitrary commands to elevate the attackers privilege level. The vulnerability is due to insufficient sanitization of user-supplied parameters that are passed to certain Python functions in the scripting sandbox of the affected device. An attacker could exploit this vulnerability to escape the scripting sandbox and execute arbitrary commands to elevate the attackers privilege level. To exploit this vulnerability  the attacker must have local access and be authenticated to the targeted device with administrative or Python execution privileges. These requirements could limit the possibility of a successful exploit.
3. A vulnerability in the TCL scripting subsystem of Cisco NX-OS System Software could allow an authenticated  local attacker to escape the interactive TCL shell and gain unauthorized access to the underlying operating system of the device. The vulnerability exists due to insufficient input validation of user-supplied files passed to the interactive TCL shell of the affected device. An attacker could exploit this vulnerability to escape the scripting sandbox and execute arbitrary commands on the underlying operating system with the privileges of the authenticated user. To exploit this vulnerability  an attacker must have local access and be authenticated to the targeted device with administrative or tclsh execution privileges. This vulnerability affects the following products running Cisco NX-OS System Software: Multilayer Director Switches  Nexus 2000 Series Fabric Extenders  Nexus 3000 Series Switches  Nexus 3500 Platform Switches  Nexus 5000 Series Switches  Nexus 5500 Platform Switches  Nexus 5600 Platform Switches  Nexus 6000 Series Switches  Nexus 7000 Series Switches  Nexus 7700 Series Switches  Nexus 9000 Series Switches in standalone NX-OS mode  Nexus 9500 R-Series Line Cards and Fabric Modules  Unified Computing System Manager. Cisco Bug IDs: CSCve93750  CSCve93762  CSCve93763  CSCvg04127.
4. An earlier fix for an Inter-process Communication (IPC) vulnerability  CVE-2011-3079  added authentication to communication between IPC endpoints and server parents during IPC process creation. This authentication is insufficient for channels created after the IPC process is started  leading to the authentication not being correctly applied to later channels. This could allow for a sandbox escape through IPC channels due to lack of message validation in the listener process. This vulnerability affects Thunderbird < 60.5  Firefox ESR < 60.5  and Firefox < 65.
5. An elevation of privilege vulnerability exists in Microsoft browsers allowing sandbox escape  aka Microsoft Browser Elevation of Privilege Vulnerability. This affects Internet Explorer 11  Microsoft Edge.

Authentication Bypass Examples:
1. Zoho ManageEngine DataSecurity Plus prior to 6.0.1 uses default admin credentials to communicate with a DataEngine Xnode server. This allows an attacker to bypass authentication for this server and execute all operations in the context of admin user.
2. Certain NETGEAR devices are affected by CSRF and authentication bypass. This affects R7300DST before 1.0.0.54  R8300 before 1.0.2.100_1.0.82  R8500 before 1.0.2.100_1.0.82  and WNDR3400v3 before 1.0.1.14.
3. cPanel before 82.0.18 allows authentication bypass because of misparsing of the format of the password file (SEC-516).
4. This vulnerability allows remote attackers to bypass authentication on affected installations of TP-Link Archer A7 Firmware Ver: 190726 AC1750 routers. Authentication is not required to exploit this vulnerability. The specific flaw exists within the handling of SSH port forwarding requests during initial setup. The issue results from the lack of proper authentication prior to establishing SSH port forwarding rules. An attacker can leverage this vulnerability to escalate privileges to resources normally protected from the WAN interface. Was ZDI-CAN-9664.
5. TP-Link cloud cameras through 2020-02-09 allow remote attackers to bypass authentication and obtain sensitive information via vectors involving a Wi-Fi session with GPS enabled  aka CNVD-2020-04855.

Man in the Middle Examples:
1. When the pre-logon feature is enabled  a missing certification validation in Palo Alto Networks GlobalProtect app can disclose the pre-logon authentication cookie to a man-in-the-middle attacker on the same local area network segment with the ability to manipulate ARP or to conduct ARP spoofing attacks. This allows the attacker to access the GlobalProtect Server as allowed by configured Security rules for the pre-login user. This access may be limited compared to the network access of regular users. This issue affects: GlobalProtect app 5.0 versions earlier than GlobalProtect app 5.0.10 when the prelogon feature is enabled; GlobalProtect app 5.1 versions earlier than GlobalProtect app 5.1.4 when the prelogon feature is enabled.
2. PuTTY 0.68 through 0.73 has an Observable Discrepancy leading to an information leak in the algorithm negotiation. This allows man-in-the-middle attackers to target initial connection attempts (where no host key for the server has been cached by the client).
3. Sigma Spectrum Infusion System vs6.x (model 35700BAX) and Baxter Spectrum Infusion System Version(s) 8.x (model 35700BAX2) at the application layer uses an unauthenticated clear-text communication channel to send and receive system status and operational data. This could allow an attacker that has circumvented network security measures to view sensitive non-private data or to perform a man-in-the-middle attack.
4. Splunk-SDK-Python before 1.6.6 does not properly verify untrusted TLS server certificates  which could result in man-in-the-middle attacks.
5. The Android App Tootdon for Mastodon version 3.4.1 and earlier does not verify X.509 certificates from SSL servers  which allows man-in-the-middle attackers to spoof servers and obtain sensitive information via a crafted certificate.

Code Execution Examples:
1. When configured to enable default typing  Jackson contained a deserialization vulnerability that could lead to arbitrary code execution. Jackson fixed this vulnerability by blacklisting known deserialization gadgets. Spring Batch configures Jackson with global default typing enabled which means that through the previous exploit  arbitrary code could be executed if all of the following is true: * Spring Batchs Jackson support is being leveraged to serialize a jobs ExecutionContext. * A malicious user gains write access to the data store used by the JobRepository (where the data to be deserialized is stored). In order to protect against this type of attack  Jackson prevents a set of untrusted gadget classes from being deserialized. Spring Batch should be proactive against blocking unknown deserialization gadgets when enabling default typing.
2. Kata Containers doesnt restrict containers from accessing the guests root filesystem device. Malicious containers can exploit this to gain code execution on the guest and masquerade as the kata-agent. This issue affects Kata Containers 1.11 versions earlier than 1.11.1; Kata Containers 1.10 versions earlier than 1.10.5; and Kata Containers 1.9 and earlier versions.
3. Lansweeper 6.0.x through 7.2.x has a default installation in which the admin password is configured for the admin account  unless Built-in admin is manually unchecked. This allows command execution via the Add New Package and Scheduled Deployments features.
4. Magento versions 2.3.4 and earlier  2.2.11 and earlier (see note)  1.14.4.4 and earlier  and 1.9.4.4 and earlier have a command injection vulnerability. Successful exploitation could lead to arbitrary code execution.
5. Adobe Premiere Rush versions 1.5.12 and earlier have an out-of-bounds write vulnerability. Successful exploitation could lead to arbitrary code execution .

"""

ten_shot_impact_method_example = """
Trust Failure Examples:
1. Zoom Client for Meetings through 4.6.9 uses the ECB mode of AES for video and audio encryption. Within a meeting  all participants use a single 128-bit key.
2. vulnerability in the Trusted Platform Module (TPM) functionality of software for Cisco Nexus 9000 Series Fabric Switches in Application Centric Infrastructure (ACI) mode could allow an unauthenticated  local attacker with physical access to view sensitive information on an affected device. The vulnerability is due to a lack of proper data-protection mechanisms for disk encryption keys that are used within the partitions on an affected device hard drive. An attacker could exploit this vulnerability by obtaining physical access to the affected device to view certain cleartext keys. A successful exploit could allow the attacker to execute a custom boot process or conduct further attacks on an affected device.
3. An information disclosure vulnerability was reported in Lenovo XClarity Administrator (LXCA) versions prior to 2.6.6 that could allow unauthenticated access to some configuration files which may contain usernames  license keys  IP addresses  and encrypted password hashes.
4. An issue was detected in ONAP Portal through Dublin. By executing a padding oracle attack using the ONAPPORTAL/processSingleSignOn UserId field  an attacker is able to decrypt arbitrary information encrypted with the same symmetric key as UserId. All Portal setups are affected.
5. An issue was discovered in Digital Persona U.are.U 4500 Fingerprint Reader v24. The key and salt used for obfuscating the fingerprint image exhibit cleartext when the fingerprint scanner device transfers a fingerprint image to the driver. An attacker who sniffs an encrypted fingerprint image can easily decrypt that image using the key and salt.
6. An issue was discovered on Mitsubishi Electric ME-RTU devices through 2.02 and INEA ME-RTU devices through 3.0. Hard-coded SSH keys allow an attacker to gain unauthorised access or disclose encrypted data on the RTU due to the keys not being regenerated on initial installation or with firmware updates. In other words  these devices use private-key values in /etc/ssh/ssh_host_rsa_key  /etc/ssh/ssh_host_ecdsa_key  and /etc/ssh/ssh_host_dsa_key files that are publicly available from the vendor web sites.
7. An issue was discovered on Zyxel GS1900 devices with firmware before 2.50(AAHH.0)C0. The firmware hashes and encrypts passwords using a hardcoded cryptographic key in sal_util_str_encrypt() in libsal.so.0.0. The parameters (salt  IV  and key data) are used to encrypt and decrypt all passwords using AES256 in CBC mode. With the parameters known  all previously encrypted passwords can be decrypted. This includes the passwords that are part of configuration backups or otherwise embedded as part of the firmware.
8. An issue was discovered on Zyxel GS1900 devices with firmware before 2.50(AAHH.0)C0. The firmware image contains encrypted passwords that are used to authenticate users wishing to access a diagnostics or password-recovery menu. Using the hardcoded cryptographic key found elsewhere in the firmware  these passwords can be decrypted. This is related to fds_sys_passDebugPasswd_ret() and fds_sys_passRecoveryPasswd_ret() in libfds.so.0.0.
9. Barco ClickShare Button R9861500D01 devices before 1.9.0 allow Information Exposure. The encrypted ClickShare Button firmware contains the private key of a test device-certificate.
10. Barco ClickShare Button R9861500D01 devices before 1.9.0 have incorrect Credentials Management. The ClickShare Button implements encryption at rest which uses a one-time programmable (OTP) AES encryption key. This key is shared across all ClickShare Buttons of model R9861500D01.

Context Escape  Examples:
1. Using an ID that can be controlled by a compromised renderer which allows any frame to overwrite the page_state of any other frame in the same process in Navigation in Google Chrome on Chrome OS prior to 62.0.3202.74 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
2. A vulnerability in the Python scripting subsystem of Cisco NX-OS Software could allow an authenticated  local attacker to escape the Python parser and issue arbitrary commands to elevate the attackers privilege level. The vulnerability is due to insufficient sanitization of user-supplied parameters that are passed to certain Python functions in the scripting sandbox of the affected device. An attacker could exploit this vulnerability to escape the scripting sandbox and execute arbitrary commands to elevate the attackers privilege level. To exploit this vulnerability  the attacker must have local access and be authenticated to the targeted device with administrative or Python execution privileges. These requirements could limit the possibility of a successful exploit.
3. A vulnerability in the TCL scripting subsystem of Cisco NX-OS System Software could allow an authenticated  local attacker to escape the interactive TCL shell and gain unauthorized access to the underlying operating system of the device. The vulnerability exists due to insufficient input validation of user-supplied files passed to the interactive TCL shell of the affected device. An attacker could exploit this vulnerability to escape the scripting sandbox and execute arbitrary commands on the underlying operating system with the privileges of the authenticated user. To exploit this vulnerability  an attacker must have local access and be authenticated to the targeted device with administrative or tclsh execution privileges. This vulnerability affects the following products running Cisco NX-OS System Software: Multilayer Director Switches  Nexus 2000 Series Fabric Extenders  Nexus 3000 Series Switches  Nexus 3500 Platform Switches  Nexus 5000 Series Switches  Nexus 5500 Platform Switches  Nexus 5600 Platform Switches  Nexus 6000 Series Switches  Nexus 7000 Series Switches  Nexus 7700 Series Switches  Nexus 9000 Series Switches in standalone NX-OS mode  Nexus 9500 R-Series Line Cards and Fabric Modules  Unified Computing System Manager. Cisco Bug IDs: CSCve93750  CSCve93762  CSCve93763  CSCvg04127.
4. An earlier fix for an Inter-process Communication (IPC) vulnerability  CVE-2011-3079  added authentication to communication between IPC endpoints and server parents during IPC process creation. This authentication is insufficient for channels created after the IPC process is started  leading to the authentication not being correctly applied to later channels. This could allow for a sandbox escape through IPC channels due to lack of message validation in the listener process. This vulnerability affects Thunderbird < 60.5  Firefox ESR < 60.5  and Firefox < 65.
5. An elevation of privilege vulnerability exists in Microsoft browsers allowing sandbox escape  aka Microsoft Browser Elevation of Privilege Vulnerability. This affects Internet Explorer 11  Microsoft Edge.
6. An issue was discovered in ProVide (formerly zFTPServer) through 13.1. It doesnt enforce permission over Windows Symlinks or Junctions. As a result  a low-privileged user (non-admin) can craft a Junction Link in a directory he has full control of  breaking out of the sandbox.
7. An issue was discovered in Total.js CMS 12.0.0. An authenticated user with the widgets privilege can gain achieve Remote Command Execution (RCE) on the remote server by creating a malicious widget with a special tag containing JavaScript code that will be evaluated server side. In the process of evaluating the tag by the back-end  it is possible to escape the sandbox object by using the following payload: <script total>global.process.mainModule.require(child_process).exec(RCE);</script>
8. An out-of-bounds write in ClearKeyDecryptor while decrypting some Clearkey-encrypted media content. The ClearKeyDecryptor code runs within the Gecko Media Plugin (GMP) sandbox. If a second mechanism is found to escape the sandbox  this vulnerability allows for the writing of arbitrary data within memory  resulting in a potentially exploitable crash. This vulnerability affects Firefox ESR < 45.9  Firefox ESR < 52.1  and Firefox < 53.
9. As part of a winning Pwn2Own entry  a researcher demonstrated a sandbox escape by installing a malicious language pack and then opening a browser feature that used the compromised translation. This vulnerability affects Firefox ESR < 60.8  Firefox < 68  and Thunderbird < 60.8.
10. Beaker before 0.8.9 allows a sandbox escape  enabling system access and code execution. This occurs because Electron context isolation is not used  and therefore an attacker can conduct a prototype-pollution attack against the Electron internal messaging API.

Authentication Bypass Examples:
1. Zoho ManageEngine DataSecurity Plus prior to 6.0.1 uses default admin credentials to communicate with a DataEngine Xnode server. This allows an attacker to bypass authentication for this server and execute all operations in the context of admin user.
2. Certain NETGEAR devices are affected by CSRF and authentication bypass. This affects R7300DST before 1.0.0.54  R8300 before 1.0.2.100_1.0.82  R8500 before 1.0.2.100_1.0.82  and WNDR3400v3 before 1.0.1.14.
3. cPanel before 82.0.18 allows authentication bypass because of misparsing of the format of the password file (SEC-516).
4. This vulnerability allows remote attackers to bypass authentication on affected installations of TP-Link Archer A7 Firmware Ver: 190726 AC1750 routers. Authentication is not required to exploit this vulnerability. The specific flaw exists within the handling of SSH port forwarding requests during initial setup. The issue results from the lack of proper authentication prior to establishing SSH port forwarding rules. An attacker can leverage this vulnerability to escalate privileges to resources normally protected from the WAN interface. Was ZDI-CAN-9664.
5. TP-Link cloud cameras through 2020-02-09 allow remote attackers to bypass authentication and obtain sensitive information via vectors involving a Wi-Fi session with GPS enabled  aka CNVD-2020-04855.
6. NETGEAR XR500 devices before 2.3.2.32 are affected by authentication bypass.
7. On Juniper Networks EX and QFX Series  an authentication bypass vulnerability may allow a user connected to the console port to login as root without any password. This issue might only occur in certain scenarios:   At the first reboot after performing device factory reset using the command  request system zeroize ; or   A temporary moment during the first reboot after the software upgrade when the device configured in Virtual Chassis mode. This issue affects Juniper Networks Junos OS on EX and QFX Series: 14.1X53 versions prior to 14.1X53-D53; 15.1 versions prior to 15.1R7-S4; 15.1X53 versions prior to 15.1X53-D593; 16.1 versions prior to 16.1R7-S4; 17.1 versions prior to 17.1R2-S11  17.1R3-S1; 17.2 versions prior to 17.2R3-S3; 17.3 versions prior to 17.3R2-S5  17.3R3-S6; 17.4 versions prior to 17.4R2-S9  17.4R3; 18.1 versions prior to 18.1R3-S8; 18.2 versions prior to 18.2R2; 18.3 versions prior to 18.3R1-S7  18.3R2. This issue does not affect Juniper Networks Junos OS 12.3.
8. On NETGEAR GS728TPS devices through 5.3.0.35  a remote attacker having network connectivity to the web-administration panel can access part of the web panel  bypassing authentication.
9. Online Course Registration 2.0 has multiple SQL injections that would can lead to a complete database compromise and authentication bypass in the login pages: admin/change-password.php  admin/check_availability.php  admin/index.php  change-password.php  check_availability.php  includes/header.php  index.php  and pincode-verification.php.
10. OpenBlocks IoT VX2 prior to Ver.4.0.0 (Ver.3 Series) allows an attacker on the same network segment to bypass authentication and to initialize the device via unspecified vectors.

Man in the Middle Examples:
1. When the pre-logon feature is enabled  a missing certification validation in Palo Alto Networks GlobalProtect app can disclose the pre-logon authentication cookie to a man-in-the-middle attacker on the same local area network segment with the ability to manipulate ARP or to conduct ARP spoofing attacks. This allows the attacker to access the GlobalProtect Server as allowed by configured Security rules for the pre-login user. This access may be limited compared to the network access of regular users. This issue affects: GlobalProtect app 5.0 versions earlier than GlobalProtect app 5.0.10 when the prelogon feature is enabled; GlobalProtect app 5.1 versions earlier than GlobalProtect app 5.1.4 when the prelogon feature is enabled.
2. PuTTY 0.68 through 0.73 has an Observable Discrepancy leading to an information leak in the algorithm negotiation. This allows man-in-the-middle attackers to target initial connection attempts (where no host key for the server has been cached by the client).
3. Sigma Spectrum Infusion System vs6.x (model 35700BAX) and Baxter Spectrum Infusion System Version(s) 8.x (model 35700BAX2) at the application layer uses an unauthenticated clear-text communication channel to send and receive system status and operational data. This could allow an attacker that has circumvented network security measures to view sensitive non-private data or to perform a man-in-the-middle attack.
4. Splunk-SDK-Python before 1.6.6 does not properly verify untrusted TLS server certificates  which could result in man-in-the-middle attacks.
5. The Android App Tootdon for Mastodon version 3.4.1 and earlier does not verify X.509 certificates from SSL servers  which allows man-in-the-middle attackers to spoof servers and obtain sensitive information via a crafted certificate.
6. IBM Sterling B2B Integrator 5.2.0.1 through 6.0.0.0 Standard Edition could allow highly sensitive information to be transmitted in plain text. An attacker could obtain this information using man in the middle techniques. IBM X-ForceID: 157008.
7. Improper download file verification vulnerability in VAIO Update 7.3.0.03150 and earlier allows remote attackers to conduct a man-in-the-middle attack via a malicous wireless LAN access point. A successful exploitation may result in a malicious file being downloaded/executed.
8. Improper validation of certificate with host mismatch in Apache Log4j SMTP appender. This could allow an SMTPS connection to be intercepted by a man-in-the-middle attack which could leak any log messages sent through that appender.
9. In addOrUpdateNetworkInternal and related functions of WifiConfigManager.java  there is a possible man in the middle attack due to improper certificate validation. This could lead to remote information disclosure with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-10Android ID: A-150500247
10. In Moonlight iOS/tvOS before 4.0.1  the pairing process is vulnerable to a man-in-the-middle attack. The bug has been fixed in Moonlight v4.0.1 for iOS and tvOS.

Code Execution Examples:
1. When configured to enable default typing  Jackson contained a deserialization vulnerability that could lead to arbitrary code execution. Jackson fixed this vulnerability by blacklisting known deserialization gadgets. Spring Batch configures Jackson with global default typing enabled which means that through the previous exploit  arbitrary code could be executed if all of the following is true: * Spring Batchs Jackson support is being leveraged to serialize a jobs ExecutionContext. * A malicious user gains write access to the data store used by the JobRepository (where the data to be deserialized is stored). In order to protect against this type of attack  Jackson prevents a set of untrusted gadget classes from being deserialized. Spring Batch should be proactive against blocking unknown deserialization gadgets when enabling default typing.
2. Kata Containers doesnt restrict containers from accessing the guests root filesystem device. Malicious containers can exploit this to gain code execution on the guest and masquerade as the kata-agent. This issue affects Kata Containers 1.11 versions earlier than 1.11.1; Kata Containers 1.10 versions earlier than 1.10.5; and Kata Containers 1.9 and earlier versions.
3. Lansweeper 6.0.x through 7.2.x has a default installation in which the admin password is configured for the admin account  unless Built-in admin is manually unchecked. This allows command execution via the Add New Package and Scheduled Deployments features.
4. Magento versions 2.3.4 and earlier  2.2.11 and earlier (see note)  1.14.4.4 and earlier  and 1.9.4.4 and earlier have a command injection vulnerability. Successful exploitation could lead to arbitrary code execution.
5. Adobe Premiere Rush versions 1.5.12 and earlier have an out-of-bounds write vulnerability. Successful exploitation could lead to arbitrary code execution .
6. In Xiaomi router R3600  ROM version<1.0.20  the connection service can be injected through the web interface  resulting in stack overflow or remote code execution.
7. Inappropriate use of JIT optimisation in V8 in Google Chrome prior to 61.0.3163.100 for Linux  Windows  and Mac allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page  related to the escape analysis phase.
8. Jenkins ElasticBox Jenkins Kubernetes CI/CD Plugin 1.3 and earlier does not configure its YAML parser to prevent the instantiation of arbitrary types  resulting in a remote code execution vulnerability.
9. Magento versions 2.3.4 and earlier  2.2.11 and earlier (see note)  1.14.4.4 and earlier  and 1.9.4.4 and earlier have a defense-in-depth security mitigation vulnerability. Successful exploitation could lead to arbitrary code execution.
10. Magento versions 2.3.4 and earlier  2.2.11 and earlier (see note)  1.14.4.4 and earlier  and 1.9.4.4 and earlier have a security mitigation bypass vulnerability. Successful exploitation could lead to arbitrary code execution.

"""
