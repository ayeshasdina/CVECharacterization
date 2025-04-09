mitigation_description = """
Mitigation
Address Space Layout Randomization (ASLR): A vulnerability is characterized by ASLR mitigation, if ASLR is an applicable protection mechanism to guard against buffer overflows.
HPKP/HSTS: If HTTP Public Key Pinning (HPKP) or HTTP Strict Transport Security (HSTS) is applicable as a mitigation strategy.
Multi-Factor Authentication (MFA): It is used if MFA is a viable protection technique for a vulnerability.
Physical Security: If ensuring physical security provides protection from the exploits that are caused by a vulnerability.
Sandboxed: If deploying a software product in the sandbox provides protection."""

all_vdo_description = """
    Remote: A vulnerability is characterized as Remote if the cyberattack originates from locations outside of the target network.
    Limited Remote: The exploit is executed from closer locations, using Cellular, Wireless, Bluetooth, Infrared, or Line-Of-Sight technologies.
    Local: The attacker has logical local access to a target computer or system to execute the exploit.
    Physical: The attacker is required to have physical access to the target system to carry out the exploit.
    Application (App): CVE is related to a program that is designed to accomplish a specific task within an operating system or firmware.
    Hypervisor (Hyp): Allows an attacker to access or manipulate resources that are shared among controlled guest operating systems.
    Firmware (Fw): An attacker exploits a vulnerability in the software that is built-in to a device.
    Host OS (HOS): This is a vulnerability in the operating system and the Hypervisor is not applicable.
    Guest OS (GOS): This is a vulnerability in the operating system that is controlled by a Hypervisor.
    Crypto: A flaw in the logical communication medium, such as the incorrect implementation of a cipher algorithm.
    Physical Hardware (Hw): This represents a flaw in the actual physical hardware, such as processors, storage, memory cells, etc.
    Trust Fail: A vulnerability is exploited if an assumed trust relationship between two parties leads to unexpected impacts.
    Context Escape: Attackers exploit a trust mechanism by breaking out of a sandbox.
    Authentication Bypass: The exploit is related to a failure to identify the adversary properly.
    Man-in-the-Middle (MitM): The attackers access a communication channel that might lead to sensitive data disclosures, impersonation, data modification, or denial of communication.
    Code Execution: A vulnerability exploit allows an attacker to execute unauthorized code.
    Write: A vulnerability is characterized with Write if an attacker can do unauthorized modifications on the data.
    Read: Indicates whether the attacker is able to gain unauthorized access to data.
    Resource Removal: Resource Removal is used to represent an unauthorized removal (deletion) of data.
    Service Interrupt: An attacker causes a loss in the availability of a target system.
    Indirect Disclosure: An attacker can learn information about the target, not through a direct read operation, but indirect methods like side-channel attacks or traffic analysis.
    Privilege Escalation: An adversary gains a level of privilege that is not intended for him/her.
    Address Space Layout Randomization (ASLR): A vulnerability is characterized by ASLR mitigation, if ASLR is an applicable protection mechanism to guard against buffer overflows.
    HPKP/HSTS: If HTTP Public Key Pinning (HPKP) or HTTP Strict Transport Security (HSTS) is applicable as a mitigation strategy.
    Multi-Factor Authentication (MFA): It is used if MFA is a viable protection technique for a vulnerability.
    Physical Security: If ensuring physical security provides protection from the exploits that are caused by a vulnerability.
    Sandboxed: If deploying a software product in the sandbox provides protection.
"""

vdo_labels = [
    "remote: A vulnerability is characterized as Remote if the cyberattack originates from locations outside of the target network.",
    "limitedRemote: The exploit is executed from closer locations, using Cellular, Wireless, Bluetooth, Infrared, or Line-Of-Sight technologies.",
    "local: The attacker has logical local access to a target computer or system to execute the exploit.",
    "physical: The attacker is required to have physical access to the target system to carry out the exploit.",
    "applicationApp: CVE is related to a program that is designed to accomplish a specific task within an operating system or firmware.",
    "hypervisorHyp: Allows an attacker to access or manipulate resources that are shared among controlled guest operating systems.",
    "firmwareFw: An attacker exploits a vulnerability in the software that is built-in to a device.",
    "hostOsHOS: This is a vulnerability in the operating system and the Hypervisor is not applicable.",
    "guestOsGOS: This is a vulnerability in the operating system that is controlled by a Hypervisor.",
    "crypto: A flaw in the logical communication medium, such as the incorrect implementation of a cipher algorithm.",
    "physicalHardwareHw: This represents a flaw in the actual physical hardware, such as processors, storage, memory cells, etc.",
    "trustFail: A vulnerability is exploited if an assumed trust relationship between two parties leads to unexpected impacts.",
    "contextEscape: Attackers exploit a trust mechanism by breaking out of a sandbox.",
    "authenticationBypass: The exploit is related to a failure to identify the adversary properly.",
    "manInTheMiddleMitM: The attackers access a communication channel that might lead to sensitive data disclosures, impersonation, data modification, or denial of communication.",
    "codeExecution: A vulnerability exploit allows an attacker to execute unauthorized code.",
    "write: A vulnerability is characterized with Write if an attacker can do unauthorized modifications on the data.",
    "read: Indicates whether the attacker is able to gain unauthorized access to data.",
    "resourceRemoval: Resource Removal is used to represent an unauthorized removal (deletion) of data.",
    "serviceInterrupt: An attacker causes a loss in the availability of a target system.",
    "indirectDisclosure: An attacker can learn information about the target, not through a direct read operation, but indirect methods like side-channel attacks or traffic analysis.",
    "privilegeEscalation: An adversary gains a level of privilege that is not intended for him/her.",
    "addressSpaceLayoutRandomizationASLR: A vulnerability is characterized by ASLR mitigation, if ASLR is an applicable protection mechanism to guard against buffer overflows.",
    "hpkpHsts: If HTTP Public Key Pinning (HPKP) or HTTP Strict Transport Security (HSTS) is applicable as a mitigation strategy.",
    "multiFactorAuthenticationMFA: It is used if MFA is a viable protection technique for a vulnerability.",
    "physicalSecurity: If ensuring physical security provides protection from the exploits that are caused by a vulnerability.",
    "sandboxed: If deploying a software product in the sandbox provides protection."
]