# CIS Controls

====================================================================================================
## CIS Control 1: Inventory and Control of Enterprise Assets
====================================================================================================

   - 1.1: Establish and Maintain Detailed Enterprise Asset Inventory
   - 1.2: Address Unauthorized Assets
   - 1.3: Utilize an Active Discovery Tool
   - 1.4: Use Dynamic Host Configuration Protocol (DHCP) Logging to Update Enterprise Asset Inventory
   - 1.5: Use a Passive Asset Discovery Tool

**Why is this CIS Control Critical?**

##### Enterprises cannot defend what they do not know they have. Managed control of all enterprise assets also plays a critical role in security monitoring, incident response, system backup, and recovery. Enterprises should know what data is critical to them, and proper asset management will help identify those enterprise assets that hold or manage this critical data, so appropriate security controls can be applied. 

##### External attackers are continuously scanning the internet address space of target enterprises, premise-based or in the cloud, identifying possibly unprotected assets attached to enterprises' networks. Attackers can take advantage of new assets that are installed, yet not securely configured and patched. Internally, unidentified assets can also have weak security configurations that can make them vulnerable to web or email-based malware; and adversaries can leverage weak security configurations for traversing the network, once they are inside.

##### Additional assets that connect to the enterprise’s network (e.g., demonstration systems, temporary test systems, guest networks, etc.) should be identified and/or isolated, in order to prevent adversarial access from affecting the security of enterprise operations.

====================================================================================================
## CIS Control 2: Inventory and Control of Software Assets
====================================================================================================

   - 2.1: Establish and Maintain a Software Inventory
   - 2.2: Ensure Authorized Software is Currently Supported
   - 2.3: Address Unauthorized Software
   - 2.4: Utilize Automated Software Inventory Tools
   - 2.5: Allowlist Authorized Software
   - 2.6: Allowlist Authorized Libraries
   - 2.7: Allowlist Authorized Scripts

**Why is this CIS Control Critical?**

##### A complete software inventory is a critical foundation for preventing attacks. Attackers continuously scan target enterprises looking for vulnerable versions of software that can be remotely exploited. For example, if a user opens a malicious website or attachment with a vulnerable browser, an attacker can often install backdoor programs and bots that give the attacker long-term control of the system. Attackers can also use this access to move laterally through the network. One of the key defenses against these attacks is updating and patching software. However, without a complete inventory of software assets, an enterprise cannot determine if they have vulnerable software, or if there are potential licensing violations.

##### Even if a patch is not yet available, a complete software inventory list allows an enterprise to guard against known attacks until the patch is released. Some sophisticated attackers use “zero-day exploits”, which take advantage of previously unknown vulnerabilities that have yet to have a patch released by the software vendor. Depending on the severity of the exploit, an enterprise can implement temporary mitigation measures to guard against attacks until the patch is released.

##### Management of software assets is also important to identify unnecessary security risks. An enterprise should review their software inventory to identify any enterprise assets running software that is not needed for business purposes. For example, an enterprise asset may come installed with default software that creates a potential security risk and provides no benefit to the enterprise. It is critical to inventory, understand, assess, and manage all software connected to an enterprise’s infrastructure.

====================================================================================================
## CIS Control 3: Data Protection
====================================================================================================

   - 3.1: Establish and Maintain a Data Management
   - 3.2: Establish and Maintain a Data Inventory
   - 3.3: Configure Data Access Control Lists
   - 3.4: Enforce Data Retention
   - 3.5: Securely Dispose of Data
   - 3.6: Encrypt Data on End-User Devices
   - 3.7: Establish and Maintain a Data Classification Scheme
   - 3.8: Document Data Flows
   - 3.9: Encrypt Data on Removable Media
   - 3.10: Encrypt Sensitive Data in Transit
   - 3.11: Encrypt Sensitive Data At Rest
   - 3.12: Segment Data Processing and Storage Based on Sensitivity
   - 3.13: Deploy a Data Loss Prevention Solution
   - 3.14: Log Sensitive Data Access

**Why is this CIS Control Critical?**

##### Data is no longer only contained within an enterprise’s border, it is in the cloud, on portable end-user devices where users work from home, and is often shared with partners or online services who might have it anywhere in the world. In addition to sensitive data an enterprise holds related to finances, intellectual property, and customer data, there also might be numerous international regulations for protection of personal data. Data privacy has become increasingly important, and enterprises are learning that privacy is about the appropriate use and management of data, not just encryption. Data must be appropriately managed through its entire lifecycle. These privacy rules can be complicated for multi-national enterprises, of any size, however there are fundamentals that can apply to all.

##### Develop processes and technical controls to identify, classify, securely handle, retain, and dispose of data.

##### Once attackers have penetrated an enterprise’s infrastructure, one of their first tasks is to find and exfiltrate data. Enterprises might not be aware that sensitive data is leaving their environment because they are not monitoring data outflows.

##### While many attacks occur on the network, others involve physical theft of portable end-user devices, attacks on service providers or other partners holding sensitive data. Other sensitive enterprise assets may also include non-computing devices that provide management and control of physical systems, such as Supervisory Control and Data Acquisition (SCADA) systems.

##### The enterprise’s loss of control over protected or sensitive data is a serious and often reportable business impact. While some data is compromised or lost as a result of theft or espionage, the vast majority are a result of poorly understood data management rules, and user error. The adoption of data encryption, both in transit and at rest, can provide mitigation against data compromise, and more importantly, is a regulatory requirement for most controlled data.

====================================================================================================
## CIS Control 4: Secure Configuration of Enterprise Assets and Software
====================================================================================================

   - 4.1: Establish and Maintain a Secure Configuration Process <control-4.1>
   - 4.2: Establish and Maintain a Secure Configuration Process for Network Infrastructure <control-4.2>
   - 4.3: Ensure the Use of Dedicated Administrative Accounts <control-4.3>
   - 4.4: Implement and Manage a Firewall on Servers <control-4.4>
   - 4.5: Implement and Manage a Firewall on End-User Devices <control-4.5>
   - 4.6: Securely Manage Enterprise Assets and Software <control-4.6>
   - 4.7: Manage Default Accounts on Enterprise Assets and Software <control-4.7>
   - 4.8: Uninstall or Disable Unnecessary Services on Enterprise Assets and Software <control-4.8>
   - 4.9: Configure Trusted DNS Servers on Enterprise Assets <control-4.9>
   - 4.10: Enforce Automatic Device Lockout on Portable End-User Devices <control-4.10>
   - 4.11: Enforce Remote Wipe Capability on Portable End-User Devices <control-4.11>
   - 4.12: Separate Enterprise Workspaces on Mobile End-User Devices <control-4.12>

**Why is this CIS Control Critical?**

##### As delivered from manufacturers and resellers, the default configurations for enterprise assets and software are normally geared towards ease-of-deployment and ease-of-use rather than security. Basic controls, open services and ports, default accounts or passwords, pre-configured Domain Name System (DNS) settings, older (vulnerable) protocols, and pre-installation of unnecessary software can all be exploitable if left in their default state. Further, these security configuration updates need to be managed and maintained over the life cycle of enterprise assets and software. Configuration updates need to be tracked and approved through configuration management workflow process to maintain a record that can be reviewed for compliance, leveraged for incident response, and to support audits. This CIS Control is important to on-premises devices, as well as remote devices, network devices, and cloud environments.

##### Service providers play a key role in modern infrastructures, especially for smaller enterprises. They often are not set up by default in the most secure configuration to provide flexibility for their customers to apply their own security policies. Therefore, the presence of default accounts or passwords, excessive access, or unnecessary services are common in default configurations. These could introduce weaknesses that are under the responsibility of the enterprise that is using the software, rather than the service provider. This extends to ongoing management and updates, as some Platform as a Service (PaaS) only extend to the operating system, so patching and updating hosted applications are under the responsibility of the enterprise.

##### Even after a strong initial configuration is developed and applied, it must be continually managed to avoid degrading security as software is updated or patched, new security vulnerabilities are reported, and configurations are “tweaked,” to allow the installation of new software or to support new operational requirements.

====================================================================================================
## CIS Control 5: Account Management
====================================================================================================
   - 5.1: Establish and Maintain an Inventory of Accounts <control-5.1>
   - 5.2: Use Unique Passwords <control-5.2>
   - 5.3: Disable Dormant Accounts <control-5.3>
   - 5.4: Restrict Administrator Privileges to Dedicated Administrator Accounts <control-5.4>
   - 5.5: Establish and Maintain an Inventory of Service Accounts <control-5.5>
   - 5.6: Centralize Account Management <control-5.6>

**Why is this CIS Control Critical?**

##### It is easier for an external or internal threat actor to gain unauthorized access to enterprise assets or data through using valid user credentials than through “hacking” the environment. There are many ways to covertly obtain access to user accounts, including: weak passwords, accounts still valid after a user leaves the enterprise, dormant or lingering test accounts, shared accounts that have not been changed in months or years, service accounts embedded in applications for scripts, a user having the same password as one they use for an online account that has been compromised (in a public password dump), social engineering a user to give their password, or using malware to capture passwords or tokens in memory or over the network.

##### Administrative, or highly privileged, accounts are a particular target, because they allow attackers to add other accounts, or make changes to assets that could make them more vulnerable to other attacks. Service accounts are also sensitive, as they are often shared among teams, internal and external to the enterprise, and sometimes not known about, only to be revealed in standard account management audits.

##### Finally, account logging and monitoring is a critical component of security operations. While account logging and monitoring are covered in CIS Control 8 (Audit Log Management), it is important in the development of a comprehensive Identity and Access Management (IAM) program.

====================================================================================================
## CIS Control 6: Access Control Management
====================================================================================================

   - 6.1: Establish an Access Granting Process <control-6.1>
   - 6.2: Establish an Access Revoking Process <control-6.2>
   - 6.3: Require MFA for Externally-Exposed Applications <control-6.3>
   - 6.4: Require MFA for Remote Network Access <control-6.4>
   - 6.5: Require MFA for Administrative Access <control-6.5>
   - 6.6: Establish and Maintain an Inventory of Authentication and Authorization Systems <control-6.6>
   - 6.7: Centralize Access Control <control-6.7>
   - 6.8: Define and Maintain Role-Based Access Control <control-6.8>
     
**Why is this CIS Control Critical?**

##### Use processes and tools to create, assign, manage, and revoke access credentials and privileges for user, administrator, and service accounts for enterprise assets and software.

##### Where CIS Control 5 deals specifically with account management, CIS Control 6 focuses on managing what access these accounts have, ensuring users only have access to the data or enterprise assets appropriate for their role, and ensuring that there is strong authentication for critical or sensitive enterprise data or functions. Accounts should only have the minimal authorization needed for the role. Developing consistent access rights for each role and assigning roles to users is a best practice. Developing a program for complete provision and de-provisioning access is also important. Centralizing this function is ideal. 

##### There are some user activities that pose greater risk to an enterprise, either because they are accessed from untrusted networks, or performing administrator functions that allow the ability to add, change, or remove other accounts, or make configuration changes to operating systems or applications to make them less secure. This also enforces the importance of using MFA and Privileged Access Management (PAM) tools.

##### Some users have access to enterprise assets or data they do not need for their role; this might be due to an immature process that gives all users all access, or lingering access as users change roles within the enterprise over time. Local administrator privileges to users’ laptops is also an issue, as any malicious code installed or downloaded by the user can have greater impact on the enterprise asset running as administrator. User, administrator, and service account access should be based on enterprise role and need.

====================================================================================================
## CIS Control 7: Continuous Vulnerability Management
====================================================================================================

   - 7.1: Establish and Maintain a Vulnerability Management Process <control-7.1>
   - 7.2: Establish and Maintain a Remediation Process <control-7.2>
   - 7.3: Perform Automated Operating System Patch Management <control-7.3>
   - 7.4: Perform Automated Application Patch Management <control-7.4>
   - 7.5: Perform Automated Vulnerability Scans of Internal Enterprise Assets <control-7.5>
   - 7.6: Perform Automated Vulnerability Scans of Externally-Exposed Enterprise Assets <control-7.6>
   - 7.7: Remediate Detected Vulnerabilities <control-7.7>

**Why is this CIS Control Critical?**

##### Develop a plan to continuously assess and track vulnerabilities on all enterprise assets within the enterprise’s infrastructure, in order to remediate, and minimize, the window of opportunity for attackers. Monitor public and private industry sources for new threat and vulnerability information.

##### Cyber defenders are constantly being challenged from attackers who are looking for vulnerabilities within their infrastructure to exploit and gain access. Defenders must have timely threat information available to them about: software updates, patches, security advisories, threat bulletins, etc., and they should regularly review their environment to identify these vulnerabilities before the attackers do. Understanding and managing vulnerabilities is a continuous activity, requiring focus of time, attention, and resources.

##### Attackers have access to the same information and can often take advantage of vulnerabilities more quickly than an enterprise can remediate. While there is a gap in time from a vulnerability being known to when it is patched, defenders can prioritize which vulnerabilities are most impactful to the enterprise, or likely to be exploited first due to ease of use. For example, when researchers or the community report new vulnerabilities, vendors have to develop and deploy patches, indicators of compromise (IOCs), and updates. Defenders need to assess the risk of the new vulnerability to the enterprise, regression-test patches   , and install the patch.

##### There is never perfection in this process. Attackers might be using an exploit to a vulnerability that is not known within the security community. They might have developed an exploit to this vulnerability referred to as a “zero-day” exploit. Once the vulnerability is known in the community, the process mentioned above starts. Therefore, defenders must keep in mind that an exploit might already exist when the vulnerability is widely socialized. Sometimes vulnerabilities might be known within a closed community (e.g., vendor still developing a fix) for weeks, months, or years before it is disclosed publicly. Defenders have to be aware that there might always be vulnerabilities they cannot remediate, and therefore need to use other controls to mitigate.

##### Enterprises that do not assess their infrastructure for vulnerabilities and proactively address discovered flaws face a significant likelihood of having their enterprise assets compromised. Defenders face particular challenges in scaling remediation across an entire enterprise, and prioritizing actions with conflicting priorities, while not impacting the enterprise’s business or mission.

