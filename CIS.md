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

##### Actively manage (inventory, track, and correct) all enterprise assets (end-user devices, including portable and mobile; network devices; non-computing/Internet of Things (IoT) devices; and servers) connected to the infrastructure, physically, virtually, remotely, and those within cloud environments, to accurately know the totality of assets that need to be monitored and protected within the enterprise. This will also support identifying unauthorized and unmanaged assets to remove or remediate.

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

##### Actively manage (inventory, track, and correct) all software (operating systems and applications) on the network so that only authorized software is installed and can execute, and that unauthorized and unmanaged software is found and prevented from installation or execution.

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

##### Develop processes and technical controls to identify, classify, securely handle, retain, and dispose of data.

##### Data is no longer only contained within an enterprise’s border, it is in the cloud, on portable end-user devices where users work from home, and is often shared with partners or online services who might have it anywhere in the world. In addition to sensitive data an enterprise holds related to finances, intellectual property, and customer data, there also might be numerous international regulations for protection of personal data. Data privacy has become increasingly important, and enterprises are learning that privacy is about the appropriate use and management of data, not just encryption. Data must be appropriately managed through its entire lifecycle. These privacy rules can be complicated for multi-national enterprises, of any size, however there are fundamentals that can apply to all.

##### Once attackers have penetrated an enterprise’s infrastructure, one of their first tasks is to find and exfiltrate data. Enterprises might not be aware that sensitive data is leaving their environment because they are not monitoring data outflows.

##### While many attacks occur on the network, others involve physical theft of portable end-user devices, attacks on service providers or other partners holding sensitive data. Other sensitive enterprise assets may also include non-computing devices that provide management and control of physical systems, such as Supervisory Control and Data Acquisition (SCADA) systems.

##### The enterprise’s loss of control over protected or sensitive data is a serious and often reportable business impact. While some data is compromised or lost as a result of theft or espionage, the vast majority are a result of poorly understood data management rules, and user error. The adoption of data encryption, both in transit and at rest, can provide mitigation against data compromise, and more importantly, is a regulatory requirement for most controlled data.

====================================================================================================
## CIS Control 4: Secure Configuration of Enterprise Assets and Software
====================================================================================================

   - 4.1: Establish and Maintain a Secure Configuration Process
   - 4.2: Establish and Maintain a Secure Configuration Process for Network Infrastructure
   - 4.3: Ensure the Use of Dedicated Administrative Accounts
   - 4.4: Implement and Manage a Firewall on Servers
   - 4.5: Implement and Manage a Firewall on End-User Devices
   - 4.6: Securely Manage Enterprise Assets and Software
   - 4.7: Manage Default Accounts on Enterprise Assets and Software
   - 4.8: Uninstall or Disable Unnecessary Services on Enterprise Assets and Software
   - 4.9: Configure Trusted DNS Servers on Enterprise Assets
   - 4.10: Enforce Automatic Device Lockout on Portable End-User Devices
   - 4.11: Enforce Remote Wipe Capability on Portable End-User Devices
   - 4.12: Separate Enterprise Workspaces on Mobile End-User Devices

**Why is this CIS Control Critical?**

##### Establish and maintain the secure configuration of enterprise assets (end-user devices, including portable and mobile; network devices; non-computing/IoT devices; and servers) and software (operating systems and applications).

##### As delivered from manufacturers and resellers, the default configurations for enterprise assets and software are normally geared towards ease-of-deployment and ease-of-use rather than security. Basic controls, open services and ports, default accounts or passwords, pre-configured Domain Name System (DNS) settings, older (vulnerable) protocols, and pre-installation of unnecessary software can all be exploitable if left in their default state. Further, these security configuration updates need to be managed and maintained over the life cycle of enterprise assets and software. Configuration updates need to be tracked and approved through configuration management workflow process to maintain a record that can be reviewed for compliance, leveraged for incident response, and to support audits. This CIS Control is important to on-premises devices, as well as remote devices, network devices, and cloud environments.

##### Service providers play a key role in modern infrastructures, especially for smaller enterprises. They often are not set up by default in the most secure configuration to provide flexibility for their customers to apply their own security policies. Therefore, the presence of default accounts or passwords, excessive access, or unnecessary services are common in default configurations. These could introduce weaknesses that are under the responsibility of the enterprise that is using the software, rather than the service provider. This extends to ongoing management and updates, as some Platform as a Service (PaaS) only extend to the operating system, so patching and updating hosted applications are under the responsibility of the enterprise.

##### Even after a strong initial configuration is developed and applied, it must be continually managed to avoid degrading security as software is updated or patched, new security vulnerabilities are reported, and configurations are “tweaked,” to allow the installation of new software or to support new operational requirements.

====================================================================================================
## CIS Control 5: Account Management
====================================================================================================

   - 5.1: Establish and Maintain an Inventory of Accounts
   - 5.2: Use Unique Passwords
   - 5.3: Disable Dormant Accounts
   - 5.4: Restrict Administrator Privileges to Dedicated Administrator Accounts
   - 5.5: Establish and Maintain an Inventory of Service Accounts
   - 5.6: Centralize Account Management

**Why is this CIS Control Critical?**

##### Use processes and tools to assign and manage authorization to credentials for user accounts, including administrator accounts, as well as service accounts, to enterprise assets and software.

##### It is easier for an external or internal threat actor to gain unauthorized access to enterprise assets or data through using valid user credentials than through “hacking” the environment. There are many ways to covertly obtain access to user accounts, including: weak passwords, accounts still valid after a user leaves the enterprise, dormant or lingering test accounts, shared accounts that have not been changed in months or years, service accounts embedded in applications for scripts, a user having the same password as one they use for an online account that has been compromised (in a public password dump), social engineering a user to give their password, or using malware to capture passwords or tokens in memory or over the network.

##### Administrative, or highly privileged, accounts are a particular target, because they allow attackers to add other accounts, or make changes to assets that could make them more vulnerable to other attacks. Service accounts are also sensitive, as they are often shared among teams, internal and external to the enterprise, and sometimes not known about, only to be revealed in standard account management audits.

##### Finally, account logging and monitoring is a critical component of security operations. While account logging and monitoring are covered in CIS Control 8 (Audit Log Management), it is important in the development of a comprehensive Identity and Access Management (IAM) program.

====================================================================================================
## CIS Control 6: Access Control Management
====================================================================================================

   - 6.1: Establish an Access Granting Process
   - 6.2: Establish an Access Revoking Process
   - 6.3: Require MFA for Externally-Exposed Applications
   - 6.4: Require MFA for Remote Network Access
   - 6.5: Require MFA for Administrative Access
   - 6.6: Establish and Maintain an Inventory of Authentication and Authorization Systems
   - 6.7: Centralize Access Control
   - 6.8: Define and Maintain Role-Based Access Control
     
**Why is this CIS Control Critical?**

##### Use processes and tools to create, assign, manage, and revoke access credentials and privileges for user, administrator, and service accounts for enterprise assets and software.

##### Where CIS Control 5 deals specifically with account management, CIS Control 6 focuses on managing what access these accounts have, ensuring users only have access to the data or enterprise assets appropriate for their role, and ensuring that there is strong authentication for critical or sensitive enterprise data or functions. Accounts should only have the minimal authorization needed for the role. Developing consistent access rights for each role and assigning roles to users is a best practice. Developing a program for complete provision and de-provisioning access is also important. Centralizing this function is ideal. 

##### There are some user activities that pose greater risk to an enterprise, either because they are accessed from untrusted networks, or performing administrator functions that allow the ability to add, change, or remove other accounts, or make configuration changes to operating systems or applications to make them less secure. This also enforces the importance of using MFA and Privileged Access Management (PAM) tools.

##### Some users have access to enterprise assets or data they do not need for their role; this might be due to an immature process that gives all users all access, or lingering access as users change roles within the enterprise over time. Local administrator privileges to users’ laptops is also an issue, as any malicious code installed or downloaded by the user can have greater impact on the enterprise asset running as administrator. User, administrator, and service account access should be based on enterprise role and need.

====================================================================================================
## CIS Control 7: Continuous Vulnerability Management
====================================================================================================

   - 7.1: Establish and Maintain a Vulnerability Management Process
   - 7.2: Establish and Maintain a Remediation Process
   - 7.3: Perform Automated Operating System Patch Management
   - 7.4: Perform Automated Application Patch Management
   - 7.5: Perform Automated Vulnerability Scans of Internal Enterprise Assets
   - 7.6: Perform Automated Vulnerability Scans of Externally-Exposed Enterprise Assets
   - 7.7: Remediate Detected Vulnerabilities

**Why is this CIS Control Critical?**

##### Develop a plan to continuously assess and track vulnerabilities on all enterprise assets within the enterprise’s infrastructure, in order to remediate, and minimize, the window of opportunity for attackers. Monitor public and private industry sources for new threat and vulnerability information.

##### Cyber defenders are constantly being challenged from attackers who are looking for vulnerabilities within their infrastructure to exploit and gain access. Defenders must have timely threat information available to them about: software updates, patches, security advisories, threat bulletins, etc., and they should regularly review their environment to identify these vulnerabilities before the attackers do. Understanding and managing vulnerabilities is a continuous activity, requiring focus of time, attention, and resources.

##### Attackers have access to the same information and can often take advantage of vulnerabilities more quickly than an enterprise can remediate. While there is a gap in time from a vulnerability being known to when it is patched, defenders can prioritize which vulnerabilities are most impactful to the enterprise, or likely to be exploited first due to ease of use. For example, when researchers or the community report new vulnerabilities, vendors have to develop and deploy patches, indicators of compromise (IOCs), and updates. Defenders need to assess the risk of the new vulnerability to the enterprise, regression-test patches   , and install the patch.

##### There is never perfection in this process. Attackers might be using an exploit to a vulnerability that is not known within the security community. They might have developed an exploit to this vulnerability referred to as a “zero-day” exploit. Once the vulnerability is known in the community, the process mentioned above starts. Therefore, defenders must keep in mind that an exploit might already exist when the vulnerability is widely socialized. Sometimes vulnerabilities might be known within a closed community (e.g., vendor still developing a fix) for weeks, months, or years before it is disclosed publicly. Defenders have to be aware that there might always be vulnerabilities they cannot remediate, and therefore need to use other controls to mitigate.

##### Enterprises that do not assess their infrastructure for vulnerabilities and proactively address discovered flaws face a significant likelihood of having their enterprise assets compromised. Defenders face particular challenges in scaling remediation across an entire enterprise, and prioritizing actions with conflicting priorities, while not impacting the enterprise’s business or mission.

====================================================================================================
## CIS Control 8: Audit Log Management
====================================================================================================

   - 8.1: Establish and Maintain an Audit Log Management Process
   - 8.2: Collect Audit Logs
   - 8.3: Ensure Adequate Audit Log Storage
   - 8.4: Standardize Time Synchronization
   - 8.5: Collect Detailed Audit Logs
   - 8.6: Collect DNS Query Audit Logs
   - 8.7: Collect URL Request Audit Logs
   - 8.8: Collect Command-Line Audit Logs
   - 8.9: Centralize Audit Logs
   - 8.10: Retain Audit Logs
   - 8.11: Conduct Audit Log Reviews
   - 8.12 Collect Service Provider Logs

**Why is this CIS Control Critical?**

##### Collect, alert, review, and retain audit logs of events that could help detect, understand, or recover from an attack.

##### Log collection and analysis is critical for an enterprise’s ability to detect malicious activity quickly. Sometimes audit records are the only evidence of a successful attack. Attackers know that many enterprises keep audit logs for compliance purposes, but rarely analyze them. Attackers use this knowledge to hide their location, malicious software, and activities on victim machines. Due to poor or nonexistent log analysis processes, attackers sometimes control victim machines for months or years without anyone in the target enterprise knowing.

##### There are two types of logs that are generally treated and often configured independently: system logs and audit logs. System logs typically provide system-level events that show various system process start/end times, crashes, etc. These are native to systems, and take less configuration to turn on. Audit logs typically include user-level events – when  a user logged in, accessed a file, etc. – and take more planning and effort to set up.

##### Logging records are also critical for incident response. After an attack has been detected, log analysis can help enterprises understand the extent of an attack. Complete logging records can show, for example, when and how the attack occurred, what information was accessed, and if data was exfiltrated. Retention of logs is also critical in case a follow-up investigation is required or if an attack remained undetected for a long period of time.

====================================================================================================
## CIS Control 9: Email and Web Browser Protections
====================================================================================================

   - 9.1: Ensure Use of Only Fully Supported Browsers and Email Clients
   - 9.2: Use DNS Filtering Services
   - 9.3: Maintain and Enforce Network-Based URL Filters
   - 9.4: Restrict Unnecessary or Unauthorized Browser and Email Client Extensions
   - 9.5: Implement DMARC
   - 9.6: Block Unnecessary File Types
   - 9.7: Deploy and Maintain Email Server Anti-Malware Protections

**Why is this CIS Control Critical?**

##### Improve protections and detections of threats from email and web vectors, as these are opportunities for attackers to manipulate human behavior through direct engagement.

##### Web browsers and email clients are very common points of entry for attackers because of their direct interaction with users inside an enterprise. Content can be crafted to entice or spoof users into disclosing credentials, providing sensitive data, or providing an open channel to allow attackers to gain access, thus increasing risk to the enterprise. Since email and web are the main means that users interact with external and untrusted users and environments, these are prime targets for both malicious code and social engineering. Additionally, as enterprises move to web-based email, or mobile email access, users no longer use traditional full-featured email clients, which provide embedded security controls like connection encryption, strong authentication, and phishing reporting buttons.

====================================================================================================
## CIS Control 10: Malware Defenses
====================================================================================================

   - 10.1: Deploy and Maintain Anti-Malware Software
   - 10.2: Configure Automatic Anti-Malware Signature Updates
   - 10.3: Disable Autorun and Autoplay for Removable Media
   - 10.4: Configure Automatic Anti-Malware Scanning of Removable Media
   - 10.5: Enable Anti-Exploitation Features
   - 10.6: Centrally Manage Anti-Malware Software
   - 10.7: Use Behavior-Based Anti-Malware Software

**Why is this CIS Control Critical?**

##### Prevent or control the installation, spread, and execution of malicious applications, code, or scripts on enterprise assets.

##### Malicious software (sometimes categorized as viruses or Trojans) is an integral and dangerous aspect of internet threats. They can have many purposes, from capturing credentials, stealing data, identifying other targets within the network, and encrypting or destroying data. Malware is ever-evolving and adaptive, as modern variants leverage machine learning techniques.

##### Malware enters an enterprise through vulnerabilities within the enterprise on end-user devices, email attachments, webpages, cloud services, mobile devices, and removable media. Malware often relies on insecure end-user behavior, such as clicking links, opening attachments, installing software or profiles, or inserting Universal Serial Bus (USB) flash drives. Modern malware is designed to avoid, deceive, or disable defenses.

##### Malware defenses must be able to operate in this dynamic environment through automation, timely and rapid updating, and integration with other processes like vulnerability management and incident response. They must be deployed at all possible entry points and enterprise assets to detect, prevent spread, or control the execution of malicious software or code.

====================================================================================================
## CIS Control 11: Data Recovery
====================================================================================================

   - 11.1: Establish and Maintain a Data Recovery Process
   - 11.2: Perform Automated Backups
   - 11.3: Protect Recovery Data
   - 11.4: Establish and Maintain an Isolated Instance of Recovery Data
   - 11.5: Test Data Recovery

**Why is this CIS Control Critical?**

##### Establish and maintain data recovery practices sufficient to restore in-scope enterprise assets to a pre-incident and trusted state.

##### In the cybersecurity triad – Confidentiality, Integrity, and Availability (CIA) – the availability of data is, in some cases, more critical than its confidentiality. Enterprises need many types of data to make business decisions, and when that data is not available or is untrusted, then it could impact the enterprise. An easy example is weather information to a transportation enterprise.

##### When attackers compromise assets, they make changes to configurations, add accounts, and often add software or scripts. These changes are not always easy to identify, as attackers might have corrupted or replaced trusted applications with malicious versions, or the changes might appear to be standard-looking account names. Configuration changes can include adding or changing registry entries, opening ports, turning off security services, deleting logs, or other malicious actions that make a system insecure. These actions do not have to be malicious; human error can cause each of these as well. Therefore, it is important to have an ability to have recent backups or mirrors to recover enterprise assets and data back to a known trusted state.

##### There has been an exponential rise in ransomware over the last few years. It is not a new threat, though it has become more commercialized and organized as a reliable method for attackers to make money. If an attacker encrypts an enterprise’s data and demands ransom for its restoration, having a recent backup to recover to a known, trusted state can be helpful. However, as ransomware has evolved, it has also become an extortion technique, where data is exfiltrated before being encrypted, and the attacker asks for payment to restore the enterprise’s data, as well as to keep it from being sold or publicized. In this case, restoration would only solve the issue of restoring systems to a trusted state and continuing operations. Leveraging the guidance within the CIS Controls will help reduce the risk of ransomware through improved cyber hygiene, as attackers usually use older or basic exploits on insecure systems.

