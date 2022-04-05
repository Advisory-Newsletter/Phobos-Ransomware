# Phobos-Ransomware


**INDICATORS OF COMPROMISE:**

**Hash (SHA-256):**

dc34fca4e03dbdf52e8c7688e7802d5dec92cc84f07a78b1b33293675340630c

72a4d2e005dcbe47887bed98ace8a0d46459790c86fcacf7b295875916d8d8a6

c544daa7a7c0bb52ab74e222bbf66d4da14e444ebcea762974c4443d476589d3

8126710dbbaa090718ff9f6d067327725144426120c043db8e078f6d03e4eea0

0b4c743246478a6a8c9fa3ff8e04f297507c2f0ea5d61a1284fe65387d172f81


**MD5:**

7826b97292b7c34fbb5ae10bae9a7f3e

2c73b0bf6f09566d5edfd98a8863fe08

9f4f7505cbf63de8c70fb4182cab68cd

1b37755c28fb994623cb89fa95fa8634

**Malicious Filename:**

AntiRecuvaAndDB.exe

Fast.exe

svchost.exe.bin



**RECOMMENDATIONS:**

1. Create rules to detect and block IOCs mentioned above in applicable security solutions - SIEM, EDR, Firewall, Proxy, Email gateway etc. to secure the network.

2. To eliminate possible malware infections, scan your computer with legitimate antivirus software.

3. Avoid opening attachments presented in irrelevant emails. Users can be trained to identify social engineering techniques. URL inspection within email can also help detect links leading to known malicious sites.

4. Download software using official websites or other reliable sources. Do not use third party downloaders or other dubious tools.

5. Do not enable macros in document attachments received via emails. A lot of malware infections rely on the action to turn ON macros.

6. For organizations, it is advised to restrict inbound SMB Version 1 and 2 communication between client systems to prevent malware from spreading from one machine to another within the local network.

7. Turn on the network level authentication as it offers the strongest available method for authenticating RDP communications. Otherewise, credentials are sent in clear text to a remote host or domain controller.

8. RDP connections and outbound traffic should be monitored rigorously for much better visibility. Monitor for suspicious network traffic that could be indicative of scanning, such as large quantities originating from a single source.

9. Harden systems and applications: This complements the principle of least privilege and can involve configuration changes, removing unnecessary rights and access, closing ports, and more. This improves system and application security and helps prevent and mitigate the potential for bugs that leave vulnerability to injection of malicious code (i.e. SQL injections), buffer overflows, etc. or other backdoors that could allow privilege escalation.

10. Maintain offline (i.e., physically disconnected) backups of data, and regularly test backup and

**References:**

https://helpransomware.com/en/phobos-ransomware/
https://geeksadvice.com/remove-phobos-ransomware-virus/
https://techbeacon.com/security/phobos-ransomware-spreads-fear-due-your-terrible-infosec
https://blogs.blackberry.com/en/2021/09/threat-thursday-phobos-ransomware
https://www.bleepingcomputer.com/news/security/the-week-in-ransomware-january-21st-2022-arrests-wipers-and-more/
https://www.comparitech.com/net-admin/phobos-ransomware/
https://www.hhs.gov/sites/default/files/overview-phobos-ransomware.pdf
