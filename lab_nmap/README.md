# Nmap Vulnerability Assessment Lab - Detailed Observations

## Lab Overview
- **Tool:** Nmap
- **Environment:** Local lab (Metasploitable2 on VMware)
- **Focus:** Reconnaissance only (no exploitation)

## Lab Environment
- **Attack Machine**: Kali Linux (VMware Workstation)
- **Target Machine**: Metasploitable2 (VMware Workstation)
- **Host System**: Windows 11
- **Purpose**: Controlled security assessment in isolated lab environment

---

## Scan Results & Analysis

### 1. nmap \<target\> (Default Scan)

**What I did:**  
Executed a default Nmap scan against the Metasploitable2 target without additional flags.

**Why I did it:**  
To perform initial reconnaissance and establish a baseline of exposed services. This scan identifies the top 1000 most commonly used ports to quickly map the attack surface.

**What I observed:**  
- Discovered 23 open ports running various services including FTP (21), SSH (22), Telnet (23), SMTP (25), HTTP (80), MySQL (3306), and others
- 977 ports reported as closed
- MAC address and VM environment details captured
- Scan completed in 0.49 seconds

**What I think the risk is:**  
Multiple unnecessary services exposed simultaneously increase the attack surface significantly. Each open port represents a potential entry point. Legacy protocols like Telnet and FTP transmit credentials in plaintext, creating immediate credential exposure risk. The large number of services suggests inadequate hardening and potential for service-specific vulnerabilities.

---

### 2. nmap -sn \<target\> (Host Discovery / Ping Scan)

**What I did:**  
Performed a host discovery scan using the `-sn` flag to check network presence without port scanning.

**Why I did it:**  
To verify target availability before committing to resource-intensive port scans. This technique is faster and generates less network traffic, making it more suitable for initial network mapping and stealthier than full scans.

**What I observed:**  
- Host confirmed as "up" and responsive
- MAC address and VM environment identified
- IP address of target recorded
- Scan completed significantly faster than default scan (sub-second)

**What I think the risk is:**  
The host responds to standard ICMP/ARP discovery requests, confirming it is discoverable on the network. While this specific scan doesn't reveal vulnerabilities, it confirms the system is reachable and can be targeted for further enumeration. In production environments, unnecessary host discovery responses aid attackers in network mapping.

---

### 3. nmap -sT -p- \<target\> (Full TCP Connect Scan - All Ports)

**What I did:**  
Executed a full TCP connect scan across all 65,535 ports using the `-sT` flag with `-p-` for comprehensive port coverage.

**Why I did it:**  
To ensure no services are missed by scanning only common ports. The full TCP handshake method is reliable and functions without requiring administrative privileges, making it useful when raw socket access is unavailable.

**What I observed:**  
- All 23 open ports identified (same as default scan)
- 65,512 ports marked as closed with "connection refused" responses
- MAC address and environment details captured
- Scan duration: 2.03 seconds (significantly longer than targeted scans)
- High volume of connection attempts logged

**What I think the risk is:**  
While this scan confirmed no additional hidden services on non-standard ports, the method itself is highly detectable. The full TCP handshake generates extensive logs on target systems and can trigger IDS/IPS alerts. In a real assessment, this would alert security teams to reconnaissance activity. The extended scan time also indicates potential for resource exhaustion on both scanner and target.

---

### 4. nmap -sS -p- \<target\> (SYN Stealth Scan - All Ports)

**What I did:**  
Performed a SYN stealth scan across all ports using the `-sS` flag combined with `-p-` for full port range coverage.

**Why I did it:**  
To achieve comprehensive port enumeration while maintaining a lower detection profile. SYN scans send the initial SYN packet but never complete the three-way handshake, resulting in "half-open" connections that may evade basic logging and are more efficient than full connects.

**What I observed:**  
- Same 23 open ports identified as previous scans
- Significantly faster completion time compared to full TCP connect scan
- Reduced logging footprint on target (no established connections)
- Requires root/administrator privileges to execute

**What I think the risk is:**  
From a defensive perspective, this technique demonstrates how attackers can enumerate services while reducing their detection signature. Modern stateful firewalls and IDS systems still detect SYN scans, but legacy or misconfigured systems may miss them. The speed advantage makes this method preferable for attackers conducting large-scale reconnaissance.

---

### 5. nmap -sS -PR \<target\> (SYN Scan with ARP Ping)

**What I did:**  
Combined a SYN scan with ARP-based host discovery using `-sS` and `-PR` flags.

**Why I did it:**  
To leverage Layer 2 (Data Link) discovery on the local network segment. ARP requests are the most reliable method for confirming host presence on a LAN since they operate below the IP layer and cannot be blocked by host-based firewalls.

**What I observed:**  
- Host discovery confirmed via ARP response
- Services enumerated via subsequent SYN scan
- Extremely fast and reliable on local network segments
- Ineffective across routed networks (ARP doesn't cross Layer 3 boundaries)

**What I think the risk is:**  
This technique is particularly effective for insider threats or attackers who have gained local network access. ARP-based discovery cannot be disabled without breaking network functionality, making it impossible to defend against on local segments. This highlights the importance of network segmentation and assumes that local network presence equals compromise visibility.

---

### 6. nmap -sA \<target\> (TCP ACK Scan)

**What I did:**  
Executed a TCP ACK scan using the `-sA` flag to send ACK packets without prior SYN.

**Why I did it:**  
To map firewall rulesets rather than identify open services. ACK scans help determine if ports are filtered by stateful firewalls or simply closed. This technique is used for firewall fingerprinting and rule enumeration.

**What I observed:**  
- Ports classified as "unfiltered" or "filtered" rather than "open/closed"
- No service information gathered (by design)
- Useful for understanding filtering behavior and firewall state tracking
- Responses indicate firewall presence and rule complexity

**What I think the risk is:**  
While this doesn't directly reveal vulnerabilities, it provides attackers with firewall architecture intelligence. Understanding which ports are filtered versus unfiltered helps attackers craft evasion techniques and identify potential filtering gaps. Improperly configured stateful firewalls may reveal their ruleset structure through ACK responses.

---

### 7. nmap -sn -PS80 \<target\> (TCP SYN Ping to Port 80)

**What I did:**  
Performed host discovery by sending TCP SYN packets specifically to port 80 using `-sn` and `-PS80` flags.

**Why I did it:**  
To detect hosts that block standard ICMP echo requests but still respond to TCP probes. Many firewalls allow HTTP traffic by default, making port 80 an ideal candidate for stealthy host discovery.

**What I observed:**  
- Host successfully detected despite potential ICMP blocking
- Alternative discovery method useful when traditional ping fails
- Port 80 commonly allowed through perimeter defenses
- Effective for discovering web servers specifically

**What I think the risk is:**  
This demonstrates a firewall bypass technique that highlights over-reliance on ICMP filtering alone. Systems that appear "offline" via standard ping may still be discoverable and exploitable. Organizations blocking ICMP without considering TCP-based discovery create a false sense of security.

---

### 8. nmap -p 22,80,443 \<target\> (Specific Port Scan)

**What I did:**  
Scanned only three specific high-value ports (SSH, HTTP, HTTPS) using the `-p` flag with a comma-separated list.

**Why I did it:**  
To perform targeted, time-efficient reconnaissance when specific services are of interest. This reduces scan time and network noise while focusing on commonly exploitable services.

**What I observed:**  
- SSH (22): Open
- HTTP (80): Open  
- HTTPS (443): Filtered/Closed (expected on Metasploitable2)
- Scan completed in a fraction of the time compared to full scans
- Reduced detection footprint

**What I think the risk is:**  
These three services represent critical entry points. SSH provides remote access and is a primary target for brute-force attacks. HTTP services often contain web application vulnerabilities (SQLi, XSS, command injection). The focused nature of this scan suggests an attacker has prior intelligence or is specifically targeting remote access and web services.

---

### 9. nmap -p 1-10 \<target\> (Port Range Scan)

**What I did:**  
Scanned a limited sequential range of ports (1-10) using the `-p 1-10` syntax.

**Why I did it:**  
To demonstrate range-based scanning for testing specific port blocks efficiently. This is useful when investigating services typically bound to low-numbered well-known ports.

**What I observed:**  
- Limited results as most low ports were closed on target
- Faster execution than full range scans
- Useful for targeted assessment of specific service categories

**What I think the risk is:**  
While this specific range revealed minimal exposure on the target, the technique itself is valuable for attackers performing systematic sweeps across multiple hosts. Scanning low-numbered ports in bulk across networks can quickly identify administrative services and legacy protocols (FTP, Telnet, SSH) commonly running in these ranges.

---

### 10. nmap -T3 / -T5 \<target\> (Timing Templates)

**What I did:**  
Executed scans using different timing templates: `-T3` (Normal) and `-T5` (Insane).

**Why I did it:**  
To understand the trade-off between scan speed and reliability/stealth. T3 provides balanced performance suitable for most networks, while T5 prioritizes speed at the cost of accuracy and detection avoidance.

**What I observed:**  
- **T3**: Reliable results, moderate speed, fewer packet drops
- **T5**: Extremely fast but generated significant network traffic, potential for missed results due to timeouts
- T5 increases risk of triggering rate-limiting or crashing unstable services
- T5 highly detectable by IDS/IPS systems

**What I think the risk is:**  
Aggressive timing can cause denial-of-service conditions on older systems or saturate network segments. From a defensive perspective, sudden traffic spikes from T4/T5 scans are clear indicators of active reconnaissance. Attackers using aggressive timing prioritize speed over stealth, suggesting urgency or lack of concern about detection.

---

### 11. nmap -O \<target\> (OS Detection)

**What I did:**  
Enabled operating system detection using the `-O` flag to fingerprint the target's OS.

**Why I did it:**  
To gather intelligence about the underlying operating system, which informs exploit selection and attack vector planning. Different OS versions have distinct vulnerabilities and security characteristics.

**What I observed:**  
- Target identified as Linux-based system (expected for Metasploitable2)
- Confidence level provided (not always 100% accurate)
- OS detection relies on TCP/IP stack fingerprinting
- Additional details about device type and OS family

**What I think the risk is:**  
Accurate OS identification allows attackers to narrow exploit selection to platform-specific vulnerabilities. Knowing the exact OS version enables targeted attacks against known kernel vulnerabilities, default configurations, and version-specific weaknesses. This information is critical for weaponizing reconnaissance into actual exploitation.

---

### 12. nmap -A \<target\> (Aggressive Scan)

**What I did:**  
Executed an aggressive scan combining OS detection, version detection, script scanning, and traceroute using the `-A` flag.

**Why I did it:**  
To perform comprehensive information gathering in a single command. This "all-in-one" approach provides maximum intelligence but generates significant network activity.

**What I observed:**  
- Complete service version information (e.g., "Apache 2.2.8")
- OS fingerprinting results
- Default NSE scripts executed automatically
- Traceroute showing network path
- Extensive banner grabbing and service enumeration
- Longest scan duration of all techniques tested

**What I think the risk is:**  
This level of enumeration provides attackers with a complete target profile for exploit matching. Service versions can be cross-referenced against CVE databases to identify known vulnerabilities. The scan is extremely noisy and will trigger any competent IDS/IPS, indicating either an attacker who doesn't care about detection or an auditor conducting authorized testing.

---

### 13. nmap -sV \<target\> (Service Version Detection)

**What I did:**  
Performed service version detection using the `-sV` flag to identify specific software versions running on open ports.

**Why I did it:**  
To gather precise version information for vulnerability correlation. Generic "port 80 open" information is insufficient for exploit matching, specific versions enable CVE lookups.

**What I observed:**  
- Detailed version strings for each service (e.g., "vsftpd 2.3.4", "OpenSSH 4.7p1")
- Additional service metadata captured
- Increased scan time due to banner grabbing and probe responses
- Some services revealed through version-specific responses

**What I think the risk is:**  
Version information is directly mappable to CVE databases. Outdated versions with known exploits become immediate high-priority targets. In this lab, vsftpd 2.3.4 was identified, which contains a famous backdoor (CVE-2011-2523). Version detection transforms reconnaissance into actionable exploitation intelligence.

---

### 14. nmap -sV -Pn \<target\> (Version Detection with No Ping)

**What I did:**  
Combined version detection with the `-Pn` flag to skip host discovery and force scanning regardless of ping response.

**Why I did it:**  
To scan hosts that appear offline or block ICMP but are actually active. Many hardened systems disable ping responses while still running services.

**What I observed:**  
- Scan proceeded despite host potentially appearing "down" to standard discovery
- All services enumerated with version details
- Longer overall scan time (no early exit for "down" hosts)
- Useful when prior intelligence confirms host existence

**What I think the risk is:**  
This technique reveals that ICMP blocking alone is insufficient security. Systems configured to ignore pings may create false confidence for defenders while remaining fully exploitable. Attackers with prior network knowledge will bypass discovery phases entirely and probe directly.

---

### 15. nmap -sU -p \<target\> (UDP Scan)

**What I did:**  
Performed UDP port scanning using the `-sU` flag to identify UDP-based services.

**Why I did it:**  
To discover services that operate over UDP rather than TCP (DNS, SNMP, DHCP, NTP, etc.). UDP scanning is essential for complete network mapping as many reconnaissance tools focus exclusively on TCP.

**What I observed:**  
- Significantly slower than TCP scans due to UDP's connectionless nature
- Services like DNS (53) and others identified
- Many ports reported as "open|filtered" due to UDP's ambiguous responses
- Requires root privileges and patient timing

**What I think the risk is:**  
UDP services are often overlooked in security audits, creating blind spots. SNMP (161/162) can leak extensive system information, DNS (53) can be exploited for cache poisoning or zone transfers, and older DHCP implementations have vulnerabilities. The stateless nature of UDP also makes these services harder to monitor and protect with traditional firewalls.

---

### 16. nmap -sS -sU -p T:1-10,U:53 \<target\> (Combined TCP/UDP Scan)

**What I did:**  
Executed a combined scan targeting both TCP ports 1-10 and UDP port 53 using `-sS -sU` with protocol-specific port notation.

**Why I did it:**  
To demonstrate simultaneous multi-protocol scanning for comprehensive service mapping. This approach captures both transport layer protocols in a single scan.

**What I observed:**  
- TCP and UDP services enumerated together
- Protocol-specific port syntax (T: and U:) allows granular control
- DNS service (UDP 53) identified if present
- Combined scan takes longer than single-protocol scans

**What I think the risk is:**  
Attackers using dual-protocol scanning ensure complete visibility into network services. Missing UDP enumeration could overlook critical services. DNS specifically can be a pivot point for reconnaissance (zone transfers, cache snooping) or exploitation (tunneling, amplification attacks).

---

### 17. nmap -f \<target\> (Fragment Packets)

**What I did:**  
Enabled packet fragmentation using the `-f` flag to split scan packets into smaller fragments.

**Why I did it:**  
To evade older intrusion detection systems and packet filters that fail to properly reassemble fragmented packets for inspection.

**What I observed:**  
- Scan traffic broken into 8-byte fragments
- Can bypass simplistic firewall rules
- Modern IDS/IPS systems typically handle fragmentation correctly
- Minimal performance impact on scan completion time

**What I think the risk is:**  
This demonstrates an evasion technique that exploits weaknesses in defensive systems. While modern security infrastructure handles fragmentation, legacy systems or misconfigured devices may allow fragmented scans to bypass detection. Organizations relying on outdated security appliances remain vulnerable to these basic evasion tactics.

---

### 18. nmap --source-port 53 \<target\> (Spoofed Source Port)

**What I did:**  
Specified source port 53 (DNS) for all scan packets using the `--source-port 53` flag.

**Why I did it:**  
To exploit firewall misconfigurations that implicitly trust traffic from DNS ports. Some poorly configured firewalls allow unrestricted traffic from port 53 assuming it's legitimate DNS responses.

**What I observed:**  
- Scan traffic appeared to originate from DNS port
- May bypass stateless firewall rules trusting source port 53
- Effective against misconfigured ACLs
- Easily defeated by stateful inspection

**What I think the risk is:**  
This highlights the danger of port-based trust models. Firewalls configured to allow "DNS traffic" based solely on port number (rather than state tracking) can be completely bypassed. Attackers can tunnel arbitrary reconnaissance or exploitation traffic through trusted ports, defeating perimeter security.

---

### 19. NSE Script: --script=http-auth-finder

**What I did:**  
Executed the `http-auth-finder` NSE script to identify web pages requiring authentication.

**Why I did it:**  
To map authentication boundaries and identify login portals, admin panels, or protected resources that may be targets for credential attacks or authorization bypasses.

**What I observed:**  
- Multiple authentication-required pages identified
- HTTP authentication mechanisms detected (Basic, Digest, Form-based)
- Potential admin interfaces discovered
- Information useful for subsequent brute-force or credential stuffing attacks

**What I think the risk is:**  
Exposed authentication portals are immediate targets for credential-based attacks. Form-based authentication without proper rate limiting, lockout policies, or MFA is particularly vulnerable. Admin panels accessible from external networks represent critical security failures. Each identified auth boundary is a potential entry point if default credentials exist or passwords are weak.

---

### 20. NSE Script: --script=http-enum

**What I did:**  
Ran the `http-enum` NSE script to enumerate common web directories and files.

**Why I did it:**  
To discover hidden directories, administrative interfaces, configuration files, and other resources not linked from the main application. Web applications often contain forgotten or unprotected admin areas.

**What I observed:**  
- Multiple directories discovered (e.g., /admin, /backup, /test, /phpmyadmin)
- Common CMS paths and admin panels identified
- Backup files and temporary directories found
- Server information leakage through directory listings

**What I think the risk is:**  
Exposed administrative interfaces and backup directories represent immediate compromise opportunities. Directories like /phpmyadmin, /admin, or /backup often contain high-privilege access points or sensitive data. Publicly accessible development/test directories may contain unpatched code or debug information. Each discovered path expands the attack surface and may contain authentication bypasses or direct data access.

---

### 21. NSE Script: --script=http-title

**What I did:**  
Executed the `http-title` NSE script to extract HTML title tags from web pages.

**Why I did it:**  
To quickly identify the purpose and technology of web services without full browsing. Titles often reveal application names, versions, or function (e.g., "phpMyAdmin 3.5.2", "Admin Login Portal").

**What I observed:**  
- Application names and versions revealed in titles
- Technology stack hints provided
- Administrative interfaces clearly labeled
- Quick service categorization achieved

**What I think the risk is:**  
Title information accelerates target profiling and exploit selection. Titles revealing version numbers enable direct CVE lookups. Administrative interface titles (e.g., "Router Admin", "Database Management") flag high-value targets. Information disclosure through titles is a minor but cumulative weakness that aids attacker reconnaissance.

---

### 22. NSE Script: --script=smtp-enum-users

**What I did:**  
Ran the `smtp-enum-users` NSE script to enumerate valid email addresses/usernames on the SMTP server.

**Why I did it:**  
To harvest valid usernames for subsequent authentication attacks. SMTP servers may respond differently to valid versus invalid recipients, enabling user enumeration.

**What I observed:**  
- Valid usernames extracted through SMTP VRFY/EXPN commands
- Service confirmed if user enumeration is possible
- User list generated for credential attacks
- Information disclosure through SMTP commands

**What I think the risk is:**  
Valid username lists eliminate the guessing phase of credential attacks, halving the brute-force complexity. Enumerated accounts can be targeted with password spraying, phishing, or social engineering. SMTP user enumeration represents an information disclosure vulnerability that directly enables authentication attacks. Modern servers should disable VRFY/EXPN or rate-limit these queries.

---

### 23. NSE Script: --script=vuln

**What I did:**  
Executed the comprehensive `vuln` script category to check for known vulnerabilities across all detected services.

**Why I did it:**  
To automatically correlate detected services against Nmap's vulnerability database and identify immediately exploitable weaknesses.

**What I observed:**  
- Multiple vulnerabilities identified, including CVE-2011-2523 (vsftpd backdoor)
- Confidence levels provided for each finding
- Direct exploitation paths suggested
- Critical vulnerabilities flagged for priority remediation

**What I think the risk is:**  
Automated vulnerability detection removes the need for manual CVE correlation, accelerating the attack timeline from reconnaissance to exploitation. The vsftpd backdoor (CVE-2011-2523) specifically allows unauthenticated remote code execution, representing complete system compromise. Any service flagged by vulnerability scripts should be considered immediately exploitable and requires urgent patching.

---

### 24. NSE Script: --script=ftp-vsftpd-backdoor

**What I did:**  
Ran the specific `ftp-vsftpd-backdoor` NSE script targeting the known backdoor in vsftpd 2.3.4.

**Why I did it:**  
To confirm the presence of CVE-2011-2523, a backdoor that allows unauthenticated remote code execution when triggered by a specific smiley face sequence in the username.

**What I observed:**  
- Backdoor confirmed as present and exploitable
- CVE-2011-2523 details retrieved
- Exploitation mechanism documented (malicious username trigger)
- Additional research conducted across multiple vulnerability databases (MITRE, NVD, Red Hat, Exploit-DB)

**What I think the risk is:**  
This represents a **critical severity vulnerability** with trivial exploitation complexity. An unauthenticated remote attacker can achieve complete system compromise (root/shell access) with a single malformed login attempt. The backdoor was intentionally inserted into the source code and widely distributed, affecting any system running this specific version. CVSS scoring indicates maximum impact on confidentiality, integrity, and availability. Immediate remediation required.

---

## Cross-Cutting Observations

### Port States Interpretation
- **Open**: Service actively accepting connections (investigate/harden)
- **Closed**: Port reachable but no service listening (not an immediate risk)
- **Filtered**: Firewall/filter dropping packets (partial security control present)
- **Open|Filtered**: Ambiguous state, typically UDP ports (requires further investigation)

### OS Detection Confidence
OS fingerprinting provides confidence percentages, not certainties. Results should be validated through multiple methods (service versions, banners, behavior) before basing security decisions on them.

### Scan Timing Trade-offs
- **T0-T2**: Slow, stealthy, evades IDS (operational attacker)
- **T3**: Balanced, default (standard auditing)
- **T4-T5**: Fast, noisy, detectable (time-constrained testing or aggressive attacker)

---

## Vulnerability Research Methodology

For identified vulnerabilities (example: vsftpd CVE-2011-2523):

1. **CVE Database (MITRE)**: Official vulnerability description and references
2. **NVD (NIST)**: CVSS scoring, severity metrics, affected versions, solution guidance
3. **Vendor Sites (Red Hat)**: Detailed CVSS breakdown, environmental scoring, real-world context
4. **Exploit-DB**: Proof-of-concept code, exploitation techniques, attacker perspective

This multi-source approach provides comprehensive understanding from both defensive (patching, mitigation) and offensive (exploitation method, attacker TTPs) perspectives.

---

## Defense Recommendations Based on Findings

1. **Service Minimization**: Disable unnecessary services (Telnet, outdated FTP)
2. **Patch Management**: Update vsftpd and all services to current versions
3. **Protocol Hardening**: Replace plaintext protocols (Telnet → SSH, FTP → SFTP)
4. **Firewall Hardening**: Implement stateful inspection, disable source port trust
5. **IDS/IPS Tuning**: Ensure detection of stealth scans, fragmentation, and evasion techniques
6. **Access Control**: Implement network segmentation and least privilege
7. **Monitoring**: Log and alert on reconnaissance patterns (port scans, user enumeration)
8. **Web Security**: Remove admin interfaces from public access, disable directory listing

---

## Lab Learning Outcomes

This controlled assessment demonstrated:
- Systematic network reconnaissance methodology
- Trade-offs between stealth, speed, and detection
- Correlation of service enumeration with vulnerability identification
- Importance of layered defense (relying on single controls creates bypasses)
- Critical nature of patch management and service hardening
- Attacker perspective for informing defensive priorities

**Ethical Note**: All testing conducted in isolated lab environment against intentionally vulnerable systems. Techniques documented here must only be used with explicit authorization in professional security assessment contexts.
