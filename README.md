# Amplified Reflection Attack Exploiting Middleboxes - Code and Test Environment

This README details the setup of the experimental environment used to analyze TCP amplified reflection attacks that exploit middleboxes. It covers the source code structure as well as the virtual and network elements of the lab. First, it presents the architecture and operation of the attack code, including execution instructions and supplementary information obtained through direct communication with its author. Following that, it describes the test environment built in VMware Workstation Pro, which consists of virtual machines representing the attacker, the victim, and the middlebox devices (pfSense and FortiGate firewalls), along with their respective configurations.

This structure enabled a controlled simulation of the attack and a detailed analysis of its behavior against different intermediary devices, providing a practical understanding of amplified reflection mechanisms and their security implications.

## Description of the Attack Code

This section documents the use and configuration of the code available at:
[https://github.com/moloch54/Ddos-TCP-Middlebox-Reflection-Attack](https://github.com/moloch54/Ddos-TCP-Middlebox-Reflection-Attack)

\<img width="850" alt="tipos\_ataque\_page" src="[https://github.com/user-attachments/assets/895bf494-9bcb-4f47-acd6-c1d6d3c32e39](https://github.com/user-attachments/assets/895bf494-9bcb-4f47-acd6-c1d6d3c32e39)" /\>
\<br\>
\<br\>

The code was highly useful for conducting lab experiments, allowing for the practical implementation of the concepts from the scientific paper "Weaponizing Middleboxes for TCP Reflected Amplification" by Bock et al. With it, we were able to replicate the Middlebox Reflection technique (b), facilitating the understanding and validation of amplified reflection mechanisms using middleboxes over the TCP protocol. In this technique, the source IP address is spoofed to be that of the victim, causing the middlebox responses to reach the target directly.

To understand the attack, it's necessary to review the TCP connection establishment process, the Three-Way Handshake, which has three steps:

1.  The client (SRC) sends a SYN packet to initiate the connection.
2.  The server (DEST) responds with a SYN, ACK packet, acknowledging the request.
3.  The client sends an ACK packet, finalizing the connection.

The attack exploits the fact that, in networks with intermediary devices (such as firewalls or proxies), packets can follow different paths. The SYN packet is spoofed (with `SRC=Victim` and `DST=Server`), but the SYN, ACK response from the real server might follow another route and not be seen by the middlebox. This creates a state inconsistency.

The attacker, after the spoofed SYN, sends a second ACK packet (also with a spoofed source IP). The middlebox, having not seen the SYN, ACK, interprets this ACK as invalid and may generate automatic responses, such as RST packets or multiple blocking/warning messages, amplifying traffic against the victim.

The attack can be refined with packets containing data. After the SYN, the attacker can send an ACK+PSH packet with a payload, such as an HTTP request. For example:

  * Sending a SYN packet with a spoofed source IP address (from the victim) and a destination to domains with a high potential for middlebox blocking: `SRC=Victim`, `DST=youporn.com (66.254.114.79), facebook.com (157.240.13.35), pornhub.com (66.254.114.41), bittorrent.com (98.143.146.7)`.
  * Subsequent sending of an ACK+PSH packet with a payload: an HTTP GET request, also with `SRC=Victim`.

These packets, when processed by content filtering middleboxes, can trigger multiple responses, reinforcing the amplification effect.

The choice of this public code was due to its clear structure and alignment with Bock et al.'s methodology, which ensured the conformity of the implementation and allowed us to focus on the experimental and analytical aspects, avoiding development from scratch.

-----

## Code Execution

To execute the amplified TCP reflection attack code, you must follow the steps described in the repository's README.md file. First, the dependencies must be installed and configured. The necessary tools are:

  * **tcpreplay**: For replaying packets on a network interface.
  * **mergecap**: For merging packets from multiple threads into a single .pcap file.
  * **scapy**: A Python library for building and manipulating TCP packets.

To install the dependencies on Debian/Ubuntu systems, use the following command:

```bash
sudo apt-get install tcpreplay mergecap python3-scapy
```

After installation, the code can be executed directly from the terminal. The command to start the attack is:

```bash
sudo python3 mra.py <time_in_seconds> <target_IP>
```

`<time_in_seconds>` defines the duration of the attack, and `<target_IP>` is the IP address you want to overload.

The script generates spoofed TCP packets, sending a SYN packet to a destination site (filtered by a middlebox) and then an ACK + PSH packet with an HTTP payload. This causes the middlebox to respond with an RST or an error page. The generated traffic is saved to .pcap files and replayed indefinitely using `tcpreplay`, sending the packets to the specified network interface.

An example of execution would be:

```bash
sudo python3 mra.py 300 123.4.5.6
```

\<img width="550" alt="execucao\_mra" src="[https://github.com/user-attachments/assets/930e1f6b-b577-4971-82d8-1ff4d028afc6](https://github.com/user-attachments/assets/930e1f6b-b577-4971-82d8-1ff4d028afc6)" /\>
\<br\>
\<br\>

This will execute the attack for 300 seconds against the IP 123.4.5.6. It is important to note that using this code for unauthorized attacks is illegal and unethical. The intent is solely for educational purposes and testing in controlled environments.

-----

## VMware Workstation Pro Virtualizer

For the virtualization of the virtual machines (target, attacker, and pfSense and FortiGate firewalls), VMware Workstation Pro 17 for Personal Use (version 17.6.3-24583834) was used, which is available for free. It can be downloaded from the official VMware website, but registration on the Broadcom portal is required.

VMware Workstation is a desktop hypervisor for Windows and Linux that allows you to create and run VMs with various operating systems without needing to restart your computer. It is a robust and versatile platform, ideal for development, testing, and software simulations in isolated virtual environments.

-----

## Lab Configuration

The lab environment was divided into three scenarios, all with the same network topology and IP addresses as shown in the image below. Each scenario had three elements: a target, an attacker, and a middlebox (represented by a firewall).

\<img width="815" alt="topologia\_lab" src="[https://github.com/user-attachments/assets/3f935515-db36-42cb-bffc-7888d9db5589](https://github.com/user-attachments/assets/3f935515-db36-42cb-bffc-7888d9db5589)" /\>
\<br\>
\<br\>

  * **Scenario 1**: Firewall with pfSense and the pfBlockerNG add-on.
  * **Scenario 2**: Firewall with pfSense and the Squid and SquidGuard software.
  * **Scenario 3**: FortiGate Firewall.

The firewalls were configured to simulate typical behaviors and also incorrect configurations, in order to show how certain choices can make these devices vulnerable to amplified TCP reflection attacks.

### Target Machine

The target machine was an instance of the Ubuntu Linux 22.04.5 LTS (Jammy) operating system, with the following specifications:

  * **RAM**: 4096 MB
  * **Processor**: 2 vCPUs
  * **Storage**: 25 GB
  * **Network adapters**: 1000 Mb/s (Intel Gigabit Internet 82545EM)

The VM has two network interfaces. The first is connected to the LAN segment (`ens34`), simulating a local network protected behind the firewall. The second (`ens37`) is in NAT mode for internet access.

The network configuration is:

  * **Hostname**: `Ubuntu`
  * **LAN IP address**: `192.168.24.61/24`
  * **INTERNET IP address**: IP via DHCP
  * **Default gateway**: `192.168.24.100`
  * **DNS server**: `192.168.24.100`

### Attacker Machine

The attacker machine was based on the Kali Linux operating system, version 2025.1. Its specifications are:

  * **RAM**: 8096 MB
  * **Processor**: 6 vCPUs
  * **Storage**: 32 GB
  * **Network adapters**: 1000 Mb/s (Intel Gigabit Internet 82545EM)

The VM also has two network interfaces. The first is connected to the WAN segment (`eth0`), simulating an external agent on the internet. The second (`eth1`) is in NAT mode for internet access.

The network configuration is:

  * **Hostname**: `kali`
  * **WAN IP address**: `10.0.0.2/24`
  * **INTERNET IP address**: IP via DHCP
  * **Default gateway**: `10.0.0.1`

### pfSense Firewall

The first firewall used in the experiments was pfSense Community Edition (CE), version 2.7.2-RELEASE. It is an open-source firewall software distribution, based on FreeBSD, which can be installed on a physical computer or in a virtual machine to act as a dedicated firewall on a network.

The virtual hardware specifications assigned to the machine are presented below:

  - **RAM**: 2048 MB
  - **Processor**: 2 vCPUs
  - **Storage**: 20 GB
  - **Network adapters**: 1000 Mb/s (Intel Gigabit Internet 82545EM)

The pfSense VM was configured with three network interfaces:

  - **em0**: Connected to the LAN segment, identified in VMware as WAN, simulating the exit of internal machines towards the internet.
  - **em1**: Connected to another LAN segment, identified as LAN, representing the internal access interface to the firewall.
  - **em3**: Configured in NAT mode and used exclusively to allow internet access via the host computer's connection, enabling the download of updates, packages, and other external communications necessary for preparing the attack environment.

The network configuration of the firewall virtual machine was defined as follows:

  - **Hostname**: `pfSense.home.arpa`
  - **WAN IP address (em0)**: `10.0.0.1/24`
  - **LAN IP address (em1)**: `192.168.24.100/24`
  - **INTERNET IP address (em2)**: assigned via DHCP

Outbound NAT was configured to redirect traffic from the LAN network to the WAN interface, simulating the exit of the internal network to the external network through the firewall, as shown in the image below.

\<img width="815" height="184" alt="rules\_nat" src="[https://github.com/user-attachments/assets/49ffa326-0630-4991-97a9-315a1b267930](https://github.com/user-attachments/assets/49ffa326-0630-4991-97a9-315a1b267930)" /\>
\<br\>
\<br\>

The firewall rules configured for the WAN interface include:

  - A rule that allows receiving ICMP (ping) packets originating from external machines to internal LAN machines.
  - A rule that allows `ping` from external machines directly to the pfSense WAN interface IP address.
  - A rule that allows external access to the target's Web server on port 80/TCP, simulating its public exposure.
  - A rule that allows machines on the internal network to freely access all sites, which are later restricted by the pfBlockerNG and squidGuard filtering solutions, responsible for blocking domains like `youporn.com`, `facebook.com`, `pornhub.com`, and `bittorrent.com`, processed before this rule.

\<img width="815" height="333" alt="rules\_wan" src="[https://github.com/user-attachments/assets/6903a8bd-f9bd-4b4f-9c5c-5aeb7c7e8e5d](https://github.com/user-attachments/assets/6903a8bd-f9bd-4b4f-9c5c-5aeb7c7e8e5d)" /\>
\<br\>
\<br\>

For the LAN interface, the rules are configured as follows, containing by default:

  - The `anti-lockout rule`, which prevents blocking access to the pfSense web interface.
  - The `default allow LAN to any` rule, allowing unrestricted outbound traffic from the LAN.
  - The `default allow LAN IPv6 to any` rule, with equivalent behavior for IPv6 traffic.

\<img width="815" height="242" alt="rules\_lan" src="[https://github.com/user-attachments/assets/d028f47a-7e66-4e3e-9e52-760c1bd751a2](https://github.com/user-attachments/assets/d028f47a-7e66-4e3e-9e52-760c1bd751a2)" /\>
\<br\>
\<br\>

#### pfSense Firewall + pfBlockerNG

pfBlockerNG is an additional pfSense package for blocking malicious domains and IPs. It uses DNSBL (DNS Blackhole List) and IP lists.

To block sites, an explicit `DROP` rule was added for packets from the internal network destined for the IPs of forbidden sites (`youporn.com`, `facebook.com`, `pornhub.com`, and `bittorrent.com`), obtained from a list created in pfBlockerNG.

The package also displays a local blocking page but does not perform the actual redirection of the request. The blocking occurs locally and does not interact with the final destination of the traffic.

\<img width="815" alt="rule\_ips\_proibidos" src="[https://github.com/user-attachments/assets/b0cebe52-fbb3-4343-a828-120b87dd0bef](https://github.com/user-attachments/assets/b0cebe52-fbb3-4343-a828-120b87dd0bef)" /\>
\<br\>
\<br\>

Blocking page for the pfBlockerNG package in pfSense.

\<img width="815" alt="bloqueio\_pfblockerng" src="[https://github.com/user-attachments/assets/3a5106be-4c42-41f2-9d47-06a63efcfaa4](https://github.com/user-attachments/assets/3a5106be-4c42-41f2-9d47-06a63efcfaa4)" /\>
\<br\>
\<br\>

#### pfSense Firewall + Squid + SquidGuard

Squid is a web caching proxy, and SquidGuard is a URL redirector that complements Squid. Together, they allow the blocking and redirection of users to a custom blocking page.

SquidGuard allows the actual redirection of the request, changing the URL and sending the blocking page to the user. To do this, a list of `target categories` was created in SquidGuard for the forbidden sites.

\<img width="815" alt="sites\_proibidos" src="[https://github.com/user-attachments/assets/0edf68a8-8c05-42c0-a4c4-b563f7638112](https://github.com/user-attachments/assets/0edf68a8-8c05-42c0-a4c4-b563f7638112)" /\>
\<br\>
\<br\>

Blocking page for the SquidGuard package in pfSense.

\<img width="815" alt="bloqueio\_squid" src="[https://github.com/user-attachments/assets/11a85cd5-acad-4508-8b9c-e31fa68097c7](https://github.com/user-attachments/assets/11a85cd5-acad-4508-8b9c-e31fa68097c7)" /\>
\<br\>
\<br\>

### FortiGate Firewall

The second firewall used in the experiments was the NGFW FortiGate-VM64, which also presents a blocking page sent to the user when accessing a forbidden domain, version 7.2.0 (build 1157, 220331 - GA.F). This version was chosen because it is on the list of vulnerable versions, as identified by the CVE-2022-27491 vulnerability.

The specifications of the virtual environment used in the tests are presented below:

  - **RAM**: 2048 MB
  - **Processor**: 1 vCPU
  - **Storage**: Not specified
  - **Network adapter**: 10000 Mb/s (Intel Gigabit Internet 82545EM)

Adopted as a substitute for pfSense, the FortiGate firewall was configured with three network interfaces, replicating the topology and function assigned in the previous configuration. The network configuration was defined as follows:

  - **Hostname**: `FortiGate-VM64-KVM`
  - **WAN IP address**: `10.0.0.1/24` (port1)
  - **LAN IP address**: `192.168.24.100/24` (port2)
  - **INTERNET IP address**: assigned via DHCP (port3)

FortiGate was chosen because it offers a content filtering mechanism more integrated into the network flow, with the real capacity to intercept connections and respond directly with custom blocking pages, which are effectively sent to the client as complete HTTP responses. Unlike the previous solutions, FortiGate does not depend on DNS manipulation or explicit proxies to display blocking messages; it acts directly on the traffic with deep packet inspection (DPI) and an immediate response, which increases the chance of the page being reflected to the spoofed destination in amplification attacks.

Furthermore, FortiGate allows more granular control of security policies and responses, with specific tools for customizing blocking messages, session analysis, and handling behavior-based connections. These features make the solution more suitable for advanced security tests and for analyzing how middleboxes interact with spoofed traffic.

Therefore, the use of FortiGate represented an evolution in the experimental methodology, offering greater control and visibility over traffic, in addition to a higher potential to generate useful reflected responses for the study of TCP amplification attacks based on middleboxes.

FortiGate was configured with firewall rules similar to those created in pfSense, according to the following policies:

  - A rule that allows the reception of ICMP (ping) packets originating from external machines (WAN network) to internal machines of the LAN network.

\<img width="415" alt="firewall\_policy\_ping\_wan\_lan" src="[https://github.com/user-attachments/assets/8ac08b55-9c57-4d6a-8880-24aa29e2ffa3](https://github.com/user-attachments/assets/8ac08b55-9c57-4d6a-8880-24aa29e2ffa3)" /\>
\<br\>
\<br\>

  - A rule that allows outbound traffic from internal machines (LAN network) to the external network (WAN network) through the FortiGate.

\<img width="415" alt="firewall\_policy\_lan\_wan" src="[https://github.com/user-attachments/assets/8afec0d7-e85d-4bc5-90d7-39353ee42454](https://github.com/user-attachments/assets/8afec0d7-e85d-4bc5-90d7-39353ee42454)" /\>
\<br\>
\<br\>

To block forbidden sites, a Web Filter profile was created, which was subsequently applied to the LAN access rules, as shown in the image below.

\<img width="415" alt="sites\_proibidos\_fortigate" src="[https://github.com/user-attachments/assets/1699794d-8796-47ec-bcf8-128ba2b44732](https://github.com/user-attachments/assets/1699794d-8796-47ec-bcf8-128ba2b44732)" /\>
\<br\>
\<br\>

FortiGate's blocking page.

\<img width="815" alt="bloqueio\_fortigate" src="[https://github.com/user-attachments/assets/5d3aaa28-f90c-42c9-a15f-4c211affe61e](https://github.com/user-attachments/assets/5d3aaa28-f90c-42c9-a15f-4c211affe61e)" /\>
\<br\>
\<br\>
