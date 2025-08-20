# Amplified Reflection Attack Exploiting Middleboxes – Code and Test Environment

This README describes the configuration of the experimental environment used to analyze amplified reflection attacks over TCP exploiting middleboxes, covering both the source code structure and the laboratory's virtual and network components. Initially, the architecture and operation of the attack code are presented, including execution instructions and additional information obtained through direct communication with its author. Next, the test environment built in VMware Workstation Pro is described, consisting of virtual machines representing the attacker, the target, and the middlebox devices (pfSense and FortiGate firewalls), with their respective configurations.

This structure enabled controlled simulation of the attack and detailed analysis of its behavior against different intermediary devices, allowing a practical understanding of amplified reflection mechanisms and their security implications.

<!-- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ -->

## Attack Code Description

This section documents the usage and configuration of the code available at:
https://github.com/moloch54/Ddos-TCP-Middlebox-Reflection-Attack

![tipos_ataque_page](https://github.com/user-attachments/assets/895bf494-9bcb-4f47-acd6-c1d6d3c32e39)

The code was very useful for conducting laboratory experiments, allowing the practical implementation of the concepts from the scientific paper "Weaponizing Middleboxes for TCP Reflected Amplification" by Bock et al. With it, it was possible to replicate the Middlebox Reflection (b) technique, facilitating the understanding and validation of the amplified reflection mechanisms using middleboxes over the TCP protocol. In this technique, the source IP address is spoofed as that of the victim, causing responses from the middleboxes to reach the target directly.

To understand the attack, it's necessary to review the TCP connection establishment process, the Three-Way Handshake, which has three steps:

1. The client (SRC) sends a SYN packet to initiate the connection;
2. The server (DEST) responds with a SYN, ACK packet, acknowledging the request;
3. The client sends an ACK packet, terminating the connection.

The attack exploits the fact that, in networks with intermediary devices (such as firewalls or middleboxes), packets can take different paths. The SYN packet is spoofed (with SRC=Victim and DST=Server), but the SYN, ACK response from the real server can take a different route and not be seen by the middlebox. This creates a state inconsistency.

The attacker, after the spoofed SYN, sends a second **ACK** packet (also with a spoofed source IP address). The *middlebox*, not having seen the SYN ACK, interprets this ACK as invalid and can generate automatic responses, such as **RST** packets or multiple blocking/warning messages, amplifying traffic against the victim.

The attack can be refined with packets containing data. After the SYN, the attacker can send an **ACK+PSH** packet with a payload, such as an HTTP request. For example:

* Sending a **SYN** packet with a spoofed source IP address (of the victim) and destined for domains with a high potential for blocking by *middleboxes*: `SRC=Victim`, `DST=Pornhub|Youporn|Bittorrent...`; * Subsequent sending of an **ACK+PSH** packet with a payload: HTTP GET request, also with `SRC=Victim`.

These packets, when processed by content filtering *middleboxes*, can trigger multiple responses, reinforcing the amplification effect.

This public code was chosen for its clear structure and alignment with the Bock et al. methodology, which ensured implementation compliance and allowed us to focus on experimental and analytical aspects, avoiding development from scratch.

-----

<!-- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ -->

## Code Execution

To execute the TCP amplified reflection attack code, follow the steps described in the repository's README.md file. First, the dependencies must be installed and configured. The required tools are:

* **tcpreplay**: to replay packets on a network interface. * **mergecap**: to merge packets from multiple threads into a single .pcap file.
* **scapy**: Python library for constructing and manipulating TCP packets.

To install the dependencies on Debian/Ubuntu systems, use the following command:

```bash
sudo apt-get install tcpreplay mergecap python3-scapy
```

After installation, the code can be executed directly from the terminal. The command to launch the attack is:

```bash
sudo python3 mra.py <time_in_seconds> <target_IP>
```

Here, `<time_in_seconds>` defines the duration of the attack, and `<target_IP>` is the IP address to be overwhelmed.

The script generates spoofed TCP packets, sending a **SYN** packet to a target website (filtered by a *middlebox*) and then an **ACK + PSH** packet with an HTTP *payload*. This causes the *middlebox* to respond with a **RST** or an error page. The generated traffic is saved in .pcap files and replayed indefinitely using `tcpreplay`, sending the packets to the specified network interface.

An example execution would be:

```bash
sudo python3 mra.py 300 123.4.5.6
```

![execucao_mra](https://github.com/user-attachments/assets/930e1f6b-b577-4971-82d8-1ff4d028afc6)

This will run the attack for 300 seconds against the IP address 123.4.5.6. It is important to note that using this code for unauthorized attacks is illegal and unethical. It is intended for educational purposes only and for testing in controlled environments.

-----

<!-- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ -->

## VMware Workstation Pro Virtualizer

For virtualization of virtual machines (target, attacker, and pfSense and FortiGate firewalls), **VMware Workstation Pro 17 for Personal Use** (version 17.6.3-24583834) was used, available free of charge. It can be downloaded from the official VMware website, but registration is required on the Broadcom portal.

VMware Workstation is a desktop hypervisor for Windows and Linux that allows you to create and run VMs with various operating systems without needing to restart the computer. It is a robust and versatile platform, ideal for software development, testing, and simulation in isolated virtual environments.

-----

<!-- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ -->

## Lab Setup

![lab_topology](https://github.com/user-attachments/assets/3f935515-db36-42cb-bffc-7888d9db5589)

The lab environment was divided into three scenarios, all with the same network topology and IP addresses as the image above. Each scenario had three elements: a target, an attacker, and a middlebox (represented by a firewall).

* Scenario 1: Firewall with pfSense and the pfBlockerNG add-on.
* Scenario 2: Firewall with pfSense and Squid and SquidGuard software.
* Scenario 3: FortiGate firewall.

The firewalls were configured to simulate typical behaviors as well as misconfigurations to demonstrate how certain choices can make these devices vulnerable to TCP Amplified Reflection attacks.

<!-- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ -->

### Target Machine

The target machine was an instance of the operating system **Ubuntu Linux 22.04.5 LTS (Jammy)**, with the following specifications:

* **RAM:** 4096 MB
* **Processor:** 2 vCPUs
* **Storage:** 25 GB
* **Network Adapters:** 1000 Mb/s (Intel Gigabit Internet 82545EM)

The VM has two network interfaces. The first is connected to the LAN segment (`ens34`), simulating a local network protected behind the firewall. The second (`ens37`) is in NAT mode for internet access.

The network configuration is:

* **Hostname:** `Ubuntu`
* **LAN IP Address:** `192.168.24.61/24`
* **INTERNET IP Address:** IP via DHCP
* **Default Gateway:** `192.168.24.100`
* **DNS Server:** `192.168.24.100`

<!-- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ -->

### Attacking Machine

The attacking machine was based on the **Kali Linux** operating system, version 2025.1. Its specifications are:

* RAM: 8096 MB
* Processor: 6 vCPUs
* Storage: 32 GB
* Network adapters: 1000 Mb/s (Intel Gigabit Internet 82545EM)

The VM also has two network interfaces. The first is connected to the WAN segment (eth0), simulating an external agent on the internet. The second (eth1) is in NAT mode for internet access.

The network configuration is:

* **Hostname:** `kali`
* **WAN IP Address:** `10.0.0.2/24`
* **INTERNET IP Address:** IP via DHCP
* **Default Gateway:** `10.0.0.1`

<!-- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ -->

### pfSense Firewall

The first firewall used in the experiments was **pfSense Community Edition (CE)**, version `2.7.2-RELEASE` [^1]. It is a software distribution forAn open-source firewall, based on FreeBSD, that can be installed on a physical computer or in a virtual machine to create a dedicated firewall on a network [^2].

The following are the virtual hardware specifications assigned to the machine:

- RAM: 2048 MB
- Processor: 2 vCPUs
- Storage: 20 GB
- Network adapters: 1000 Mb/s (Intel Gigabit Internet 82545EM)

The pfSense VM was configured with three network interfaces:

- em0: Connected to the LAN segment, identified in VMware as WAN, simulating the egress of internal machines to the internet;
- em1: Connected to another LAN segment, identified as LAN, representing the internal access interface to the firewall;
- **em3:** Configured in NAT mode and used exclusively to allow internet access via the host computer's connection, enabling the download of updates, packages, and other external communications necessary to prepare the attack environment.

The network configuration of the firewall virtual machine was defined as follows:

- **Hostname:** `pfSense.home.arpa`
- **WAN IP Address (em0):** `10.0.0.1/24`
- **LAN IP Address (em1):** `192.168.24.100/24`
- **INTERNET IP Address (em2):** assigned via DHCP

**Outbound NAT** was configured to redirect traffic from the LAN network to the WAN interface, simulating egress from the internal network to the external network through the firewall, as shown in the following image.

<img width="1442" height="184" alt="rules_nat" src="https://github.com/user-attachments/assets/49ffa326-0630-4991-97a9-315a1b267930" />

The firewall rules configured for the WAN interface include:

- A rule that allows ICMP (ping) packets from external machines to be received by internal LAN machines;
- A rule that allows pinging from external machines directly to the IP address of the pfSense WAN interface;
- A rule that allows external access to the target's web server via port 80/TCP, simulating its public exposure;
- A rule that allows machines on the internal network to freely access all websites, which are subsequently restricted by the pfBlockerNG and SquidGuard filtering solutions, which block domains such as youporn.com, facebook.com, pornhub.com, and bittorrent.com, processed before this rule.

<img width="1152" height="333" alt="rules_wan" src="https://github.com/user-attachments/assets/6903a8bd-f9bd-4b4f-9c5c-5aeb7c7e8e5d" />

For the LAN interface, the rules are configured as shown in the following image, containing by default:

- The anti-lockout rule, which prevents blocking access to the pfSense web interface;
- The `default allow LAN to any` rule, allowing unrestricted outbound traffic from the LAN;
- The `default allow LAN IPv6 to any` rule, with equivalent behavior for IPv6 traffic.

<img width="1153" height="242" alt="rules_lan" src="https://github.com/user-attachments/assets/d028f47a-7e66-4e3e-9e52-760c1bd751a2" />

<!-- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ -->

<!-- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ -->
##
## pfSense Firewall + pfBlockerNG

**pfBlockerNG** is an add-on package for pfSense to block malicious domains and IPs. It uses DNSBL (DNS Blackhole List) and IP lists.

To block websites, an explicit `DROP` rule was added for packets from the internal network destined for banned website IPs (such as `youporn.com`, `pornhub.com`, etc.), obtained from lists in pfBlockerNG.

<img width="1446" height="155" alt="rule_ips_proibidos" src="https://github.com/user-attachments/assets/b0cebe52-fbb3-4343-a828-120b87dd0bef" />

The package also displays a local blocking page, but does not perform the actual redirection of the request. Since pfBlockerNG does not reflect the content to an external target, it was not useful for the amplification attack. The blocking occurs locally and does not interact with the final destination of the traffic.

<img width="1293" height="223" alt="bloqueio_pfblockerng" src="https://github.com/user-attachments/assets/3a5106be-4c42-41f2-9d47-06a63efcfaa4" />

<!-- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ -->

<!-- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ -->
##
## pfSense Firewall + Squid + SquidGuard

**Squid** is a web caching proxy, and **SquidGuard** is a URL redirector that complements Squid. Together, they allow user blocking and redirection.aries to a custom block page.

SquidGuard was the main component of this experiment because it allows for **real request redirection**, changing the URL and sending the block page to the user. To achieve this, a list of `target categories` was created in SquidGuard for banned sites.

<img width="1058" height="218" alt="bloqueio_squid" src="https://github.com/user-attachments/assets/11a85cd5-acad-4508-8b9c-e31fa68097c7" />

<img width="1158" height="463" alt="sites_proibidos" src="https://github.com/user-attachments/assets/0edf68a8-8c05-42c0-a4c4-b563f7638112" />

<!-- ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ -->

## FortiGate Firewall

The second firewall used in the experiments was **NGFW FortiGate-VM64**, version 7.2.0 (build 1157, 220331 - GA.F) [^1]. This version was chosen because it appears on the list of vulnerable versions, as identified by the vulnerability **CVE-2022-27491** [^2][^3][^4]. FortiGate NGFWs offer advanced protection for users and data, combining security features with high performance through Fortinet's dedicated processors. They are a well-established and widely adopted commercial solution in the market [^5].

Large institutions, such as the **University of Brasília (UnB)**, actively adopt this solution to ensure the security of their networks. A practical example of this use can be seen in the following image, which shows the blocking page displayed by FortiGate when a user attempts to access a prohibited website. This test was conducted within UnB itself, confirming the institution's effective use of the system. Furthermore, the same page can be viewed on the target machine when accessing the same site in the lab.

<!-- IMAGE HERE - FortiGate blocking page (fortigate_blocking) -->

The specifications of the virtual environment used in the tests are presented below:

- **RAM:** 2048 MB
- **Processor:** 1 vCPU
- **Storage:** Not specified
- **Network adapter:** 10000 Mb/s (Intel Gigabit Internet 82545EM)

Adopted as a replacement for pfSense, the **FortiGate** firewall was configured with three network interfaces, replicating the topology and function assigned in the previous configuration. The network configuration was defined as follows:

- **Hostname:** `FortiGate-VM64-KVM`
- **WAN IP Address:** `10.0.0.1/24` (port 1)
- **LAN IP Address:** `192.168.24.100/24` (port 2)
- **INTERNET IP Address:** assigned via DHCP (port 3)

Given that neither pfBlockerNG nor Squid with SquidGuard were able to reflect block pages to the victim during testing, it was necessary to find a more suitable alternative for the experiment's objectives. In this context, we chose to use FortiGate, a next-generation firewall solution developed by Fortinet, which proved to be more effective for the proposed scenario.

FortiGate was chosen because it offers a content filtering engine that is more integrated into the network flow, with the ability to intercept connections and respond directly with customized block pages, which are effectively sent to the client as full HTTP responses. Unlike previous solutions, FortiGate does not rely on DNS manipulation or explicit proxies to display block messages; it acts directly on the traffic, with deep packet inspection (DPI) and immediate response, which increases the chance of the page being reflected to the forged destination in amplification attacks.

Furthermore, FortiGate allows for more granular control over security policies and responses, with specific tools for customizing block messages, session analysis, and behavior-based connection handling. These features make the solution more suitable for advanced security testing and analyzing how middleboxes interact with forged traffic.

Therefore, the use of FortiGate represented an evolution in the experimental methodology, offering greater control and visibility over traffic, as well as a greater potential for generating reflected responses useful for studying middlebox-based TCP amplification attacks.

FortiGate was configured with firewall rules similar to those created in pfSense, as illustrated in the following images, which correspond, respectively, to the following policies:

- A rule that allows ICMP (ping) packets originating from external machines (WAN network) to internal machines on the LAN network;
- A rule that allows outbound traffic from internal machines (LAN network) to the external network (WAN network) through FortiGate.

<img width="515" height="411" alt="firewall_policy_ping_wan_lan" src="https://github.com/user-attachments/assets/8ac08b55-9c57-4d6a-8880-24aa29e2ffa3" />

<img width="515" height="413" alt="firewall_policy_lan_wan" src="https://github.com/user-attachments/assets/8afec0d7-e85d-4bc5-90d7-39353ee42454" />

To block prohibited sites, a **Web Filter** profile was created, which was then applied to the LAN access rules, as shown in the following image.

<img width="663" height="614" alt="sites_proibidos_fortigate" src="https://github.com/user-attachments/assets/1699794d-8796-47ec-bcf8-128ba2b44732" />
