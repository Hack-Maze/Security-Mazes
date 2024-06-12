# Network Forensics

> A **Protocol** is a set of rules that defines how communication should be carried out.
> 

**It is also important to note that Protocols can either be:**
• Public standards (i.e. have a known format and can be used by anyone)
• Preparatory (i.e. owned by a company)

<aside>
🔎 ***To sum it up:***

- We have protocols which are a language for communicating
- We put protocols that accomplish similar tasks in Groups (later we’ll call them layers)
- The assembly of groups together is called a **Protocol Stack (or Suit)**

The **TCP/IP Protocol Suite** is a stack of groups (from now on we’ll call them layers) of protocols.

</aside>

<aside>
⚠️ ***NOTE:***

1. Most of the protocols on the internet are built using this model and most communications are usually between two types of programs, server and the client. The server, as the name suggests, is the part that resides on the server it controls and the resources which the user requires. The client is the part of the application that resides on the user's machine which is used to request the resources held by the server.
2. although TCP and UDP are the most famous transport layer protocols, they are not the only ones. There are other famous protocol's such as SCTP, DCCP, and RSVP.
</aside>

a normal TCP connection will start by a **three-way handshake**, followed by data exchange, where each message is acknowledged by the recipient, and a **four way connection teardown.**

<aside>
🔎 ***4 way tear-down:***

1. The sender signals its intention to close the connection by sending a TCP **FIN** (Finish) segment to the receiver.
2. The receiver acknowledges the sender's request to close the connection by sending an **ACK** (Acknowledgment) segment. The receiver can still send data to the sender at this point.
3. When the receiver is ready to close the connection, it sends its own **FIN** segment to the sender.
4. The sender acknowledges the receiver's request to close the connection. The sender is now in a state where it can receive any remaining data from the receiver but cannot send any more data.
</aside>

> **Stream oriented** property of the TCP protocol means that it sends data byte by byte (hence the name).
> 

<aside>
⚠️ ***NOTE:***

UDP a best effort protocol meaning that it cannot guarantee the delivery of the message. If a client sends data to a port with no server running behind
it (closed port), the operating system will respond with an ICMP destination Port unreachable message telling the client that this port is closed.

The **IP** protocol is a **connectionless** best effort protocol. The recipient doesn't have to acknowledge the messages it receives. Also, the two communicating parties don't have to establish a connection before exchanging data.

</aside>

Alongside data delivery from one network to another, which is handled by the IP protocol, there are other network layer protocols which handles routing (such as **RIP** and **EIGRP**) and control message delivery (such as **ICMP**).

Multicast communication usually uses special addresses from the **class D** addressing scheme.

> A **hub** is a legacy networking device that is used to connect devices together. It is a physical layer device, meaning it does not understand Network protocols. It's simply works as a physical electrical repeater. It receives a signal from one device on a port and forwards that signal to all other ports.
> 

> **Switch** is a layer 2 device which replaces the Hub. Unlike the hub, switch understands data link layer protocols and Mac addresses, which is why it doesn't need to broadcast every frame for every device on the network.
> 

<aside>
⚠️ ***NOTES:***

Switch stores the Mac addresses of every connected device in a table called **content addressable memory** (CAM) and uses that table to make forwarding decision

</aside>

<aside>
🔎 ***Status Code:***

1. Responses that starts with 1 are usually informational.
2. start with 2; the most famous one is 200, which is the status code the server replies with when they requested resource is found.
3. the server replies with the 3 status code, which means that the client has to be redirected to the new location of the requested resource.
4. 4 responses are the famous 404 resource not found response and the forbidden 403 response.
5. 5 are used when the server experiences a crash or unexpected error caused by the user's input or request. When you see a response that starts with 5, in general it indicates a server-side error.
</aside>

## SSL/TLS

SSL was originally developed for the **Netscape** web browser at Netscape labs back in the early 90s. SSL version 2 had many security weaknesses and forced Netscape to start working on developing SSL version 3.

<aside>
🔎 ***How ssl/tls works***

1. The first phase is called the **handshake** protocol and it's where the client and the server establish a shared key to be used to secure the communicate. starts when the client requests the desired resource under http.
2. The **record layer** protocol, the second phase, is where the communicating parties uses the established key to secure their communication.
3. When a client requests a servers public key, the public key is sent alongside a few other parameters in an object called certificate. Think of a certificate as an envelope that contains the key and metadata describing that key and its owner.
4. When doing so, the client alongside the request since a randomly-generated number called **nounce** which stands for "number only used once."
5. When the client has verified the authenticity of the certificate and the public key within it, it can move to the next step and use it . The client generates a random key called **PMK (pre-master key)**, which is encrypted using the servers public key and sends it to the server.
6. the client uses the primary master and both the server and the client nounces to generate a master key. That master key is later used to generate four keys using a **Random Generator**.
</aside>

<aside>
⚠️ ***NOTE:***

- a client cannot store the public keys for all servers on the internet. If a server’s private key gets compromised taking the necessary precautions on the large scale would be very hard. This is why SSL relies on a mechanism to distribute and maintain public keys called the **public key infrastructure.**
- In order to solve the complexity and the authentication problem discussed earlier, there is a need for a trusted thirdparty to make the authentication process more scalabl . This trusted third party is usually called the **Certificate Authority (CA).** The certificate authorities public key is embedded in most known browsers and are frequently updated using special protocols such as **OSCP**.
- The encryption and authentication operations of the record layer protocol relies on the **four keys** that were previously generated. The server will use the first two keys to encrypt and authenticate all the messages it's sending.
- Performing encryption and authentication using different keys is usually called **authenticated encryption**.
</aside>

## SMTP

SMTP is a text-based protocol, meaning that it relies on exchanging ASCII based strings as commands between the server and the client.

![Untitled](Network%20Forensics%20976fca7e887b4488936bf79b4d4d28be/Untitled.png)

> **ESMTP** was developed. ESMTP was an extension to the original SMTP protocol with some modification. Some of the modifications included new commands such as using **EHLO** instead of **HELO** for identification.
> 

<aside>
🔎 ***What happens there:***

1. The client starts the conversation with the EHLO command, which is the extended version of the Helo command.
2. The server replies with the options which an SMTP client can pick from. Among these options is the authentication login option where the client asks for authentication to login.
3. we can see the server asking the client for the username.
4. After receiving the username, the server asks the client for the password also in base 64 encoding.
5. Using the MAIL FROM and RCPT TO command, the client tells the server that it wants to send an email.
6. the mail body is specified using the DATA command.
</aside>

## DNS

<aside>
🔎 ***DNS record:***

1. Records of **type A** are answer records they map a domain name for an IP address. 
2. Same goes for **AAAA** records, the only difference is that they map names to IPv6 addresses.
3. **CNAME** records is used to map aliases to a single domain. [www.fb.com](http://www.fb.com/) is an example of canonical name record.
4. **PTR** records are the opposite of A records, since they map an IP to a domain name and use it for the reverse DNS queries.
5. **TXT** records contains arbitrary Text data.
6. **NS** records contains the name server of a given domain.
7. **MX** records contains the mail servers for given domain.
</aside>

<aside>
🔎 ***DNS headers structure:***

1. DNS ID number is used to map each DNS query packet to its response packet.
2. The QR field specifies whether this packet is a query packet or a response packet .
3. The opcode field tells the type of the query encapsulated within the message.
4. The RA field within a DNS response is used to tell the client that the server supports recursive queries (The local DNS server begins asking other DNS servers for information. It starts by asking the root DNS server for information about ".com" domains) .
5. Response Code( Rcode) is used tell if there are any errors within the message.
</aside>

<aside>
⚠️ ***NOTE:***

If the TC field is set, its means that the response was truncated because it's too long.

If the RD field is set within the query, it is asking the server to perform a recursive query if the requested information does not exist on the server

</aside>

## DHCP

<aside>
🔎 ***What it does:***

- The **opcode** is used to differentiate between DHCP requests and DHCP replies.
- The **hardware type** field is used to indicate what type of data link technology is being used (ethernet, frame relay,etc.).
- The **hardware length** field is used to indicate the data link layer address.
- The **transaction ID** field is used to map each request to its response (chosen randomly)
- The **second elapsed** describes the number of seconds passed since the client requested an address from the server
- **Flags** are used to tell the server what type of traffic a DHCP client can accept (unicast, broadcast).
- The **client IP** address is the IP address offered by the DHCP server.
- **Server IP address** is the DHCP servers address.
- The **gateway address** is the IP of the default gateway configured by the network administrator hardware address is the client the Mac address.
- The **options** field is where we'll find most of the interesting data within the DHCP packets. The option (53) has the value one, which is the discover value telling us that this is a dhcp discover message.
- The **client identifier** holds information about the clients addresses such as the MAC address and its type.
- The **requested IP address** field is used to indicate the address which the client is requesting.
- The **hostname field** is used to hold me name of the computer that is requesting the address.
- The **parameter request** list is used to list other parameters, in which decline means besides an IP address, such as the subnet mask and default gateway.
</aside>

<aside>
🔎 ***how it happen:***

The DHCP address acquisition process is called DORA, which stands for discover, offer, request, acknowledge.

![Untitled](Network%20Forensics%20976fca7e887b4488936bf79b4d4d28be/Untitled%201.png)

***NOTE:*** When trying to capture DHCP traffic, you will notice that Wireshark labels DHCP traffic under the name bootstrap. DHCP traffic can be filtered in water for using the **bootp** filter option.

The last step in the DORA process is for the server to send the IP address the client requested. This is done through the **ACK** 

</aside>

## ICMP

The type of error or information being queried gets determined by a code number within the packet.

![Untitled](Network%20Forensics%20976fca7e887b4488936bf79b4d4d28be/Untitled%202.png)

![Untitled](Network%20Forensics%20976fca7e887b4488936bf79b4d4d28be/Untitled%203.png)

## ARP

<aside>
⚠️ ***NOTE:***

- Remember that a machine is not a router and doesn't save routing table that tells it how to reach other networks.
- When the source computer looks at the destination IP address, it realizes that this is a remote address that is not present on the
local network. That means it has to find someone who knows how to reach that remote machine.
- In a local network, usually the device that knows how to reach other computers on other remote networks is the router, hence
the name default gateway.
- On the data link layer, the network interface card needs to send that packet to the default gateway.
- However, the network interface card doesn't deal with IP addresses, it needs a MAC address to deliver an encapsulated packet (frame) to.
</aside>

# Protocol Analysis

> **packet details markup language** is an xml-based language that is used to describe the packets starting from the application layer all the way down to the data link layer
> 

> **Flow analysis** is the next step after packet analysis. Packet analysis included analyzing separate packets regardless of their relationship to each other. On the other hand, flow analysis is about analyzing a group of related packets and looking for pattern and/or anomalies.
> 

## statistical flow analysis

<aside>
⚠️ ***NOTE:***

- Flow statistics could help the investigator confirm or deny the existence of data leakage on a certain machine within the network.
- It is possible to find a certain pattern associated with each user on the network. That pattern could be a group of IP addresses that gets visited frequently, or certain amount of traffic at a certain time.
</aside>

> A flow record is typically called **sensor**. An example of a sensor could be a router working as a gateway for a network segment.
> 
> 
> The flow record gets exported to a **collector** which is usually a server used to store flow records.
> 

In an enterprise network there may be a need to use multiple collectors within the network. Those different collectors may be storing related data. In order to avoid decentralization, a central node is used to connect different connectors together. That central node is usually called an **aggregator**.

<aside>
🔎 ***Record Formats:***

1. **Cisco Netflow**, which is a protocol developed for billing purposes. Most Cisco routers can be turned into netflow sensors by typing few commands.
2. **IPFIX**, which is considered to be the successor of netflow (Sometimes it’s called Netwflow V10).
3. **S-flow,** which is the standard protocol adapted by the internet engineering task force, is a network record flow format which
offers Advanced statistical features over Cisco's netflow.
</aside>

# Network Forensics

> **Network digital evidence** is an evidence created because of a communication or an action over the network.
> 

# E-mail Forensics

<aside>
🔎 ***Network digital evidence is an evidence created because of a communication or an action over the network.***

1. The **return-path** contains the address which the message should go back to in case of failed delivery.
2. **Delivery date** is when the message was delivered to the client.
3. **Date** specifies when the message was sent.
4. The **message ID** is a unique string that identified that message.
5. **X-Miller** is the name of the mail client which was used by the sender to send this email.
</aside>

# OSCAR

Just like other fields of forensic investigation, forensics also has a well defined methodology which is a slightly modified version of the methodology discussed in the first module of this course. The methodology is usually referred to as OSCAR, which stands for obtaining information, strategize, collect evidence, analyze and report.

> Acquiring data from the wire is usually referred to as **wiretapping** and it requires a specific devices for each types of cables.
> 

Unlike wired networks which requires physical access to the wire, wireless networks are much easier to acquire packets from than wired networks. Sometimes a wireless network interface card on monitoring mode with a good antenna is all what the investigator may need to monitor frames that are traversing the network.

<aside>
⚠️ ***NOTE:***

depending on the encryption protocol and on which layer of the TCP/IP stack the encryption occurred, the investigator may still extract many forensic relative data. 

it is possible to extract data from the transport layer protocol header and the protocols below when the SSL protocol (which occurs in the application layer) is used to encrypt the payload. The same cannot be said when **IPSEC ESP** mode is used. Since IPsec ESP encapsulates the whole packet, only the data link layer header is retrievable

</aside>

If the switch supports it, frame acquisition can be done on the hardware level using features such as **span ports** and **port mirroring**.

> **port mirroring** is a feature that can be enabled through the switch operating system. Once configured, the switch will send a copy of every frame going through one of the source ports to the destination port.
> 

<aside>
🔎 ***What if:***

the switch does not support port mirroring or doesn't have span port, like home users unmanaged switches, we can still acquire the traffic that is going between the devices. However, instead of enabling on the hardware level the investigators computer has to trick the other devices into sending him/her the traffic. This can be done by conducting an attack (arp poisoning)

</aside>

<aside>
🔎 ***Router:***

Routers can also be configured to work as an access controller for the network using network access lists (ACLs).

Routers can also be configured to export their logs to a remote server using protocols such as netflow.

It is important to remember that due to memory size issues, evidence such as cam and routing tables are very volatile.

</aside>

# Berkeley packet filters

One of the main challenges an investigator may face when capturing packets from the network is separating the useful packet ,which is relevant for the investigation, from the "noise" packets. Sometimes you'll find that capturing every frame on the network is a very resource consuming thing to do. This is where Berkeley packet filters comes into our service. Since it allows us to pick which frames we want to capture.

> **Berkeley Packet Filter (BPF)** provides a raw interface to data link layers, permitting raw link-layer packets to be sent and received.
> 
> 
> It is available on most Unix-like operating systems. In addition, if the driver for the network interface supports promiscuous mode, it allows the interface to be put into that mode so that all packets on the network can be received, even those destined to other hosts
> 

# web forensics

- A web browser usually consists of a **user interface** which handles in the user's input and actions, a **browser engine** which links the user interface with the **browser's stored data** and the **rendering engine** which is responsible for interpreting the client-side code and the back and operations of the browser.
- There are many rendering engines out there. Some of the most famous engines are **khtml/ webkit** and **Gecko-based** browsers. There are other less famous engines such as trident, and specialty.
- And finally, although not very common, you may find **text-based** browser.

<aside>
🔎 ***Types:***

**Webkit rendering engines** are usually implemented by Chrome and Safari browsers.
**Gecko rendering engines** on the other hand are usually implemented by Firefox browsers.

</aside>

<aside>
🔎 ***VERY IMPORTANT NOTE:***

Windows stores its cash in a file called **index.dat** which we’ll see how to examine later

</aside>

# Network Attacks

They are attacks that target application-layer protocols such as **Rogue DHCP** and **DNS servers**. 

Denial-of-service attacks such as **SYN-Flood** can be found at the next layer, the transport layer. SYN flood is an attack that takes advantage of the three way handshake to exhaust the victim's resources

> **DHCP starvation** is a relatively simple attack where the attacker performs the DHCP IP request process many times with many spoof Mac addresses until they consume the whole IP address available in the pool.
> 

> The more dangerous attack on the application layer and the DHCP protocol is installing a fake DHCP server within the network.  This attack is known as **Rouge DHCP**. Remember that the DHCP not only provides the client with IP address, it also provides them with the default mask and the network's default Gateway.
> 

<aside>
⚠️ ***NOTE:***

An attacker with a rogue DHCP server can reply to the DHCP discover messages issued by the victims and provide them
with an incorrect IP configuration. For example, if the attacker sends his IP address to the clients as the default gateway, the clients will send the traffic going to the internet to the attacker since it was told by the fake DHCP that this is its default gateway out of the network

</aside>

> **Rogue DHCP** server attacks can usually be avoided by activating DHCP snooping on the network switches.
> 

> **DHCP snooping** allows the administrator to determine which port on the switch is allowed to relay DHCP offer messages preventing an attacker from sending fake DHCP offers messages from an untrusted port.
> 

> **rogue DNS** where the attacker, just like the rouge DHCP, installs a rouge DNS and sends spoofed answers to the victims DNS queries.
> 

<aside>
🔎 ***how rogue dns works:***

The Browser will first issue a DNS query asking about the IP address of the bank's site. If a rogue DNS is installed within the network, it can spoof DNS reply and send the attackers IP address instead of the bank account IP address.

On his/her machine, the attacker can install a web page that looks similar to the bank account login page tricking the user into supplying his or her credentials.

</aside>

The simplest way to perform port scanning on a target machine is to perform a complete **three-way handshake** with the desire to port, which is known as a full TCP scan. A faster way to perform port scanning is called **half open scan**.

> To save time, the attacker does not complete the three-way handshake, instead it terminates the session immediately after receiving the ACK message. This is known as **SYN scan** or **stealth scan.**
> 

> More stealthy technique to perform a scan is called **zombie scan**, where the attacker impersonates a third machine on the network and probes ports using its spoofed IP addresses. The attacker later can either spoof the reply coming from the victim to the zombie machine.
> 

<aside>
🔎 ***How zombie scan works:***

1. it can ping the zombie machine and calculate the **ipid** differences to know whether that zombie replied to the victim's SYN-ACK or not.
2. A network administrator checking only the IP address of the attacker will think that the zombie machine is the one behind the scanning and not the attacker
</aside>