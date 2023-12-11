#### Networking
clear text protocols enforce no use of encryption or information scrambling, they are used within trusted networks with have no form of obsfucation over transmitted data. e.g Telnet & HTTP

- You can tunnel a clear text protoocol over a cryptographic one -- VPN


 A VPN uses cryptography to extend a private network over a public one, it makes this extension by performing a protected connection  to a private network 
 
 - when you connect to a vpn you are using the same protocols of the remote private network  and this allows you perform even lowlevel operations lke packet sniffing
 
- A network sniffer allows you see data in transit over a network to and from your computer also e.g Wireshark

> The reason you get that untrusted connection popup when doing a box that runs https is because the site server is not a public one and hence does not have a valid certificate...
> most times its SELF SIGNED


Bitwise Ops:
XOR -- if JUST ONE is true its true

> Protocols 
- packets are streams of bit data running as electrcal signals over physical media used for data transmission
- the electrical signals are then interpreted as bits

> STRUCTURE OF A PACKET
- Every packet has the structure of a "HEADER" and the "PAYLOAD"
- A header has a protocol specific structure : this ensures the host on receiving end can correctly interpret the content of the payload
- The payload is the actual information such as the content of an email or content of a file during download

example: The IP protocol packet header is around 160 bits or 20 bytes


> Protocol layers 
- each layer serves the layer above it, and each layer has its own set of protocols
- a layer above does not need to know how to do the functions of the lower layers it just uses the underlying layers

> ISO/OSI model
- The OSI model was never really implemented but is used to conceptualize and reference the implementation of actual protocols  
- How do protocols work together then? reason is because every protocol packet has a header and a payload how a protocol is able to use the underlying protocol is this:

1. The Entire upper protocol packet (header + payload) = payload of lower one -- THIS IS ENCAPSULATION
2. You could say: (PAYLOAD)l = u(HEADER+PAYLOAD)

- TCP/IP stack is the protocol used over the internet
A <-- T <-- N <-- D
- encapsulation happens downwards

#### IP addressing
- IP is a protocol that runs on the internet layer of the IP suite aka TCP/IP
- IP packets are called **datagrams**
- IP is in charge of delivering datagrams between hosts using IP addresses to identify hosts
- IPV4 address is an address of 4bytes or 32bits, a dot is a delimeter to each byte
- There are reserved addresses: 
1. 0.0.0.0 --> 0.255.255.255 represents "this" network 
2. 127.0.0.0 --> 127.255.255.255 represents a loopback address
3. 192.168.0.0 --> 192.168.255.255 represents private IP addressses

> Identifying IP addresses and Subnetting
 
 - To identify the network of a host you would need its SUBNET MASK and IP address
 1. The subnet mask can be gotten from the Class of the IP e.g 
 `class A` --> 255.0.0.0
 `class B` --> 255.255.0.0
 `class C` --> 255.255.255.0
 the corresponding 255 parts of the ip and the netmask is the Network portion the rest is the host

- To find a network prefix and write in cidre notation 
example: say you have an `IP: 192.168.33.12/255.255.244.0` --> Class B ip thats how we know its using its first two parts but is also using some bits in third octet for network part, so to represent it in CIDRE notation you would need to find the network prefix Do this by: 
- Convert both the Ip address and Netmask to binary form 
- do a Bitwise AND operation between their corresponding bits
- convert the resulting bit into its decimal form back 
you should get 192.168.32.0/19 as the answer to the example above
- this is the cidre notation,
alte: you could just line the bits of the IP and the netmask opposite each other and cancel out the consecutive 1s that becomes  the network part then fill the rest on the right side woth zeros that beomes the network prefix.


> Routing 

- routing protocols are used to determine the best path to reach a network 
- routers inspect the destination IP of packets then forward to an interface
- to do this forwarding it as to check/lookup its Routing table to find an IP - Interface binding
- the routing table also contains a default IP: 0.0.0.0 and uses this entry when the computer receives a packet from an unknown network i.e if the computer receives a packet from a computer who's network portion does not match any of the entries of the network portion bound to any interface on the destination computer it will use the 0.0.0.0 address/ default route