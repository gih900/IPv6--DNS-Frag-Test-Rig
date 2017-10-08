## IPv6--DNS-Frag-Test-Rig - en example of raw IPv6 UDP sockets using the DNS

This is a program which acts as a front to a UDP-based DNS server that
performs IPv6 packet fragmentation. The program is intended to test
the capability of DNS resolvers to receive fragmented IPv6 packets in
the DNS.

The program uses raw IPv6 sockets as the way in which the fragmented
IPv6 packets are constructed.

This code relies on system calls in Linux, and has been developed on a
Debian 4.9.25-1. 

For FreeBSD and similar platforms such as Mac OSX the raw socket calls
need to be replaced with calls into the pcap library to both send and
receive raw packets.
