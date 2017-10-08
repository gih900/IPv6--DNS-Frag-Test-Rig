## IPv6--DNS-Frag-Test-Rig - en example of raw IPv6 UDP sockets using the DNS

This is a program which acts as a front to a UDP-based DNS server that
performs IPv6 packet fragmentation. The program is intended to test
the capability of DNS resolvers to receive fragmented IPv6 packets in
the DNS.

The program uses raw IPv6 sockets as the way in which the fragmented
IPv6 packets are constructed.
