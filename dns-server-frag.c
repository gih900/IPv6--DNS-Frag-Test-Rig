/*
 * dns-server-frag.c
 *
 * This is a middleware shim that accepts incoming DNS requests
 * and forwards the request to a 'real' DNS server
 * The response is fragmented at by offset 80 and then at 512 byte chunks
 * The set of IPv6 fragments are sent on the active interface via a raw 
 * socket interface
 * 
 * parameters
 *  -i interface
 *  -l listen IPv6 address
 *  -p listen port (default 53)
 *  -d dns server
 *  -m mac address of the local gateway
 *
 * dns-server-frag -i eth0 -l 2a01:4f8:161:50ad::e:cd5a -p 53 -d 8.8.8.8
 *
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/times.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <bits/socket.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>
#include <bits/ioctls.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <pcap.h>
#include <time.h>

#define ETH_HDRLEN 14
#define DNSPORT 53

typedef struct _pktinfo6 pktinfo6;
typedef struct in6_addr in6_addr_t;
struct _pktinfo6 {
  struct in6_addr ipi6_addr;
  int ipi6_ifindex;
  };

#define MAXBUF	65536 
#define BACK_PORTNO 53
#define BACK_HOST "dns.google.com"

int portno = BACK_PORTNO ;
char *hostname = BACK_HOST ;

struct sockaddr_in serveraddr4 ;
struct sockaddr_in6 serveraddr6 ;

struct hostent *server ;
time_t t ;
struct response {
  int len ;
  char buf[MAXBUF] ;
  }  dns_response ;
struct in_addr ip4_addr ;
struct in6_addr ip6_addr ;
int proto ;
uint8_t src_mac[6] ;
uint8_t dst_mac[6] ;
char *dns ;
char *host ;
int port ;
char *interface ;
struct sockaddr_ll device; 
struct ifreq ifr ;
int sd ;
char *target, *src_ip, *dst_ip ;
uint8_t *data, *ether_frame ;
int dst_mac_set = 0 ;

char *allocate_strmem (int);

/* 
 * find_ancillary
 *
 * search through ancillary message chain for a message of type cmsg_type
 */

static void *
find_ancillary (struct msghdr *msg, int cmsg_type)
{
  struct cmsghdr *cmsg = NULL;

  for (cmsg = CMSG_FIRSTHDR (msg); cmsg != NULL; cmsg = CMSG_NXTHDR (msg, cmsg)) {
    if ((cmsg->cmsg_level == IPPROTO_IPV6) && (cmsg->cmsg_type == cmsg_type)) {
      return (CMSG_DATA (cmsg));
      }
    }
  return (NULL);
  }


/*
 * allocate_stream
 *
 * Allocate memory for an array of chars.
 */

char *
allocate_strmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: allocate_strmem length: %i\n", len);
    exit (EXIT_FAILURE);
    }

  tmp = (char *) malloc (len * sizeof (char));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (char));
    return (tmp);
    }
  else {
    fprintf (stderr, "ERROR: allocate_strmem malloc failed\n") ;
    exit (EXIT_FAILURE);
    }
  }

/*
 * allocate_ustrmem
 *
 * Allocate memory for an array of unsigned 8 bit ints.
 */

uint8_t *
allocate_ustrmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: allocate_ustrmem length: %i\n", len);
    exit (EXIT_FAILURE);
    }

  tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (uint8_t));
    return (tmp);
    } 
  else {
    fprintf (stderr, "ERROR: allocate_ustrmem malloc failed\n") ;
    exit (EXIT_FAILURE);
    }
}




/*
 * 
 * ra_mac
 *
 * get the MAC address of the local router (needed for the IPv6
 * raw IP packet interface) 
 */ 

uint8_t *
ra_mac()
{
  int sd;
  int ifindex;
  int len;
  int i;
  uint8_t *inpack;
  struct msghdr msghdr;
  struct iovec iov[2];
  struct ifreq ifr;
  struct nd_router_advert *ra;
  uint8_t *pkt;

  // Allocate memory for various arrays.
  inpack = allocate_ustrmem (IP_MAXPACKET);

  // Prepare msghdr for recvmsg().
  memset (&msghdr, 0, sizeof (msghdr));
  msghdr.msg_name = NULL;
  msghdr.msg_namelen = 0;
  memset (&iov, 0, sizeof (iov));
  iov[0].iov_base = (uint8_t *) inpack;
  iov[0].iov_len = IP_MAXPACKET;
  msghdr.msg_iov = iov;
  msghdr.msg_iovlen = 1;

  msghdr.msg_control = allocate_ustrmem (IP_MAXPACKET);
  msghdr.msg_controllen = IP_MAXPACKET * sizeof (uint8_t);

  /* Request a socket descriptor sd. */
  if ((sd = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
    perror ("Failed to get socket descriptor ");
    exit (EXIT_FAILURE);
    }

  /* Obtain MAC address of this node. */
  memset (&ifr, 0, sizeof (ifr));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
    perror ("ioctl() failed to get source MAC address ");
    exit (EXIT_FAILURE);
    }

  /* Retrieve interface index of this node. */
  if ((ifindex = if_nametoindex (interface)) == 0) {
    perror ("if_nametoindex() failed to obtain interface index ");
    exit (EXIT_FAILURE);
    }

  /* Bind socket to interface of this node. */
  if (setsockopt (sd, SOL_SOCKET, SO_BINDTODEVICE, (void *) &ifr, sizeof (ifr)) < 0) {
    perror ("SO_BINDTODEVICE failed");
    exit (EXIT_FAILURE);
  }

  /* Listen for incoming message from socket sd.
     Keep at it until we get a router advertisement. */
  ra = (struct nd_router_advert *) inpack;
  while (ra->nd_ra_hdr.icmp6_type != ND_ROUTER_ADVERT) {
    if ((len = recvmsg (sd, &msghdr, 0)) < 0) {
      perror ("recvmsg failed ");
      exit (EXIT_FAILURE);
      }
    }

  /* got it - all we need is the source mac address */
  pkt = (uint8_t *) inpack;
  for (i=2; i<=7; i++) {
    dst_mac[i-2] = pkt[sizeof (struct nd_router_advert) + i];
    }
  close (sd);
  return (&dst_mac[0]);
}


/*
 * open_raw_socket
 *
 * open a raw ethernet socket
 */

void
open_raw_socket()
{
  /* the mac address of the next hop router can be set by -m <mac_addr>
     if it is not set then we need to listen for RA messages and pull
     the mac address of one of them */
   
  if (!dst_mac_set) 
    ra_mac();

  /* Allocate memory for various arrays. */
  data = allocate_ustrmem (IP_MAXPACKET); 
  ether_frame = allocate_ustrmem (IP_MAXPACKET); 
  target = allocate_strmem (INET6_ADDRSTRLEN); 
  src_ip = allocate_strmem (INET6_ADDRSTRLEN); 
  dst_ip = allocate_strmem (INET6_ADDRSTRLEN); 
  
  /* Submit request for a socket descriptor to look up interface. */
  if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) { 
    perror ("socket() failed to get socket descriptor for using ioctl() "); 
    exit (EXIT_FAILURE); 
    } 
 
  /* Use ioctl() to look up interface name and get its MAC address. */
  memset (&ifr, 0, sizeof (ifr)); 
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface); 
  if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) { 
    perror ("ioctl() failed to get source MAC address "); 
    exit (EXIT_FAILURE); 
    } 
  close (sd); 
 
  /* Copy source MAC address into src_mac */
  memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t)); 
 
  /* Find interface index from interface name and store index in 
     struct sockaddr_ll device, which will be used as an argument of sendto().  */
  memset (&device, 0, sizeof (device)); 
  if ((device.sll_ifindex = if_nametoindex (interface)) == 0) { 
    perror ("if_nametoindex() failed to obtain interface index "); 
    exit (EXIT_FAILURE); 
    } 

  /* Fill out sockaddr_ll. */
  device.sll_family = AF_PACKET; 
  memcpy (device.sll_addr, src_mac, 6 * sizeof (uint8_t)); 
  device.sll_halen = 6; 
 
  /* Submit request for a raw socket descriptor. */
  if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) { 
    perror ("socket() failed "); 
    exit (EXIT_FAILURE); 
    }
  return;
  } 


/*
 * resolve_v6_name
 *
 * local DNS AAAA resolver
 */

int 
resolve_v6_name(char *name, char *address, struct in6_addr *a6) { 
  struct addrinfo hints, *res, *res0; 
  int error; 
  struct sockaddr_in6 *si6 ; 
 
  memset(&hints, 0, sizeof(hints)); 
  hints.ai_family = AF_INET6; 
  if (getaddrinfo(name,0, &hints, &res0)) { 
    return(0) ; 
    } 

  res = res0 ; 
  si6 = (struct sockaddr_in6*) res->ai_addr ; 
  if (address)
    inet_ntop(hints.ai_family,&(si6->sin6_addr),address,INET6_ADDRSTRLEN) ; 
  if (a6) 
    bcopy(&si6->sin6_addr,a6,sizeof a6) ;
  freeaddrinfo(res0); 
  return(1) ; 
} 
 

/*
 * resolve_v4_name
 *
 * local DNS A resolver
 */

int 
resolve_v4_name(char *name, char *address, struct in_addr *a4) { 
  struct addrinfo hints, *res, *res0; 
  int error; 
  struct sockaddr_in *si ; 
 
  memset(&hints, 0, sizeof(hints)); 
  hints.ai_family = AF_INET; 
  if (getaddrinfo(name,0, &hints, &res0)) { 
    return(0) ; 
  } 
  res = res0 ; 
  si = (struct sockaddr_in*) res->ai_addr ; 
  if (address) 
    inet_ntop(hints.ai_family,&(si->sin_addr),address,INET_ADDRSTRLEN) ; 
  if (a4) 
    bcopy(&si->sin_addr,a4,sizeof a4) ;
  
  freeaddrinfo(res0); 
  return(1) ; 
} 
 



/***************************************************
 * server_request
 *
 * In response to an incoming request:
 *   generate an equivalent UDP request to the DNS server and collect the response
 *   repackage the data into a IPv6 packet with fragmentation
 *   send the response back as a stream of packets
 **************************************************/


int 
server_request(char *s, int data_size) {
  int sockfd ;
  unsigned int serverlen ;
  char str[256] ;
  int i ;
  

  /* connect: create a connection with the server */
  /* IPv4 code */
  if (proto == AF_INET) {
    /* send the modified query to slave DNS */
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
      perror("UDP slave socket() error") ;
      return 1;
      }

    if (connect(sockfd, (struct sockaddr *) &serveraddr4, sizeof(serveraddr4)) < 0) {
      perror("UDP V4 connect error") ;
	  return 1;
      // exit(EXIT_FAILURE) ;
      }

    if (inet_ntop(AF_INET,&serveraddr4.sin_addr,str,INET_ADDRSTRLEN) == NULL) {
      perror("inet_ntop");
      return 1;
      }
    serverlen = sizeof(serveraddr4);
    i = ntohs(serveraddr4.sin_port) ;

    /* send the message line to the server */
    i = write(sockfd, s, data_size) ;
    if (i < 0) {
      perror("ERROR writing to socket");
      return 1;
      }

    /* collect the server's reply */  
    dns_response.len = recvfrom(sockfd, dns_response.buf, MAXBUF, 0, (struct sockaddr *) &serveraddr4, &serverlen);
    if (dns_response.len < 0) {
      perror("UDP recvfrom");
      return 1;
      }
    close(sockfd);
    }
  else {
    /* IPv6 code */
    /* send the modified query to slave DNS */
    if ((sockfd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
      perror("UDP slave socket() error") ;
      return 1;
      }

    if (connect(sockfd, (struct sockaddr *) &serveraddr6, sizeof(serveraddr6)) < 0) {
      perror("UDP V6 connect error") ;
      return 1;
      }
    if (inet_ntop(AF_INET6,&serveraddr6.sin6_addr,str,INET6_ADDRSTRLEN) == NULL) {
      perror("inet_ntop");
      return 1;
      }
    serverlen = sizeof(serveraddr6);
    i = ntohs(serveraddr6.sin6_port) ;


    /* send the message line to the server */
    i = write(sockfd, s, data_size) ;
    if (i < 0) {
      perror("ERROR writing to socket");
      return 1;
      }
  
    dns_response.len = recvfrom(sockfd, dns_response.buf, MAXBUF, 0, (struct sockaddr *) &serveraddr6, &serverlen);
    if (dns_response.len < 0) {
      perror("UDP recvfrom");
      return 1;
      }
    close(sockfd);
    }
  return 0;
}



/***************************************************
 * udp checksum
 *
 * calculate the UDP checksum
 **************************************************/

uint16_t 
udp_checksum (const void *buff, size_t len, in6_addr_t *src_addr, in6_addr_t *dest_addr) 	
{
  const uint16_t *buf=buff;
  uint16_t *ip_src=(void *)src_addr, *ip_dst=(void *)dest_addr;
  uint32_t sum;
  size_t length=len;
  int i  ;
 
  /* Calculate the sum */
  sum = 0;
  while (len > 1) {
    sum += *buf++;
    if (sum & 0x80000000)
      sum = (sum & 0xFFFF) + (sum >> 16);
    len -= 2;
    }
  if ( len & 1 )
    /* Add the padding if the packet length is odd */
    sum += *((uint8_t *)buf);
 
  /* Add the pseudo-header */
  for (i = 0 ; i <= 7 ; ++i) 
    sum += *(ip_src++);
 
  for (i = 0 ; i <= 7 ; ++i) 
    sum += *(ip_dst++);
 
  sum += htons(IPPROTO_UDP);
  sum += htons(length);
 
  /* Add the carries */
  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);
 
  /* Return the one's complement of sum */
  return((uint16_t)(~sum));
}

/***************************************************
 *  respond
 *
 *  Take the DNS response from the back end server
 *  and send a fragmented response to the client
 **************************************************/
 
int  
respond(struct response *dns_response, struct sockaddr_in6 *srcaddr, struct sockaddr_in6 *cliaddr)   
{  
  char out_packet_buffer[4500] ;  
  char payload[4500] ;  
  struct ip6_hdr *iphdr ;
  struct udphdr *uhdr ;
  struct ip6_frag *fhdr ;
  int to_send ;
  char *to_buf ;
  int units ;
  int datalen ;
  int frag_offset ;
  int bytes ;
  int frame_length ;

        
  /* IPv6 header  */
  iphdr = (struct ip6_hdr *) &out_packet_buffer[0] ;  

  // IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits) 
  iphdr->ip6_flow = htonl ((6 << 28) | (0 << 20) | 0); 
 
  // Next header (8 bits): 44 for Frag
  iphdr->ip6_nxt = 44; 
 
  // Hop limit (8 bits): default to maximum value 
  iphdr->ip6_hops = 255; 
  
  // src address
  bcopy(&srcaddr->sin6_addr,&(iphdr->ip6_src), 16) ;  

  // dst address
  bcopy(&cliaddr->sin6_addr,&(iphdr->ip6_dst), 16);
 
  // printf("set up the UDP header\n") ;
  uhdr = (struct udphdr *) &(payload[0]);
  uhdr->uh_sport = htons(port) ;
  uhdr->uh_dport = cliaddr->sin6_port;
  uhdr->uh_ulen = htons(dns_response->len + 8);
  uhdr->uh_sum = 0;
  /* copy payload bytes from the dns response buffer to the payload buffer */
  bcopy(dns_response->buf,&payload[8],dns_response->len) ;    

  /* calculate the UDP checksum */  
  uhdr->uh_sum = udp_checksum(uhdr,dns_response->len + 8, &srcaddr->sin6_addr, &cliaddr->sin6_addr);

  /* now fragment the output */
  /* set up the frag header */
  fhdr = (struct ip6_frag *) &out_packet_buffer[40];
  fhdr->ip6f_nxt = 17 ;
  fhdr->ip6f_reserved = 0 ;
  fhdr->ip6f_offlg = htons(1);
  fhdr->ip6f_ident = rand() % 4294967296 ; 

  /* the total size to send is the payload size plus the UDP header */
  to_send = dns_response->len + 8 ;
  to_buf = (char *) uhdr ;

  /* now carve up the UDP response into frags */
  /* initial block of UDP payload size is at least 8 bytes less than the original dns response */
  units = dns_response->len / 8 ;
  if (units > 16) datalen = 128 ; 
  else datalen = (units - 1) * 8 ;
  frag_offset = 0 ;
  
  /* add in the size of the UDP header into datalen in the first instance */
  datalen += 8 ;

  // Destination and Source MAC addresses 
  memcpy(ether_frame, dst_mac, 6 * sizeof (uint8_t)); 
  memcpy(ether_frame + 6, src_mac, 6 * sizeof (uint8_t)); 
 
  // Next is ethernet type code (ETH_P_IPV6 for IPv6). 
  // http://www.iana.org/assignments/ethernet-numbers 
  ether_frame[12] = ETH_P_IPV6 / 256;   
  ether_frame[13] = ETH_P_IPV6 % 256; 

  
  while (to_send > 0) {

    /* each time we send datalen bytes plus the 8 byte frag header */
    iphdr->ip6_plen = htons(datalen + 8); 
    /* now assemble the ether frame */    
    frame_length = 6 + 6 + 2 + 40 + 8 + datalen;     
 
    /* IPv6 header + frag header */
    memcpy (ether_frame + ETH_HDRLEN, iphdr, 48); 
    
    /* payload fragment */
    memcpy (ether_frame + ETH_HDRLEN + 48, to_buf, datalen); 

    // printf("Packet %d - Byte %d to %d\n",pc,frag_offset * 8, (frag_offset * 8) + datalen) ; ++pc ;

    // Send ethernet frame to socket. 
    if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) { 
      perror ("sendto() failed"); 
      exit (EXIT_FAILURE); 
      } 
      
    to_send -= datalen ;
    to_buf += datalen ;
    
    if (to_send > 0) {
      if (to_send <= 512) {
        /* last frag */
        frag_offset += (datalen / 8) ;
        fhdr->ip6f_offlg = htons(frag_offset << 3) ;
        datalen = to_send ;
        // memcpy(ether_frame + ETH_HDRLEN + 48,to_buf,datalen);
        }
      else {
        frag_offset += (datalen / 8) ;
        fhdr->ip6f_offlg = htons((frag_offset << 3) + 1);
        datalen = 512 ; 
        // memcpy(ether_frame + ETH_HDRLEN + 48,to_buf,datalen);
        }
      }
    }
  return(1) ;
  }




/***************************************************
 *  set up the parameters for the UDP connection to the back
 *  end DNS server 
 **************************************************/

void
resolve_dns(char *server_name, int port) {
  int status ;
  
  if (strchr(server_name,':')) {
    if (!inet_pton(AF_INET6,server_name,&ip6_addr)) {
      status = errno;
      fprintf (stderr, "inet_pton() failed (%s).\nError message: %s",server_name, strerror (status));
      exit (EXIT_FAILURE);
      }
    proto = AF_INET6 ;
    }
  else if (inet_aton(server_name, &ip4_addr)) {
    proto = AF_INET ;
    }
  else if (resolve_v4_name(server_name,0,&ip4_addr)) {
    proto = AF_INET ;
    }
  else if (!resolve_v6_name(server_name,0,&ip6_addr)) {
    fprintf (stderr, "dns-server-frag -d <dns-server> - unable to resolve dns server name %s\n",server_name) ;
    exit (EXIT_FAILURE);
    }
  else {
    proto = AF_INET6 ;
    }
  if (proto == AF_INET) {
    serveraddr4.sin_family = proto ;
    serveraddr4.sin_port = htons(portno) ;
    bcopy(&ip4_addr,&(serveraddr4.sin_addr),4) ;
    }
  else {
    serveraddr6.sin6_family = proto ;
    serveraddr6.sin6_port = htons(portno) ;
    serveraddr6.sin6_flowinfo = 0 ;
    serveraddr6.sin6_scope_id = 0 ;
    bcopy(&ip6_addr,&(serveraddr6.sin6_addr),16) ;
    }
    
}

/***************************************************
 *  main
 * read parameters, then enter a loop to listen for
 * and then process each query
 **************************************************/

int main(int argc, char **argv)
{
  int sockfd;
  ssize_t m;
  int n;
  socklen_t addrlen, len;
  struct sockaddr_in6 *cliaddr;
  struct sockaddr_in6 listen ;
  char *host ;
  struct addrinfo hints, *res, *ressave;
  char buf[MAXBUF];
  char str[INET6_ADDRSTRLEN];
  int status ;
  int ch ;
  int rc ;

  /* DEFAULTS */
  interface = "eth0";
  host = "::1";
  port = 53;
  dns = "8.8.8.8";
  

  while (((ch = getopt(argc,argv, "i:m:p:d:l:"))) != -1) {
    switch(ch) {
      case 'i':
        // interface name of 'listen' address
        interface = strdup(optarg) ;
        break ;

      case 'l':
        // interface name of 'listen' address
        host = strdup(optarg) ;
        break ;
        
      case 'm':
        // mac address of V6 gateway on listen address network
	if (sscanf(optarg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &dst_mac[0], &dst_mac[1], &dst_mac[2], &dst_mac[3], &dst_mac[4], &dst_mac[5]) != 6) {
          fprintf(stderr,"%s not a MAC address\n",optarg) ;
          exit(1) ;
	  }
	dst_mac_set = 1 ;
	break;

      case 'p':
        port = strtoul(optarg,0,10) ;
        break ;

      case 'd':
        dns = strdup(optarg) ;
        break ;

      default:
        fprintf(stderr, "dns-server-frag  parameters\n  -i interface\n  -l listen IPv6 address\n  -p listen port (default 53)\n  -d dns server\n  -m mac address of the local gateway\n\ne.g. dns-server-frag -i eth0 -l 3a01:4f8:161:50ad::e:cd5a -p 53 -d 8.8.8.8\n") ;
        exit (EXIT_FAILURE);
      }
    }   

  argc -= optind;
  argv += optind;
  /* Intializes random number generator */
  srand((unsigned) time(&t));

  /* resolve the back end DNS server name */
  resolve_dns(dns,53) ;

  /* open a raw socket */  
  open_raw_socket() ;
       
  sockfd = socket(AF_INET6,SOCK_DGRAM,17);
  if (sockfd < 0) {
    perror("Socket") ;
    exit(EXIT_FAILURE) ;
    }

  /* set up the local port 53 listener */
  if (((status = inet_pton(AF_INET6,host,&listen.sin6_addr))) <= 0) {
    if (!status)
      fprintf(stderr, "Not in presentation format");
    else
      perror("inet_pton");
    exit(EXIT_FAILURE);
    }

  listen.sin6_family = AF_INET6 ;
  listen.sin6_port = htons(port);

  if (inet_ntop(AF_INET6,&listen.sin6_addr,str,INET6_ADDRSTRLEN) == NULL) {
    perror("inet_ntop");
    exit(EXIT_FAILURE);
    }

  /* and open up the listening socket */
  if (bind(sockfd,(const struct sockaddr *) &listen,(sizeof listen))) {
    perror("bind") ;
    exit(EXIT_FAILURE) ;
    }

  addrlen= sizeof *cliaddr ;
  cliaddr=malloc(addrlen);
  len=addrlen;

  for ( ;; ) {     /* do forever */

    /* receive a packet from the Internet */
    if ((rc = recvfrom(sockfd, buf, MAXBUF, 0, (struct sockaddr *) cliaddr, &len)) < 0 ) {
      printf("server error: errno %d\n",errno);
      perror("reading datagram");
      exit(1);
      }

    /* pass the packet to the back-end server and get the response */
    if (server_request(buf, rc))
      continue;
      
    /* write the response back to the original sender */  
    respond(&dns_response,&listen,cliaddr) ;
    }
    
  /* can't get here, but just in case: close sockets */
  close(sockfd);
  return(0);
  }
