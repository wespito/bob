/*
1. Ethernet Header의 src mac / dst mac
2. IP Header의 src ip / dst ip
3. TCP Header의 src port / dst port
4. Payload(Data)의 hexadecimal value(최대 16바이트까지만)
*/

#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

//구조체선언
//Ethernet header
#define ETHER_ADDR_LEN	6 //Ethernet addresses are 6 bytes
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN];
    u_char ether_shost[ETHER_ADDR_LEN];
    u_short ether_type;
};

//IP header
struct sniff_ip {
    u_char ip_vhl;
    u_char ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
    #define IP_RF 0x8000
    #define IP_DF 0x4000
    #define IP_MF 0x2000
    #define IP_OFFMASK 0x1fff
    u_char ip_ttl;
    u_char ip_p; //protocol
    u_short ip_sum;
    struct in_addr ip_src,ip_dst;
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

//TCP header
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;
    u_short th_dport;
    tcp_seq th_seq;
    tcp_seq th_ack;
    u_char th_offx2; //data offset, rsvd
    #define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
};

#define SIZE_ETHERNET 14 //ethernet headers are always exactly 14 bytes
const struct sniff_ethernet *ethernet;
const struct sniff_ip *ip;
const struct sniff_tcp *tcp;
const char *payload;

u_int size_ip;
u_int size_tcp;


void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

int main(int argc, char* argv[]) {
    int i;

    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1]; //ens33
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        printf("%u bytes captured\n", header->caplen);

        //------------------------------------------------------
        ethernet = (struct sniff_ethernet*)(packet);
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip) *4;
        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp) *4;
        payload = (char*)(packet + SIZE_ETHERNET + size_ip + size_tcp);

        if(ip->ip_p==6){ //if TCP
            printf("[TCP %d]\n", ip->ip_p);

            //Ethernet src, dest MAC
            printf("Ethernet Header MAC src : ");
            for(i = 0; i < ETHER_ADDR_LEN; i++ ){
                printf("%.2x", ethernet->ether_shost[i]);
            }
            printf("\nEthernet Header MAC dest : ");
            for(i = 0; i < ETHER_ADDR_LEN; i++ ){
                printf("%.2x", ethernet->ether_dhost[i]);
            }

            //IP src, dest
            printf("\nIP Header src ip : %s\n", inet_ntoa(ip->ip_src));
            printf("IP Header dest ip : %s\n", inet_ntoa(ip->ip_dst));

            //TCP src, dest port
            printf("TCP Header src port : %d\n", tcp->th_sport);
            printf("TCP Header dest port : %d\n", tcp->th_dport);

            //payload
            printf("Payload data(~16byte) : \n");
            for(i = 0; i < 16; i++) {
                printf("%.2x", payload[i]);
            }

            printf("\n------------------------------------------------------\n");
        }
    }

    pcap_close(handle);
}
