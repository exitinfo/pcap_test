#include <pcap.h>
#include <stdio.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_payload(u_int64_t pl, const u_char* payload)
{
    u_int64_t n;
    if(pl > 10) n = 10;
    else n = pl;
    printf("TCP Data Length : %ld\n", pl);
    printf("TCP Data :");
    for(u_int64_t i = 0; i < n; i++)
    {
        printf(" %02x", payload[i]);
    }
    printf("\n");
}
void print_mac(const u_char *mac)
{
    printf("D-MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    printf("S-MAC : %02x:%02x:%02x:%02x:%02x:%02x\n", mac[6], mac[7], mac[8], mac[9], mac[10], mac[11]);
}
void print_ip(const u_char *ip)
{
    printf("D-IP : %d.%d.%d.%d\n", ip[4], ip[5], ip[6], ip[7]);
    printf("S-IP : %d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
}
void print_port(const u_char *port)
{
    printf("D-PORT : %d\n", (port[2] << 8) | port[3]);
    printf("D-PORT : %d\n", (port[0] << 8) | port[1]);
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);

    if(packet[12] == 0x08 && packet[13] == 0x00) //IP = 0x0800 (2byte)
    {
        printf("IPv4!\n");
        if(packet[23] == 0x06) //IP Protocol Number : TCP = 0x06 (1byte)
        {
            printf("TCP!\n");
            u_int8_t ihl = (packet[14] & 0x0F) * 4; //IP Header Length (4bit), packet[14] = Version(4bit) and IHL(4bit)
            u_int8_t thl = packet[26 + ihl] / 4; //TCP Header Length, 14 + ihl + 13 - 1
            u_int8_t tp = 14 + ihl + thl; //TCP Payload Start Point
            u_int64_t tpl = header->caplen - 14 - ihl - thl; //Payload Length
      //      u_int16_t tpl = (packet[tp + 3] << 8) + packet[tp + 4] - ihl - thl;
      //      printf("IPHTL = %d TPL = %d\n", (packet[tp + 3] << 8) + packet[tp + 4], tpl);
          //TCP Payload Length = IP Header Total Length - IP Header Length - TCP Header Length
            print_mac(&packet[0]);
            print_ip(&packet[26]);
            print_port(&packet[14 + ihl]);
            print_payload(tpl, &packet[tp]);
        }

    }//Start Point ={ Ehernet Header: packet[0], IP Header: packet[14], TCP Header: packet[14+ihl], TCP Payload: packet[14+ihl+thl] }
    printf("\n");
  }

  pcap_close(handle);
  return 0;
}
