#include <iostream>
#include <pcap.h>
#include <string.h>
#include <vector>
#include <linux/wireless.h>

using namespace std;

struct radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
};

struct beacon {
    uint8_t bssid[6];
    int beacons;
    char essid[IW_ESSID_MAX_SIZE];
};

void usage() {
    printf("airodump <interface>\n");
    printf("sample: airodump mon0\n");
}

void print_network(vector<struct beacon> &networks) {
    printf("BSSID\t\t\tBeacons\t\tESSID\t\n");
    for (struct beacon tmp : networks) {
        for (int i = 0; i < 6; i++) {
            printf("%02X", tmp.bssid[i]);
            if(i != 5) printf(":");
        }
        printf("\t%d\t\t%s\t\n", tmp.beacons, tmp.essid);
    }
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        usage();
        return -1;
    }

    vector<struct beacon> networks;
    char* dev = argv[1];
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
        struct radiotap_header *radio_hdr = (struct radiotap_header *)packet;
        uint16_t it_len = radio_hdr->it_len;
        struct beacon tmp;
        bool is_new = true;

        if(*(packet + it_len) != 0x80) continue;

        memcpy(tmp.bssid, packet + it_len + 16, 6);
        memcpy(tmp.essid, packet + it_len + 38, *(packet + it_len + 37));
        tmp.beacons = 1;
        for (int i = 0; i < (int)networks.size(); i++) {
            if (memcmp(networks[i].bssid, tmp.bssid, 6) == 0) {
                networks[i].beacons++;
                is_new = false;
            }
        }
        if (is_new) {
            networks.push_back(tmp);
        }
        print_network(networks);
    }

    pcap_close(handle);
}
