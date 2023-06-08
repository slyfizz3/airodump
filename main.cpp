#include <pcap.h>
#include <string>
#include <utility>
#include "mac.h"
#include "802-11.h"

using namespace std;

struct Arrmap {
    Mac bssid;
    uint8_t beacons;
    string essid;
};

#define beacon_type 0x80
constexpr int max_array = 100;
Arrmap arr[max_array];
int arr_size = 0;

void usage()
{
    printf("syntax : airodump <interface>\n");
    printf("sample : airodump mon0\n");
    exit(1);
}

int main(int argc, char *argv[]) {
    if (argc != 2)
        usage();

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        exit(1);
    }

    struct pcap_pkthdr *header;
    const u_char *packet;
    while (1) {
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            pcap_close(pcap);
            exit(1);
        }

        ieee80211_radiotap_header *radio = (ieee80211_radiotap_header *)packet;
        beacon_header *beacon = (beacon_header *)(packet + radio->it_len);
        if (beacon->type != beacon_type){
            continue;
        }

        fixed_parameter *fp = (fixed_parameter *)((u_char *)beacon + sizeof(beacon_header));
        tagged_parameter *tp = (tagged_parameter *)((u_char *)fp + sizeof(fixed_parameter));

        if (tp->num != 0) continue;

        char *ssid = (char *)tp + 2;
        string essid;
        int i=tp->len;
        while (i>=0){
            essid += *ssid++;
            i--;
        }

        bool found = false;
        for (int i = 0; i < arr_size; i++) {
            if (arr[i].bssid == beacon->bssid) {
                arr[i].beacons++;
                found = true;
                break;
            }
        }
        if (!found) {
            if (arr_size < max_array) {
                arr[arr_size++] = {beacon->bssid, 1, essid};
            } else {
                printf("%s","too many arrays!!\n");
            }
        }
        
        system("clear");
        printf("BSSID\t\t   Beacons\tESSID\n\n");
        for (int i = 0; i < arr_size; i++) {
            printf("%s\t%d\t%s\n", string(arr[i].bssid).c_str(), arr[i].beacons, arr[i].essid.c_str());
        }
    }
}