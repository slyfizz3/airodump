#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <fstream>
#include <unistd.h>
#include <fcntl.h>
#include <pcap.h>
#include <sys/ioctl.h> 
#include <net/if.h>


using namespace std;


void usage() {
    printf("syntax : airodump <interface>\n");
    printf("sample : airodump mon0\n");
}


int main(int argc, char* argv[])
{
    if(argc!=2){
        usage();
        return -1;
    }

    string dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev.c_str(), errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle,&header,&packet);
        if(res == 0) continue;
        if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            cout << "pcap_next_ex return "<<res<<'('<<pcap_geterr(handle)<<')'<<endl;
            break;
        }

        
    }
    pcap_close(handle);

    return 0;
}
