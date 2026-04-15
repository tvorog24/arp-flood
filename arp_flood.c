#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <locale.h>
#include <string.h>

#define DEV_NUMER 5
#define ARP_PACKET_LEN 18 + 24


void rand_mac_fill(uint8_t* vec, short int is_src) {
    for (int i = 0; i < 6; i++) {
        vec[i] = rand() % 256;
    } 
    // avoid group mac
    if (is_src) {
        vec[0] = vec[0] - (vec[0] % 2);
    }
}

void rand_ip_fill(uint8_t* vec) {
    for (int i = 0; i < 3; i++) {
        vec[i] = rand() % 256;
    }
    vec[3] = 1 + rand() % 255;
}

void fill_packet(uint8_t* packet) {
    uint8_t sender_mac[6], target_mac[6], sender_ip[4], target_ip[4];

    rand_mac_fill(sender_mac, 1);
    rand_mac_fill(target_mac, 0);
    rand_ip_fill(sender_ip);
    rand_ip_fill(target_ip);
    // ethernet header
    memcpy(packet, target_mac, 6);
    memcpy(packet + 6, sender_mac, 6);
    packet[12] = 0x08; packet[13] = 0x06; 
    // arp reply
    packet[14] = 0x00; packet[15] = 0x01; 
    packet[16] = 0x08; packet[17] = 0x00; 
    packet[18] = 0x06; 
    packet[19] = 0x04; 
    packet[20] = 0x00; packet[21] = 0x02;
    memcpy(packet + 22, sender_mac, 6); 
    memcpy(packet + 28, sender_ip, 4); 
    memcpy(packet + 32, target_mac, 6); 
    memcpy(packet + 38, target_ip, 4); 
}

void dev_free(char** devs, int k_devs) {
    for (int i = 0; i < k_devs; i++) {
        free(devs[i]);
    }
    free(devs);
}

void dev_move(char** new_devs, char** devs, int k_devs) {
    for (int i = 0; i < k_devs; i++) {
        new_devs[i] = devs[i];
    }
    free(devs);
}

int fill_devs(char*** devs) {
    pcap_if_t* alldevs, *d;
    char** new_devs;
    int n_alloc = DEV_NUMER;
    char* name;
    char errbuf[PCAP_ERRBUF_SIZE];
    int k_devs = 0;

    if (pcap_findalldevs(&alldevs, errbuf)) {
        printf("error in pcap_findalldevs: %s\n", errbuf);
        return -1;
    }

    *devs = (char**)malloc(sizeof(char*) * n_alloc);
    if (*devs == NULL) {
        printf("fill_devs: memory alloc error\n");
        return -1;
    }

    for (d = alldevs; d; d = d->next) {
        name = strdup(d->name);
        if (name == NULL) {
            printf("fill_devs: memory alloc error\n");
            dev_free(*devs, k_devs);
            pcap_freealldevs(alldevs);
            return -1;
        }
        if (n_alloc == k_devs) {
            n_alloc += DEV_NUMER;
            new_devs = (char**)malloc(sizeof(char*) * n_alloc);
            if (new_devs == NULL) {
                printf("fill_devs: memory alloc error\n");
                dev_free(*devs, k_devs);
                pcap_freealldevs(alldevs);
                return -1;
            }
            else {
                dev_move(new_devs, *devs, k_devs);
                *devs = new_devs;
            }
        }
        (*devs)[k_devs] = name;

        printf("[%d] %s ", k_devs, name);
        if (d->description) {
            printf("(%s)", d->description);
        }
        printf("\n");

        k_devs++;
    }

    if (k_devs == 0) {
        printf("no interfaces found\n");
        free(*devs);
    }

    pcap_freealldevs(alldevs);
    return k_devs;
}

char* choose_dev(char** devs, int k) {
    int choice;
    printf("input dev number (%d-%d): ", 0, k-1);
    if (scanf("%d", &choice) != 1 || choice > k-1 || choice < 0) {
        printf("invalid dev number\n");
        return NULL;
    }
    return devs[choice];
}

int main() {
    char** devs;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    uint8_t packet[ARP_PACKET_LEN];
    int k_arp_packets;

    // system locale
    setlocale(LC_ALL, "");

    int k_devs = fill_devs(&devs);
    if (k_devs <= 0) {
        return -1;
    }
     
    srand((unsigned)time(NULL));

    char* dev = choose_dev(devs, k_devs);
    if (dev == NULL) {
        dev_free(devs, k_devs);
        return 1;
    }
    
    printf("input arp packets amount: ");
    if (scanf("%d", &k_arp_packets) != 1 || k_arp_packets <= 0) {
        printf("%s", "invalid arp packets amount\n");
        dev_free(devs, k_devs);
        return 2;
    }
    // interface, packet size, promiscouous flag, read timeout (ms), authentication, error buffer) 
    handle = pcap_open(dev, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
    if (handle == NULL) {
        printf("can't open device %s: %s\n", dev, errbuf);
        dev_free(devs, k_devs);
        return 3;
    }

    for (int n = 0; n < k_arp_packets; n++) {
        fill_packet(packet);
        if (pcap_sendpacket(handle, packet, ARP_PACKET_LEN) != 0) {
            printf("error sending packet: %s\n", pcap_geterr(handle));
        }
        else {
            printf("sent packet #%d\n", n+1);
        }
        // 500 ms
        Sleep(500);
    }

    pcap_close(handle);
    dev_free(devs, k_devs);
    return 0;
}