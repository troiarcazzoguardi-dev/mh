#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sched.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <net/if.h>
#include <x86intrin.h>

#include <bpf/xsk.h>
#include <bpf/libbpf.h>

#define MAX_PKT_SIZE 1500
#define MAX_RATE_PPS 50000000
#define BATCH_SIZE 64

struct opts {
    char **ifaces;
    int n_ifaces;
    char **targets;
    int n_targets;
    int port;
    int rate;
    int duration;
    bool af_xdp;
    int xsk_frames;
    int xsk_frame_size;
    int src_port;
    char *payload;
    int nthreads;
};

struct packet { uint8_t buf[MAX_PKT_SIZE]; size_t len; };

static uint16_t checksum(uint16_t *buf, size_t len){
    uint32_t sum=0;
    while(len>1){sum+=*buf++; len-=2;}
    if(len) sum += *(uint8_t*)buf;
    sum=(sum>>16)+(sum&0xffff);
    sum+=(sum>>16);
    return ~sum;
}

static uint32_t autodetect_src(uint32_t dst){
    int s=socket(AF_INET,SOCK_DGRAM,0);
    struct sockaddr_in tmp={.sin_family=AF_INET,.sin_port=htons(9),.sin_addr.s_addr=dst};
    connect(s,(void*)&tmp,sizeof(tmp));
    struct sockaddr_in name;
    socklen_t len=sizeof(name);
    getsockname(s,(void*)&name,&len);
    close(s);
    return name.sin_addr.s_addr;
}

static void build_udp(struct packet *p, struct opts *o, const char *target){
    struct iphdr *ip=(void*)p->buf;
    struct udphdr *udp=(void*)(p->buf+sizeof(*ip));
    uint8_t *payload=p->buf+sizeof(*ip)+sizeof(*udp);
    size_t plen=strlen(o->payload);
    memcpy(payload,o->payload,plen);

    udp->source=htons(o->src_port);
    udp->dest=htons(o->port);
    udp->len=htons(sizeof(*udp)+plen);

    ip->ihl=5; ip->version=4; ip->ttl=64; ip->protocol=IPPROTO_UDP;
    inet_pton(AF_INET,target,&ip->daddr);
    ip->saddr=autodetect_src(ip->daddr);
    ip->tot_len=htons(sizeof(*ip)+sizeof(*udp)+plen);
    ip->check=checksum((uint16_t*)ip,sizeof(*ip));
    p->len=sizeof(*ip)+sizeof(*udp)+plen;
}

static void load_xdp(const char *iface){
    struct bpf_object *obj=bpf_object__open_file("xdp_tx_kern.o",NULL);
    if(!obj){ perror("bpf_object__open_file"); exit(1);}
    if(bpf_object__load(obj)){ perror("bpf_object__load"); exit(1);}
    struct bpf_program *prog=bpf_object__find_program_by_name(obj,"xdp_tx_prog");
    int ifidx=if_nametoindex(iface);
    if(bpf_set_link_xdp_fd(ifidx,bpf_program__fd(prog),0)<0){
        perror("bpf_set_link_xdp_fd");
        exit(1);
    }
}

struct thread_arg { struct packet pkt; struct opts *o; int cpu; const char *iface; const char *target; bool af_xdp; };

static void *tx_thread(void *arg){
    struct thread_arg *a=(struct thread_arg*)arg;
    if(a->af_xdp){
        size_t umem_size = a->o->xsk_frames * a->o->xsk_frame_size;
        void *umem;
        if(posix_memalign(&umem,getpagesize(),umem_size)!=0){ perror("posix_memalign"); exit(1); }

        struct xsk_ring_prod fill;
        struct xsk_ring_cons comp;
        struct xsk_umem *u;
        struct xsk_socket *xsk;
        struct xsk_umem_config uc = {.fill_size = a->o->xsk_frames,
                                      .comp_size = a->o->xsk_frames,
                                      .frame_size = a->o->xsk_frame_size,
                                      .frame_headroom = 0};

        if(xsk_umem__create(&u, umem, umem_size, &fill, &comp, &uc)){
            perror("xsk_umem__create"); exit(1);
        }

        struct xsk_socket_config sc = {.rx_size = 0, .tx_size = a->o->xsk_frames, .bind_flags = XDP_USE_NEED_WAKEUP};
        if(xsk_socket__create(&xsk, a->iface, a->cpu, u, NULL, &fill, &sc)){
            perror("xsk_socket__create"); exit(1);
        }

        cpu_set_t set; CPU_ZERO(&set); CPU_SET(a->cpu,&set); sched_setaffinity(0,sizeof(set),&set);

        for(int i=0;i<a->o->xsk_frames;i++){
            memcpy((uint8_t*)umem + i*a->o->xsk_frame_size, a->pkt.buf, a->pkt.len);
            xsk_ring_prod__tx_desc(&fill, i)->addr = i*a->o->xsk_frame_size;
            xsk_ring_prod__tx_desc(&fill, i)->len = a->pkt.len;
        }
        xsk_ring_prod__submit(&fill, a->o->xsk_frames);

        uint64_t sent=0;
        time_t start = time(NULL);
        while(time(NULL)-start < a->o->duration){
            uint32_t idxs[BATCH_SIZE];
            int n = xsk_ring_prod__reserve(&fill, BATCH_SIZE, idxs);
            for(int i=0;i<n;i++){
                idxs[i] = i % a->o->xsk_frames;
                xsk_ring_prod__tx_desc(&fill, idxs[i])->addr = idxs[i]*a->o->xsk_frame_size;
                xsk_ring_prod__tx_desc(&fill, idxs[i])->len = a->pkt.len;
            }
            xsk_ring_prod__submit(&fill,n);
            sendto(xsk_socket__fd(xsk),NULL,0,MSG_DONTWAIT,NULL,0);
            sent += n;
        }
        printf("CPU %d, IFACE %s, TARGET %s sent %lu packets (AF_XDP)\n", a->cpu,a->iface,a->target,sent);
    } else {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if(s<0){ perror("socket"); return NULL; }
        struct sockaddr_in addr;
        memset(&addr,0,sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(a->o->port);
        inet_pton(AF_INET, a->target, &addr.sin_addr);

        cpu_set_t set; CPU_ZERO(&set); CPU_SET(a->cpu,&set); sched_setaffinity(0,sizeof(set),&set);

        uint64_t sent=0;
        time_t start=time(NULL);
        while(time(NULL)-start < a->o->duration){
            if(sendto(s, a->pkt.buf, a->pkt.len, 0, (struct sockaddr*)&addr, sizeof(addr))>=0) sent++;
        }
        close(s);
        printf("CPU %d, TARGET %s sent %lu packets (UDP socket)\n",a->cpu,a->target,sent);
    }
    return NULL;
}

static void parse_cli(int argc,char **argv,struct opts *o){
    memset(o,0,sizeof(*o));
    o->rate=1000000;
    o->xsk_frames=8192;
    o->xsk_frame_size=2048;
    o->src_port=12345;
    o->payload="HPINGX-ACADEMIC";
    o->nthreads=0;

    int c;
    while((c=getopt(argc,argv,"p:r:d:i:t:Xf:F:s:m:n:"))!=-1){
        switch(c){
            case 'p': o->port=atoi(optarg); break;
            case 'r': o->rate=atoi(optarg); break;
            case 'd': o->duration=atoi(optarg); break;
            case 'i':
                o->n_ifaces++;
                o->ifaces = realloc(o->ifaces, o->n_ifaces * sizeof(char*));
                o->ifaces[o->n_ifaces-1] = strdup(optarg);
                break;
            case 't':
                o->n_targets++;
                o->targets = realloc(o->targets, o->n_targets * sizeof(char*));
                o->targets[o->n_targets-1] = strdup(optarg);
                break;
            case 'X': o->af_xdp=true; break;
            case 'f': o->xsk_frames=atoi(optarg); break;
            case 'F': o->xsk_frame_size=atoi(optarg); break;
            case 's': o->src_port=atoi(optarg); break;
            case 'm': o->payload=strdup(optarg); break;
            case 'n': o->nthreads=atoi(optarg); break;
            default: exit(1);
        }
    }

    if(!o->port || !o->duration || o->n_ifaces==0 || o->n_targets==0){
        fprintf(stderr,"Usage: %s -p port -d duration -i iface -t target [options]\n", argv[0]);
        exit(1);
    }

    if(o->rate>MAX_RATE_PPS) o->rate=MAX_RATE_PPS;
    if(o->nthreads==0) o->nthreads = sysconf(_SC_NPROCESSORS_ONLN);
}

int main(int argc,char **argv){
    struct opts o;
    parse_cli(argc,argv,&o);

    int total_threads = o.nthreads * o.n_ifaces * o.n_targets;
    pthread_t *threads = malloc(sizeof(pthread_t)*total_threads);
    struct thread_arg *args = malloc(sizeof(struct thread_arg)*total_threads);

    int idx=0;
    for(int c=0;c<o.nthreads;c++){
        for(int i=0;i<o.n_ifaces;i++){
            if(o.af_xdp) load_xdp(o.ifaces[i]);
            for(int t=0;t<o.n_targets;t++){
                struct packet pkt;
                build_udp(&pkt,&o,o.targets[t]);
                args[idx].pkt = pkt;
                args[idx].o = &o;
                args[idx].cpu = c%o.nthreads;
                args[idx].iface = o.ifaces[i];
                args[idx].target = o.targets[t];
                args[idx].af_xdp = o.af_xdp;
                pthread_create(&threads[idx],NULL,tx_thread,&args[idx]);
                idx++;
            }
        }
    }

    for(int i=0;i<total_threads;i++) pthread_join(threads[i],NULL);

    free(threads);
    free(args);
    return 0;
}
