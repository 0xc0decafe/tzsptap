/*
 *      tzsptap.c
 *
 *      Copyright 2023 Daniel Mende <mail@danielmen.de>
 */

/*
 *      Redistribution and use in source and binary forms, with or without
 *      modification, are permitted provided that the following conditions are
 *      met:
 *      
 *      * Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *      * Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following disclaimer
 *        in the documentation and/or other materials provided with the
 *        distribution.
 *      * Neither the name of the  nor the names of its
 *        contributors may be used to endorse or promote products derived from
 *        this software without specific prior written permission.
 *      
 *      THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *      "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *      LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *      A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *      OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *      SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *      LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *      DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *      THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *      (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *      OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#if defined(__linux__)
    #include <linux/if.h>
    #include <linux/if_tun.h>
#elif defined(__FreeBSD__)
    #include <libgen.h>
    #include <net/if.h>
#else
    #error ### neither __linux__ nor __FreeBSD__ defined ###
#endif

#define TUN_DEV_NAME_LENGTH 32
#define MAX_TUN_NR 100
#define RECV_BUFFER_LENGTH 10000
#define TZSP_MAX_FIELDS 32

#define TZSP_FLAG_NOFIELDS  0x01
#define TZSP_FLAG_NODATA    0x02

#define TZSP_HDR_PAD        0x00
#define TZSP_HDR_END        0x01

struct tzsphdr {
    unsigned short version:8;
    unsigned short flags:4;
    unsigned short type:4;
    unsigned short enc:16;
};

struct tzspfield {
    uint8_t tag;
    uint8_t len;
    char *data;
};

struct tzsppkg {
    //hdr
    struct tzsphdr *hdr;
    //tagged fields
    struct tzspfield *fields[TZSP_MAX_FIELDS];
    unsigned short num_fields;
    //data
    char *data;
    size_t datalen;
};

int tun_fd, sock_fd;
char tun_device[TUN_DEV_NAME_LENGTH];

void shut() {
    close(tun_fd);
    close(sock_fd);

#if defined(__FreeBSD__)
    int fd, err;
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, tun_device, IFNAMSIZ);
    if ((fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        return;
    }
    err = ioctl(fd, SIOCIFDESTROY, (void *) &ifr);
    if( err < 0 ) {
         close(fd);
         fprintf(stderr, "Can't destroy tunnel device: %s\n", strerror(errno));
         return;
    }
    close(fd);
#endif
}

void sigint(int sig) {
    shut();
    exit(1);
}

int parse_tzsppkg(char *data, size_t datalen, struct tzsppkg *pkg) {
    if (!data) return -1;
    if (datalen < 4) return -1;
    if (!pkg) return -1;

    pkg->num_fields = 0;
    pkg->hdr = (struct tzsphdr *) data; data += 4; datalen -= 4;

    if (!(pkg->hdr->flags & TZSP_FLAG_NOFIELDS)) {
        for (int n = 0; n < TZSP_MAX_FIELDS; n++) {
            pkg->num_fields += 1;
            if (datalen < 1) return -1;
            pkg->fields[n] = (struct tzspfield *) data;
            if (pkg->fields[n]->tag > 2) { //not PAD nor END; carries len and data
                data += (1 + 1 + pkg->fields[n]->len);
                datalen -= (1 + 1 + pkg->fields[n]->len);
            } else {
                data += 1; datalen -= 1;
                if (pkg->fields[n]->tag == TZSP_HDR_END)
                    break;
            }
        }
    }

    if (datalen > 0) {
        pkg->data = data;
        pkg->datalen = datalen;
    } else {
        pkg->data = NULL;
        pkg->datalen = 0;
    }

    return 0;
}

int tun_alloc(char *tun_device) {
    int fd = -1;

#if defined(__linux__)
    char *dev;
    int err;
    struct ifreq ifr;

    if( (fd = open("/dev/net/tun", O_RDWR)) < 0 )
        return -1;

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    dev = "tap%d";
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    err = ioctl(fd, TUNSETIFF, (void *) &ifr);
    if( err < 0 ) {
         close(fd);
         return err;
    }
    strncpy(tun_device, ifr.ifr_name, TUN_DEV_NAME_LENGTH);

#elif defined(__FreeBSD__)
    char tunname[128];
    for(int i = 0; i < MAX_TUN_NR; i++ ) {        
        sprintf(tunname, "/dev/tap%d", i);
        if( (fd = open(tunname, O_RDWR)) != -1 ) {
            break;
        }
    }
    if(fd < 0)
        return -1;
    strncpy(tun_device, basename(tunname), TUN_DEV_NAME_LENGTH);

#else
    #error ### neither __linux__ nor __FreeBSD__ defined ###
#endif

    return fd;
}

int get_ifflags(char *devname, short *flags) {
    int fd, err;
    struct ifreq ifr;

    if (!devname) {
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, devname, IFNAMSIZ);
    if ((fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        return -1;
    }
    err = ioctl(fd, SIOCGIFFLAGS, (void *) &ifr);
    if( err < 0 ) {
         close(fd);
         return err;
    }
    close(fd);
    *flags = ifr.ifr_flags;

    return 0;
}

int set_ifflags(char *devname, short flags) {
    int fd, err;
    struct ifreq ifr;

    if (!devname) {
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = flags;
    strncpy(ifr.ifr_name, devname, IFNAMSIZ);
    if ((fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        return -1;
    }
    err = ioctl(fd, SIOCSIFFLAGS, (void *) &ifr);
    if( err < 0 ) {
         close(fd);
         return err;
    }
    close(fd);

    return 0;
}

void usage(char *progname) {
    fprintf(stderr, "Usage: %s [-v] -l address [-p port]\n\n", progname);
    fprintf(stderr, "-v\t\t: Be verbose\n");
    fprintf(stderr, "-l address\t: the IP address to listen on\n");
    fprintf(stderr, "-p port\t\t: the port to listen on [default: 37008]\n");
    fprintf(stderr, "-h\t\t: Print this help\n");
}

int main(int argc, char *argv[]) {
    int opt, verbose = 0, on = 1, run = 1;
    short ifflags;
    char *listen_addr = NULL, *listen_port = "37008";

    struct addrinfo *ai = NULL;

    while ((opt = getopt(argc, argv, "vl:p:h")) != -1) {
        switch (opt) {
        case 'v':
            verbose = 1;
            break;
        case 'l':
            listen_addr = optarg;
            break;
        case 'p':
            listen_port = optarg;
            break;
        case 'h':
        default:
            usage(argv[0]);
            return -1;
        }
    }

    if (!listen_addr) {
        fprintf(stderr, "No listen address given.\n");
        usage(argv[0]);
        return -1;
    }

    if ((getaddrinfo(listen_addr, listen_port, NULL, &ai)) < 0) {
        fprintf(stderr, "Invalid listen address given: %s\n", strerror(errno));
        return -1;
    }

    signal(SIGINT, sigint);
    
    sock_fd = socket(ai->ai_family, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        fprintf(stderr, "Can't create socket: %s\n", strerror(errno));
        return -1;
    }
    if ((setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on))) < 0) {
        fprintf(stderr, "Can't set sockopt: %s\n", strerror(errno));
        return -1;
    }
    if ((bind(sock_fd, ai->ai_addr, ai->ai_addrlen)) < 0) {
        fprintf(stderr, "Can't bind to socket: %s\n", strerror(errno));
        return -1;
    }
    freeaddrinfo(ai);
    if (verbose)
        printf("Listening on %s:%s\n", listen_addr, listen_port);

    tun_fd = tun_alloc(tun_device);
    if (tun_fd < 0) {
        fprintf(stderr, "Can't create tunnel device: %s\n", strerror(errno));
        return -1;
    }
    if (verbose)
        printf("Tunnel interface %s created\n", tun_device);
    if (get_ifflags(tun_device, &ifflags) < 0) {
        fprintf(stderr, "Can't get tunnel device flags: %s\n", strerror(errno));
        return -1;
    }
    ifflags |= IFF_UP;
    if (set_ifflags(tun_device, ifflags) < 0) {
        fprintf(stderr, "Can't set tunnel device up: %s\n", strerror(errno));
        return -1;
    }

    while(run) {
        size_t len;
        char recvbuf[RECV_BUFFER_LENGTH], hostbuf[NI_MAXHOST], servbuf[NI_MAXSERV];
        struct sockaddr sa_from;
        socklen_t from_len;
        struct tzsppkg pkg;

        len = recvfrom(sock_fd, recvbuf, sizeof(recvbuf), 0, &sa_from, &from_len);
        if (verbose) {
            if (getnameinfo(&sa_from, from_len, hostbuf, sizeof(hostbuf), servbuf, sizeof(servbuf), NI_NUMERICHOST|NI_NUMERICSERV)) {
                fprintf(stderr, "Can't resolve sockaddr: %s\n", strerror(errno));\
                printf("Received %zu bytes\n", len);
            } else {
                printf("Received %zu bytes from %s:%s\n", len, hostbuf, servbuf);
            }
        }

        if (parse_tzsppkg(recvbuf, len, &pkg) < 0) {
            fprintf(stderr, "Couldn't parse TZSP package\n");
            continue;
        }
        if (pkg.datalen > 0) {
            write(tun_fd, pkg.data, pkg.datalen);
        }
    }

    //should never get here, but who knows xD
    shut();

    return 0;
}
