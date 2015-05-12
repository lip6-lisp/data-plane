/*-/usr/src/sbin/mapd/mapd.c
 *
 * Copyright (c) 2010 - 2011 The OpenLISP Project
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Contributors:
 *              Luigi Iannone <ggx@openlisp.org>
 *              Lorand Jakab  <ljakab@ac.upc.edu>
 *
 * $Id: mapd.c 183 2011-09-22 16:29:20Z ggx $
 *
 */


/*
 * Copyright (c) 2010, Lorand Jakab <ljakab@ac.upc.edu>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     o Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     o Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     o Neither the name of the University nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sysexits.h>
#include <err.h>
#include <errno.h>
#include <syslog.h>
#include <fcntl.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netdb.h>
#include <poll.h>
#include <time.h>
#include <libutil.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <net/lisp/lisp.h>
#include <net/lisp/maptables.h>

#include <libconfig.h>

#define MAPD
#include "lig.h"

/*
 * DEFINES
 */

#define MAX_LOOKUPS             100     /* Maximum allowed concurrent lookups */

/* Same as in map.c */
union sockunion {
    struct  sockaddr sa;
    struct  sockaddr_in sin;
    struct  sockaddr_in6 sin6;
    struct  sockaddr_storage ss;
};

struct static_rloc {
    struct sockaddr_storage rloc_addr;
    struct rloc_mtx metrics;
};

struct srloc {
    struct static_rloc rloc;
    struct srloc * next;
};

/* Static Empty RLOC chain */
struct rloc_chain_struct {
    int rloc_count;
    struct srloc * head;
    struct srloc * tail;
};

/*
 * Global variables required by source files from lig
 */

unsigned int debug                 = 0;     /* debuglevel */
unsigned int disallow_eid          = 0;     /* don't allow an EID as the source
                                               in the inner IP header */
unsigned int udp_checksum_disabled = 0;
unsigned short emr_inner_src_port;

#define MAXNAMELENGTH 256


/*
 * Global variables defined in map.c and used here
 */

extern int pid;
extern uid_t uid;

extern int debugonlyflag;
extern int nameflag;
extern int quietflag;
extern int verboseflag;

int rflag = 0; /* Config File */
int config_fd = 0; 

extern int map_addrs;
extern int s;               /* mapping socket */
extern int afeid, afleneid, afrloc, aflenrloc;
extern union sockunion so_eid, so_rloc;

/* RLOC flags and parameters */
extern uint8_t rlocpriority;
extern uint8_t rlocweight;
extern uint16_t rlocflags;
extern uint32_t rlocmtu;
extern uint32_t rlocnonce;

extern struct rloc_chain_struct rloc_chain;


/*
 * GLOBAL VARIABLES
 */

/*
 * Configuration Handler
 */

config_t mapd_cfg, *pcfg;
char     mapd_cfg_file[MAXNAMELENGTH];

const char *name;   /* Canonical program name (argv[0] w/o leading directories) */
int fgflag;         /* Option for running in foreground mode */

struct sockaddr_storage my_addr;
struct sockaddr_storage map_resolver;

//char map_resolver_str[MAXNAMELENGTH] = "";
const char map_resolver_str[MAXNAMELENGTH];
const char *temp_map_resolver_str = NULL;

int udpproto;
int tx;             /* lig sending socket */
int count   = COUNT;
int timeout = MAP_REPLY_TIMEOUT;

struct pollfd fds[MAX_LOOKUPS + 1];
int fds_idx[MAX_LOOKUPS +1];
nfds_t nfds = 0;

/* Structure to keep info about an ongoing EID lookup */
struct eid_lookup {
    struct sockaddr_storage eid;/* Destination EID */
    int rx;                     /* Receiving socket */
    uint32_t nonce0[MAX_COUNT]; /* First half of the nonce */
    uint32_t nonce1[MAX_COUNT]; /* Second half of the nonce */
    uint16_t sport;             /* EMR inner header source port */
    struct timespec start;      /* Start time of lookup */
    int count;                  /* Current count of retries */
    uint64_t active;            /* Unique lookup identifier, 0 if inactive */
} lookups[MAX_LOOKUPS];

uint64_t nlookups = 0;      /* Total number of lookups, used as lookup ID */
uint64_t nmisses  = 0;      /* Total number of MAPM_MISS_EID messages received */


/*
 * PID structures.
 */
struct pidfh *pidfile;
pid_t    runningpid;


/*
 * FUNCTION PROTOTYPES
 */

void usage_exit(const char *) __dead2;
static void logmsg(int, const char *, ...) __printflike(2, 3);
static void init_lig(const char *);
static void event_loop(void);
static void map_message_handler(void);
void new_lookup(struct sockaddr *);
int send_mr(int);
int read_mr(int);
void add_mapping(struct map_reply_pkt *);

void get_nonce(uint32_t *);
void get_sport(uint16_t *);
int timespec_subtract(struct timespec *, struct timespec *, struct timespec *);


static void sig_handler(int signum);


/* From map.c */
extern void print_mapmsg(struct map_msghdr *, int);
extern const char *mapaddr(struct sockaddr *);
extern void append_rloc(void);
extern int send_mapmsg(int, int);
extern void flush_rloc_chain(void);
extern int prefixlen(int);

/* From lig */
extern int get_my_ip_addr(int, struct sockaddr *);
extern int send_map_request(int, unsigned int, unsigned int, struct timeval *,
        struct sockaddr *, struct sockaddr *, struct sockaddr *);


int
main(argc, argv)
    int argc;
    char **argv;
{
    int opt,i;

    signal(SIGINT, sig_handler);

    bzero(map_resolver_str, MAXNAMELENGTH);

    if ((name = strrchr(argv[0], '/')) != NULL)
        ++name;
    else
        name = argv[0];
    if (*name == '-')
        ++name;

    while ((opt = getopt(argc, argv, "dfhnqvc:r:t:")) != -1) {
        switch(opt) {
        case 'd':
            debugonlyflag = 1;
            break;

        case 'f':
            fgflag = 1;
            break;

        case 'h':
            usage_exit((char *)NULL);

        case 'n':
            nameflag = 1;
            break;

        case 'q':
            quietflag = 1;
            break;

        case 'v':
            verboseflag = 1;
            break;

	case 'c':
	    count = atoi(optarg);
	    if ((count < MIN_COUNT) || (count > MAX_COUNT)) {
	      (void) fprintf(stderr, "value of <count> out of range: ");
	      (void) fprintf(stderr, "%d <= count <= %d\n",
			     MIN_COUNT, MAX_COUNT);
	      usage_exit((char *)NULL);
	    }
	    break;

	case 'r':
	    rflag = 1;
	    strcpy(mapd_cfg_file,  optarg);

	    (void)fprintf(stdout, "Configuration file: %s\n",mapd_cfg_file);

	    break;

	case 't':
	    timeout = atoi(optarg);
	    if ((timeout < MIN_MR_TIMEOUT) || (timeout > MAX_MR_TIMEOUT)) {
	      (void) fprintf(stderr, "value of <timeout> out of range: ");
	      (void) fprintf(stderr, "%d <= timeout <= %d\n",
			     MIN_MR_TIMEOUT, MAX_MR_TIMEOUT);
	      usage_exit((char *)NULL);
	    }
	    break;

        default:
            usage_exit((char *)NULL);
        }
    };

    debug = debugonlyflag;

    if (verboseflag && !fgflag) {
        (void) fprintf(stderr, "Verbose operation is only available in foreground mode!\n");
        exit(EX_USAGE);
    }


    argc -= optind;
    argv += optind;
    pid = getpid();
    uid = geteuid();

    if (*argv)
        usage_exit((char *)NULL);

    /* 
     * Read Config
     */
    
    if (rflag) {

      pcfg = &mapd_cfg;
      config_init(pcfg);
 
      if (!config_read_file(pcfg, mapd_cfg_file)) {
	fprintf(stderr, "%s:%d - %s\n",
		mapd_cfg_file,
		/*		config_error_file(pcfg),*/
		config_error_line(pcfg),
		config_error_text(pcfg));
	config_destroy(pcfg);
	return(EXIT_FAILURE);
      };
      
      if (config_lookup_string(pcfg, "resolver", &temp_map_resolver_str)) {

	(void)strcpy(map_resolver_str, temp_map_resolver_str);
	printf("Resolver: %s\n", map_resolver_str);
 
      } else {
	printf("Resolver not defined\n");
	return(EXIT_FAILURE);
      };
      
      config_destroy(pcfg);

    };


    /*
     * Start Daemon
     */

    openlog(name, LOG_CONS, LOG_DAEMON);

    pidfile = pidfile_open("/var/run/mapd.pid", 0600, &runningpid);
    if (pidfile == NULL) {
      if (errno == EEXIST) {
	errx(EXIT_FAILURE, "Daemon already running, pid: %jd.",
	     (int)runningpid);
      }
      /* If we cannot create pidfile from other reasons, only warn. 
       */
      warn("Cannot open or create pidfile");
 
   };


    if (!fgflag) {
        if (daemon(0,0)) {
            logmsg(LOG_ERR, "cannot fork");
	    pidfile_remove(pidfile);
            exit(EX_OSERR);
        }
    }

    pidfile_write(pidfile);

    if ((s = socket(PF_MAP, SOCK_RAW, 0)) < 0) {
        logmsg(LOG_ERR, "mapping socket: %m");
        exit(EX_UNAVAILABLE);
    }

    /* The mapping socket is the first descriptor in the array 
     *  passed to poll() 
     */
    fds[0].fd = s;
    fds[0].events = POLLIN;
    fds_idx[0] = -1;
    nfds = 1;

    /* Initialize lookups[]: all inactive */
    for (i = 0; i < MAX_LOOKUPS; i++)
        lookups[i].active = 0;

    /* Initialize lig related variables */
    init_lig(NULL);

    /* Initialize random number generator */
    srandom(time(NULL));

    logmsg(LOG_NOTICE, "Mapping daemon for OpenLISP started");

    event_loop();

    exit(0);
} /* main() */


void 
sig_handler(signum)
     int signum;
{
  
  logmsg(LOG_NOTICE, "Mapping daemon for OpenLISP exiting");

  signal(SIGINT, sig_handler);

  pidfile_remove(pidfile);
  
  exit(0);

} /* sig_handler() */


void
usage_exit(cp)
    const char *cp;
{
    if (cp)
        warnx("%s", cp);
    (void) fprintf(stderr, "usage: mapd [-dfhnqv] [-c count] [-t timeout] [-r config_file]\n");
    exit(EX_USAGE);
} /* usage_exit() */

static void
init_lig(src_ip_addr)
    const char *src_ip_addr;
{
    char buf[NI_MAXHOST];     /* buffer for getnameinfo() results */
    int err;                  /* generic errno holder */

    struct addrinfo hints;
    struct addrinfo *res;
    struct protoent *proto;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family    = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
    hints.ai_socktype  = SOCK_DGRAM;    /* Datagram socket */
    hints.ai_flags     = AI_ADDRCONFIG; /* Only return families configured 
					 * on host 
					 */
    hints.ai_protocol  = 0;   /* Any protocol */
    hints.ai_canonname = NULL;
    hints.ai_addr      = NULL;
    hints.ai_next      = NULL;
    
    if ((err = getaddrinfo(map_resolver_str, LISP_CONTROL_PORT_STR, &hints, &res)) != 0) {

      logmsg(LOG_ERR, "Resolver: [getaddrinfo] %s (errno = %d)", gai_strerror(err), err);
        exit(EX_NOHOST);
    }

    memcpy(&map_resolver, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    if (src_ip_addr) {
        if ((err = getaddrinfo(src_ip_addr, NULL, &hints, &res)) != 0) {
            logmsg(LOG_ERR, "getaddrinfo: %s", gai_strerror(err));
            exit(EX_NOHOST);
        }
        memcpy(&my_addr, res->ai_addr, res->ai_addrlen);
        freeaddrinfo(res);
    } else if (get_my_ip_addr(map_resolver.ss_family, (struct sockaddr *)&my_addr)) {
            logmsg(LOG_ERR, "no usable %s source address",
                    (map_resolver.ss_family == AF_INET) ? "IPv4" : "IPv6");
            exit(EX_NOHOST);
    }

    if (debugonlyflag || verboseflag) {
        if ((err = getnameinfo((struct sockaddr *)&my_addr, my_addr.ss_len,
                        buf, NI_MAXHOST, NULL, 0, NI_NUMERICHOST)) != 0) {
            logmsg(LOG_ERR,"getnameinfo: %s",gai_strerror(err));
            exit(EX_NOHOST);
        }
        logmsg(LOG_INFO, "using source address (ITR-RLOC) %s", buf);
    }

    if ((proto = getprotobyname("UDP")) == NULL) {
        logmsg(LOG_ERR, "getprotobyname: %m");
        exit(EX_NOHOST);
    }
    udpproto = proto->p_proto;

    if ((tx = socket(map_resolver.ss_family, SOCK_DGRAM, udpproto)) < 0) {
        logmsg(LOG_ERR, "creating sending socket: %m");
        exit(EX_UNAVAILABLE);
    }

} /* init_lig() */


/* This function is used to check if there is an ongoing lookup for an EID */
int
check_eid(eid)
    struct sockaddr *eid;
{
    int i;
    for (i = 0; i < MAX_LOOKUPS; i++)
        if (lookups[i].active)
            if (!memcmp(eid, &lookups[i].eid, lookups[i].eid.ss_len))
                return 0;
    return 1;
} /* check_eid() */

static void
event_loop(void)
{
    for (;;) {
        int e, i, j, l = -1;
        int poll_timeout = INFTIM; /* poll() timeout in milliseconds. We initialize
                                   to INFTIM = -1 (infinity). If there are no
                                   active lookups, we wait in poll() until a
                                   mapping socket event is received. */
        struct timespec now, deadline, delta, to, tmp;

        to.tv_sec  = timeout;
        to.tv_nsec = 0;

        nfds = 1;

        clock_gettime(CLOCK_REALTIME, &now);

        for (i = 0; i < MAX_LOOKUPS; i++) {
            if (!(lookups[i].active)) continue;

            deadline.tv_sec = lookups[i].start.tv_sec + 
	                      (lookups[i].count +1) * timeout; 
            deadline.tv_nsec = lookups[i].start.tv_nsec;

            timespec_subtract(&delta, &deadline, &now);

            fds[nfds].fd     = lookups[i].rx;
            fds[nfds].events = POLLIN;
            fds_idx[nfds]    = i;
            nfds++;

            /* Find the minimum delta */
            if (timespec_subtract(&tmp, &delta, &to)) {
                to.tv_sec    = delta.tv_sec;
                to.tv_nsec   = delta.tv_nsec;
                poll_timeout = to.tv_sec * 1000 + to.tv_nsec / 1000000;
                if (to.tv_sec < 0) poll_timeout = 0;
                l = i;
            }
        } /* Finished iterating through all lookups */

        if (verboseflag)
            printf("\npoll(fds, %d, %d);\n\n", nfds, poll_timeout);
        e = poll(fds, nfds, poll_timeout);
        if (e < 0) continue;
        if (e == 0)                             /* If timeout expires */
            if (l >= 0)                         /* and slot is defined */
	         send_mr(l);                    /* retry Map-Request */

        for (j = nfds - 1; j >= 0; j--) {
            if (fds[j].revents == POLLIN) {
                /*printf("event on fds[%d]\n", j);*/
                if (j == 0)
                    map_message_handler();
                else
                    read_mr(fds_idx[j]);
            }
        }
    }
} /* event_loop() */

static void
map_message_handler(void)
{
    struct timespec now;
    char msg[8192];         /* buffer for mapping messages */
    int n = 0;              /* number of bytes received on mapping socket */
    struct sockaddr *eid;

    n = read(s, msg, 8192);
    clock_gettime(CLOCK_REALTIME, &now);
    if (verboseflag)
        logmsg(LOG_DEBUG, "mapping socket: got message of size %d on %s", n, ctime(&(now.tv_sec)));

    if (verboseflag)
        print_mapmsg((struct map_msghdr *)msg, n);

    if (((struct map_msghdr *)msg)->map_type != MAPM_MISS_EID)
        return;

    ++nmisses;

    eid = (struct sockaddr *)(msg + sizeof(struct map_msghdr));

    if (debugonlyflag || verboseflag)
        logmsg(LOG_DEBUG, "mapping socket: MAPM_MISS_EID for %s", mapaddr(eid));

    if (check_eid(eid)) {
        new_lookup(eid);
    }
} /* map_message_handler() */

void
new_lookup(eid)
    struct sockaddr *eid;
{
    int i,e,r;
    uint16_t sport;             /* inner EMR header source port */
    char sport_str[NI_MAXSERV]; /* source port in string format */
    struct addrinfo hints;
    struct addrinfo *res;

    /* Find an inactive slot in the lookup table */
    for (i = 0; i < MAX_LOOKUPS; i++)
        if (!lookups[i].active)
            break;

    if (i >= MAX_LOOKUPS) {
        logmsg(LOG_WARNING, "lookup table full, ignoring lookup request for %s", mapaddr(eid));
        return;
    }

    if ((r = socket(map_resolver.ss_family, SOCK_DGRAM, udpproto)) < 0) {
        logmsg(LOG_ERR, "creating lookup receiving socket: %m");
        exit(EX_UNAVAILABLE);   /* XXX: we should probably try harder */
    }

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family    = map_resolver.ss_family;    /* Bind on AF based on AF of Map-Resolver */
    hints.ai_socktype  = SOCK_DGRAM;                /* Datagram socket */
    hints.ai_flags     = AI_PASSIVE;                /* For wildcard IP address */
    hints.ai_protocol  = udpproto;
    hints.ai_canonname = NULL;
    hints.ai_addr      = NULL;
    hints.ai_next      = NULL;

    do {
        get_sport(&sport);
        sprintf(sport_str, "%d", sport);

        if ((e = getaddrinfo(NULL, sport_str, &hints, &res)) != 0) {
            logmsg(LOG_ERR, "getting local socket: getaddrinfo: %s", gai_strerror(e));
            /* XXX: Decisions should depend on types of errors.
             * For now, we just generate a different source port and retry */
            e = -1;
            continue;
        }

        if ((e = bind(r, res->ai_addr, res->ai_addrlen)) == -1) {
            logmsg(LOG_ERR, "bind: %m");
            if (errno != EADDRINUSE)
                exit(EX_UNAVAILABLE);
        }

        freeaddrinfo(res);
    } while (e == -1);

    memcpy(&lookups[i].eid, eid, eid->sa_len);
    lookups[i].rx = r;
    lookups[i].sport = sport;
    clock_gettime(CLOCK_REALTIME, &lookups[i].start);
    lookups[i].count = -1;
    lookups[i].active = ++nlookups;
    send_mr(i);
} /* new_lookup() */

int
send_mr(idx)
    int idx;
{
    uint32_t nonce0, nonce1;
    struct timeval before;      /* Unused -- only present to avoid breaking the
                                   lig "API" when calling send_map_request() */
    time_t now;
    int cnt;
    struct sockaddr *eid = (struct sockaddr *)&lookups[idx].eid;

    if (lookups[idx].count == count - 1) {
        lookups[idx].active = 0;
        close(lookups[idx].rx);
        return 0;
    }

    get_nonce(&nonce0);
    get_nonce(&nonce1);
    emr_inner_src_port = lookups[idx].sport;

    if (send_map_request(tx, nonce0, nonce1, &before, eid,
                (struct sockaddr *)&map_resolver, (struct sockaddr *)&my_addr)) {
        logmsg(LOG_ERR, "send_map_request: can't send map-request");
        return 0;
    } else {
        cnt = ++lookups[idx].count;
        lookups[idx].nonce0[cnt] = nonce0;
        lookups[idx].nonce1[cnt] = nonce1;
        if (debugonlyflag || verboseflag) {
            now = time(NULL);
            /*printf("%s", ctime(&now));*/
            logmsg(LOG_DEBUG, "sent map-request %d, slot %d to %s for %s",
                    cnt + 1, idx, map_resolver_str, mapaddr(eid));
        }
    }
    return 1;
} /* send_mr() */

static int
nonce_found(idx, map_reply)
    int idx;
    struct map_reply_pkt *map_reply;
{
    int c = lookups[idx].count;
    if (lookups[idx].nonce0[c] != (ntohl(map_reply->lisp_nonce0))) return 0;
    if (lookups[idx].nonce1[c] != (ntohl(map_reply->lisp_nonce1))) return 0;
    return 1;
} /* check_nonce() */

int
read_mr(idx)
    int idx;
{
    unsigned char packet[MAX_IP_PACKET];
    struct map_reply_pkt *map_reply;
    struct sockaddr from;
    socklen_t fromlen;

    fromlen = map_resolver.ss_len;
    map_reply = (struct map_reply_pkt *)packet;

    if (recvfrom(lookups[idx].rx, packet, MAX_IP_PACKET, 0,
                &from, &fromlen) < 0) {
        logmsg(LOG_DEBUG, "recvfrom (slot %d, rx = %d): %m", idx, lookups[idx].rx);
        return 0;
    }

    if (((struct map_reply_pkt *)packet)->lisp_type != LISP_MAP_REPLY) return 0;

    if (!nonce_found(idx, map_reply)) return 0;

    if (debugonlyflag || verboseflag)
        logmsg(LOG_DEBUG, "received map-reply from %s, slot %d", mapaddr(&from), idx);

    add_mapping(map_reply);

    lookups[idx].active = 0;
    close(lookups[idx].rx);

    return 1;
} /* read_mr() */

static void
set_afi_and_addr_offset(loc_afi,afi,addr_offset,aflen)
    ushort loc_afi;
    int *afi;
    unsigned int *addr_offset;
    int *aflen;
{
    switch (loc_afi) {
    case LISP_AFI_IP:
        *afi = AF_INET;
        *addr_offset = sizeof(struct in_addr);
        *aflen = sizeof(struct sockaddr_in);
        break;
    case LISP_AFI_IPV6:
        *afi = AF_INET6;
        *addr_offset = sizeof(struct in6_addr);
        *aflen = sizeof(struct sockaddr_in6);
        break;
    default:
        logmsg(LOG_ERR, "Unknown AFI (0x%x)", loc_afi);
        break;
    }
}

void
add_mapping(map_reply)
    struct map_reply_pkt *map_reply;
{
    struct lisp_map_reply_eidtype *eidtype = NULL;
    struct lisp_map_reply_loctype *loctype = NULL;
    int record_count = 0, locator_count = 0;
    int record = 0, locator = 0;
    unsigned int offset = 0;
    union sockunion *su;

    record_count = map_reply->record_count;
    eidtype = (struct lisp_map_reply_eidtype *) &map_reply->data;

    for (record = 0; record < record_count; record++) {
        set_afi_and_addr_offset(ntohs(eidtype->eid_afi), &afeid, &offset, &afleneid);

        map_addrs |= MAPA_EID;

        su = &so_eid;
        su->sa.sa_len = afleneid;
        su->sa.sa_family = afeid;

        switch (afeid) {
        case AF_INET:
            memcpy(&su->sin.sin_addr, &eidtype->eid_prefix, offset);
            break;
        case AF_INET6:
            memcpy(&su->sin6.sin6_addr, &eidtype->eid_prefix, offset);
            break;
        }

        (void)prefixlen(eidtype->eid_mask_len);

        locator_count = eidtype->loc_count;

        if (locator_count) {            /* we have some locators */
            map_addrs |= MAPA_RLOC;
            loctype = (struct lisp_map_reply_loctype *)
                    CO(eidtype->eid_prefix, offset);

            for (locator = 0; locator < locator_count; locator++) {
                set_afi_and_addr_offset(ntohs(loctype->loc_afi),
                        &afrloc, &offset, &aflenrloc);
                su = &so_rloc;
                su->sa.sa_len = aflenrloc;
                su->sa.sa_family = afrloc;

                switch (afrloc) {
                case AF_INET:
                    memcpy(&su->sin.sin_addr, &loctype->locator, offset);
                    break;
                case AF_INET6:
                    memcpy(&su->sin6.sin6_addr, &loctype->locator, offset);
                    break;
                }

                rlocpriority = loctype->priority;
                rlocweight = loctype->weight;
                if (loctype->reach_bit)
                    rlocflags |= RLOCF_UP;

                append_rloc();

                loctype = (struct lisp_map_reply_loctype *)
                    CO(loctype, (sizeof(struct lisp_map_reply_loctype) + offset));
            }

            if ((send_mapmsg(MAPM_ADD, MAPF_UP | MAPF_DONE) == 0) && (debugonlyflag || verboseflag))
                logmsg(LOG_DEBUG, "added mapping for %s/%d to kernel",
                        mapaddr((struct sockaddr *)&so_eid),eidtype->eid_mask_len);
            flush_rloc_chain();
            rloc_chain.rloc_count = 0;
            eidtype = (struct lisp_map_reply_eidtype *) loctype;
        } else {
            /* Add negative cache entry -- to be implemented on the kernel side first */
        }
    }
} /* add_mapping() */


void
get_nonce(nonce)
    uint32_t *nonce;
{
    int fd;
    struct timespec now;

    if ((fd = open("/dev/random", O_RDONLY)) != -1) {
        unsigned char *buf = (unsigned char *)nonce;
        ssize_t n = 0;
        ssize_t m = 4;
        do {
            n = read(fd, buf, m);
            if (n == -1 && errno == EINTR) continue;
            else if (n <= 0) break;
            m -= n;
            buf += n;
        } while (m != 0);
        close(fd);
    } else
        *nonce = (uint32_t) random();

    clock_gettime(CLOCK_REALTIME, &now);
    *nonce ^= (uint32_t) pid;
    *nonce ^= (uint32_t) now.tv_sec;
    *nonce ^= (uint32_t) now.tv_nsec;
}

void
get_sport(sport)
    uint16_t *sport;
{
    uint32_t rand;
    get_nonce(&rand);
    *sport = IPPORT_HIFIRSTAUTO + rand % (IPPORT_HILASTAUTO - IPPORT_HIFIRSTAUTO);
}

/* res = x - y */
int
timespec_subtract(res, x, y)
     struct timespec *res, *x, *y;
{
    /* perform the carry for the later subtraction by updating y */
    if (x->tv_nsec < y->tv_nsec) {
        int sec = (y->tv_nsec - x->tv_nsec) / 1000000000 + 1;
        y->tv_nsec -= 1000000000 * sec;
        y->tv_sec += sec;
    }
    if (x->tv_nsec - y->tv_nsec > 1000000000) {
        int sec = (x->tv_nsec - y->tv_nsec) / 1000000000;
        y->tv_nsec += 1000000000 * sec;
        y->tv_sec -= sec;
    }

    res->tv_sec = x->tv_sec - y->tv_sec;
    res->tv_nsec = x->tv_nsec - y->tv_nsec;

    /* return 1 if result is negative */
    return x->tv_sec < y->tv_sec;
}

static int
expand_syslog_m(fmt, newfmt)
    const char *fmt;
    char **newfmt;
{
    const char *str, *msg;
    char *p, *np;

    p = strdup("");
    str = fmt;
    while ((msg = strstr(str, "%m")) != NULL) {
        asprintf(&np, "%s%.*s%s", p, (int)(msg - str),
            str, strerror(errno));
        free(p);
        if (np == NULL) {
            errno = ENOMEM;
            return -1;
        }
        p = np;
        str = msg + 2;
    }

    if (*str != '\0') {
        asprintf(&np, "%s%s", p, str);
        free(p);
        if (np == NULL) {
            errno = ENOMEM;
            return -1;
        }
        p = np;
    }

    *newfmt = p;
    return 0;
} /* expand_syslog_m() */

static void
logmsg(int pri, const char *fmt, ...)
{
    va_list v;
    FILE *fp;
    char *newfmt;

    va_start(v, fmt);
    if (fgflag) {
        if (pri == LOG_ERR)
            fp = stderr;
        else
            fp = stdout;
        if (expand_syslog_m(fmt, &newfmt) == -1) {
            vfprintf(fp, fmt, v);
        } else {
            vfprintf(fp, newfmt, v);
            free(newfmt);
        }
        fputs("\n", fp);
        fflush(fp);
    } else {
        vsyslog(pri, fmt, v);
    }
    va_end(v);
} /* logmsg() */

/* vim: set tabstop=8 softtabstop=4 shiftwidth=4 expandtab: */
