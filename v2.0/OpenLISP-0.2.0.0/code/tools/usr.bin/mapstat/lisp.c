/*- /usr/src/usr.bin/mapstat/lisp.c
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
 *  Contributors: 
 *               Luigi Iannone <ggx@openlisp.org>
 *
 * $Id: lisp.c 182 2011-09-22 16:11:37Z ggx $
 *
 */

/*
 * Copyright (c) 1983, 1988, 1993, 1995
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
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
 */

/*
 * Copyright (c) 1983, 1988, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
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
 */


#include <sys/param.h>
#include <sys/queue.h>
#include <sys/domain.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/protosw.h>

#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_carp.h>
#ifdef INET6
#include <netinet/ip6.h>
#endif /* INET6 */
#include <netinet/in_pcb.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp_var.h>
#include <netinet/igmp_var.h>
#include <netinet/ip_var.h>
#include <netinet/pim_var.h>
#include <netinet/tcp.h>
#include <netinet/tcpip.h>
#include <netinet/tcp_seq.h>
#define TCPSTATES
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_debug.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>

#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <libutil.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include "netstat.h"
#include "mapstat.h"


#include <net/lisp/lisp.h>
#include <net/lisp/maptables.h>




int	do_mapent = 0;
struct  mapentry mapentry;
struct	radix_node_head *map_tables[MAX_TABLES];

static void map_size_cols (int, struct radix_node *);
static void map_size_cols_tree (struct radix_node *);
static void map_size_cols_entry (struct mapentry *);
static const char *fmt_mapsockaddr (struct sockaddr *, struct sockaddr *, int);
const char * mapname(u_long , u_long );
const char * mapname6(struct sockaddr_in6 *, struct in6_addr *);
static void map_tree(struct radix_node *);
static void map_node (void);
static void maptreestuff (void);
static void nprint_mapentry (struct map_msghdr *);
static void print_mapsockaddr (struct sockaddr *, struct sockaddr *, int, int);
static void print_mapflags (int, const char *);
static const char *fmt_mapflags(int);
static void print_rlocflags (int, const char *);
static const char *fmt_rlocflags(int);
static void print_mapentry (struct mapentry *);

/*
 * Variable & Co. already declared elsewhere
 */
extern struct radix_node rnode;
extern struct radix_mask rmask;
extern int NewTree;

typedef union {
	long	dummy;		/* Helps align structure. */
	struct	sockaddr u_sa;
	struct	sockaddr_storage u_ss;
	u_short	u_data[128];
} ss_u;

char	mapbuf[20];

/*
 * Column sizes
 */

static int wid_eid;
static int wid_mflags;
static int wid_mvnum;
static int wid_mrefs;
static int wid_mrlocsnum;
static int wid_rlocs;
static int wid_rlocpriority;
static int wid_rlocweight;
static int wid_rlocflags;
static int wid_rlocmtu;
static int wid_rlochit;
static int wid_txnonce;
static int wid_rxnonce;

#define	WID_EID_DEFAULT(af) \
	((af) == AF_INET6 ? 20 : 18)
#define	WID_RLOC_DEFAULT(af) \
	((af) == AF_INET6 ? (numeric_addr ? 30 : 15) : 15)

/*
 * Definitions and procedures for kernel memory read.
 */
#define kget(p, d) (kread((u_long)(p), (char *)&(d), sizeof (d)))

static ss_u ptr_u;

static struct sockaddr *
kgetmapsa(struct sockaddr *dst)
{

	kget(dst, ptr_u.u_sa);
	if (ptr_u.u_sa.sa_len > sizeof (ptr_u.u_sa))
		kread((u_long)dst, (char *)ptr_u.u_data, ptr_u.u_sa.sa_len);
	return (&ptr_u.u_sa);

}  /* kgetmapsa() */

/*
 * Functions for string formatting
 */

/*
 * Definition and Format routine for RLOCs flag
 */

struct bits {
	u_long	b_mask;
	char	b_val;
} mbits[] = {
        { MAPF_DB,	        'D' },
	{ MAPF_VERSIONING,	'V' },
	{ MAPF_LOCBITS,	        'L' },
	{ MAPF_STATIC,	        'S' },
	{ MAPF_UP,	        'U' },
	{ MAPF_NEGATIVE,        'N' },
	{ 0 , 0 }
};

struct bits rlocbits[] = {
	{ RLOCF_UP,	'U' },
	{ RLOCF_LIF,	'i' },
	{ RLOCF_TXNONCE,'t' },
	{ RLOCF_RXNONCE,'r' },
	{ 0 , 0 }
};


static const char *
fmt_rlocflags(int f)
{
	static char name[33];
	char *flags;
	struct bits *p = rlocbits;

	for (flags = name; p->b_mask; p++)
		if (p->b_mask & f)
			*flags++ = p->b_val;
	*flags = '\0';
	return (name);

}  /* fmt_rlocflags() */

static void
print_rlocflags(int f, const char *format)
{
	printf(format, fmt_rlocflags(f));
}  /* print_rlocflags() */


static const char *
fmt_mapflags(int f)
{
	static char name[33];
	char *flags;
	struct bits *p = mbits;

	for (flags = name; p->b_mask; p++)
		if (p->b_mask & f)
			*flags++ = p->b_val;
	*flags = '\0';
	return (name);

}  /* fmt_mapflag() */

static void
print_mapflags(int f, const char *format)
{
	printf(format, fmt_mapflags(f));
}  /* print_mapflags() */


/*
 * Format socket address
 */
static const char *
fmt_mapsockaddr(struct sockaddr *sa, struct sockaddr *mask, int flags)
{
	static char workbuf[128];
	const char *cp;

	switch(sa->sa_family) {
	case AF_INET:
	    {
		struct sockaddr_in *sockin = (struct sockaddr_in *)sa;

		if ((sockin->sin_addr.s_addr == INADDR_ANY) &&
			mask &&
			ntohl(((struct sockaddr_in *)mask)->sin_addr.s_addr)
				==0L)
				cp = "default" ;
		else if (mask)
			cp = mapname(sockin->sin_addr.s_addr,
				     ntohl(((struct sockaddr_in *)mask)
					   ->sin_addr.s_addr));
		else
			cp = mapname(sockin->sin_addr.s_addr, 0L);
		break;
	    }

#ifdef INET6
	case AF_INET6:
	    {
	      
	        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)sa;
		struct in6_addr *in6 = &sa6->sin6_addr;

		/*
		 * XXX: This is a special workaround for KAME kernels.
		 * sin6_scope_id field of SA should be set in the future.
		 */
		if (IN6_IS_ADDR_LINKLOCAL(in6) ||
		    IN6_IS_ADDR_MC_LINKLOCAL(in6)) {
		       /* XXX: override is ok? */
		        sa6->sin6_scope_id = (u_int32_t)ntohs(*(u_short *)&in6->s6_addr[2]);
			*(u_short *)&in6->s6_addr[2] = 0;
		};
		
		if (mask) {
		        cp = mapname6(sa6,
				      &((struct sockaddr_in6 *)mask)->sin6_addr);
		} else {

		        cp = mapname6(sa6, NULL);
		};

		break;
	    
	    }
#endif /*INET6*/

	default:
	    {
		u_char *s = (u_char *)sa->sa_data, *slim;
		char *cq, *cqlim;

		cq = workbuf;
		slim =  sa->sa_len + (u_char *) sa;
		cqlim = cq + sizeof(workbuf) - 6;
		cq += sprintf(cq, "(%d)", sa->sa_family);
		while (s < slim && cq < cqlim) {
			cq += sprintf(cq, " %02x", *s++);
			if (s < slim)
			    cq += sprintf(cq, "%02x", *s++);
		}
		cp = workbuf;
	    }

	};

	return (cp);

}  /*fmt_mapsockaddr() */


static void
print_mapsockaddr(struct sockaddr *sa, struct sockaddr *mask, int flags, int width)
{
	const char *cp;

	cp = fmt_mapsockaddr(sa, mask, flags);

	if (width < 0 )
		printf("%s ", cp);
	else {
		if (numeric_addr)
			printf("%-*s ", width, cp);
		else
			printf("%-*.*s ", width, width, cp);
	}

}  /* print_mapsockaddr() */


/*
 * Print Mapping tables.
 */
void
mappr(u_long maptree)
{
    	struct radix_node_head *rnh, head;
	
	printf("Mapping tables:\n");

	if (Aflag == 0 && NewTree)
		maptreestuff();
	else {
		if (maptree == 0) {
			printf("map_tables: symbol not in namelist\n");
			return;
		}

		kget(maptree, map_tables);
		if ( ((rnh = map_tables[0]) != 0)  
		     && ((af == AF_INET) || (af == AF_UNSPEC)) ) { /*IPv4 EID*/

		        kget(rnh, head);
			map_size_cols(AF_INET, head.rnh_treetop);
			pr_family(AF_INET);
			do_mapent = 1;
			pr_maptblhdr(AF_INET);
			map_tree(head.rnh_treetop);

		};
		if ( ((rnh = map_tables[1]) != 0) 
		     && ((af == AF_INET6) || (af == AF_UNSPEC)) ){ /*IPv6 EID*/

		        kget(rnh, head);
			map_size_cols(AF_INET6, head.rnh_treetop);
			pr_family(AF_INET6);
			do_mapent = 1;
			pr_maptblhdr(AF_INET6);
			map_tree(head.rnh_treetop);
		  
		};
		if ( ((rnh = map_tables[2]) != 0)  
		     && ((af == AF_INET) || (af == AF_UNSPEC)) ) { /*IPv4 EID*/

		        kget(rnh, head);
			map_size_cols(AF_INET, head.rnh_treetop);
			pr_family(AF_INET);
			do_mapent = 1;
			pr_maptblhdr(AF_INET);
			map_tree(head.rnh_treetop);

		};
		if ( ((rnh = map_tables[3]) != 0) 
		     && ((af == AF_INET6) || (af == AF_UNSPEC)) ){ /*IPv6 EID*/

		        kget(rnh, head);
			map_size_cols(AF_INET6, head.rnh_treetop);
			pr_family(AF_INET6);
			do_mapent = 1;
			pr_maptblhdr(AF_INET6);
			map_tree(head.rnh_treetop);
		  
		};
	}
}  /* mappr() */



static void
domask(char *dst, u_long addr, u_long mask)
{
	int b, i;

	if ((mask == 0) || (mask == (u_long) -1)) {
	  /* XXX - Cast to be fixed 
	   */
		*dst = '\0';
		return;
	};

	i = 0;
	for (b = 0; b < 32; b++)
		if (mask & (1 << b)) {
			int bb;

			i = b;
			for (bb = b+1; bb < 32; bb++)
				if (!(mask & (1 << bb))) {
					i = -1;	/* noncontig */
					break;
				}
			break;
		}
	if (i == -1)
		sprintf(dst, "&0x%lx", mask);
	else
		sprintf(dst, "/%d", 32-i);

}  /* domask() */


/*
 * Return the name of the network whose address is given.
 * The address is assumed to be that of a net or subnet, not a host.
 */
const char *
mapname(u_long in, u_long mask)
{
	char *cp = 0;
	static char line[MAXHOSTNAMELEN];
	struct netent *np = NULL;
	struct hostent *hp = NULL;
	u_long i;

	i = ntohl(in);

	if ( !numeric_addr && i) {

	  if ((mask == (u_long) -1) || (!mask)) {
	    /* XXX - cast to be fixed
	     */
		        hp = gethostbyaddr((char *)&in, sizeof (struct in_addr),
					   AF_INET);
			if (hp) {
			        cp = hp->h_name;
				trimdomain(cp, strlen(cp));
			};
		} else {
		        np = getnetbyaddr(i, AF_INET);
			if (np != NULL) {
			        cp = np->n_name;
				trimdomain(cp, strlen(cp));
			};
		};

	};

	if (cp != NULL) {
		strncpy(line, cp, sizeof(line) - 1);
		line[sizeof(line) - 1] = '\0';
	} else {
		inet_ntop(AF_INET, (char *)&in, line, sizeof(line) - 1);
		domask(line + strlen(line), i, mask);
	};

	return (line);

} /* mapname() */


#ifdef INET6
const char *
mapname6(struct sockaddr_in6 *sa6, struct in6_addr *mask)
{
	static char line[MAXHOSTNAMELEN];
	u_char *p = (u_char *)mask;
	u_char *lim;
	int masklen = 0, illegal = 0;
	int failed = 0;

	/* use local variable for safety */
	struct sockaddr_in6 sa6_local;
	
	sa6_local.sin6_family = AF_INET6;
	sa6_local.sin6_len = sizeof(sa6_local);
	sa6_local.sin6_addr = sa6->sin6_addr;
	sa6_local.sin6_scope_id = sa6->sin6_scope_id;

       /* try to get a name if fails retry as numeric 
	*/

	if (numeric_addr || (failed =getnameinfo((struct sockaddr *)&sa6_local, 
						 sa6_local.sin6_len, line, 
						 sizeof(line), NULL, 0, 
						 NI_NAMEREQD)) ) {
	
	        getnameinfo((struct sockaddr *)&sa6_local, sa6_local.sin6_len,
			    line, sizeof(line), NULL, 0, NI_NUMERICHOST);
	};

	if (mask) {
		for (masklen = 0, lim = p + 16; p < lim; p++) {
			switch (*p) {
			 case 0xff:
				 masklen += 8;
				 break;
			 case 0xfe:
				 masklen += 7;
				 break;
			 case 0xfc:
				 masklen += 6;
				 break;
			 case 0xf8:
				 masklen += 5;
				 break;
			 case 0xf0:
				 masklen += 4;
				 break;
			 case 0xe0:
				 masklen += 3;
				 break;
			 case 0xc0:
				 masklen += 2;
				 break;
			 case 0x80:
				 masklen += 1;
				 break;
			 case 0x00:
				 break;
			 default:
				 illegal ++;
				 break;
			}
		}
		if (illegal)
			fprintf(stderr, "illegal prefixlen\n");
	};

	if (masklen == 0 && IN6_IS_ADDR_UNSPECIFIED(&sa6->sin6_addr))
		return("default");
	
	if ((numeric_addr || failed) && masklen && (masklen != 128))
	        sprintf(&line[strlen(line)-1], "/%d", masklen);

	return line;

}  /* mapname6() */

#endif /* INET6 */


/*
 * Set column width
 */
static void
map_size_cols(int ef, struct radix_node *rn)
{
	wid_eid = WID_EID_DEFAULT(ef);
	wid_mflags = 6;
	wid_mvnum = 8;
	wid_mrefs = 6;
	wid_rlocs = WID_RLOC_DEFAULT(AF_INET6);
	wid_mrlocsnum = 3;
	wid_rlocpriority = 4;
	wid_rlocweight = 4;
	wid_rlocflags = 3;
	wid_rlocmtu = 5;
	wid_rlochit = 12;
	wid_rxnonce = 9;
	wid_txnonce = 9;

	if (Wflag || numeric_addr) {
	        map_size_cols_tree(rn);
	};

}  /* map_size_cols() */

/*
 * Recursively scan the maptable to..
 */
static void
map_size_cols_tree(struct radix_node *rn)
{
again:
	kget(rn, rnode);
	if (rnode.rn_bit < 0) {
		if ((rnode.rn_flags & RNF_ROOT) == 0) {
		    kget(rn, mapentry);
		    map_size_cols_entry(&mapentry);
		}
		if ((rn = rnode.rn_dupedkey))
			goto again;
	} else {
		rn = rnode.rn_right;
		map_size_cols_tree(rnode.rn_left);
		map_size_cols_tree(rn);
	};

}  /* map_size_cols_tree() */

/*
 * Check addresses in an entry and keeps trace of the longer.
 */
static void
map_size_cols_entry(struct mapentry *map)
{
	const char *bp;
	struct sockaddr *sa;
	ss_u addr, mask;
	int len;

	bzero(&addr, sizeof(addr));

	if ((sa = kgetmapsa(map_key(map))))
		bcopy(sa, &addr, sa->sa_len);

	bzero(&mask, sizeof(mask));
	if (map_mask(map) && (sa = kgetmapsa(map_mask(map))))
		bcopy(sa, &mask, sa->sa_len);

	bp = fmt_mapsockaddr(&addr.u_sa, &mask.u_sa, map->map_flags);
	len = strlen(bp);
	wid_eid = MAX(len, wid_eid);

	bp = fmt_mapflags(map->map_flags);
	len = strlen(bp);
	wid_mflags = MAX(len, wid_mflags);

}  /* map_size_cols_entry() */



/*
 * Print header for mapping table columns.
 */
void
pr_maptblhdr(int af1)
{

	if (Aflag)
		printf("%-8.8s ","Address");
	if (Wflag) {
	        printf("%-*.*s %-*.*s %*.*s %*.*s %*.*s %-*.*s %*.*s %*.*s %-*.*s %*.*s %*.*s %*.*s %*.*s\n",
		       wid_eid,	wid_eid,	         "EID",
		       wid_mflags,	wid_mflags,	 "Flags",
		       wid_mrefs,	wid_mrefs,	 "Refs",
		       wid_mvnum,       wid_mvnum,       "Version",
		       wid_mrlocsnum,	wid_mrlocsnum,	 "#",
		       wid_rlocs,       wid_rlocs,       "RLOC(s)",
		       wid_rlocpriority,wid_rlocpriority,"P",
		       wid_rlocweight,  wid_rlocweight,  "W",
		       wid_rlocflags,   wid_rlocflags,   "F",
		       wid_rlocmtu,     wid_rlocmtu,     "MTU",
		       wid_rlochit,     wid_rlochit,     "Hit",
		       wid_txnonce,     wid_txnonce,     "TxNonce",
		       wid_rxnonce,     wid_rxnonce,     "RxNonce");
	} else {
		printf("%-*.*s %-*.*s %-*.*s %*.*s %*.*s %-*.*s\n",
		       wid_eid,	wid_eid,	         "EID",
		       wid_mflags,	wid_mflags,	 "Flags",
		       wid_rlocs,       wid_rlocs,       "RLOC(s)",
		       wid_rlocpriority,wid_rlocpriority,"P",
		       wid_rlocweight,  wid_rlocweight,  "W",
		       wid_rlocflags,   wid_rlocflags,   "F");
	}

}  /* pr_maptblhdr() */


/*
 * Maptbl tree exploring routing
 */
static void
map_tree(struct radix_node *rn)
{

again:
	kget(rn, rnode);
	if (rnode.rn_bit < 0) {
		if (Aflag)
			printf("%-8.8lx ", (u_long)rn);

		if (rnode.rn_flags & RNF_ROOT) {
			if (Aflag)
				printf("(root node)%s",
				    rnode.rn_dupedkey ? " =>\n" : "\n");
		} else if (do_mapent) {
			kget(rn, mapentry);
			print_mapentry(&mapentry);
			if (Aflag)
				map_node();
		} else {
			print_mapsockaddr(kgetmapsa((struct sockaddr *)rnode.rn_key),
				   NULL, 0, 44);
			putchar('\n');
		}
		if ((rn = rnode.rn_dupedkey))
			goto again;
	} else {
		if (Aflag && do_mapent) {
			printf("%-8.8lx ", (u_long)rn);
			map_node();
		}
		rn = rnode.rn_right;
		map_tree(rnode.rn_left);
		map_tree(rn);
	}

} /* map_tree() */



static void
map_node(void)
{
	struct radix_mask *rm = rnode.rn_mklist;

	if (rnode.rn_bit < 0) {
		if (rnode.rn_mask) {
			printf("\t  mask ");
			print_mapsockaddr(kgetmapsa((struct sockaddr *)rnode.rn_mask),
				   NULL, 0, -1);
		} else if (rm == 0)
			return;
	} else {
		sprintf(mapbuf, "(%d)", rnode.rn_bit);
		printf("%6.6s %8.8lx : %8.8lx", mapbuf, (u_long)rnode.rn_left, (u_long)rnode.rn_right);
	}
	while (rm) {
		kget(rm, rmask);
		sprintf(mapbuf, " %d refs, ", rmask.rm_refs);
		printf(" mk = %8.8lx {(%d),%s",
			(u_long)rm, -1 - rmask.rm_bit, rmask.rm_refs ? mapbuf : " ");
		if (rmask.rm_flags & RNF_NORMAL) {
			struct radix_node rnode_aux;
			printf(" <normal>, ");
			kget(rmask.rm_leaf, rnode_aux);
			print_mapsockaddr(kgetmapsa((struct sockaddr *)rnode_aux.rn_mask),
				    NULL, 0, -1);
		} else
		    print_mapsockaddr(kgetmapsa((struct sockaddr *)rmask.rm_mask),
				NULL, 0, -1);
		putchar('}');
		if ((rm = rmask.rm_mklist))
			printf(" ->");
	}
	putchar('\n');
} /* map_node() */


static void
maptreestuff(void)
{
	size_t needed;
	int mib[6];
	char *buf, *next, *lim;
	struct map_msghdr *mapmsg;

	mib[0] = CTL_NET;
	mib[1] = AF_MAP;
	mib[2] = 0;
	mib[3] = 0;
	mib[4] = NET_MAPTBL_DUMP;
	mib[5] = 0;

	if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0) {
		err(1, "sysctl: net.maptables.0.0.dump estimate");
	}

	if ((buf = malloc(needed)) == 0) {
		errx(2, "malloc(%lu)", (unsigned long)needed);
	}

	if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0) {
		err(1, "sysctl: net.maptables.0.0.dump");
	}
	lim  = buf + needed;

	for (next = buf; next < lim; next += mapmsg->map_msglen) {
		mapmsg = (struct map_msghdr *)next;
		nprint_mapentry(mapmsg);
	}

}  /* maptreestuff */



static void
nprint_mapentry(struct map_msghdr *mapmsg)
{
	struct sockaddr *eid = (struct sockaddr *)(mapmsg + 1);
	struct sockaddr *eidmask;
#ifdef notdef
	static int masks_done, banner_printed;
#endif
	int af1 = 0, interesting = MAPF_UP | MAPF_DB | MAPF_STATIC ;

	af1 = eid->sa_family;
	
	if (mapmsg->map_addrs == MAPA_EID)
		print_mapsockaddr(eid, NULL, 0, 36);
	else {
	  if (mapmsg->map_addrs | MAPA_EIDMASK) {

	        eidmask = (struct sockaddr *)(SA_SIZE(eid) + (char *)eid);
		print_mapsockaddr(eid, eidmask, mapmsg->map_flags, 18);

	  } else {
		print_mapsockaddr(eid, NULL, mapmsg->map_flags, 16);
	  }

	};
	print_mapflags(mapmsg->map_flags & interesting, "%-6.6s ");

	putchar('\n');
}

/* 
 * Print a complete mapentry 
 */
static void
print_mapentry(struct mapentry *map)
{

	struct sockaddr *sa;
	ss_u addr, mask, rloc;
	static char buffer[128];
        struct locator_chain lc;  
	struct locator_chain *onemore = NULL;
	int i = 0;
	int priority, weight, mtu, rlochit;
	uint32_t rxnonce, txnonce;
	uint16_t flags;

	bzero(&addr, sizeof(addr));
	if ((sa = kgetmapsa(map_key(map))))
		bcopy(sa, &addr, sa->sa_len);

	
	bzero(&mask, sizeof(mask));
	if (map_mask(map) && (sa = kgetmapsa(map_mask(map))))
		bcopy(sa, &mask, sa->sa_len);

	print_mapsockaddr(&addr.u_sa, &mask.u_sa, map->map_flags, wid_eid);

	snprintf(buffer, sizeof(buffer), "%%-%d.%ds ", wid_mflags, wid_mflags);
	print_mapflags(map->map_flags, buffer);

	if (Wflag) {
		printf("%*ld ", wid_mrefs, map->map_refcnt);
		if (map->map_flags & MAPF_VERSIONING)
		        printf("%*u ", wid_mvnum, ntohs(map->vnum));
		else
		        printf("%*s ", wid_mvnum," ");

	};

	if (map->rlocs) {
	        onemore = map->rlocs;
		kget(map->rlocs,lc);
		i++;
	}

	while (onemore) {

		 bzero(&rloc, sizeof(rloc));
	  
		 if ((sa = kgetmapsa((struct sockaddr *)(lc.rloc.rloc_addr))))
		         bcopy(sa, &rloc, sa->sa_len);

		 if ( i>1 ) {
		         if (Wflag)
		                 printf(" %-*s   ",(wid_eid + wid_mflags + wid_mrefs + wid_mvnum)," ");
			 else
		                 printf("%-*s  ",(wid_eid + wid_mflags)," ");
		 };
		 if (Wflag) {
		         printf("%*ld ", wid_mrlocsnum, (long)i);
		 };

		 print_mapsockaddr(&rloc.u_sa, NULL, 0, wid_rlocs);

		 priority = lc.rloc.rloc_metrix.rlocmtx.priority;
		 weight = lc.rloc.rloc_metrix.rlocmtx.weight;
		 flags = lc.rloc.rloc_metrix.rlocmtx.flags;
		 mtu = lc.rloc.rloc_metrix.rlocmtx.mtu;	
		 rlochit = lc.rloc.rloc_metrix.rloc_hit;
		 rxnonce = (uint32_t)ntohl(lc.rloc.rloc_metrix.rlocmtx.rx_nonce.nvalue) >> 8;
		 txnonce = (uint32_t)ntohl(lc.rloc.rloc_metrix.rlocmtx.tx_nonce.nvalue) >>8;

		 printf("%*ld %*ld ", wid_rlocpriority, (long) priority,
			wid_rlocweight,  (long) weight);

		 snprintf(buffer, sizeof(buffer), "%%-%d.%ds ", wid_rlocflags,
			  wid_rlocflags);

		 print_rlocflags(flags, buffer);
		 
		 if (Wflag) {
		         if (mtu)
			         printf("%*ld ", wid_rlocmtu, (long) mtu);
			 else
			         printf("%*s ", wid_rlocmtu," ");

		         printf("%*ld ", wid_rlochit, (long) rlochit);

		         if (flags & RLOCF_TXNONCE)
			         printf("%*u ", wid_txnonce, txnonce);
			 else
			         printf("%*s ", wid_txnonce," ");

		         if (flags & RLOCF_RXNONCE)
			         printf("%*u ", wid_rxnonce, rxnonce);
			 else
			         printf("%*s ", wid_rxnonce," ");

		 };

		 putchar('\n');

	         if ((onemore = lc.next)) {
		         kget(lc.next,lc);
			 i++;
		 };
	};


	putchar('\n');
}  /* print_mapentry() */


/*
 * Dump LISP statistics structure.
 */
void
map_stats()
{
	struct mappingstats mapstat, zerostat;
	size_t len = sizeof (struct mappingstats);

	if (zflag)
		memset(&zerostat, 0, len);

	if (sysctlbyname("net.lisp.maptables", &mapstat, &len,
	    zflag ? &zerostat : NULL, zflag ? len : 0) < 0) {
		warn("sysctl: net.lisp.maptables");
		return;
	}

	printf("MapTables Statistics:\n");
	printf("\t %"PRIu64" Database\n", (mapstat.db.hit + mapstat.db.miss));
	printf("\t\t %"PRIu64" Hit\n",mapstat.db.hit);
	printf("\t\t %12"PRIu64" Miss\n",mapstat.db.miss);
	printf("\t %"PRIu64" Cache \n", (mapstat.cache.hit + mapstat.cache.miss));
	printf("\t\t %"PRIu64" Hit\n",mapstat.cache.hit);
	printf("\t\t %"PRIu64" Miss\n",mapstat.cache.miss);

} /* map_stats() */


void
lisp_stats(u_long off __unused, const char *name __unused, int af1 __unused, int proto __unused)
{
	struct lispbasicstat lispstat, zerostat;
	size_t len = sizeof (struct lispbasicstat);
	u_long delivered, sent, received;

	if (zflag)
		memset(&zerostat, 0, len);

	if (sysctlbyname("net.inet.lisp.stats", &lispstat, &len,
	    zflag ? &zerostat : NULL, zflag ? len : 0) < 0) {
		warn("sysctl: net.inet.lisp.stats");
		return;
	}

	printf("lisp over ip:\n");

#define	p(f, m) if (lispstat.f || sflag <= 1) \
    printf(m, lispstat.f, plural(lispstat.f))
#define	p1a(f, m) if (lispstat.f || sflag <= 1) \
    printf(m, lispstat.f)

	received = lispstat.ipackets + lispstat.ioafpackets;
	if (received || sflag <= 1)
	        printf("\t%lu Datagrams received\n", received);
	p1a(ioafpackets, "\t\t(%u of which had IPv6 outer header)\n");
	p1a(ihdrops, "\t\t%u with incomplete header\n");
	p1a(ibadencap, "\t\t%u with bad encap header\n");
	p1a(ibadlen, "\t\t%u with bad data length field\n");
	p1a(ibadsrcvnum, "\t\t%u with bad source version number field\n");
	p1a(ibaddstvnum, "\t\t%u with bad destination version number field\n");
	delivered = lispstat.ipackets +
	            lispstat.ioafpackets -
		    lispstat.ihdrops -
		    lispstat.ibadlen -
	            lispstat.ibadencap;
	if (delivered || sflag <= 1)
		printf("\t\t%lu delivered\n", delivered);

	p(opackets, "\t%u datagram%s output\n");
	p1a(ooafpackets, "\t\t(%u of which with IPv6 inner packet)\n");
        p1a(omissdrops, "\t\t%u dropped due to cache-miss\n"); 
        p1a(onorlocdrops, "\t\t%u dropped due to no suitable RLOC\n");  
        p1a(osizedrops, "\t\t%u dropped due to MTU\n"); 
        p1a(onobufdrops, "\t\t%u dropped due to no buffer space\n"); 
	p1a(odrops, "\t\t%u dropped on output\n");
	sent = lispstat.opackets -
	       lispstat.odrops;
	if (sent || sflag <= 1)
		printf("\t\t%lu sent\n", sent);
	
#undef p
#undef p1a
} /* lisp_stats() */

void
lisp6_stats(u_long off __unused, const char *name, int af1 __unused, int proto __unused)
{
	struct lispbasicstat lispstat, zerostat;
	size_t len = sizeof (struct lispbasicstat);
	u_long delivered, sent, received;

	if (zflag)
		memset(&zerostat, 0, len);

	if (sysctlbyname("net.inet6.lisp.stats", &lispstat, &len,
	    zflag ? &zerostat : NULL, zflag ? len : 0) < 0) {
		warn("sysctl: net.inet6.lisp6.stats");
		return;
	}

	printf("lisp over ip6:\n");
#define	p(f, m) if (lispstat.f || sflag <= 1) \
    printf(m, lispstat.f, plural(lispstat.f))
#define	p1a(f, m) if (lispstat.f || sflag <= 1) \
    printf(m, lispstat.f)

	received = lispstat.ipackets + lispstat.ioafpackets;
	if (received || sflag <= 1)
	        printf("\t%lu Datagrams received\n", received);
	p1a(ioafpackets, "\t\t(%u had IPv4 outer header)\n");
	p1a(ihdrops, "\t\t%u with incomplete header\n");
	p1a(ibadencap, "\t\t%u with bad encap header\n");
	p1a(ibadlen, "\t\t%u with bad data length field\n");
	p1a(ibadsrcvnum, "\t\t%u with bad source version number field\n");
	p1a(ibaddstvnum, "\t\t%u with bad destination version number field\n");
	delivered = lispstat.ipackets +
	            lispstat.ioafpackets -
		    lispstat.ihdrops -
		    lispstat.ibadlen -
	            lispstat.ibadencap;
	if (delivered || sflag <= 1)
		printf("\t\t%lu delivered\n", delivered);
	p(opackets, "\t%u datagram%s output\n");
	p1a(ooafpackets, "\t\t(%u of which with IPv4 inner packet)\n");
        p1a(omissdrops, "\t\t%u dropped due to cache-miss\n"); 
        p1a(onorlocdrops, "\t\t%u dropped due to no suitable RLOC\n");  
        p1a(osizedrops, "\t\t%u dropped due to MTU\n"); 
        p1a(onobufdrops, "\t\t%u dropped due to no buffer space\n"); 
	p1a(odrops, "\t\t%u dropped on output\n");
	sent = lispstat.opackets -
	       lispstat.odrops;

	if (sent || sflag <= 1)
		printf("\t\t%lu sent\n", sent);
	
#undef p
#undef p1a
} /* lisp_stats() */


void 
lisp_stats_wrapper(u_long off __unused, const char *name __unused, int af1, int proto __unused)
{

  if ( (af1 == AF_INET) || (af1 == AF_UNSPEC) )
    lisp_stats(off, name, af1, proto);

  if ( (af1 == AF_INET6) || (af1 == AF_UNSPEC) )
    lisp6_stats(off, name, af1, proto);

}  /* lisp_stats_wrapper() */
