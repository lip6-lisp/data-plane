/*- /usr/src/sbin/map/map.c
 *
 * Copyright (c) 2009 - Luigi Iannone <luigi@net.t-labs.tu-berlin.de>
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
 *
 * GgX - This is the code implementing the user space access to mapping 
 * cache and database.
 * The code is inspired from the route.c code of 
 * FreeBSD. The original copyright is maintained hereafter.
 *
 *----------------------------------------------------------------------------
 */
/* Copyright (c) 1983, 1989, 1991, 1993
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
 * For mapd, the original map.c source file is retained with minimal changes
 * for code maintenance reasons.  The only things removed are the usage_exit()
 * and main() functions, which now reside in mapd.c  The only thing added is
 * this comment.
 */

#include <sys/param.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/types.h>

#include <net/if.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/if_ether.h>
#include <netatalk/at.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <ifaddrs.h>

#include <net/lisp/lisp.h>
#include <net/lisp/maptables.h>


/* List of recognized protocols
 */
struct prototab {
	char	*pt_cp;
} protocols[] = {
#include "proto-numbers.h"
};


/* List of recognized commands
 */
struct keytab {
	char	*kt_cp;
	int	kt_i;
} keywords[] = {
#include "keywords.h"
	{0, 0}
};

/* List of recognized flags
 */
struct flagtable {
	char	*ft_cp;
	int	ft_f;
} mapflags[] = {
  { "Database",	    MAPF_DB},
  { "Versioning",   MAPF_VERSIONING},
  { "LocBits", 	    MAPF_LOCBITS},
  { "Static",	    MAPF_STATIC},
  { "Up",	    MAPF_UP},
  {"All",	    MAPF_ALL},	
  {"Done",	    MAPF_DONE},	
  {0, 0}
};

/* Name of the addresses in the message
 */
struct flagtable addrnames[] = {
  {"EID",     MAPA_EID},
  {"EIDMASK", MAPA_EIDMASK},
  {"RLOC",    MAPA_RLOC},
  {0, 0}
};

union	sockunion {
	struct	sockaddr sa;
	struct	sockaddr_in sin;
#ifdef INET6
	struct	sockaddr_in6 sin6;
#endif
	struct	sockaddr_storage ss; 
} so_eid, so_eidmask, so_rloc;

typedef union sockunion *sup;

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
} rloc_chain = {0, NULL, NULL};

int	map_addrs;
int	s; /* MAPPING SOCKET*/

/* Options flags
 */
int	nameflag, quietflag, testonlyflag, verboseflag, debugonlyflag;
int     cmdflag;

int     pid;
uid_t	uid;

/* DB or Cache */
int     fordb = 0, forcache = 0, forall = 0;

/* RLOC flags and parameters */
uint8_t rlocpriority = 255;
uint8_t rlocweight = 100;
uint16_t rlocflags = 0;
uint32_t rlocmtu = 0;
uint32_t rlocnonce = 0;

/* Header flags */
int L_bit = 0, V_bit = 0;
uint16_t Vnumber = 0;

#define MAX_VNUM 65535
#define MAX_NONCE 16777215
#define MAX_PRIORITY 255
#define MAX_WEIGHT 100
#define MAX_STATUS 1
/* From Kernel */
#define MAX_MTU 65535
#define MIN_MTU 72

int     afeid = 0, afleneid = sizeof(struct sockaddr_storage);
int     afrloc = 0, aflenrloc = sizeof(struct sockaddr_storage);

struct bits {
	u_long	b_mask;
	char	b_val;
} rlocflagsbits[] = {
	{ RLOCF_UP,	'U' },
	{ RLOCF_LIF,	'i' },
	{ RLOCF_TXNONCE,'n' },
	{ 0 , 0 }
};

/* Message buffer */
struct {
	struct	map_msghdr m_map;
	char	m_space[8192];
} m_mapmsg;

/*
 * List Messages types
 */
char *msgtypes[] = {
	"",
	"[MAPM_ADD]\n  Map Add",
	"[MAPM_DELETE]\n  Map Delete",
	"[MAPM_CHANGE]\n  Change Metrics or flags",
	"[MAPM_GET]\n  Report Metrics",
	"[MAPM_MISS]\n  Lookup Failed  (general case)",
	"[MAPM_MISS_EID]\n  Lookup Failed  and EID returned",
	"[MAPM_MISS_HEADER]\n  Lookup Failed  and IP header returned",
	"[MAPM_MISS_PACKET]\n  Lookup Failed  and Packet returned",
	"[MAPM_LSBITS]\n  Loc Status Bits Changed",
	"[MAPM_LOCALSTALE]\n   Local Map Version is stale",
	"[MAPM_REMOTESTALE]\n  Remote Map Version is stale",
	"[MAPM_NONCEMISMATCH]\n  Received a mismatching nonce",
	0,
};

/* Subroutines
 */
void    monitor(), flushmappings(), handlemap();
void    sodump(), rlocdump();
void    flagprintf(), printmsg(), print_getmsg(), print_mapmsg();
void    mask_addr(), append_rloc(), flush_rloc_chain();
int     prefixlen(), send_mapmsg(), keyword(), getaddr();
const char * mapaddr();
static const char * format_rlocflags();

void    inet_makenetandmask();
static  int     inet6_makenetandmask();

void usage_exit(const char *) __dead2;

/* Usefull Definition Max Arguments Number
 */
#define ARG_MONITOR 1
#define ARG_FLUSH 3

#define CHECK_ARGS_NUM(c,n)                        \
  if (c > n) {					   \
  warnx("Too many arguments");			   \
  usage_exit((char *)NULL);			   \
  /* NOTREACHED */				   \
  };

#define CHECK_ADDR(s)						   \
  if (addrexp) {						   \
    warnx("Keyword found where address expected: %s",s);	   \
    usage_exit((char *)NULL);					   \
    /* NOTREACHED */						   \
  };


/*
 * Monitor mode (sniffing mapping sockets)
 */
void
monitor()
{
 
	int n;
	char msg[8192];
	
	/* Force verbose mode */
	verboseflag = 1;

	if (debugonlyflag || testonlyflag) {
	        /* Nothing ot do */
		exit(0);
	};

	for(;;) {
		time_t now;
		n = read(s, msg, 8192);
		now = time(NULL);
		(void) printf("\nGot message of size %d on %s \n", n, ctime(&now));
		print_mapmsg((struct map_msghdr *)msg, n);
	};

} /* monitor() */


/*
 * Purge entries in the mapping tables
 */
void
flushmappings(argc, argv)
	int argc;
	char *argv[];
{
        int mib[6], afflush = 0, count = 0, seqno = 0, mlen = 0;
	int databaseflush = 0, cacheflush = 1, allflush = 0, modifierflag = 0;
	size_t needed;
	char *buffer, *limit, *next;
    
        struct map_msghdr *mapmsg;
  
        if (uid && !debugonlyflag) {
                errx(EX_NOPERM, "Must be root to alter mapping table");
        }

	shutdown(s, SHUT_RD); /* Don't want to read back our messages */
	
	CHECK_ARGS_NUM(argc,ARG_FLUSH);

	if (argc > 1) {

	        if  (**(++argv)== '-' )  {

		        switch (keyword(1+*argv)) {

		        case M_ALL:
			        allflush = 1 ;
				cacheflush = 0;
				modifierflag = 1;
				break;

		        case M_DATABASE:
			        databaseflush = 1 ;
				cacheflush = 0;
				modifierflag = 1;
				break;

		        case M_CACHE:
			        modifierflag = 1;
				break;
		        default:
				usage_exit(1+*argv);

			};
			
		} else {
		        usage_exit(*argv);
		};

		if (modifierflag && argc > 2)
		        argv++;
	
		if (!modifierflag || (modifierflag && argc > 2)) {
		        if  (**(argv)== '-' )  {
			        switch (keyword(1+*argv)) {

			        case M_INET:
				  afflush = AF_INET;
				  break;

#ifdef INET6
			        case M_INET6:
				  afflush = AF_INET6;
				  break; 
#endif
		                default:
				  usage_exit(1+*argv);
				  /* NOT REACHED */
				};
				
			} else {
			        usage_exit(*argv);
			};

		};
		  	
	};
retry:
        mib[0] = CTL_NET;
        mib[1] = PF_MAP;
        mib[2] = 0;             /* protocol */
        mib[3] = 0;             /* wildcard address family */
        mib[4] = NET_MAPTBL_DUMP;
        mib[5] = 0;             /* no flags */

	if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0)
                err(EX_OSERR, "map-sysctl-estimate");

	if ((buffer = malloc(needed)) == NULL)
                errx(EX_OSERR, "malloc failed");

	if (sysctl(mib, 6, buffer, &needed, NULL, 0) < 0) {
                if (errno == ENOMEM && count++ < 10) {
                        warnx("Mapping table grew, retrying");  
                        sleep(1);
                        free(buffer);
                        goto retry;
                }
                err(EX_OSERR, "map-sysctl-get");
        }
        limit = buffer + needed;
	
        if (verboseflag)
                (void) printf("\nExamining mapping table from sysctl\n\n");
		
        for (next = buffer; next < limit; next += mapmsg->map_msglen) {

	        mapmsg = (struct map_msghdr *)next;
		
		if (afflush) {
                        struct sockaddr *sa = (struct sockaddr *)(mapmsg + 1);

                        if (sa->sa_family != afflush)
                                continue;
		};

		if (!allflush) {

		  if (cacheflush && (mapmsg->map_flags & MAPF_DB)) {
		           continue;
		  };

		  if (databaseflush && !(mapmsg->map_flags & MAPF_DB)) {
		    continue;
		  };
                
		};

                if (verboseflag)
                        print_mapmsg(mapmsg, mapmsg->map_msglen);
 
		if (debugonlyflag)
                        continue;

		mapmsg->map_type = MAPM_DELETE;
                mapmsg->map_seq = seqno;

                mlen = write(s, next, mapmsg->map_msglen);
 
		if (mlen < 0 && errno == EPERM)
                        err(1, "write to mapping socket");

                if (mlen < (int)mapmsg->map_msglen) {
                        warn("write to mapping socket");
                        (void) printf("got only %d for mlen\n", mlen);
                        free(buffer);
                        goto retry;
                        break;
		};

                seqno++;

                if (quietflag)
                        continue;


                if (verboseflag) {

                        print_mapmsg(mapmsg, mlen);

	        } else {
                        struct sockaddr *sa = (struct sockaddr *)(mapmsg + 1);
                        (void) printf("%-20.20s ", mapaddr(sa));
                        sa = (struct sockaddr *)(SA_SIZE(sa) + (char *)sa);
                        (void) printf("%-20.20s ", mapaddr(sa));
                        (void) printf("done\n");
		};

	} /* for */

} /* flushmappings() */

/*
 * Manage everything related to single mappings
 */

void
handlemap(argc, argv)
	int argc;
	char **argv;
{
        const char *err;

        char *eid = "", *rloc = "";
        char *cmd;

	int addrexp = 0, staticflag = 0, rlocstatus = 0;

        int ret, oerrno; 
	int key, flags = MAPF_STATIC;

	if (uid) {
	        flush_rloc_chain();
	        errx(EX_NOPERM, "Must be root to alter mapping table");
	}

	cmd = argv[0];
	if (*cmd != 'g') 
	       shutdown(s, SHUT_RD); /* If it is a GET
				      * Don't want to read back our messages 
				      */
	while (--argc > 0) {
 	
	        if  (**(++argv)== '-' )  {
		       /* Modifier case
			*/

		        CHECK_ADDR((1 + *argv));

		        switch (key = keyword(1 + *argv)) {

			case M_CACHE:
 			        if ( forall || forcache || fordb) {
				         warnx("Conflicting or wrong modifier: %s ",1+*argv);
					 usage_exit((char*)NULL);
				};
				
				forcache++;
				flags &= ~MAPF_DB;
				break;

			case M_DATABASE:
 			        if ( forall || forcache || fordb ) {
				         warnx("Conflicting or wrong modifier: %s ",1+*argv);
					 usage_exit((char*)NULL);
				};
				
				fordb++;
				flags |= MAPF_DB;
				break;

			case M_ALL:
 			        if ( forall || forcache || fordb) {
				         warnx("Conflicting or wrong modifier: %s ",1+*argv);
					 usage_exit((char*)NULL);
				};
				
 			        if ( cmdflag == M_ADD ) {
				         warnx("Modifier not allowed: %s ",1+*argv);
					 usage_exit((char*)NULL);
				};

				forall++;
				flags |= MAPF_ALL;
				break;
			

			case M_NOSTATIC:
 			        if ( staticflag ) {
				         warnx("Conflicting or wrong modifier: %s ",1+*argv);
					 usage_exit((char*)NULL);
				};

			        if ( cmdflag != M_ADD ) {
				         warnx("Modifier not allowed: %s ",1+*argv);
					 usage_exit((char*)NULL);
				};
				
				staticflag++;
				flags &= ~MAPF_STATIC;
				break;

			
			case M_STATIC:
 			        if ( staticflag ) {
				         warnx("Conflicting or wrong modifier: %s ",1+*argv);
					 usage_exit((char*)NULL);
				};

			        if ( cmdflag != M_ADD ) {
				         warnx("Modifier not allowed: %s ",1+*argv);
					 usage_exit((char*)NULL);
				};

				staticflag++;
				flags |= MAPF_STATIC;
				break;

			case M_LOCBITS:
 			        if ( L_bit || V_bit ) {
				         warnx("Conflicting or wrong modifier: %s ",1+*argv);
					 usage_exit((char*)NULL);
				};

			        if ( cmdflag != M_ADD ) {
				         warnx("Modifier not allowed: %s ",1+*argv);
					 usage_exit((char*)NULL);
				};

				L_bit++;
				flags |= MAPF_LOCBITS;
				break;

			case M_VERSION:
 			        if ( L_bit || V_bit ) {
				         warnx("Conflicting or wrong modifier: %s ",1+*argv);
					 usage_exit((char*)NULL);
				};

			        if ( cmdflag != M_ADD ) {
				         warnx("Modifier not allowed: %s ",1+*argv);
					 usage_exit((char*)NULL);
				};

				if  ( ((argc - 1) > 0) && ((**(argv+1))!= '-')){
				       /* Read Version Number */

				        Vnumber = strtonum(*(++argv), 0, MAX_VNUM, &err);
					if (err) {
					        warnx("Unable to convert \"%s\": %s ",*argv, err);
						usage_exit((char*)NULL);

					};
	
					argc--;

				} else {

				         warnx("Number expected after: %s ",1+*argv);
					 usage_exit((char*)NULL);
				}; 


				V_bit++;
				flags |= MAPF_VERSIONING;
				break;

		  	case M_INET:
			        addrexp++;
			        if (afeid == 0 ) {
				        afeid = AF_INET;
				        afleneid = sizeof(struct sockaddr_in);
				}
				else {
				        afrloc = AF_INET;
				        aflenrloc = sizeof(struct sockaddr_in);
				};
				break;

#ifdef INET6
			case M_INET6:
			        addrexp++;
			  	if (afeid == 0 ) {
				        afeid = AF_INET6;
				        afleneid = sizeof(struct sockaddr_in6);
				}
				else {
				        afrloc = AF_INET6;
				        aflenrloc = sizeof(struct sockaddr_in6);
				}
			        break;
#endif

			default:
				usage_exit(1+*argv);
			}
		} else {

		        if (!addrexp) {
			        warnx("Wrong expression");
				usage_exit((char*)NULL);
			};

			addrexp = 0;
		  
		  	if ((map_addrs & MAPA_EID) == 0) {
			        
			        eid = *argv;
				(void) getaddr(MAPA_EID, *argv, 0);

			} else {

			        rloc = *argv;
				if (getaddr(MAPA_RLOC, *argv, 0) == 0) {
				       flush_rloc_chain();
				       errx(EX_NOPERM, "RLOC must be an host address");
				};
			
				/* Check for RLOC's priority, weight, status.
				 * First number always considered as the 
				 * priority, then the weight then the status.
				 * nonce, and mtu.
				 */
				if  ( ((argc - 1) > 0) && ((**(argv+1))!= '-')){
				  /* Priority */

				  rlocpriority = (uint8_t)strtonum(*(++argv), 0, MAX_PRIORITY, &err);
				  if (err) {
				    flush_rloc_chain();
				    warnx("Unable to convert \"%s\": %s ",*argv, err);
				    usage_exit((char*)NULL);
				    
				  };
				  
				  argc--;
				  
				  if  ( ((argc - 1) > 0) && ((**(argv+1))!= '-')){
				    /* Weight */
				    
				    rlocweight = (uint8_t)strtonum(*(++argv), 0, MAX_WEIGHT, &err);
				    if (err) {
				      flush_rloc_chain();
				      warnx("Unable to convert \"%s\": %s ",*argv, err);
				      usage_exit((char*)NULL);
				      
				    };
				    
				    argc--;
				    
				    if  ( ((argc - 1) > 0) && ((**(argv+1))!= '-')){
				      /* Status */
				      
				      rlocstatus = strtonum(*(++argv), 0, MAX_STATUS, &err);
				      if (err) {
					flush_rloc_chain();
					warnx("Unable to convert \"%s\": %s ",*argv, err);
					usage_exit((char*)NULL);

				      };
							
				      rlocflags |= rlocstatus;
						
				      argc--;

				      if  ( ((argc - 1) > 0) && ((**(argv+1))!= '-')){
					/* nonce */

					if (strcmp(*(++argv),"0") ) {

					  rlocnonce = strtonum(*(argv), 0, MAX_NONCE, &err);
					  rlocflags |= RLOCF_TXNONCE;

					  if (err) {
					    flush_rloc_chain();
					    warnx("Unable to convert \"%s\": %s ",*argv, err);
					    usage_exit((char*)NULL);

					  };

					};
		
					argc--;

				      };
				      
				      if  ( ((argc - 1) > 0) && ((**(argv+1))!= '-')){
					/* MTU */

					if (strcmp(*(++argv),"0") ) {

					  rlocmtu = strtonum(*(argv), MIN_MTU, MAX_MTU, &err);
					  if (err) {
					    flush_rloc_chain();
					    warnx("Unable to convert \"%s\": %s ",*argv, err);
					    usage_exit((char*)NULL);

					  };

					};
		
					argc--;

				      };

				    };

				  };

				};
				
				/* GgX - Add rloc to the RLOC's chain */

				append_rloc();

			};
		  
		};
	
	}; /*while*/

	if ( !(forall || forcache || fordb))
	       /* By default operation on cache is assumed */
	        forcache++;


	flags |= MAPF_UP;
	if (fordb)
		flags |= MAPF_DB;

	errno = 0;
	ret = send_mapmsg(cmdflag, flags);

	if ((*cmd == 'g') && (ret == 0)) {
	        exit(0);
		/* NOT REACHED */
	};

	if (!quietflag) {
		oerrno = errno;
		(void) printf("%s %s %s", cmd, forall? "all" : (forcache ? "cache" : "database"), eid);

		if (ret == 0) {
			(void) printf(" Done!\n");
		} else {
			switch (oerrno) {
			case ESRCH:
				err = "not in table";
				break;
			case EBUSY:
				err = "entry in use";
				break;
			case ENOBUFS:
				err = "not enough memory";
				break;

			case EEXIST:
				err = "map already in table";
				break;
			default:
				err = strerror(oerrno);
				break;
			}
			(void) printf(": %s\n", err);
		}
	}

	exit(ret != 0);

}  /* newmap() */

/*
 * Matches Keyword
 */
int
keyword(cp)
	char *cp;
{
	struct keytab *kt = keywords;

	while (kt->kt_cp && strcmp(kt->kt_cp, cp))
		kt++;

	return kt->kt_i;
}  /* keyword() */ 


/*
 * Interpret an argument as a network address of some kind,
 * returning 1 if a host address, 0 if a network address.
 */
int
getaddr(which, s, hpp)
	int which;
	char *s;
	struct hostent **hpp;
{
  	sup su;
	struct hostent *hp;
	u_long network = 0;
	int subnet = 0;
	char *q;
	int afamily, aflength;  /* local copy of af so we can change it */
	const char * err = NULL;

	map_addrs |= which;

	switch (which) {

	case MAPA_EID:
	        if (afeid == 0) {
		        /* Address family MUST be declared 
			 * before each address 
			 */
		        flush_rloc_chain(); /* Not necessary but be safe */
		        errx(EX_NOPERM, "Address Family must be declared before each address");
		}
	        afamily = afeid;
		aflength = afleneid;
	  	su = &so_eid;
		break;

	case MAPA_RLOC:
	        if (afrloc == 0) {
		        /* Address family MUST be declared 
			 * before each address 
			 */
		        flush_rloc_chain();
		        errx(EX_NOPERM, "Address Family must be declared before each address");
		}
        	afamily = afrloc;
		aflength = aflenrloc;
	        su =  &so_rloc;
		break;
	default:
		usage_exit("Internal Error");
		/*NOTREACHED*/
	}

	su->sa.sa_len = aflength;
	su->sa.sa_family = afamily; 

	switch (afamily) {

	case AF_INET:

	        if (hpp == NULL)
		        hpp = &hp;

	        *hpp = NULL;

		/* Check first if prefix length specified 
		 * In the case of an RLOC this is not allowed 
		 * But error condition is checked in the caller 
		 */
	        q = strchr(s,'/');

	        if (q) {
		        *q = '\0';
		        if ((network = inet_network(s)) != INADDR_NONE) {
			  
			        subnet = strtonum(q+1,0,32, &err);

				if (err) {
			                warnx("Unable to convert \"%s\": %s ", q+1, err);
					usage_exit((char*)NULL);
				};

				inet_makenetandmask(network, &su->sin, subnet);

			        return (0);
		        } else {
			        warnx("Address not valid: %s ", s);
				usage_exit((char*)NULL);
			};
	
			/* NOT REACHED */
	        };

		/* If no prefix length is specified it is assumed 
		 * that we are dealing with host addresses
		 */
		if (which == MAPA_EID  && inet_aton(s, &su->sin.sin_addr)) {
	                network = su->sin.sin_addr.s_addr;
		        return (1);
		        /*NOTREACHED*/ 
		}
		if (which == MAPA_RLOC  && inet_aton(s, &su->sin.sin_addr)) {
	                network = su->sin.sin_addr.s_addr;
		        return (1);
		        /*NOTREACHED*/ 
		}

		/* Address has not been correctly interpreted */
		flush_rloc_chain();
		errx(EX_NOHOST, "bad address: %s", s);
	        /*NOTREACHED*/ 

#ifdef INET6
	case AF_INET6:
	       {
		 struct addrinfo hints, *res;
		 int ecode;

		/* Check first if prefix length specified 
		 * In the case of an RLOC this is not allowed 
		 * But error condition is checked in the caller 
		 */
		 q = NULL;
		 if ((q = strchr(s,'/')) != NULL) 
		        *q = '\0';

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = afamily;	/*AF_INET6*/
		hints.ai_socktype = SOCK_DGRAM;	/*dummy*/

		ecode = getaddrinfo(s, NULL, &hints, &res);
		if (ecode != 0 || res->ai_family != AF_INET6 ||
			             res->ai_addrlen != sizeof(su->sin6)) {
		        flush_rloc_chain();
			errx(EX_NOHOST,"%s: %s\n", s,gai_strerror(ecode));
			        /*NOTREACHED*/ 
		};

       		memcpy(&su->sin6, res->ai_addr, sizeof(su->sin6));

#ifdef __KAME__
		if ((IN6_IS_ADDR_LINKLOCAL(&su->sin6.sin6_addr) ||
		     IN6_IS_ADDR_MC_LINKLOCAL(&su->sin6.sin6_addr)) &&
		    su->sin6.sin6_scope_id) {
			*(uint16_t *)&su->sin6.sin6_addr.s6_addr[2] =
				htons(su->sin6.sin6_scope_id);
			su->sin6.sin6_scope_id = 0;
		}
#endif

		freeaddrinfo(res);
		
		if (q != NULL) {
			*q++ = '/';
		
			subnet = strtonum(q,0,128, &err);
				
			if (err) {
			        warnx("Unable to convert \"%s\": %s ", q+1, err);
				usage_exit((char*)NULL);
			};

		};

		return (inet6_makenetandmask(&su->sin6, subnet, which));


		}

#endif /* INET6 */

	default: 
	        flush_rloc_chain();
	        errx(EX_NOHOST, "bad address: %s", s);
		/*NOTREACHED*/
	}

}  /* getaddr() */


/*
 * Flush the RLOC chain.
 * Function is safe, works also for an empty chain.
 */
void 
flush_rloc_chain(void)
{
       struct srloc * sr = rloc_chain.head;

       while (rloc_chain.head){

	 rloc_chain.head = rloc_chain.head->next;
	 free(sr);

       };

}; /*flush_rloc_chain()*/


/*
 * Generates address and netmask
 */
void
inet_makenetandmask(net, sin, bits)
	u_long net;
	struct sockaddr_in *sin;
	u_long bits;
{
	sin->sin_addr.s_addr = htonl(net);

	if (bits && (bits <32)) {

  	       (void)prefixlen(bits);
	  
	};

}  /*inet_makenetandmask() */


#ifdef INET6
/*
 * XXX the function may need more improvement...
 */
static int
inet6_makenetandmask(sin6, plen, which)
	struct sockaddr_in6 *sin6;
	int plen;
	int which;
{
	struct in6_addr in6;

	if (!plen) {
	       /* This is an host address or 
		*/
		if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr) &&
		    sin6->sin6_scope_id == 0) {

			plen = 0;

		} else if ((sin6->sin6_addr.s6_addr[0] & 0xe0) == 0x20) {
			/* aggregatable global unicast - RFC2374 */

			memset(&in6, 0, sizeof(in6));
			if (!memcmp(&sin6->sin6_addr.s6_addr[8],
				    &in6.s6_addr[8], 8))
				plen = 64;
		};
	}

	if (!plen || (plen == 128))
		return 1;

	(void)prefixlen(plen);

	return 0;

}  /* inet6_makenetandmask() */

#endif

/*
 * Generates EIDMASK
 */
int
prefixlen(len)
        int len;
{
	int q, r;
	int max, af, aflen;
	char *p;

	map_addrs |= MAPA_EIDMASK;
	af = afeid;
	aflen = afleneid;

	switch (af) {

#ifdef INET6
	case AF_INET6:
	        max = 128;
	        p = (char *)&so_eidmask.sin6.sin6_addr;
	        break;
#endif

	case AF_INET:
	        max = 32;
	        p = (char *)&so_eidmask.sin.sin_addr;
	        break;

	default:
	        (void) fprintf(stderr, "prefixlen not supported in this af\n");
		exit(1);
		/*NOTREACHED*/
	
	};

	if (len < 0 || max < len) {
	       (void) fprintf(stderr, "%d: bad value\n", len);
	       exit(1);
	}
	
	q = len >> 3;
	r = len & 7;

	so_eidmask.sa.sa_family = af;
	so_eidmask.sa.sa_len = aflen;

	memset((void *)p, 0, max / 8);
	if (q > 0)
	       memset((void *)p, 0xff, q);
	       
	if (r > 0)
	        *((u_char *)p + q) = (0xff00 >> r) & 0xff;
	       
	if (len == max)
	         return -1;
	else
	         return len;
	
} /* prefixlen() */



/* 
 * Creates a new locator_chain entry and appends it to 
 * rloc_chain.
 * Order does not matter, the kernel will handle this correctly.
 */
void 
append_rloc(void)
{
       struct srloc *newrloc = NULL;
       newrloc = malloc(sizeof(struct srloc));
       union sockunion * pso_rloc = &so_rloc;

       if (newrloc == NULL) {
	      flush_rloc_chain();
              errx(EX_OSERR, "Malloc for new RLOC failed!");	
       };

       rloc_chain.rloc_count++;

       bzero(newrloc, sizeof(struct srloc));
       if (rloc_chain.head == NULL)
	      /* The list is empty */
	      rloc_chain.head = rloc_chain.tail = newrloc;
       else
	      rloc_chain.tail = rloc_chain.tail->next = newrloc;

       bcopy(&so_rloc, &(rloc_chain.tail->rloc.rloc_addr), SA_SIZE(pso_rloc));
       rloc_chain.tail->rloc.metrics.priority = rlocpriority;
       rloc_chain.tail->rloc.metrics.weight = rlocweight;
       rloc_chain.tail->rloc.metrics.flags = rlocflags;
       rloc_chain.tail->rloc.metrics.mtu = rlocmtu;
       if (rloc_chain.tail->rloc.metrics.flags & RLOCF_TXNONCE)
	       rloc_chain.tail->rloc.metrics.tx_nonce.nvalue = rlocnonce;
       

       /* re-initialize */
       bzero(&so_rloc, sizeof(union sockunion));
       rlocpriority = 255;
       rlocweight = 100;
       rlocflags = 0;
       rlocnonce = 0;
       rlocmtu = 0;

}; /* append_rloc() */

/* 
 * Prepare Msg to send through socket.
 */

int
send_mapmsg(cmd, flags)
     int cmd; 
     int flags;
{
	static int seq;
	int rlen;
	char *cp = m_mapmsg.m_space;
	int l;
        struct srloc * sr = rloc_chain.head;

	
#define NEXTADDR(w, u, z)			                 \
	if (map_addrs & (w)) {					 \
	    l = SA_SIZE(&(u.sa)); memmove(cp, &(u), l); cp += l; \
	    if (verboseflag) sodump(&(u), z);			 \
	}
 

#define NEXTRLOC(w, u)						       \
	if (map_addrs & (w)) {					       \
	    l = SS_SIZE(&(u.rloc_addr)); memmove(cp, &(u), l); cp += l;\
	    memmove(cp, &(u.metrics), sizeof(struct rloc_mtx));	       \
	    cp += sizeof(struct rloc_mtx);			       \
	    if (verboseflag) rlocdump(u,"RLOC\t");		       \
	}

	errno = 0;

#define map m_mapmsg.m_map

	switch (cmd) {

	case M_ADD:
	        map.map_type = MAPM_ADD;
		break;

	case M_GET:
	        map.map_type = MAPM_GET;
		break;

	case M_DELETE:
	        map.map_type = MAPM_DELETE;
		break;

	default:
   	        warnx("Command not recognized!");
	        usage_exit((char *)NULL);
	};

	map.map_flags = flags;
	map.map_version = MAPM_VERSION;
	map.map_seq = ++seq;
	map.map_addrs = map_addrs;
	map.map_rloc_count = rloc_chain.rloc_count;
	if (V_bit)
	        map.map_versioning = Vnumber;

	if (map_addrs & MAPA_EIDMASK)
	       /* Chek if address really masked!
		*/
	        mask_addr();
	      
	NEXTADDR(MAPA_EID, so_eid, "EID    ");
	NEXTADDR(MAPA_EIDMASK, so_eidmask, "EIDMASK");

        /*Appending RLOCs */
	while (sr){
	        NEXTRLOC(MAPA_RLOC, sr->rloc);
		sr = sr->next;
	};

	map.map_msglen = l = cp - (char *)&m_mapmsg;

	if (verboseflag)
	        print_mapmsg(&map, l);

	if (debugonlyflag)
		return (0);

	if ((rlen = write(s, (char *)&m_mapmsg, l)) < 0) {
		if (errno == EPERM)
			err(1, "writing to mapping socket");
		warn("writing to mapping socket");
		return (-1);
	};

       	if (cmd == M_GET) {
		do {
			l = read(s, (char *)&m_mapmsg, sizeof(m_mapmsg));
		} while (l > 0 && (map.map_seq != seq || map.map_pid != pid));

		if (l < 0)
			warn("read from mapping socket");
		else
		        print_getmsg(&map, l);
	};
	
#undef map

	return (0);

}  /* send_mapmsg() */

/*
 * Dump socket information
 */
void
sodump(su, which)
	sup su;
	char *which;
{

        char printableaddr[SOCK_MAXADDRLEN]; 

	switch (su->ss.ss_family) {

	case AF_INET:

	        if (inet_ntop(su->ss.ss_family, 
			      &(su->sin.sin_addr), 
			      printableaddr, sizeof(printableaddr)) == NULL ) {
 
	                flush_rloc_chain();
			errx(EFAULT,"Internal Error");
		};

		(void) printf("%s: inet %s\n", which, printableaddr);
		
		break;

	case AF_INET6:

	        if (inet_ntop(su->ss.ss_family, 
			      &(su->sin6.sin6_addr), 
			      printableaddr, sizeof(printableaddr)) == NULL ) { 
		
		        flush_rloc_chain();
			errx(EFAULT,"Internal Error");
		};

		(void) printf("%s: inet6 %s\n", which, printableaddr);
		
		break;

	default:
	  
	        flush_rloc_chain();
		errx(EFAULT,"Internal Error");

	};

	(void) fflush(stdout);

}  /* sodump() */

/*
 *
 */
void
mask_addr()

{

	int olen = so_eidmask.sa.sa_len;
	char *cp1 = olen + (char *)&so_eidmask, *cp2;

	for (so_eidmask.sa.sa_len = 0; cp1 > (char *)&so_eidmask; )
		if (*--cp1 != 0) {
			so_eidmask.sa.sa_len = 1 + cp1 - (char *)&so_eidmask;
			break;
		}

	cp1 = so_eidmask.sa.sa_len + 1 + (char *)&so_eid;
	cp2 = so_eid.sa.sa_len + 1 + (char *)&so_eid;
	while (cp2 > cp1)
		*--cp2 = 0;
	cp2 = so_eidmask.sa.sa_len + 1 + (char *)&so_eidmask;
	while (cp1 > so_eid.sa.sa_data)
		*--cp1 &= *--cp2;

}  /* mask_addr */



void
rlocdump(sr, which)
	struct static_rloc sr;
	char *which;
{

        char printableaddr[SOCK_MAXADDRLEN]; 


	switch (sr.rloc_addr.ss_family) {

	case AF_INET:

	        if (inet_ntop(sr.rloc_addr.ss_family, 
			      &((*(struct sockaddr_in *)&sr.rloc_addr).sin_addr), 
			      printableaddr, sizeof(printableaddr)) == NULL ) {
 
	                flush_rloc_chain();
			errx(EFAULT,"Internal Error");
		};

	        (void) printf("%s: inet  ", which);
		
		break;

	case AF_INET6:

	        if (inet_ntop(sr.rloc_addr.ss_family, 
			      &((*(struct sockaddr_in6 *)&sr.rloc_addr).sin6_addr), 
			      printableaddr, sizeof(printableaddr)) == NULL ) { 
		
		        flush_rloc_chain();
			errx(EFAULT,"Internal Error");
		};

	        (void) printf("%s: inet6 ", which);
		
		break;

	default:
	  
	        flush_rloc_chain();
		errx(EFAULT,"Internal Error");

	};

	(void) printf("%s \t P: %3d  W: %3d  Flags: %s ",
		      printableaddr, sr.metrics.priority,
		      sr.metrics.weight, format_rlocflags(sr.metrics.flags));
	
	if (sr.metrics.mtu) printf("MTU: %4d", sr.metrics.mtu);
	
	printf("\n");

	if (sr.metrics.flags & RLOCF_TXNONCE) 
	  printf("\t\t TxN: %8u", (uint32_t)sr.metrics.tx_nonce.nvalue);

	if (sr.metrics.flags & RLOCF_RXNONCE) 
	        printf(" RxN: %8u", (uint32_t)sr.metrics.rx_nonce.nvalue);

	if (sr.metrics.flags & (RLOCF_TXNONCE | RLOCF_RXNONCE)) 
	        printf("\n");

	(void) fflush(stdout);
	
}  /* rlocdump() */


/*
 * Prepares string for RLOC's flags.
 */
static const char *
format_rlocflags(int f)
{
	static char name[33];
	char *flags;
	struct bits *p = rlocflagsbits;

	for (flags = name; p->b_mask; p++)
		if (p->b_mask & f)
			*flags++ = p->b_val;

	*flags = '\0';

	return (name);

}  /*format_rlocflags() */



/* 
 * Print the map header message
 */
void
print_mapmsg(mapm, msglen)
        struct map_msghdr *mapm;
	int msglen;
{

	if (verboseflag == 0)
		return;

	if (mapm->map_errno)  {
		errno = mapm->map_errno;
		warn("message indicates error %d", errno);
		printf("\n");
	};

	if (msgtypes[mapm->map_type] != NULL)
		(void)printf("%s: ", msgtypes[mapm->map_type]);
	else
		(void)printf("#%d: ", mapm->map_type);

	(void)printf("len %d, ", mapm->map_msglen);
	(void) printf("pid: %ld, seq %d, errno %d \n \t flags: ",
			(long)mapm->map_pid, mapm->map_seq, mapm->map_errno);

	flagprintf(stdout, mapm->map_flags, mapflags);

	(void)printf("\n");

	if (V_bit) 
 	        (void)printf("\t Map Version: %d\n", mapm->map_versioning);

	printmsg(mapm);

} /* print_mapmsg() */

/*
 * Print out map_msg flags
 */
void
flagprintf(fp, bits, flagtbl)
	FILE *fp;
	int bits;
	struct flagtable *flagtbl;
{
	int cp;
	char* sp;
	int gotsome = 0;

	if (bits == 0)
		return;

	while ( flagtbl->ft_f ) {

		if (bits & flagtbl->ft_f) {
		        sp = flagtbl->ft_cp;
			if (gotsome == 0)
				cp = '<';
			else
				cp = ',';
			(void) putc(cp, fp);
			gotsome = 1;
			for (; (cp = *sp); sp++)
				(void) putc(cp, fp);
		};

		flagtbl++;

	};

	if (gotsome)
		(void) putc('>', fp);

} /* flagprintf */

/* 
 * Print content of IP header
 */
void
print_iphdr(struct ip iphdr)
{
  /* Probably there should be some sanity check.
   */

  printf("IPv4 Header\n--------------------------------------->\n");
  
  printf("Version: \t\t %u\n", iphdr.ip_v);
  printf("Protocol: \t\t %u %s\n", iphdr.ip_p, 
	 protocols[iphdr.ip_p].pt_cp);
  printf("Header length: \t\t %u\n",iphdr.ip_hl);
  printf("Type of service: \t 0x%x\n",iphdr.ip_tos);
  printf("Total length: \t\t %u\n",iphdr.ip_len);
  printf("Identification: \t %u\n",iphdr.ip_id);
  printf("Reserved Fragment bit: \t %u\n", (iphdr.ip_off & 0x8000));
  printf("Don't Fragment bit: \t %u\n", (iphdr.ip_off & 0x4000));
  printf("More Fragments bit: \t %u\n", (iphdr.ip_off & 0x2000));
  printf("Offset length: \t\t %u\n", (iphdr.ip_off & 0x1FFF));
  printf("Time to live: \t\t %u\n", iphdr.ip_ttl);
  printf("Checksum: \t\t %u\n", iphdr.ip_sum);
  printf("Source Address:\t\t %s\n", inet_ntoa(iphdr.ip_src));
  printf("Destination Address:\t %s\n", inet_ntoa(iphdr.ip_dst));

}  /* print_iphdr() */


/* 
 * Print content of IP header
 */
void
print_ip6hdr(struct ip6_hdr ip6hdr)
{
  /* Probably there should be some sanity check.
   */
  char ip6addr[SOCK_MAXADDRLEN];

  printf("IPv6 Header\n--------------------------------------->\n");
  printf("Version: \t\t %u\n", (ip6hdr.ip6_vfc >> 4));
  printf("Traffic Class: \t\t %u\n", (ntohs(ip6hdr.ip6_flow) & IPV6_FLOWLABEL_MASK) >> 20 );
  printf("Flow-Id: \t\t %u\n", (ntohs(ip6hdr.ip6_flow) & IPV6_FLOWLABEL_MASK));
  printf("Payload length: \t %u\n", ntohs(ip6hdr.ip6_plen));
  printf("Next Protocol: \t\t %u %s\n", ip6hdr.ip6_nxt, 
	 protocols[ip6hdr.ip6_nxt].pt_cp);
  printf("Hop limit: \t\t %u\n", ip6hdr.ip6_hlim);
  (void) inet_ntop(AF_INET6, &ip6hdr.ip6_src, ip6addr, SOCK_MAXADDRLEN);
  printf("Source Address:\t\t %s\n", ip6addr);
  (void) inet_ntop(AF_INET6, &ip6hdr.ip6_dst, ip6addr, SOCK_MAXADDRLEN);
  printf("Destination Address:\t %s\n", ip6addr);
 
}  /* print_ip6hdr() */

void
print_payload(char * payload, uint32_t len)
{
  int i = 0;
  int byteperline = 8;
  char hexbuffer[1024];
  char asciibuffer[1024];
  char * hcp = hexbuffer;
  char * acp = asciibuffer;

  bzero(hexbuffer, 1024);
  bzero(asciibuffer, 1024);

  printf("\nPrinting %u bytes payload:\n--------------------------------------->\n", len);


  while ( i < len ) {

      ( ((uint8_t)payload[i] > 0x0F) ? 
      sprintf(hcp," %X", (uint8_t)payload[i]) :
      sprintf(hcp," 0%X", (uint8_t)payload[i]));

      ( (((uint8_t)payload[i] > 0x1F) && ((uint8_t)payload[i] < 0x7F) ) ? 
	(*acp = payload[i]) :
	(*acp = '.') );

      acp++;
      hcp += 3;

      i++;

      if ( (i%byteperline) == 0 ) {
	printf("%s \t %s\n", hexbuffer, asciibuffer);
	bzero(hexbuffer, 1024);
	bzero(asciibuffer, 1024);
	hcp = hexbuffer;
	acp = asciibuffer;

      };
      

  };

  if (i%byteperline) {

    while ( i%byteperline) {

      sprintf(hcp,"   ");
      hcp += 3;
      i++;

    };

    printf("%s \t %s\n", hexbuffer, asciibuffer);

  };


}  /*print_payload() */


/*
 * Print the trailing the mapmsg header
 */
void
printmsg(mapm)
	struct map_msghdr *mapm;
{
        char *cp = (char *)(mapm + 1);
	int addrs = mapm->map_addrs;
	int numrlocs = mapm->map_rloc_count;

	struct sockaddr *sa;
	int i, flags;
	uint32_t payloadlen = 0;
	uint32_t mtu;
	struct nonce_type rxnonce, txnonce;
	struct ip iphdr;
	struct ip6_hdr ip6hdr;

	if (addrs == 0) {
		(void) putchar('\n');
		return;
	}

	(void) printf("\t Sockaddrs: ");

	flagprintf(stdout, addrs, addrnames);

	printf("\n");

	if (mapm->map_flags & MAPF_VERSIONING) {
	        printf("\t Version: %u\n", mapm->map_versioning);
	};

	for (i = 1; i; i <<= 1)

	  switch (i & addrs) {

	  case MAPA_EID:
	  case MAPA_EIDMASK:
	          sa = (struct sockaddr *)cp;
		  (void) printf("\t %s\n", mapaddr(sa));
		  cp += SA_SIZE(sa);
		  break;

	  case MAPA_RLOC:
	    
	          (void) printf("\t RLOCS: %d\n",mapm->map_rloc_count);

	          while (numrlocs--) {
		          sa = (struct sockaddr *)cp;
			  (void) printf("\t %s", mapaddr(sa));
			  cp += SA_SIZE(sa);
			  (void) printf(" %d", (uint8_t) *cp++);
			  (void) printf(" %d", (uint8_t) *cp++);
			  bcopy(cp, &flags, sizeof(uint16_t));    
			  cp += sizeof(uint16_t); /* flags are uint16_t */
			  if (flags & RLOCF_UP) { 
			          (void)printf(" Up");
			  } else { 
			          (void)printf(" Down");
			  };
			  if (flags & RLOCF_LIF)  
			          (void)printf(" LocalIf");
			  bcopy(cp, &mtu, sizeof(uint32_t));
			  cp += sizeof(uint32_t); /* mtu is uint32_t */
			  (void)printf(" MTU %d", mtu);
			  bcopy(cp, &txnonce, sizeof(struct nonce_type));
			  cp += sizeof(struct nonce_type); 
			  if (flags & RLOCF_TXNONCE) { 
			          (void)printf(" TX Nonce %u", txnonce.nvalue);
			  };
			  bcopy(cp, &rxnonce, sizeof(struct nonce_type));    
			  cp += sizeof(struct nonce_type);
			  if (flags & RLOCF_RXNONCE) { 
			          (void)printf(" RX Nonce %u", rxnonce.nvalue);
			  };

			  (void) putchar('\n');

		  };
	  
		  break;

	  };
	
	(void) putchar('\n');

	if ( mapm->map_type == MAPM_MISS_HEADER )  {
	 
	        switch ( ((struct ip *)cp)->ip_v ) {

		case IPVERSION:
		  
		        bcopy(cp, &iphdr,  sizeof(struct ip));
			cp += sizeof(struct ip);

			print_iphdr(iphdr);

			break;

		case (IPV6_VERSION >> 4):

		        bcopy(cp, &ip6hdr,  sizeof(struct ip6_hdr));
			cp += sizeof(struct ip6_hdr);
		
			print_ip6hdr(ip6hdr);
		
			break;

		};
	   
	};

	if ( mapm->map_type == MAPM_MISS_PACKET ) {
	  /* Need to print packet content 
	   */
	        switch ( ((struct ip *)cp)->ip_v ) {

		case IPVERSION:
		  
		        bcopy(cp, &iphdr,  sizeof(struct ip));
			cp += sizeof(struct ip);
			payloadlen = iphdr.ip_len - (iphdr.ip_hl << 2);

			print_iphdr(iphdr);

			break;

		case (IPV6_VERSION >> 4):

		        bcopy(cp, &ip6hdr,  sizeof(struct ip6_hdr));
			cp += sizeof(struct ip6_hdr);
			payloadlen = ntohs(ip6hdr.ip6_plen);
		
			print_ip6hdr(ip6hdr);
		
			break;

		};
	  
		print_payload(cp, payloadlen);

	};

	

	(void) fflush(stdout);

}  /* printmsg() */

/*
 * Print Address
 */
const char *
mapaddr(sa)
	struct sockaddr *sa;
{
	static char line[MAXHOSTNAMELEN + 1];
	static char domain[MAXHOSTNAMELEN + 1];
	static int first = 1, n;
  	char *cp;
	struct hostent *hp;

	if (first) {
		first = 0;
		if ((gethostname(domain, MAXHOSTNAMELEN) == 0)
		    && (cp = strchr(domain, '.'))) {
			domain[MAXHOSTNAMELEN] = '\0';
			(void) strcpy(domain, cp + 1);
		} else {
			domain[0] = 0;
		};
	};

	if (sa->sa_len == 0)
		strcpy(line, "default");

	else {
	        switch (sa->sa_family) {

	        case AF_INET: {

		        struct in_addr in = ((struct sockaddr_in *)sa)->sin_addr;

			cp = 0;
			if (in.s_addr == INADDR_ANY || sa->sa_len < 4)
			         cp = "default";
	
			if (cp == 0 && !nameflag) {
			        hp = gethostbyaddr((char *)&in, 
						   sizeof (struct in_addr),
						   AF_INET);
				if (hp) {
				        if ((cp = strchr(hp->h_name, '.')) &&
					    !strcmp(cp + 1, domain))
					        *cp = 0;

					cp = hp->h_name;
				};
			};
	
			if (cp) {
			        strncpy(line, cp, sizeof(line) - 1);
				line[sizeof(line) - 1] = '\0';
			} else
			        (void) sprintf(line, "%s", inet_ntoa(in));

			break;
		};
		  
#ifdef INET6
	        case AF_INET6: {

		        struct sockaddr_in6 sin6; 
			int niflags = 0;

			memset(&sin6, 0, sizeof(sin6));
			memcpy(&sin6, sa, sa->sa_len);
			sin6.sin6_len = sizeof(struct sockaddr_in6);
			sin6.sin6_family = AF_INET6;

#ifdef __KAME__
			if (sa->sa_len == sizeof(struct sockaddr_in6) &&
			    (IN6_IS_ADDR_LINKLOCAL(&sin6.sin6_addr) ||
			     IN6_IS_ADDR_MC_LINKLOCAL(&sin6.sin6_addr)) &&
			    sin6.sin6_scope_id == 0) {
			        sin6.sin6_scope_id =
				  ntohs(*(uint16_t *)&sin6.sin6_addr.s6_addr[2]);
				sin6.sin6_addr.s6_addr[2] = 0;
				sin6.sin6_addr.s6_addr[3] = 0;
			};
#endif
			if (nameflag)
			        niflags |= NI_NUMERICHOST;

			if (getnameinfo((struct sockaddr *)&sin6, sin6.sin6_len,
					line, sizeof(line), NULL, 0, 
					niflags) != 0)
			        strncpy(line, "invalid", sizeof(line));

		        break;
		};
#endif

	        default: {
		        uint8_t *s = (uint8_t *)sa;
			uint8_t *slim = s + ((sa->sa_len + 1) >> 1);
			char *cp = line + sprintf(line, "(%d)", sa->sa_family);
			char *cpe = line + sizeof(line);

			while (++s < slim && cp < cpe) { 
			       /* start with sa->sa_data */
			        if ((n = snprintf(cp, cpe - cp, " %x", *s)) > 0)
				        cp += n;
				else
				        *cp = '\0';
			}; 

			break;
		  
		};
		
		};

	};

	return (line);

}  /* mapaddr() */


/*
 * Print GET messages
 */
void
print_getmsg(mapmsg, mapmsglen)
	struct map_msghdr *mapmsg;
	int mapmsglen;
{
        struct sockaddr_storage *eid = NULL, *eidmask = NULL; 
	char * rloc = NULL;
	struct sockaddr_storage *ss;
	char *cp;
	int i, rlocnumber = 0;
	struct static_rloc sr;
  
        printf("Mapping for EID: %s\n", mapaddr(&so_eid));

	if (mapmsg->map_version != MAPM_VERSION) {
		warnx("mapping message version %d not understood",
		     mapmsg->map_version);
		return;
	};

	if (mapmsg->map_msglen > mapmsglen) {
		warnx("message length mismatch, in packet %d, returned %d",
		      mapmsg->map_msglen, mapmsglen);
	};

	if (mapmsg->map_errno)  {
		errno = mapmsg->map_errno;
		warn("message indicates error %d", errno);
		return;
	};

	cp = ((char *)(mapmsg + 1));

	if (mapmsg->map_addrs) {
	        for (i = 1; i; i <<= 1) {
			if (i & mapmsg->map_addrs) {
				ss = (struct sockaddr_storage *)cp;
				switch (i) {
				case MAPA_EID:
					eid = ss;
					break;
				case MAPA_EIDMASK:
					eidmask = ss;
					break;
				case MAPA_RLOC:
				        rloc = (char *)ss;
					rlocnumber = mapmsg->map_rloc_count;

					break;

				};
				cp += SS_SIZE(ss);
			};
		};
	};

	if (eid && eidmask)
		eidmask->ss_family = eid->ss_family;	/* XXX */

	if (eid)
		printf("EID    : %s\n", mapaddr(eid));

	if (eidmask) {
		int savenflag = nameflag;
		nameflag = 1;
		printf("EIDMASK: %s\n", mapaddr(eidmask));
		nameflag = savenflag;
	};


	if (rloc) {
	        cp = rloc;  /* GgX - Re-initialize cp */	
	        /* GgX - double check rloc and rlocnumber */
	        while (rlocnumber--) {
		        bcopy(cp, &sr.rloc_addr, SS_SIZE(cp));
			cp += SS_SIZE(&sr.rloc_addr);
			bcopy(cp, &sr.metrics, sizeof(struct rloc_mtx));    
			cp += sizeof(struct rloc_mtx); 
			rlocdump(sr,"RLOC   ");
		};
	};

	if (mapmsg->map_flags & MAPF_VERSIONING) {
	        printf("Version: %u\n", mapmsg->map_versioning);
	};
  
	printf("Flags  : ");

	flagprintf(stdout, mapmsg->map_flags, mapflags);

	printf("\n");
	
	if (verboseflag)
		printmsg(mapmsg);
	
	
} /* print_getmsg() */











