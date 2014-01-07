/*- /usr/src/sys/net/lisp/lisp.c
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
 * $Id: lisp.c 177 2011-09-22 14:33:51Z ggx $
 *
 */

#include "opt_inet.h"
#include "opt_inet6.h"
#include "opt_lisp.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/domain.h>
#include <sys/eventhandler.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mac.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/signalvar.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sx.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>

#include <vm/uma.h>
 
#include <net/if.h>
#include <net/route.h>
#include <net/netisr.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#ifdef INET6
#include <netinet/ip6.h>
#endif
#include <netinet/ip_icmp.h>
#include <netinet/icmp_var.h>
#include <netinet/ip_var.h>
#ifdef INET6
#include <netinet6/ip6_var.h>
#endif

#include <net/lisp/lisp.h>
#include <net/lisp/maptables.h>


/* Sysctl Declaration
 */

SYSCTL_NODE(_net, OID_AUTO, lisp, CTLFLAG_RW, 0, "General LISP node");

int lispdebug = 0;
SYSCTL_INT(_net_lisp, OID_AUTO, debug, CTLFLAG_RW, &lispdebug, 0, 
	   "Debug Mode LISP");

/*PCD*/
int xtr_te = 0;
SYSCTL_INT(_net_lisp, OID_AUTO, te, CTLFLAG_RW, &xtr_te, 0, 
	   "Debug Mode LISP");

/*DPC*/
extern struct mappingstats mappingstats;
SYSCTL_STRUCT(_net_lisp, OID_AUTO, maptables, CTLFLAG_RW,
	      &mappingstats, mappingstats, 
	      "LISP Database and Cache stats (struct mappingstat, net/lisp/maptables.h)");


int
sysctl_matchkeyword(char *cp, struct keytab * keywords)
{
	struct keytab *kt = keywords;

	while (kt->cptr && strcmp(kt->cptr, cp))
		kt++;
	return kt->seq;

} /* sysctl_matchkeyword() */

/* Sysctl for source port selection in LISP encapsulated packets
 * - lispdata: Use LISP reserved port 4341 as source port.
 * - shorthash: perform hash on the following field of the original 
 *       packet <src IP, dst IP, Proto Number >.
 * - longhash: perform hash on the following field of the original 
 *       packet <src IP, dst IP, Proto Number, src Port, dst Port>. 
 *       Actually there is no check if the protocol is UDP/TCP/SCTP
 *       the bytes in the corresponding position are read and used
 *       for the hash computation.
 * - adaptivehash: perform a longhash for UDP/TCP/SCTP packets but short  *       hash for the rest.
 */

struct keytab srcport_keywords[] = {

#define SRCPORT_LISPDATA      1
        {"lispdata", SRCPORT_LISPDATA},

#define SRCPORT_SHORTHASH     2
        {"shorthash", SRCPORT_SHORTHASH},

#define SRCPORT_LONGHASH      3
        {"longhash", SRCPORT_LONGHASH},

#define SRCPORT_ADAPTIVEHASH  4
        {"adaptivehash", SRCPORT_ADAPTIVEHASH},

	{0, 0}
};

static char lisp_src_port_string[LISPMAXSTRLEN] = "lispdata\0";
static int  lispsrcport = SRCPORT_LISPDATA; 

static int
sysctl_net_lisp_srcport(SYSCTL_HANDLER_ARGS)
{
  
        int error = 0;
	int new = 0;
	char tmpvalue[LISPMAXSTRLEN];

	strcpy(tmpvalue, lisp_src_port_string);

	error = sysctl_handle_string(oidp, lisp_src_port_string, 
				     LISPMAXSTRLEN, req);
	
	if (error || req->newptr == NULL) 
	        return (error);

	if ( !(new = sysctl_matchkeyword(lisp_src_port_string, 
					 srcport_keywords)) ) {

	        strcpy(lisp_src_port_string, tmpvalue);
  	        return(EINVAL);
	 
	};

	lispsrcport = new;
   
         return (0);

}  /* sysctl_net_lisp_srcport() */

SYSCTL_PROC(_net_lisp, OID_AUTO, srcport, CTLTYPE_STRING | CTLFLAG_RW,
	    0, 0, sysctl_net_lisp_srcport, "A", 
	    "Algorithm used to set source port in LISP encapsulated packets");

int lisphashseed = LISPDATA;
SYSCTL_INT(_net_lisp, OID_AUTO, hashseed, CTLFLAG_RW, &lisphashseed, 0, 
	   "Seed for Source Port selection Hash function (ignored if srcport is on <lispdata> mode");


/* Sysctl for miss messages type:
 * - ip: the miss message returns only the destination EID (IP address)
 *       that generated the miss. This is the default setting.
 * - header: the miss message returns the complete IP header of the 
 *           packet that generated the miss. 
 * - packet: the miss message returns the entire packet that generated 
 *           the miss.
 */

struct keytab missmsg_keywords[] = {

        {"eid", LISP_MISSMSG_EID},

        {"header", LISP_MISSMSG_HEADER},

        {"packet", LISP_MISSMSG_PACKET},

	{0, 0}
};


static char lisp_miss_msg_string[LISPMAXSTRLEN] = "eid\0";
int  lispmissmsg = LISP_MISSMSG_EID; 

static int
sysctl_net_lisp_missmsg(SYSCTL_HANDLER_ARGS)
{
  
        int error = 0;
	int new = 0;
	char tmpvalue[LISPMAXSTRLEN];

	strcpy(tmpvalue, lisp_miss_msg_string);

	error = sysctl_handle_string(oidp, lisp_miss_msg_string, 
				     LISPMAXSTRLEN, req);
	
	if (error || req->newptr == NULL) 
	        return (error);

	if ( !(new = sysctl_matchkeyword(lisp_miss_msg_string, 
					 missmsg_keywords)) ) {

	        strcpy(lisp_miss_msg_string, tmpvalue);
  	        return(EINVAL);
	 
	};

	lispmissmsg = new;
   
         return (0);

}  /* sysctl_net_lisp_missmsg() */

SYSCTL_PROC(_net_lisp, OID_AUTO, missmsg, CTLTYPE_STRING | CTLFLAG_RW,
	    0, 0, sysctl_net_lisp_missmsg, "A", 
	    "Type of message returned to the userspace upon cache miss");


/* Sysctl for ETR policy:
 * - standard (default): If an entry exists for the destination EID in the 
 *         Database, then the packet is decapsulated and forwarded 
 *         regardless if it exists an entry for the source EID into the 
 *         cache. This is in accordance with the main specs
 *         draft-ietf-lisp-06.txt.
 * - notify: If an entry exists for the destination EID in the Database, 
 *         then the packet is decapsulated and forwarded, 
 *         if there is no entry in the Cache for the source EID a miss 
 *         message is generate. 
 * - secure: If an entry exists for the destination EID in the Database, 
 *         then the packet is decapsulated only if an entry exists in the 
 *         Cache for the source EID, otherwise a miss message is generated 
 *	   and the packet is dropped.
 *
 * In all cases, if the entry in the cache exists, sanity checks are 
 * performed.
 */

struct keytab ETR_keywords[] = {

        {"standard", LISP_ETR_STANDARD},

        {"notify", LISP_ETR_NOTIFY},

        {"secure", LISP_ETR_SECURE},

	{0, 0}
};

/*PCD - patch */
struct keytab FLISP_keywords[] = {

        {"xtr", LISP_XTR},

        {"pxtr", LISP_PXTR},

        {"rtr", LISP_RTR},

	{0, 0}
};

/*PCD*/

static char lisp_etr_string[LISPMAXSTRLEN] = "standard\0";
int  lispetr = LISP_ETR_STANDARD;
/*PCD*/
static char lisp_func_string[LISPMAXSTRLEN] = "xtr\0";
int  lispfunc = LISP_XTR; 

static int
sysctl_net_lisp_func(SYSCTL_HANDLER_ARGS)
{
  
        int error = 0;
	int new = 0;
	char tmpvalue[LISPMAXSTRLEN];

	strcpy(tmpvalue, lisp_func_string);

	error = sysctl_handle_string(oidp, lisp_func_string, 
				     LISPMAXSTRLEN, req);
	
	if (error || req->newptr == NULL) 
	        return (error);

	if ( !(new = sysctl_matchkeyword(lisp_func_string, 
					 FLISP_keywords)) ) {

	        strcpy(lisp_func_string, tmpvalue);
  	        return(EINVAL);
	 
	};

	lispfunc = new;
   
         return (0);

}
/*DPC*/
static int
sysctl_net_lisp_etr(SYSCTL_HANDLER_ARGS)
{
  
        int error = 0;
	int new = 0;
	char tmpvalue[LISPMAXSTRLEN];

	strcpy(tmpvalue, lisp_etr_string);

	error = sysctl_handle_string(oidp, lisp_etr_string, 
				     LISPMAXSTRLEN, req);
	
	if (error || req->newptr == NULL) 
	        return (error);

	if ( !(new = sysctl_matchkeyword(lisp_etr_string, 
					 ETR_keywords)) ) {

	        strcpy(lisp_etr_string, tmpvalue);
  	        return(EINVAL);
	 
	};

	lispetr = new;
   
         return (0);

}  /* sysctl_net_lisp_etr() */

SYSCTL_PROC(_net_lisp, OID_AUTO, etr, CTLTYPE_STRING | CTLFLAG_RW,
	    0, 0, sysctl_net_lisp_etr, "A", 
	    "ETR behavior for incoming LISP encapsulated packets");

/*PCD*/
SYSCTL_PROC(_net_lisp, OID_AUTO, function, CTLTYPE_STRING | CTLFLAG_RW,
	    0, 0, sysctl_net_lisp_func, "A", 
	    "LISP data plane function: xtr, pxtr, rte");

/*DPC*/

/*
 * The following are hash functions developped by Bob Jenkins
 * and publicly available at http://burtleburtle.net/bob/c/lookup3.c
 * They are used to produce the hash value to put in the 
 * source port number of the LISP encapsulation.
 *
 */

#define rot(x,k) (((x)<<(k)) | ((x)>>(32-(k))))

/*
-------------------------------------------------------------------------------
mix -- mix 3 32-bit values reversibly.
-------------------------------------------------------------------------------
*/
#define mix(a,b,c) \
{ \
  a -= c;  a ^= rot(c, 4);  c += b; \
  b -= a;  b ^= rot(a, 6);  a += c; \
  c -= b;  c ^= rot(b, 8);  b += a; \
  a -= c;  a ^= rot(c,16);  c += b; \
  b -= a;  b ^= rot(a,19);  a += c; \
  c -= b;  c ^= rot(b, 4);  b += a; \
}

/*
-------------------------------------------------------------------------------
final -- final mixing of 3 32-bit values (a,b,c) into c
-------------------------------------------------------------------------------
*/
#define final(a,b,c) \
{ \
  c ^= b; c -= rot(b,14); \
  a ^= c; a -= rot(c,11); \
  b ^= a; b -= rot(a,25); \
  c ^= b; c -= rot(b,16); \
  a ^= c; a -= rot(c,4);  \
  b ^= a; b -= rot(a,14); \
  c ^= b; c -= rot(b,24); \
}

/*
--------------------------------------------------------------------
 This works on all machines.  To be useful, it requires
 -- that the key be an array of uint32_t's, and
 -- that the length be the number of uint32_t's in the key
--------------------------------------------------------------------
*/
static uint32_t hashword(
const uint32_t *k,                   /* the key, an array of uint32_t values */
size_t          length,               /* the length of the key, in uint32_ts */
uint32_t        initval)         /* the previous hash, or an arbitrary value */
{
  uint32_t a,b,c;

  /* Set up the internal state */
  a = b = c = 0xdeadbeef + (((uint32_t)length)<<2) + initval;

  /*------------------------------------------------- handle most of the key */
  while (length > 3)
  {
    a += k[0];
    b += k[1];
    c += k[2];
    mix(a,b,c);
    length -= 3;
    k += 3;
  }

  /*------------------------------------------- handle the last 3 uint32_t's */
  switch(length)                     /* all the case statements fall through */
  { 
  case 3 : c+=k[2];
  case 2 : b+=k[1];
  case 1 : a+=k[0];
    final(a,b,c);
  case 0:     /* case 0: nothing left to add */
    break;
  }
  /*------------------------------------------------------ report the result */
  return c;
}

/* Routine to provide src port based on sysctl selection
 */
uint16_t 
get_lisp_srcport( m )
     struct mbuf ** m;
{
        uint32_t  keyarray[MAXKEYLEN];
	uint32_t  hash;
	uint16_t  port;
	int  skipsize = 0; 
	int keylen = 0;
	struct ip * ip = NULL;
	struct ip6_hdr * ip6 = NULL;

	bzero(keyarray,(MAXKEYLEN*4));

	if ( lispsrcport == SRCPORT_LISPDATA ) {
	       /* This is the easy and fast case
		*/

                hash = LISPDATA;

	} else {

	       /* In the following do not care about network and host 
		* byte order, we just want to have an hash value.
		*/
	        ip = mtod((*m), struct ip *);

		switch (ip->ip_v) {
	
		case IPVERSION:

		        keyarray[keylen++] = (uint32_t) ip->ip_src.s_addr;
			keyarray[keylen++] = (uint32_t) ip->ip_dst.s_addr;
			keyarray[keylen++] = ip->ip_p;
			skipsize = sizeof(struct ip);

			break;

		case (IPV6_VERSION >> 4):

		        ip6 = mtod((*m), struct ip6_hdr *);
			bcopy( &(ip6->ip6_src), &keyarray[keylen],
			      ( 2 * sizeof(struct in6_addr) )  );
			keylen += 8; /* number of uint32_t for 2 IPv6 addr */
			keyarray[keylen++] = ip6->ip6_nxt;
			skipsize = sizeof(struct ip6_hdr);

			break;

		default:
	  
		        hash = LISPDATA;
			/* GgX - Should generate an error??? 
			 */
		};

		
		switch ( lispsrcport ) {
	  
		case SRCPORT_ADAPTIVEHASH:

		        if ( (keyarray[keylen-1] != IPPROTO_UDP) &&
			     (keyarray[keylen-1] != IPPROTO_TCP) &&
			     (keyarray[keylen-1] != IPPROTO_SCTP) )
			       /* Last inserted item is the protocol number.
				* If it is UDP, TCP, or SCTP fall through and 
				* take the ports number. 
				*/ 
			        break;
 
		case SRCPORT_LONGHASH:
	 
		       /* Be sure we can access port numbers*/
		        (*m) = m_pullup((*m), skipsize + sizeof(uint32_t) );
			if ( (*m) == NULL )
			       /* GgX - Should handle error differently?
				*/
			        return(0);
			  
			keyarray[keylen++] = *(uint32_t *)(mtod((*m), caddr_t) + skipsize);

			break;

		default:
		       /* This should really never happen!
			*/
		        hash = LISPDATA;

		};
		
	        hash = hashword(keyarray, keylen, lisphashseed);

	};


       /* Reduce the hash on 16 bits */
        port = *((uint16_t *)&hash) + *(((uint16_t *)&hash)+1);

	return(port);

}  /* get_lisp_srcport() */




void
m_copylisphdr(m, lisphdr)
	register struct mbuf **m;
	struct lispshimhdr * lisphdr;
{
	(*m) = m_pullup((*m), sizeof(struct lispshimhdr));

	/* Previous check should guarantee that the LISP header is there
	 * but for safety let's check again.
	 */

	if ( m ) {
	   
	        m_copydata((*m),0, sizeof(struct lispshimhdr),(caddr_t) lisphdr);

	};

}  /* m_copylisphdr() */



struct mbuf *
m_lisphdrprepend( m, remotemap, localmap, drloc, srloc)
       struct mbuf *m;	
       struct eidmap * remotemap;
       struct eidmap * localmap;
       struct locator * drloc;
       struct locator * srloc;
/* 
 * Prepends the lisp header to the mbuf m
 */
{
        struct lispshimhdr * hdrptr = NULL; 
  
        M_PREPEND(m, sizeof(struct lispshimhdr), M_DONTWAIT);

	if ( m ) {
	   
	        hdrptr = mtod(m, struct lispshimhdr *);
		bzero( hdrptr, sizeof(struct lispshimhdr));
	
		/* Added destination dependent infos
		 */

		if ( drloc->rloc_metrix.rlocmtx.flags & RLOCF_TXNONCE ) {

		       /* Set N bit and copy the nonce
			*/
		        hdrptr->Nbit = 1;
			hdrptr->Nonce = drloc->rloc_metrix.rlocmtx.tx_nonce.nvalue;

		};
		/*PCD*/
		if( lispfunc == LISP_XTR){
			if ( (localmap->mapping->map_flags & MAPF_VERSIONING) 
				 &&  (remotemap->mapping->map_flags & MAPF_VERSIONING) ) {

					   /* Copy the version numbers
					*/
						hdrptr->Vbit = 1;
						hdrptr->Dvnum = remotemap->mapping->vnum;
						hdrptr->Svnum = localmap->mapping->vnum;

			} else if (localmap->mapping->map_flags & MAPF_LOCBITS ) {
					   /* Remote ETR does not support versioning
					* If necessary put
					* Locator Status Bits.
					*/
					hdrptr->Lbit = 1;
					hdrptr->LSbits = localmap->mapping->rlocs_statusbits;
					
			};			     
		};
		/*DPC*/
	};


	return m;

}  /* m_lisphdrprepend() */


int
check_lisphdr( lisphdr, localmap, remotemap, drloc, srloc, why)
     struct lispshimhdr * lisphdr;
     struct eidmap localmap; 
     struct eidmap remotemap;
     struct locator * drloc;
     struct locator * srloc;
     int *why;
{
	struct map_addrinfo info;
	int err = 0, msgtype = 0; 

	*why = 0;

	if  (lisphdr == NULL)  {
	       
#ifdef LISP_DEBUG
		DEBUGLISP("[MAP_CHECK_RBITS] Received NULL pointer \n");
#endif /* LISP_DEBUG */

	        return(EINVAL);
	};
	  
	bzero(&info, sizeof(info));	

	if  (lisphdr->Nbit) {
	       /* Received LISP Header contains a nonce.
		*/

	        if ( (remotemap.mapping) && (drloc) ) {
		       /* LISP header contains nonce and we have 
			* an entry in the cache. By now we just 
			* copy the last received nonce
			*/

		        drloc->rloc_metrix.rlocmtx.flags |= RLOCF_RXNONCE;
			drloc->rloc_metrix.rlocmtx.rx_nonce.nvalue = lisphdr->Nonce;
		
		};

	} else if (lisphdr->Vbit)  {
		          /* Versioning bit is set.
		           */
		   
	        if ( MASKVNUM(ntohs(lisphdr->Dvnum)) &&
		     (localmap.mapping->map_flags & MAPF_VERSIONING) &&
		     ((lisphdr->Dvnum) != (localmap.mapping->vnum)) ) {
	  
		             if ( NEWERVNUM(ntohs(localmap.mapping->vnum),
					    ntohs(lisphdr->Dvnum)) ) {
			            /* Received version DST version number 
				     * newer that the one stored in the DB.
				     * Could not happen since the system is 
				     * authoritative on the mapping
				     */
			            err = EINVAL;
				    *why = ELISP_DSTVNUMINVAL;

			     } else {
			            /* Received version DST version number 
				     * older that the one stored in the DB.
				     * Notify Control Plane.
				     */

			             msgtype = MAPM_REMOTESTALE;

			     }; 

		} else if ( (remotemap.mapping) &&
			    (remotemap.mapping->map_flags & MAPF_VERSIONING) &&  
			    MASKVNUM(ntohs(lisphdr->Svnum)) &&
			    ((lisphdr->Svnum) != (remotemap.mapping->vnum)) ) {

		        if ( NEWERVNUM(ntohs(remotemap.mapping->vnum),
				       ntohs(lisphdr->Svnum)) ) {
			       /* Received version SRC version number 
				* newer that the one stored in the 
				* Cache.
				*/

			        msgtype = MAPM_LOCALSTALE;

			} else {
			       /* Received version SRC version number 
				* older that the one stored in the 
				* Cache.
				*/
		        
			       /* This is too strict (causing drops), 
				* but can work for early tests.
				*/

			        err = EINVAL;
				*why = ELISP_SRCVNUMINVAL;

			};

		};
			
	};

	
	if (!msgtype) {

	       if (lisphdr->Lbit) {
	              /* Locator Status Bit is set and something changed 
		       * notify otherwise do nothing.
		       */

		       if (  (remotemap.mapping) && (drloc) && 
			     ((lisphdr->LSbits) != (remotemap.mapping->rlocs_statusbits)) ) {
			       /* If there is an entry in the cache and 
				* Received status bits have changed.
				* Notify the Control Plane about this change.
				* Changes are actually not sent. User space 
				* processes interested in the change must 
				* perform a GET.
				*/

			        msgtype = MAPM_LSBITS;

		       };

	       } else if (lisphdr->Ibit)  {
		          /* Instance ID bit is set.
			   * The Instance ID is just ignored right now.
			   * This means ignoring also the short LS
			   * bits.
		           */
	       };
	       
	};
	  
	if (msgtype) {

	          info.mapi_addrs |= MAPA_EID;
		  info.mapi_info[MAPX_EID] = (struct sockaddr_storage *)map_key(remotemap.mapping);
		  map_notifymsg(msgtype, &info, NULL, NULL, 0, &err);

	  };

	  return err;

}  /* check_lisphdr() */


