/*- /usr/src/sys/netinet/lisp/ip_lisp.c
 *
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
 * $Id: ip_lisp.c 178 2011-09-22 14:50:11Z ggx $
 *
 */

/*
 * Copyright (c) 1982, 1986, 1988, 1990, 1993, 1995
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
 *
 *	@(#)udp_usrreq.c	8.6 (Berkeley) 5/23/95
 * $FreeBSD: src/sys/netinet/udp_usrreq.c,v 1.175.2.8 2006/10/06 20:26:06 andre Exp $
 */

#include "opt_ipfw.h"
#include "opt_ipsec.h"
#include "opt_inet6.h"
#include "opt_mac.h"
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
#include <sys/types.h>
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
#include <netinet/udp.h>
#include <netinet/udp_var.h>

#include <net/lisp/lisp.h>
#include <net/lisp/maptables.h>

#include <netinet/lisp/ip_lisp.h>

#include <netinet6/lisp6/ip6_lisp6.h>

#include <machine/in_cksum.h>


/* IPv4 Related Stats */
struct  lispbasicstat lisp4stat;

/* Link to IPv6 Stats variable */
extern struct lispbasicstat lisp6stat;

/* Sysctl Declarations specific to IPv4.
 */

SYSCTL_NODE(_net_inet, OID_AUTO, lisp, CTLFLAG_RW, 0, "IPv4 related LISP node");

SYSCTL_STRUCT(_net_inet_lisp, OID_AUTO, stats, CTLFLAG_RW,
	      &lisp4stat, lispbasicstat, 
	      "LISP IPv4 stats (struct lispbasicstat, net/lisp/lisp.h)");


extern  struct protosw inetsw[];


int 
lisp_ip_mapencap( m, flags, local_map, remote_map)
        struct mbuf ** m;
        int flags;
	struct eidmap ** local_map;
	struct eidmap ** remote_map;
/*
 * The function check if it exists in the mapping table a mapping 
 * for the source EID and destination EID. 
 * Function return 0 if no error is generated.
 *
 * If source EID mapping does not exist or is a negative mapping 
 * both *local_map and *remote_map are returned as NULL. 
 * The same if a source EID mapping exists but the mapping for the 
 * destination EID is a negative mapping.
 *
 * Otherwise *local_map and *remote_map will contain pointer to an eidmap 
 * structure containing the mapping.
 *
 * Note that in this latter case *remote_map can be NULL
 * since it is just the case of a cache miss.
 * Whether to do dataprobe or not is up to lisp_output (or the 
 * consumer of the result).
 */
{
        struct ip * ip = NULL;
	struct eidmap * localmap = NULL;
	struct eidmap * remotemap = NULL;
	struct map_addrinfo info;
	int err = 0;

        if (flags & IP_LISP) {
	       /* The packet has already been LISP-encapsulated:
		*/
	        return 0;
	};

	ip = mtod( (*m), struct ip *);

       /* Source address validation */
        if ( ip->ip_src.s_addr == INADDR_ANY ) {
	       /* Source Address not yet defined, encapsulation not possible.
		*/
	        return 0;
	};

	localmap = malloc(sizeof(struct eidmap), M_TEMP, M_NOWAIT);
	if ( !localmap ){
	       /* No space to allocate buffers
		*/
	        return ENOBUFS;
	};
	    
	bzero(localmap, sizeof(struct eidmap));
	localmap->eid.ss_family = AF_INET;
	localmap->eid.ss_len = sizeof(struct sockaddr_in);
	/*PCD*/
	/* XTR only encap if source EID exist in Local database
	   PXTR,RTR only encap if destination EID exist in Forward database */
	switch (lispfunc) {
		case LISP_XTR:
			((struct sockaddr_in *)&(localmap->eid))->sin_addr = ip->ip_src;	
			break;
		case LISP_PXTR:
		case LISP_RTR:
			((struct sockaddr_in *)&(localmap->eid))->sin_addr = ip->ip_dst;
			break;
	}
	//((struct sockaddr_in *)&(localmap->eid))->sin_addr = ip->ip_src;
	/*DPC*/
	
	dblookup(localmap);

	if (  localmap->mapping  &&
	      !(localmap->mapping->map_flags & MAPF_NEGATIVE) && 
	      ((lispfunc == LISP_XTR)?!IN_ARE_MASKED_ADDR_EQUAL(
					 &(((struct sockaddr_in *)(map_key(localmap->mapping)))->sin_addr) ,
					 &(((struct sockaddr_in *)(map_mask(localmap->mapping)))->sin_addr), 
					 &(ip->ip_dst)):!IN_ARE_MASKED_ADDR_EQUAL(
					 &(((struct sockaddr_in *)(map_key(localmap->mapping)))->sin_addr) ,
					 &(((struct sockaddr_in *)(map_mask(localmap->mapping)))->sin_addr), 
					 &(ip->ip_src)))   ) { 


	       /* There is a mapping for the source EID and
		* destination is not in the same address range
		* of source, thus now look for the 
		* destination EID mapping.
		*/

	        remotemap = malloc(sizeof(struct eidmap), M_TEMP, M_NOWAIT);
		if ( !remotemap ){
		       /* No space to allocate buffers
			*/

		        FREE_EIDMAP(localmap);
			return ENOBUFS;
		};
  			   
	        bzero(remotemap, sizeof(struct eidmap));
	        remotemap->eid.ss_family = AF_INET;
  		remotemap->eid.ss_len = sizeof(struct sockaddr_in);
		((struct sockaddr_in *)&(remotemap->eid))->sin_addr = ip->ip_dst;
  
		cachelookup(remotemap);

		if (remotemap->mapping  == NULL) {
		       /* If there is no mapping for the destination EID
			* roll back like no mapping was present and
			* notify a cache miss.
			* Just leave the localmap to be used in the lisp_output
			* in case dataprobe will ever be implemented.  
			*/

		        bzero(&info, sizeof(struct map_addrinfo));
		        info.mapi_addrs |= MAPA_EID;
			info.mapi_info[MAPX_EID] = (struct sockaddr_storage *)&(remotemap->eid);
		        map_notifymsg(MAPM_MISS, &info, NULL, m, 0, &err);
			      /*should check error condition*/

		        free(remotemap, M_TEMP);
			remotemap = NULL;

		} else if (remotemap->mapping->map_flags & MAPF_NEGATIVE) { 
		       /* There is a negative mapping rollback to 
			* no mappings foud at all. This way ip_output 
			* will try to forward the packet natively.
			*/

		        free(remotemap, M_TEMP);
			remotemap = NULL;

			free(localmap, M_TEMP);
			localmap = NULL;

		};

	} else {
	       /* No Local Mapping exists or it is a Negative Mapping
		* free allocated buffer
		*/
	        free(localmap, M_TEMP);
		localmap = NULL;

	};

	/* Hand back references to mappings. 
	 */
	*local_map = localmap;
	*remote_map = remotemap;

	return 0;

} /* lisp_ip_mapencap() */


int lisp_ip_needencap( m )
	register struct mbuf ** m;
/*
 * Check whether the packet should be LISP encapsulated.
 * Means that it exists a local mapping for the source EID (addr).
 * Returns 1 if it is the case otherwise 0. Error conditions 
 * must be handled by the caller, usually ip_input().
 */
{
 
         struct ip * ip = NULL;
	 struct eidmap srcEID;

	 KASSERT((m != NULL), "[lisp_ip_needencap] NULL mbuf!");

	 if (( (*m) = m_pullup((*m), sizeof(struct ip))) == 0) {
		        /* This should never happen due to previous check
			 */
		         return  0;
			 
	 };

	 ip = mtod( (*m), struct ip *);

	 /* Source address validation */
	 if ( ip->ip_src.s_addr == INADDR_ANY ) {
	        /* Source Address not yet defined, encapsulation not possible.
		 */
	         return 0;
	 };


	bzero(&srcEID, sizeof(struct eidmap));
	srcEID.eid.ss_family = AF_INET;
	srcEID.eid.ss_len = sizeof(struct sockaddr_in);
	/*PCD*/
	/* XTR only encap if source EID exist in Local database
	   PXTR,RTR only encap if destination EID exist in Forward database */
	switch (lispfunc) {
		case LISP_XTR:		
			((struct sockaddr_in *)&(srcEID.eid))->sin_addr = ip->ip_src;	
			break;
		case LISP_PXTR:
		case LISP_RTR:
			((struct sockaddr_in *)&(srcEID.eid))->sin_addr = ip->ip_dst;
			break;
	}
	//((struct sockaddr_in *)&(srcEID.eid))->sin_addr = ip->ip_src;
	/*DPC*/
	

	dblookup(&srcEID);
  	  
	if (srcEID.mapping) {

	  if ( (lispfunc == LISP_XTR) && (IN_ARE_MASKED_ADDR_EQUAL(
					 &(((struct sockaddr_in *)(map_key(srcEID.mapping)))->sin_addr) ,
					 &(((struct sockaddr_in *)(map_mask(srcEID.mapping)))->sin_addr), 
					 &(ip->ip_dst) ) ) ) { 

		     /* GgX - Destination is in the same address range
		      * of source, thus there is no need to encapsulate.
		      */

	    MAP_REMREF(srcEID.mapping);
	    return 0;

	  }; 
			
	  if ( ( (lispfunc == LISP_PXTR) || (lispfunc == LISP_RTR) ) && (IN_ARE_MASKED_ADDR_EQUAL(
					 &(((struct sockaddr_in *)(map_key(srcEID.mapping)))->sin_addr) ,
					 &(((struct sockaddr_in *)(map_mask(srcEID.mapping)))->sin_addr), 
					 &(ip->ip_src) ) ) ) { 

		     /* GgX - Destination is in the same address range
		      * of source, thus there is no need to encapsulate.
		      */

	    MAP_REMREF(srcEID.mapping);
	    return 0;

	  };
	  
	  MAP_REMREF(srcEID.mapping);
	  return 1;
	
	};

	 return 0;

}  /* lisp_ip_needencap() */


int lisp_ip_needdecap( m )
	register struct mbuf **m;
/*
 * Check whether the received packet is an IPv4 LISP packet.
 * Means UDP + specific LISPDATA port number.
 * Returns 1 if it is the case otherwise 0. Error conditions 
 * must be handled by the caller, usually ip_input().
 */
{

         struct ip * ip = NULL;
	 struct udphdr * uh = NULL;

	 KASSERT((m != NULL), "[lisp_ip_needdecap] NULL mbuf!");

	 if ( m_length( (*m), NULL) < ( sizeof(struct ip) + 
				     sizeof(struct udphdr) + 
				     sizeof(struct lispshimhdr) ) ) {
	       /* Packet is too short to be a LISP Packet 
		*/  

		return 0;

	 };
	      
	 if ((*m)->m_len < sizeof(struct ip) + sizeof(struct udphdr)) {
	   if (((*m) = m_pullup((*m), sizeof(struct ip) + sizeof(struct udphdr))) == 0) {
		        /* This should never happen due to previous check
			 */

		         return  0;
			 
		 };

	 };
		
	 ip = mtod((*m), struct ip *);
	 
	 if (inetsw[ip_protox[ip->ip_p]].pr_protocol == IPPROTO_UDP) {
	        /* GgX - UDP packet destined to this machine  
		 * remains to check the port number.
		 */
		  
	         uh = (struct udphdr *)((caddr_t)ip + sizeof(struct ip));
		 
		 if (ntohs(uh->uh_dport) == LISPDATA) {
		        /* Got a LISP packet
			 */
  		   
		         return 1;
  
		 };
		 
	 };

	 return 0;

}  /* lisp_ip_needdecap() */



int
lisp_check_ip_mappings(m, drloc, srloc, lisphdr)
     register struct mbuf ** m;
     struct sockaddr_storage * drloc;
     struct sockaddr_storage * srloc;
     struct lispshimhdr * lisphdr; 
/* 
 * Check if mappings for the received packet exists.
 * Returns 0 if everything is ok. 
 */
{
        struct eidmap local_map, remote_map; /* Will be zeroed later */
	struct ip * ip = NULL;
	struct locator * srcrloc = NULL;
	struct locator * dstrloc = NULL;
	struct map_addrinfo info;
	int error = 0;
	
	/* Not necessary, but just in case
	 */
	(*m) = m_pullup((*m), sizeof(struct ip));

	ip = mtod((*m), struct ip *);

       /*
	* Construct eidmap for local map.
	* Stuff destination address in the structure.
	*/

        bzero(&local_map, sizeof(local_map));
	local_map.eid.ss_family = AF_INET;
	local_map.eid.ss_len = sizeof(struct sockaddr_in);
	
	/*PCD*/
	/* with XTR,RTR only decap if destinaton EID exist in Local database
	   else PxTR, only decap when source EID belong to Forward table */
	switch (lispfunc) {
		case LISP_XTR:
		case LISP_RTR:
			((struct sockaddr_in *)&local_map.eid)->sin_addr = ip->ip_dst;
			break;
		case LISP_PXTR:
			((struct sockaddr_in *)&local_map.eid)->sin_addr = ip->ip_src;
			break;
	}	
	//((struct sockaddr_in *)&local_map.eid)->sin_addr = ip->ip_dst;
	/*DPC*/
	
	/* Checkout for local mapping */
	dblookup(&local_map); 	   

	if (!local_map.mapping) {
	      /* Received a LISP packet but this is not the 
	       * correct ETR so drop it. 
	       * The assumption is that local mappings are always present 
	       * in the maptable, thus this is either an error or
	       * a spoof.
	       */

#ifdef LISP_DEBUG
	        DEBUGLISP("[LISP_CHECK_IP_MAPPINGS] Drop! No Mapping in DB\n");
#endif /* LISP_DEBUG */
	  
	       lisp4stat.ibadencap++;
	       return(ENOENT);
	};
	/*PCD */
	if ( !(dstrloc = map_findrloc(local_map.mapping, drloc)) ) {
	       /* RLOC not present in the mapping
		* This should really never happen if the local mappings 
		* are checked before insertion in the maptable.
		* --- Panic?
		*/

	        MAP_REMREF(local_map.mapping);

#ifdef LISP_DEBUG
	        DEBUGLISP("[LISP_CHECK_IP_MAPPINGS] Drop! No RLOC in DB Mapping\n");
#endif /* LISP_DEBUG */

		lisp4stat.ibadencap++;
	        return(ENOATTR);
	};


		  
	/*
	 * Construct eidmap for remote map.
	 * Stuff source address in the structure.
	 */

	bzero(&remote_map, sizeof(remote_map));
	remote_map.eid.ss_family = AF_INET;
	remote_map.eid.ss_len = sizeof(struct sockaddr_in);
	((struct sockaddr_in *)&remote_map.eid)->sin_addr = ip->ip_src;


	/* Checkout for mapping */
	cachelookup(&remote_map); 	   

	if (remote_map.mapping) {
	       /* Got a mapping in the Cache
		*/
			/*PCD*/
	        if ( !xtr_te && (lispfunc == LISP_XTR) &&!(srcrloc = map_findrloc(remote_map.mapping, srloc)) ) {
		       /* RLOC not present in the mapping present in cache.
			* --- Should send msg through map socket?
			*/
		  
		        MAP_REMREF(local_map.mapping);
			MAP_REMREF(remote_map.mapping);

#ifdef LISP_DEBUG
	                DEBUGLISP("[LISP_CHECK_IP_MAPPINGS] Drop! No RLOC Cache in Mapping\n");
#endif /* LISP_DEBUG */

			lisp4stat.ibadencap++;
			return(ENOATTR);

		};
		
		if( xtr_te || (lispfunc == LISP_PXTR) || (lispfunc == LISP_RTR)  ){
			/* Get first rloc */
			srcrloc = &(remote_map.mapping->rlocs->rloc);
			if(!srcrloc){
				MAP_REMREF(local_map.mapping);
				MAP_REMREF(remote_map.mapping);

#ifdef LISP_DEBUG
	                DEBUGLISP("[LISP_CHECK_IP_MAPPINGS] Drop! No RLOC Cache in Mapping\n");
#endif /* LISP_DEBUG */

				lisp4stat.ibadencap++;
				return(ENOATTR);
			}
	
		}
		/*DPC*/

	} else {

	       /* There is no mapping in the Cache.
		* Behavior is now controlled by net.lisp.etr sysctl.
		*/
	  switch  (lispetr) {

	  case LISP_ETR_SECURE:
	         /* If no entry in the cache drop and notify
		  */

  	          bzero(&info, sizeof(struct map_addrinfo));
		  info.mapi_addrs |= MAPA_EID;
		  info.mapi_info[MAPX_EID] = ((struct sockaddr_storage *) &remote_map.eid);

		 /* Fix IP header if necessary
		  */
		  if (lispmissmsg > LISP_MISSMSG_EID) {
	
 	                  ip->ip_len = ntohs(ip->ip_len);
			  ip->ip_off = ntohs(ip->ip_off);
 	                 	    
		  };

		  map_notifymsg(MAPM_MISS, &info, NULL, m, 0, &error);
		  /* Should check error condition*/

		  MAP_REMREF(local_map.mapping);

#ifdef LISP_DEBUG
		  DEBUGLISP("[LISP_CHECK_IP_MAPPINGS] Drop! No Mapping in Cache\n");
#endif /* LISP_DEBUG */

		  lisp4stat.ibadencap++;
		  return(ENOENT);

		  break; /* XXX - Never reached */

	  case LISP_ETR_NOTIFY:

	         /* If no entry in the cache notify and forward
		  */
  	          bzero(&info, sizeof(struct map_addrinfo));
		  info.mapi_addrs |= MAPA_EID;
		  info.mapi_info[MAPX_EID] = ((struct sockaddr_storage *) &remote_map.eid);

		 /* Fix IP header if necessary
		  */
		  if (lispmissmsg > LISP_MISSMSG_EID) {
	
	                  ip->ip_len = ntohs(ip->ip_len);
			  ip->ip_off = ntohs(ip->ip_off);						
		  };

		  map_notifymsg(MAPM_MISS, &info, NULL, m, 0, &error);
		  /* Should check error condition*/


		  /* Put IP header back to original state for re-injection
		   */
		  if (lispmissmsg > LISP_MISSMSG_EID) {
	
	                 ip->ip_len = htons(ip->ip_len);
			  ip->ip_off = htons(ip->ip_off);					
		  };
	    
		  break;

	  case LISP_ETR_STANDARD:
	  default:
	    /* Do nothing */
	    ;

	  };

	};

	if (check_lisphdr( lisphdr, local_map, remote_map, dstrloc, 
			   srcrloc, &error)) {

	        MAP_REMREF(local_map.mapping);

	        if (remote_map.mapping) 
		        MAP_REMREF(remote_map.mapping);
	     
#ifdef LISP_DEBUG
	        DEBUGLISP("[LISP_CHECK_IP_MAPPINGS] Drop! LISP Header\n");
#endif /* LISP_DEBUG */

		lisp4stat.ibadencap++;

		if ( error == ELISP_SRCVNUMINVAL ) {
		 
		        lisp4stat.ibadsrcvnum++;

		} else if ( error == ELISP_DSTVNUMINVAL ) {
		 
		        lisp4stat.ibaddstvnum++;

		};

		return(EINVAL);

	};

	MAP_REMREF(local_map.mapping);

	if (remote_map.mapping)  
	        MAP_REMREF(remote_map.mapping);

	return 0; /* Everything's fine */

}  /* lisp_check_ip_mappings() */


/* int 
lisp_ip_encap( m, len, srlocaddr, drlocaddr, ttl, usport )
        struct mbuf ** m;
	int len;
	struct in_addr * srlocaddr;
	struct in_addr * drlocaddr;
	u_char ttl;
	uint16_t usport;
{ */
int 
lisp_ip_encap( struct mbuf ** m, 
				int len,
				struct in_addr * srlocaddr,
				struct in_addr * drlocaddr,
				u_char ttl,
				uint16_t usport)
{
       /*
	* Calculate data length and get a mbuf for UDP, 
	* IP, and possible link-layer headers.  
	* Immediate slide the data pointer back forward
	* since we won't use that space at this layer.
	*/
  
        struct udpiphdr * ui = NULL;        
	struct ip * ip = NULL;
  
        M_PREPEND((*m), sizeof(struct udpiphdr) + max_linkhdr, M_DONTWAIT);

	if ((*m) == NULL) {
		return(ENOBUFS);
	};

	(*m)->m_data += max_linkhdr;
	(*m)->m_len -= max_linkhdr;
	(*m)->m_pkthdr.len -= max_linkhdr;

       /*
	* Fill in mbuf with extended UDP header
	* and addresses and length put into network format.
	*/
	ui = mtod((*m), struct udpiphdr *);
	bzero(ui->ui_x1, sizeof(ui->ui_x1));	/* XXX still needed? */
	
	ui->ui_pr = IPPROTO_UDP;
	ui->ui_src = *srlocaddr;
	ui->ui_dst = *drlocaddr;
	ui->ui_sport = htons(usport);
	ui->ui_dport = htons(LISPDATA);
	ui->ui_ulen = htons((u_short)(len + sizeof(struct udphdr)) );

    /*
	* Set the Don't Fragment bit in the IP header.
	*/
	
	ip = (struct ip *)&ui->ui_i;
	ip->ip_off |= IP_DF;
	
	ui->ui_sum = 0;    /* LISP uses udp checksum = 0 */
	(*m)->m_pkthdr.csum_flags &= ~CSUM_UDP;
		
	ip->ip_len = htons(sizeof (struct udpiphdr) + len );
	ip->ip_ttl = ttl;	
	ip->ip_tos = 0;	/* Default TOS */
	ip->ip_v = IPVERSION;	
	ip->ip_off = htons(ip->ip_off);
	
        return(0);

}  /* lisp_ip_encap() */



void
lisp_input(m, off)
	struct mbuf * m;
	int off;
{

  	int iphlen = off;
	register struct ip *ip;
	register struct udphdr *uh;
	struct sockaddr_storage srloc,drloc;
	int len;
	u_char saved_ttl;
	int error = 0;
	int isr = 0;
	uint16_t delta_ttl;
	struct ip6_hdr * ip6 = NULL;
	struct lispshimhdr rlisphdr;
	
	lisp4stat.ipackets++;
	
	/*
	 * Get IP and UDP header together in first mbuf.
	 */
	ip = mtod(m, struct ip *);
	if (m->m_len < (iphlen + sizeof(struct udphdr))) {
		if ((m = m_pullup(m, iphlen + sizeof(struct udphdr))) == 0) {

#ifdef LISP_DEBUG
		        DEBUGLISP("[LISP_INPUT] Drop! Mbuf length smaller then IP + UDP header length \n");
#endif /* LISP_DEBUG */
			lisp4stat.ihdrops++;
			goto lisp_input_drop;
		}
		ip = mtod(m, struct ip *);
	}
	uh = (struct udphdr *)((caddr_t)ip + iphlen);

	/*
	 * Strip outer IP+UDP header.
	 * If not enough data to reflect minimum LISP inner packet length, drop.
	 */
	
	len = ntohs((u_short)uh->uh_ulen);
		
	if ( ip->ip_len != len) {
	        if (len > ip->ip_len || 
		    len < (sizeof(struct udphdr) + sizeof(struct lispshimhdr))) {
			lisp4stat.ibadlen++;
			goto lisp_input_drop;
		}
		m_adj(m, (len - ip->ip_len));		
	}
	
	if (len <= (sizeof(struct udphdr) + sizeof(struct lispshimhdr) + sizeof(struct ip))) {

#ifdef LISP_DEBUG
	        DEBUGLISP("[LISP_INPUT] Drop! Packet legth shorter than UDP + LISP + IP headers length \n");
#endif /* LISP_DEBUG */

  	        lisp4stat.ihdrops++;
		goto lisp_input_drop;
	}

	/* Before really stripping the outer header save RLOCs for 
	 * further checks.
	 */
	drloc.ss_family = srloc.ss_family = AF_INET;
	drloc.ss_len = srloc.ss_len = sizeof(struct sockaddr_in);
	((struct sockaddr_in *)&drloc)->sin_addr = ip->ip_dst;
	((struct sockaddr_in *)&srloc)->sin_addr = ip->ip_src;

	/* Save the value of the TTL in order to copy it back in the 
	 * inner header.
	 */

	saved_ttl= ip->ip_ttl;

	m_adj(m, (iphlen + sizeof(struct udphdr)));

	m_copylisphdr(&m, &rlisphdr);

	/*  Strip Lisp Shim Header */
	m_adj(m, sizeof(struct lispshimhdr));
	/* There is at least an IPv4 header XXXX */
	   
	m = m_pullup(m, sizeof(struct ip));
	ip = mtod(m, struct ip *);

	switch (ip->ip_v) {
	
	case IPVERSION:
		error = lisp_check_ip_mappings(&m, &drloc, &srloc, &rlisphdr);			
		if (error)  
		        goto lisp_input_drop;

		/* Everything went fine
		 * Copy back the TTL and re-inject in the IP layer
		 */
		delta_ttl = ip->ip_ttl - saved_ttl;
		ip->ip_ttl = saved_ttl;

	       /* Update Checksum due to TTL recalculation 
		*/
		if (ip->ip_sum >= (u_int16_t) ~htons(delta_ttl << 8))
		        ip->ip_sum -= ~htons(delta_ttl << 8);
		else
		        ip->ip_sum += htons(delta_ttl << 8);

 	        isr = NETISR_IP;

		break;

	case (IPV6_VERSION >> 4):

	        lisp6stat.ioafpackets++;
			error = lisp_check_ip6_mappings(&m, &drloc, &srloc, &rlisphdr);  
				        

		if (error)
		        goto lisp_input_drop;

		ip6 = mtod(m, struct ip6_hdr *);

		ip6->ip6_hlim = saved_ttl;
		
 	        isr = NETISR_IPV6;

		break;

	default:
	  
#ifdef LISP_DEBUG
	        DEBUGLISP("[LISP_INPUT] Drop! Unrecongnized inner packet AF\n");
#endif /* LISP_DEBUG */

	        lisp4stat.ihdrops++;
	        goto lisp_input_drop;

	};
			
	netisr_dispatch(isr, m);

	return;

lisp_input_drop:

	if (m)
	        m_freem(m);

	return;

}    /* lisp_input() */


int
lisp_output(m, hlen, local_map, remote_map)
	struct mbuf *m;
	int hlen;
        struct eidmap *local_map;        
	struct eidmap *remote_map;
{
  	int len = m->m_pkthdr.len;
	struct locator * srcrloc;
	struct locator * dstrloc;
	int error = 0;
	u_char saved_ttl;
	uint16_t usrcport;

	struct ip *ip = mtod(m, struct ip *);


	KASSERT(local_map->mapping,"[LISP_OUTPUT] LISP output without local mapping");
	KASSERT(m, "[LISP_OUTPUT] Output without packet");
	
	if (remote_map  == NULL)  {
	       /* There is no mapping for the destination EID.
		* Do not set error, so that we silently drop
		*/

	        lisp4stat.omissdrops++;
		goto lisp_output_drop;
		 
	};


	/* Fix the IP header before going further, then 
	 * encapsulate.
	 */
	
	if (m->m_pkthdr.csum_flags & CSUM_DELAY_DATA) {
	        in_delayed_cksum(m);
		m->m_pkthdr.csum_flags &= ~CSUM_DELAY_DATA;
	};
  	
	ip->ip_len = htons(ip->ip_len);
	ip->ip_off = htons(ip->ip_off);
	ip->ip_sum = 0;
	ip->ip_sum = in_cksum(m, hlen);
       
	/* Save original TTL value to copy it back in the new outer header.
	 */
	saved_ttl = ip->ip_ttl;

	/* Destination RLOC selection 
	 */
	if ((error = map_select_dstrloc(remote_map->mapping, &dstrloc))){
	       /* There is no available RLOC that can be used 
		*/

	        lisp4stat.onorlocdrops++;
	        goto lisp_output_drop;
	};

	/* If the MTU of the destination locator is set a check on 
	 * the size is performed.
	 */
	if (dstrloc->rloc_metrix.rlocmtx.mtu &&
	    ((len + sizeof(struct udphdr) + 
	      SIZEOF_IPHDR(dstrloc->rloc_addr->ss_family) +
	      sizeof(struct lispshimhdr)) > dstrloc->rloc_metrix.rlocmtx.mtu)) {
		  
	        error = EMSGSIZE;
	        lisp4stat.osizedrops++;
		goto lisp_output_drop;

	};
		

	/* Source RLOC selection 
	 * Must match the destination RLOC AF (drloc_af)
	 * and also be the address of the interface through which 
	 * the packet will be sent 
	 */
	if ((error = map_select_srcrloc(local_map->mapping, dstrloc, 
					&srcrloc))) {
	       /* There is no available source RLOC that can be used 
		*/

	        lisp4stat.onorlocdrops++;
	        goto lisp_output_drop;

	};

	/* If the MTU of the source locator is set a check on the size
	 * is performed.
	 */
	if (srcrloc->rloc_metrix.rlocmtx.mtu &&
	    ((len + sizeof(struct udphdr) + 
	      SIZEOF_IPHDR(srcrloc->rloc_addr->ss_family) + 
	      sizeof(struct lispshimhdr)) > srcrloc->rloc_metrix.rlocmtx.mtu)) {

		error = EMSGSIZE;
	        lisp4stat.osizedrops++;
		goto lisp_output_drop;

	};

	/* Global IPv4 MTU check 
	 */
	if (len + sizeof(struct udphdr) + 
	    SIZEOF_IPHDR(srcrloc->rloc_addr->ss_family) +
	    sizeof(struct lispshimhdr) > IP_MAXPACKET) {

		error = EMSGSIZE;
		lisp4stat.osizedrops++;
		goto lisp_output_drop;

	};

	/* Ready to encapsulate.
	 * Before do it let's calculate the src port
	 * Src port is hash based on the inner header.
	 */

	usrcport = get_lisp_srcport(&m);

	m = m_lisphdrprepend(m, remote_map, local_map, dstrloc, srcrloc);

	if (m == NULL) {

		error = ENOBUFS;
	        lisp4stat.onobufdrops++;
		goto lisp_output_drop;

	};

	switch (srcrloc->rloc_addr->ss_family) {
	  
	        case AF_INET:	 
	
		        if ( !(error = lisp_ip_encap(&m, (len + sizeof(struct lispshimhdr)), 
						     &((struct sockaddr_in *)srcrloc->rloc_addr)->sin_addr, 	     
						     &((struct sockaddr_in *)dstrloc->rloc_addr)->sin_addr, 
						     saved_ttl,
						     usrcport))){
			
		                lisp4stat.opackets++;
				error = ip_output(m, NULL, NULL, IP_LISP, NULL, NULL);

			};
			
			FREE_EIDMAP(local_map);
		        FREE_EIDMAP(remote_map);

			return (error);
			
			break;
	
                 case AF_INET6:

		        lisp6stat.ooafpackets++;

		        if ( !(error = lisp_ip6_encap(&m, (len + sizeof(struct lispshimhdr)),
						     &((struct sockaddr_in6 *)srcrloc->rloc_addr)->sin6_addr, 	     
						     &((struct sockaddr_in6 *)dstrloc->rloc_addr)->sin6_addr, 
						      ((int)saved_ttl),
						      usrcport))) {
			
		                lisp6stat.opackets++;
				error = ip6_output(m, NULL, NULL, IP_LISP, NULL, NULL, NULL);

			};

			FREE_EIDMAP(local_map);
		        FREE_EIDMAP(remote_map);

			return(error);

			break;

	         default:
		        error = EPFNOSUPPORT;

	};  



lisp_output_drop:

	if (remote_map) {
	        FREE_EIDMAP(remote_map);
	};

	FREE_EIDMAP(local_map);
  
	m_freem(m);
	
	lisp4stat.odrops++;
	lisp4stat.opackets++;

	return (error);

}   /* lisp_output() */

