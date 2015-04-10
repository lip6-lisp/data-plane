/*- /usr/src/sys/netinet6/lisp6/ip6_lisp6.c
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
 * $Id: ip6_lisp6.c 178 2011-09-22 14:50:11Z ggx $
 *
 */

#include "opt_inet.h"
#include "opt_inet6.h"
#include "opt_lisp.h"

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mbuf.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/signalvar.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sx.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/systm.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/netisr.h>

#include <netinet/in.h>
#include <net/lisp/lisp.h>
#include <net/lisp/maptables.h>
#include <netinet/in_pcb.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp_var.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/lisp/ip_lisp.h>

#include <netinet6/ip6protosw.h>
#include <netinet6/ip6_var.h>
#include <netinet6/in6_pcb.h>
#include <netinet6/udp6_var.h>
#include <netinet6/scope6_var.h>
#include <netinet6/lisp6/ip6_lisp6.h>

/*
 * LISP protocol implementation for IPv6 encap/decap.
 */

/* IPv6 Related Stats */
struct  lispbasicstat lisp6stat;

/* Link to IPv4 Stats variable */
extern struct lispbasicstat lisp4stat;

/* Sysctl Declarations
 */

#ifdef SYSCTL_DECL
SYSCTL_DECL(_net_inet6);
#endif /* SYSCTL_DECL */

SYSCTL_NODE(_net_inet6, OID_AUTO, lisp, CTLFLAG_RW, 0, "IPv6 related LISP node");

SYSCTL_STRUCT(_net_inet6_lisp, OID_AUTO, stats, CTLFLAG_RW,
	      &lisp6stat, lispbasicstat, 
	      "LISP IPv6 stats (struct lispbasicstat, net/lisp/lisp.h)");


int 
lisp_ip6_mapencap( m, flags, local_map, remote_map)
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
 * Whether to do dataprobe or not is up to lisp6_output (or the 
 * consumer of the result).
 */
{
        struct ip6_hdr * ip6 = NULL;
	struct eidmap * localmap = NULL;
	struct eidmap * remotemap = NULL;
	struct map_addrinfo info;
	int err = 0;
	
        if (flags & IP_LISP) {
	       /* The packet has already been LISP-encapsulated:
		*/
	        return 0;
	};

	ip6 = mtod((*m), struct ip6_hdr *);

       /* Source address validation */
        if (IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src) &&
	    (flags & IPV6_UNSPECSRC) == 0) {
	       /* Source Address not yet defined, encapsulation not 
		* possible.
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
	localmap->eid.ss_family = AF_INET6;
	localmap->eid.ss_len = sizeof(struct sockaddr_in6);
	/*PCD*/
	/* XTR,RTR only encap if source EID exist in Local database
	   PXTR only encap if destination EID exist in Forward database */
	switch (lispfunc) {
		case LISP_XTR:
			((struct sockaddr_in6 *)&(localmap->eid))->sin6_addr = ip6->ip6_src;	
			break;
		case LISP_PXTR:
		case LISP_RTR:
			((struct sockaddr_in6 *)&(localmap->eid))->sin6_addr = ip6->ip6_dst;
			break;
	}
	//((struct sockaddr_in6 *)&(localmap->eid))->sin6_addr = ip6->ip6_src;
	/*DPC*/	

	dblookup(localmap);
  	  
	if (localmap->mapping  &&
	    !(localmap->mapping->map_flags & MAPF_NEGATIVE) && 
	    ((lispfunc == LISP_XTR)? !IN6_ARE_MASKED_ADDR_EQUAL(
					 &(((struct sockaddr_in6 *)(map_key(localmap->mapping)))->sin6_addr) ,  &(ip6->ip6_dst),

					 &(((struct sockaddr_in6 *)(map_mask(localmap->mapping)))->sin6_addr)):\
						!IN6_ARE_MASKED_ADDR_EQUAL(
					 &(((struct sockaddr_in6 *)(map_key(localmap->mapping)))->sin6_addr) ,  &(ip6->ip6_src),

					 &(((struct sockaddr_in6 *)(map_mask(localmap->mapping)))->sin6_addr)) )) { 

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
	        remotemap->eid.ss_family = AF_INET6;
  		remotemap->eid.ss_len = sizeof(struct sockaddr_in6);
		((struct sockaddr_in6 *)&(remotemap->eid))->sin6_addr = ip6->ip6_dst;
  
		cachelookup(remotemap);

		if (remotemap->mapping  == NULL)  {
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
	       /* No Local Mapping exists free allocated buffer
		*/
	        free(localmap, M_TEMP);
		localmap = NULL;

	};

	/* Hand back references to mappings. 
	 */
	*local_map = localmap;
	*remote_map = remotemap;

	return 0;

} /* lisp_ip6_mapencap() */


int 
lisp_ip6_needdecap( m, off, proto)
	register struct mbuf **m;
	int off;
	int proto;
{
        /* Check whether the received packet is an IPv6 LISP packet.
	 * Means UDP + specific LISPDATA port number.
	 * Returns 1 if it is the case otherwise 0. Error conditions 
	 * must be handled by the caller, usually ip6_input().
	 */

	struct udphdr *uh;
	struct ip6_hdr *ip6;

	if (proto != IPPROTO_UDP) {
	       /* It is not UDP packet, thus not a LISP packet 
		*/
	       return 0;
	};

#ifndef PULLDOWN_TEST
	IP6_EXTHDR_CHECK((*m), off, sizeof(struct udphdr), IPPROTO_DONE);
	ip6 = mtod((*m), struct ip6_hdr *);
	uh = (struct udphdr *)((caddr_t)ip6 + off);
#else	

	IP6_EXTHDR_GET(uh, struct udphdr *, (*m), off, sizeof(*uh));
        if (!uh) {
                 return 0;
	};
#endif /*PULLDOWN_TEST */

	if (ntohs(uh->uh_dport) == LISPDATA) {
	       /* Got a LISP packet
		*/
	        return 1;
	};

	return 0;

}  /* lisp__ip6_needdecap() */


int
lisp_check_ip6_mappings(m, drloc, srloc, lisphdr)
        register struct mbuf ** m;
	struct sockaddr_storage * drloc;
	struct sockaddr_storage * srloc;
	struct lispshimhdr * lisphdr; 
{

        struct eidmap local_map, remote_map;
	struct ip6_hdr * ip6 = NULL;
	struct locator * srcrloc = NULL;
	struct locator * dstrloc = NULL;
	struct map_addrinfo info;
	int error = 0;
	
       /* Not necessary, but just in case
	*/
	(*m) = m_pullup((*m), sizeof(struct ip6_hdr));

	ip6 = mtod((*m), struct ip6_hdr *);

       /*
	* Construct eidmap for local map.
	* Stuff source address in the structure.
	*/

        bzero(&local_map, sizeof(local_map));
	local_map.eid.ss_family = AF_INET6;
	local_map.eid.ss_len = sizeof(struct sockaddr_in6);
	
	/*PCD*/
	switch (lispfunc) {
		case LISP_XTR:
		case LISP_RTR:
			((struct sockaddr_in6 *)&local_map.eid)->sin6_addr = ip6->ip6_dst;
			break;
		case LISP_PXTR:
			((struct sockaddr_in6 *)&local_map.eid)->sin6_addr = ip6->ip6_src;
			break;
	}
	//((struct sockaddr_in6 *)&local_map.eid)->sin6_addr = ip6->ip6_dst;
	/*DPC*/

	/* Checkout for local mapping */
	dblookup(&local_map); 	   

	if (!local_map.mapping) {
	      /* Received a LISP packet but this is not the 
	       * correct ETR so drop it. 
	       * We assume that local mapping are always present 
	       * in the maptable, thus this is either an error or
	       * a spoof.
	       */
		  
#ifdef LISP_DEBUG
	        DEBUGLISP("[LISP_CHECK_IP6_MAPPINGS] Drop! No Mapping in DB\n");
#endif /* LISP_DEBUG */

	       lisp6stat.ibadencap++;
	       return(ENOENT);
	};

	if ( !(dstrloc = map_findrloc(local_map.mapping, drloc)) ) {
	       /* RLOC not present in the mapping
		* This should really never happen if the local mappings 
		* are checked before insertion in the maptable.
		* --- Panic?
		*/

	        MAP_REMREF(local_map.mapping);

#ifdef LISP_DEBUG
	        DEBUGLISP("[LISP_CHECK_IP6_MAPPINGS] Drop! No RLOC in DB Mapping\n");
#endif /* LISP_DEBUG */

		lisp6stat.ibadencap++;
	        return(ENOATTR);
	};
		  
	/*
	 * Construct eidmap for remote map.
	 * Stuff source address in the structure.
	 */

	bzero(&remote_map, sizeof(remote_map));
	remote_map.eid.ss_family = AF_INET6;
	remote_map.eid.ss_len = sizeof(struct sockaddr_in6);
	((struct sockaddr_in6 *)&remote_map.eid)->sin6_addr = ip6->ip6_src;


	/* Checkout for mapping */
	cachelookup(&remote_map); 	   

	if (remote_map.mapping && !(remote_map.mapping->map_flags & MAPF_NEGATIVE)) {
	       /* Got a mapping in the Cache
		*/
			/*PCD*/
	        if ( !xtr_te && (lispfunc == LISP_XTR) && !(srcrloc = map_findrloc(remote_map.mapping, srloc)) ) {
		       /* RLOC not present in the mapping present in cache.
			* --- Should send msg through map socket?
			*/
		  
		        MAP_REMREF(local_map.mapping);
			MAP_REMREF(remote_map.mapping);

#ifdef LISP_DEBUG
	                DEBUGLISP("[LISP_CHECK_IP6_MAPPINGS] Drop! No RLOC Cache in Mapping\n");
#endif /* LISP_DEBUG */

			lisp6stat.ibadencap++;
			return(ENOATTR);

			};

			if( xtr_te || (lispfunc == LISP_PXTR) || (lispfunc == LISP_RTR) ){
				srcrloc = &(remote_map.mapping->rlocs->rloc);
				if(!srcrloc){
					MAP_REMREF(local_map.mapping);
					MAP_REMREF(remote_map.mapping);

#ifdef LISP_DEBUG
	                DEBUGLISP("[LISP_CHECK_IP6_MAPPINGS] Drop! No RLOC Cache in Mapping\n");
#endif /* LISP_DEBUG */

					lisp6stat.ibadencap++;
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

		  map_notifymsg(MAPM_MISS, &info, NULL, m, 0, &error);
		  /* Should check error condition*/

		  MAP_REMREF(local_map.mapping);

#ifdef LISP_DEBUG
		  DEBUGLISP("[LISP_CHECK_IP6_MAPPINGS] Drop! No Mapping in Cache\n");
#endif /* LISP_DEBUG */

		  lisp6stat.ibadencap++;
		  return(ENOENT);

		  break; /* XXX - Never reached */

	  case LISP_ETR_NOTIFY:

	         /* If no entry in the cache notify and forward
		  */
  	          bzero(&info, sizeof(struct map_addrinfo));
		  info.mapi_addrs |= MAPA_EID;
		  info.mapi_info[MAPX_EID] = ((struct sockaddr_storage *) &remote_map.eid);

		  map_notifymsg(MAPM_MISS, &info, NULL, m, 0, &error);
		  /* Should check error condition*/

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

		lisp6stat.ibadencap++;

		if ( error == ELISP_SRCVNUMINVAL ) {
		 
		        lisp6stat.ibadsrcvnum++;

		} else if ( error == ELISP_DSTVNUMINVAL ) {
		 
		        lisp6stat.ibaddstvnum++;

		};

		return(EINVAL);

	};

	MAP_REMREF(local_map.mapping);

	if (remote_map.mapping)  
	        MAP_REMREF(remote_map.mapping);

	return 0; /* Everything's fine */

}  /* lisp_check_ip6_mappings() */


/* int 
lisp_ip6_encap( m, len, srlocaddr, drlocaddr, hlim, usport)
        struct mbuf ** m;
	int len;
	struct in6_addr * srlocaddr;
	struct in6_addr * drlocaddr;
	int hlim;
	uint16_t usport;
{ */
int 
lisp_ip6_encap(struct mbuf ** m,
				int len,
				struct in6_addr * srlocaddr,
				struct in6_addr * drlocaddr,
				int hlim,
				uint16_t usport)
{
       /*
	* Calculate data length and get a mbuf for UDP, 
	* IP, and possible link-layer headers.  
	* Immediate slide the data pointer back forward
	* since we won't use that space at this layer.
	*/
  
        uint32_t ulen = (*m)->m_pkthdr.len;
	uint32_t plen = sizeof(struct udphdr) + ulen;        
	struct udphdr * uh = NULL;        
	struct ip6_hdr * ip6 = NULL;
 
	M_PREPEND((*m), sizeof(struct ip6_hdr) + 
		  sizeof(struct udphdr), M_DONTWAIT);

	if ((*m) == 0) {
	        return(ENOBUFS);
	};

	/*
	 * Stuff UDP Header.
	 */

	uh = (struct udphdr *)(mtod((*m), caddr_t) + sizeof(struct ip6_hdr));
	uh->uh_sport = htons(usport);
 	uh->uh_dport = htons(LISPDATA);
	uh->uh_ulen = htons((u_short)plen);

	uh->uh_sum = 0;    /* LISP uses udp checksum = 0 */
	(*m)->m_pkthdr.csum_flags &= ~CSUM_UDP;


	/*
	 * Stuff IPv6 Header.
	 */

	ip6 = mtod((*m), struct ip6_hdr *);

	ip6->ip6_flow	=  0 & IPV6_FLOWINFO_MASK;
       /* GgX:
	* draft-ietf-lisp-04.txt does not specify values
	* to be used for the "Traffic Class" and the "Flow Label"
	* fields. 
	* 
	* We just set them to 0.
	*
	* Note also that copy these information from the inner header 
	* works only in the case of IPv6-over-IPv6. Furthermore,
	* copying back these information can raise similar problems
	* like in the udp source port, when a state-full firewall is 
	* present.
	*   
	*/

	ip6->ip6_vfc	&= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc	|= IPV6_VERSION;

	ip6->ip6_plen	= htons((u_short)(*m)->m_pkthdr.len);

	ip6->ip6_nxt	= IPPROTO_UDP;
	ip6->ip6_hlim	= hlim;
	ip6->ip6_src	= *srlocaddr;
	ip6->ip6_dst	= *drlocaddr;

        return(0);

}  /* lisp_ip6_encap() */




int
lisp6_input(struct mbuf **mp, int *offp, int proto)
{
  	struct mbuf *m = *mp;
	int off = *offp;
	struct ip6_hdr *ip6;
	struct udphdr *uh;
	int plen, ulen, saved_hlim;
	struct sockaddr_storage srloc,drloc;
	struct ip * ip = NULL;
	int error = 0;  
	int isr = 0;
	uint16_t delta_ttl;
	struct lispshimhdr rlisphdr;

	lisp6stat.ipackets++;

	ip6 = mtod(m, struct ip6_hdr *);
 
#ifndef PULLDOWN_TEST
	IP6_EXTHDR_CHECK(m, off, sizeof(struct udphdr), IPPROTO_DONE);
	ip6 = mtod(m, struct ip6_hdr *);
	uh = (struct udphdr *)((caddr_t)ip6 + off);
#else
	IP6_EXTHDR_GET(uh, struct udphdr *, m, off, sizeof(*uh));
	if (!uh)
		return (IPPROTO_DONE);
#endif

	plen = ntohs(ip6->ip6_plen) - off + sizeof(struct ip6_hdr);
	ulen = ntohs((u_short)uh->uh_ulen);
	
	/* This is used for packet length check assuming that there is at 
	 * least an IPv4 header inside the encapsulation.
	 */

	if (plen != ulen) {
  	        lisp6stat.ibadlen++;
		goto lisp6_input_drop;
	}


	if (ulen <= (sizeof(struct udphdr) + sizeof(struct lispshimhdr) 
		     + sizeof(struct ip))) {

#ifdef LISP_DEBUG
	        DEBUGLISP("[LISP6_INPUT] Drop! Packet legth shorter than UDP + LISP + IP headers length \n");
#endif /* LISP_DEBUG */

  	        lisp6stat.ihdrops++;
		goto lisp6_input_drop;
	}

	/* Before really stripping the outer header save RLOCs for 
	 * further checks.
	 */
	drloc.ss_family = srloc.ss_family = AF_INET6;
	drloc.ss_len = srloc.ss_len = sizeof(struct sockaddr_in6);
	((struct sockaddr_in6 *)&drloc)->sin6_addr = ip6->ip6_dst;
	((struct sockaddr_in6 *)&srloc)->sin6_addr = ip6->ip6_src;

	/* Save the value of the TTL in order to copy it back in the 
	 * inner header.
	 */
	saved_hlim= ip6->ip6_hlim;

	/* GgX - off already counts for the ip6hdr. */
	m_adj(m, (off + sizeof(struct udphdr)));

	m_copylisphdr(&m, &rlisphdr);

	/*  Strip Lisp Shim Header */
	m_adj(m, sizeof(struct lispshimhdr));

	/* XXX - There is at least an IPv4 header */
	m = m_pullup(m, sizeof(struct ip));
	ip = mtod(m, struct ip *);

	switch (ip->ip_v) {
	
	case IPVERSION:

	        lisp4stat.ioafpackets++;

	        error = lisp_check_ip_mappings( &m, &drloc, &srloc, 
						&rlisphdr );

		if (error)
		        goto lisp6_input_drop;

		delta_ttl = ip->ip_ttl - saved_hlim;
		ip->ip_ttl = (u_char) saved_hlim;

	       /* Update Checksum due to TTL recalculation 
		*/
		if (ip->ip_sum >= (u_int16_t) ~htons(delta_ttl << 8))
		        ip->ip_sum -= ~htons(delta_ttl << 8);
		else
		        ip->ip_sum += htons(delta_ttl << 8);

 	
 	        isr = NETISR_IP;

		break;

	case (IPV6_VERSION >> 4):

	        error = lisp_check_ip6_mappings( &m, &drloc, &srloc, 
						 &rlisphdr );

		if (error)
		        goto lisp6_input_drop;

		ip6 = mtod(m, struct ip6_hdr *);
		
		ip6->ip6_hlim = saved_hlim;
		
 	        isr = NETISR_IPV6;

		break;

	default:
	  
#ifdef LISP_DEBUG
	        DEBUGLISP("[LISP6_INPUT] Drop! Unrecongnized inner packet AF\n");
#endif /* LISP_DEBUG */

	        lisp6stat.ihdrops++;
	        goto lisp6_input_drop;

	};

	netisr_dispatch(isr, m);

	return (IPPROTO_DONE);

lisp6_input_drop:	

	if (m)
		m_freem(m);

	return (IPPROTO_DONE);

}  /* lisp6_input() */



int
lisp6_output(m, hlen, local_map, remote_map)
	struct mbuf *m;
	int hlen;
        struct eidmap *local_map;        
        struct eidmap *remote_map;        
{

        register int len = m->m_pkthdr.len;
        struct locator * srcrloc;
	struct locator * dstrloc;
	int error = 0;
	u_char saved_hlim;
	uint16_t usrcport;

	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);

	KASSERT(local_map->mapping,"[LISP6_OUTPUT] Output without local mapping");
	KASSERT(m, "[LISP6_OUTPUT] Output without packet");

	if (remote_map == NULL)  {
	        /* There is no mapping for the destination EID.
		 * Do not set error, so that we silently drop
		 */

	         lisp6stat.omissdrops++;
		 goto lisp6_output_drop;
		 
	};


       /* Fix the IP header before going further, then 
	* encapsulate.
	*/
	
	if (m->m_pkthdr.csum_flags & CSUM_DELAY_DATA) {
	        in_delayed_cksum(m);
		m->m_pkthdr.csum_flags &= ~CSUM_DELAY_DATA;
	};
  	
	ip6->ip6_plen = htons((len - sizeof(struct ip6_hdr)));

	/* Save original TTL value to copy it back in the new outer header.
	 */
	saved_hlim = ip6->ip6_hlim;


	/* Destination RLOC selection */
	if ((error = map_select_dstrloc(remote_map->mapping, &dstrloc))) {
	       /* There is no available RLOC that can be used 
		*/

	        lisp6stat.onorlocdrops++;
	        goto lisp6_output_drop;

	};
	
	/* If the MTU of the destination locator is set a check on 
	 * the size is performed.
	 */
	if (dstrloc->rloc_metrix.rlocmtx.mtu &&
	    ((len + sizeof(struct udphdr) + 
	      SIZEOF_IPHDR(dstrloc->rloc_addr->ss_family) +
	      sizeof(struct lispshimhdr)) > dstrloc->rloc_metrix.rlocmtx.mtu )) {
		  
	        error = EMSGSIZE;
	        lisp6stat.osizedrops++;
		goto lisp6_output_drop;
	   
	};
		

	/* Source RLOC selection 
	 * Must match the destination RLOC AF (drloc_af)
	 * and also be the address of the interface through which 
	 * the packet will be sent 
	 */
	if ((error = map_select_srcrloc(local_map->mapping, dstrloc, 
					&srcrloc))) {
	       /* There is no available RLOC that can be used. 
		*/

	        lisp6stat.onorlocdrops++;
	        goto lisp6_output_drop;

	};

	/* If the MTU of the source locator is set a check on the size
	 * is performed.
	 */
	if (srcrloc->rloc_metrix.rlocmtx.mtu &&
	    ((len + sizeof(struct udphdr) + 
	      SIZEOF_IPHDR(srcrloc->rloc_addr->ss_family) + 
	      sizeof(struct lispshimhdr)) > srcrloc->rloc_metrix.rlocmtx.mtu)) {

		error = EMSGSIZE;
	        lisp6stat.osizedrops++;
		goto lisp6_output_drop;

	};
	

	/* Global IPv6 MTU check 
	 */
	if (len + sizeof(struct udphdr) + 
	    SIZEOF_IPHDR(srcrloc->rloc_addr->ss_family) +
	    sizeof(struct lispshimhdr) > IPV6_MAXPACKET) {

		error = EMSGSIZE;
	        lisp6stat.osizedrops++;
		goto lisp6_output_drop;

	};
	
	/* Ready to encapsulate.
	 * Before do it let's calculate the src port
	 * Src port is hash based on the inner header.
	 */

	usrcport = get_lisp_srcport(&m);

	m = m_lisphdrprepend(m, remote_map, local_map, dstrloc, srcrloc);

	if (m == NULL) {

		error = ENOBUFS;
	        lisp6stat.onobufdrops++;
		goto lisp6_output_drop;
	};


	switch (srcrloc->rloc_addr->ss_family) {
	  
	        case AF_INET:	 
	
		        lisp4stat.ooafpackets++;

		        if ( !(error = lisp_ip_encap(&m,
						     (len + sizeof(struct lispshimhdr)), 
						     &((struct sockaddr_in *)srcrloc->rloc_addr)->sin_addr, 	     
						     &((struct sockaddr_in *)dstrloc->rloc_addr)->sin_addr, 	     
						     ((u_char) saved_hlim),
						     usrcport))){
			
		                lisp4stat.opackets++;
				error = ip_output(m, NULL, NULL, IP_LISP, NULL, NULL);

			};
			
			FREE_EIDMAP(local_map);
			FREE_EIDMAP(remote_map);

			return(error);

			break;

                 case AF_INET6:

		        if ( !(error = lisp_ip6_encap(&m, 
						      (len + sizeof(struct lispshimhdr)), 
						     &((struct sockaddr_in6 *)srcrloc->rloc_addr)->sin6_addr, 	     
						     &((struct sockaddr_in6 *)dstrloc->rloc_addr)->sin6_addr, 
						      saved_hlim,
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
	

lisp6_output_drop:

	if (remote_map) {
	        FREE_EIDMAP(remote_map);
	};

	FREE_EIDMAP(local_map);

 	m_freem(m);

	lisp6stat.odrops++;
	lisp6stat.opackets++;

	return (error); 

}   /* lisp6_output() */


