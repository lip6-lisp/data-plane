/*- /usr/src/sys/net/lisp/mapsock.c
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
 * $Id: mapsock.c 176 2011-09-22 14:06:30Z ggx $
 *
 */

/*-
 * Copyright (c) 1988, 1991, 1993
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
 *	@(#)rtsock.c	8.7 (Berkeley) 10/12/95
 * $FreeBSD: src/sys/net/rtsock.c,v 1.123.2.7 2006/04/04 20:07:23 andre Exp $
 */

#include <sys/param.h>
#include <sys/domain.h>
#include <sys/kernel.h>
#include <sys/jail.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/signalvar.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/systm.h>

#include "/usr/include/syslog.h"


#include <net/if.h>
#include <net/netisr.h>
#include <net/raw_cb.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <net/lisp/lisp.h>
#include <net/lisp/maptables.h>

static struct	sockaddr map_src = { 2, PF_ROUTE, };
static struct	sockaddr_storage ss_ones_inet    = { sizeof(struct sockaddr_in),
						     AF_INET, };
static struct	sockaddr_storage ss_ones_inet6   = { sizeof(struct sockaddr_in6),
						     AF_INET6, };
 

static struct {
  int	ip_count;	/* attached w/ AF_INET */
  int	ip6_count;	/* attached w/ AF_INET6 */
  int	ipx_count;	/* attached w/ AF_IPX */
  int	any_count;	/* total attached */
} map_cb;

struct mtx mapsock_mtx;
MTX_SYSINIT(mapsock, &mapsock_mtx, "mapsock map_cb lock", MTX_DEF);

#define	MAPSOCK_LOCK()	mtx_lock(&mapsock_mtx)
#define	MAPSOCK_UNLOCK()	mtx_unlock(&mapsock_mtx)
#define	MAPSOCK_LOCK_ASSERT()	mtx_assert(&mapsock_mtx, MA_OWNED)
  
struct walkarg {
	int	w_tmemsize;
	int	w_op, w_arg;
	caddr_t	w_tmem;
	struct sysctl_req *w_req;
};
    

static void	map_input(struct mbuf *m);
static int	map_output(struct mbuf *m, struct socket *so);
static void	map_dispatch(struct mbuf *, const struct sockaddr_storage *);
static int	map_msg2(int type, struct map_addrinfo *mapinfo,
			 caddr_t cp, struct walkarg *w);
static int	map_xaddrs(caddr_t cp, caddr_t cplim, 
			   struct map_addrinfo *mapinfo);
static int	sysctl_dumpmapentry(struct radix_node *rn, void *vw);


SYSCTL_NODE(_net, OID_AUTO, mapsock, CTLFLAG_RD, 0, "");

static struct netisr_handler mapsock_nh = {
        .nh_name = "mapsock",
	.nh_handler = map_input,
	.nh_proto = NETISR_MAPPING,
	.nh_policy = NETISR_POLICY_SOURCE,
};
 

static int
sysctl_mapsock_netisr_maxqlen(SYSCTL_HANDLER_ARGS)
{
        int error, qlimit;

        netisr_getqlimit(&mapsock_nh, &qlimit);
        error = sysctl_handle_int(oidp, &qlimit, 0, req);

        if (error || !req->newptr)
	        return (error);

	if (qlimit < 1)
	        return (EINVAL);

	return (netisr_setqlimit(&mapsock_nh, qlimit));

} /* sysctl_maptables_netisr_maxqlen() */

SYSCTL_PROC(_net_mapsock, OID_AUTO, netisr_maxqlen, CTLTYPE_INT|CTLFLAG_RW,
	    0, 0, sysctl_mapsock_netisr_maxqlen, "I",
	    "maximum mapping socket dispatch queue length");


static void
map_init(void)
{
	int tmp;

	if (TUNABLE_INT_FETCH("net.maptables.netisr_maxqlen", &tmp))
	         mapsock_nh.nh_qlimit = tmp;

	netisr_register(&mapsock_nh);
	/* Init static structures */

	memset( &(((struct sockaddr_in *)&ss_ones_inet)->sin_addr), 0xFF,
		sizeof(struct in_addr));
	memset( &(((struct sockaddr_in6 *)&ss_ones_inet6)->sin6_addr), 0xFF,
		sizeof(struct in6_addr));

} /* map_init() */

SYSINIT(mapsock, SI_SUB_PROTO_DOMAIN, SI_ORDER_THIRD, map_init, 0);

static void
map_input(struct mbuf *m)
{
  	struct sockproto map_proto;
	unsigned short *family;
	struct m_tag *tag;

	map_proto.sp_family = PF_MAP;
	tag = m_tag_find(m, PACKET_TAG_MAPSOCKFAM, NULL);
	if (tag != NULL) {
		family = (unsigned short *)(tag + 1);
		map_proto.sp_protocol = *family;
		m_tag_delete(m, tag);
	} else
		map_proto.sp_protocol = 0;

	raw_input(m, &map_proto, &map_src);/*, &map_dst); from 7.0*/
}

/*
 * It really doesn't make any sense at all for this code to share much
 * with raw_usrreq.c, since its functionality is so restricted.  XXX
 */
static void
map_abort(struct socket *so)
{

	raw_usrreqs.pru_abort(so);
}

static void
map_close(struct socket *so) 
{                                                                            

        raw_usrreqs.pru_close(so);                                            
} 

static int
map_attach(struct socket *so, int proto, struct thread *td)
{
	struct rawcb *rp;
	int s, error;

	KASSERT(so->so_pcb == NULL, ("map_attach: so_pcb != NULL"));    

	/* XXX */
	MALLOC(rp, struct rawcb *, sizeof *rp, M_PCB, M_WAITOK | M_ZERO);
	if (rp == NULL)
		return ENOBUFS;

	/*
	 * The splnet() is necessary to block protocols from sending
	 * error notifications while
	 * this PCB is extant but incompletely initialized.
	 * Probably we should try to do more of this work beforehand and
	 * eliminate the spl.
	 */
	s = splnet();
	so->so_pcb = (caddr_t)rp;
	error = raw_attach(so, proto);
	rp = sotorawcb(so);
	if (error) {
		splx(s);
		so->so_pcb = NULL;
		free(rp, M_PCB);
		return error;
	}
	MAPSOCK_LOCK();
	switch(rp->rcb_proto.sp_protocol) {
	case AF_INET:
		map_cb.ip_count++;
		break;
	case AF_INET6:
		map_cb.ip6_count++;
		break;
	case AF_IPX:
		map_cb.ipx_count++;
		break;
	}
	map_cb.any_count++;
	MAPSOCK_UNLOCK();
	soisconnected(so);
	so->so_options |= SO_USELOOPBACK;
	splx(s);
	return 0;
}


static int
map_bind(struct socket *so, struct sockaddr *nam, struct thread *td)
{

  return (raw_usrreqs.pru_bind(so, nam, td)); /* xxx just EINVAL */
}

static int
map_connect(struct socket *so, struct sockaddr *nam, struct thread *td)
{

  return (raw_usrreqs.pru_connect(so, nam, td)); /* XXX just EINVAL */
}


static void
map_detach(struct socket *so)
{
  	struct rawcb *rp = sotorawcb(so);

	KASSERT(rp != NULL, ("map_detach: rp == NULL"));

	MAPSOCK_LOCK();
	switch(rp->rcb_proto.sp_protocol) {
	case AF_INET:
	        map_cb.ip_count--;
		break;
	case AF_INET6:
	        map_cb.ip6_count--;
		break;
	}

	map_cb.any_count--;
	MAPSOCK_UNLOCK();
	raw_usrreqs.pru_detach(so);

}

static int
map_disconnect(struct socket *so)
{

	return (raw_usrreqs.pru_disconnect(so));
}

static int
map_peeraddr(struct socket *so, struct sockaddr **nam)
{

	return (raw_usrreqs.pru_peeraddr(so, nam));
}

static int
map_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *nam,
	 struct mbuf *control, struct thread *td)
{

	return (raw_usrreqs.pru_send(so, flags, m, nam, control, td));
}


static int
map_shutdown(struct socket *so)
{

	return (raw_usrreqs.pru_shutdown(so));
}


static int
map_sockaddr(struct socket *so, struct sockaddr **nam)
{

	return (raw_usrreqs.pru_sockaddr(so, nam));
}


static struct pr_usrreqs map_usrreqs = {
	.pru_abort =		map_abort,
	.pru_attach =		map_attach,
	.pru_bind =		map_bind,
	.pru_connect =		map_connect,
	.pru_detach =		map_detach,
	.pru_disconnect =	map_disconnect,
	.pru_peeraddr =		map_peeraddr,
	.pru_send =		map_send,
	.pru_shutdown =		map_shutdown,
	.pru_sockaddr =		map_sockaddr,
	.pru_close =            map_close,
};


static int
map_output(struct mbuf *m, struct socket *so)
{
#define	sa_equal(a1, a2) (bcmp((a1), (a2), (a1)->ss_len) == 0)
	struct map_msghdr *mapmsg = NULL;
	struct mapentry *map = NULL;
	struct radix_node_head *rnh;
	struct map_addrinfo mapinfo;
	int len, error = 0;

#define senderr(e) { error = e; goto flush;}
	if (m == NULL || ((m->m_len < sizeof(long)) &&
		       (m = m_pullup(m, sizeof(long))) == NULL))
		return (ENOBUFS);

	if ((m->m_flags & M_PKTHDR) == 0)
		panic("map_output");
	len = m->m_pkthdr.len;

	if (len < sizeof(*mapmsg) ||
	    len != mtod(m, struct map_msghdr *)->map_msglen) {
		mapinfo.mapi_info[MAPX_EID] = NULL;

#ifdef LISP_DEBUG
		DEBUGLISP("[MAP_OUTPUT] Message Length Missmatch \n");
#endif /* LISP_DEBUG */

		senderr(EINVAL);
	}

	R_Malloc(mapmsg, struct map_msghdr *, len);
	if (mapmsg == NULL) {
		mapinfo.mapi_info[MAPX_EID] = NULL;
		senderr(ENOBUFS);
	}

	m_copydata(m, 0, len, (caddr_t)mapmsg);
	if (mapmsg->map_version != MAPM_VERSION) {
		mapinfo.mapi_info[MAPX_EID] = NULL;
		senderr(EPROTONOSUPPORT);
	}

	mapmsg->map_pid = curproc->p_pid;
	bzero(&mapinfo, sizeof(mapinfo));
	mapinfo.mapi_addrs = mapmsg->map_addrs;
	mapinfo.mapi_rloc_count = mapmsg->map_rloc_count;
	mapinfo.mapi_versioning = mapmsg->map_versioning;
	mapinfo.mapi_flags = mapmsg->map_flags;

	/* GgX - map_xaddrs checks also the condition ss_family 
	 * is either AF_INET or AF_INET6.
	 * If the condition is true, EINVAL is returned.
	 * Thus here no checks on ss_family are necessary.
	 */
	if (map_xaddrs((caddr_t)(mapmsg + 1), len + (caddr_t)mapmsg, &mapinfo)) {
		 mapinfo.mapi_info[MAPX_EID] = NULL;

#ifdef LISP_DEBUG
		 DEBUGLISP("[MAP_OUTPUT] Message Addresses Not Valid \n");
#endif /* LISP_DEBUG */

		 senderr(EINVAL);
	}

	/* 
	 *Force exact match lookup unless it is a GET 
	 */	
	if ( mapmsg->map_type != MAPM_GET
	     && mapinfo.mapi_info[MAPX_EID] 
	     && !(mapinfo.mapi_info[MAPX_EIDMASK])) {
	       /* If no mask is provided point to a safe address
		* with with a host length mask (i.e., /32 for IPv4
		* and /128 for IPv6).
		*/
	  
	        mapinfo.mapi_addrs |= MAPA_EIDMASK;
	  
		switch (mapinfo.mapi_info[MAPX_EID]->ss_family) {
		case AF_INET:
		        mapinfo.mapi_info[MAPX_EIDMASK] = &ss_ones_inet;
			break; 
			      
		case AF_INET6:
		        mapinfo.mapi_info[MAPX_EIDMASK] = &ss_ones_inet6;
			break;
		};

	};

	if ((mapinfo.mapi_rloc_count && (mapinfo.mapi_info[MAPX_RLOC] == NULL)) ||
	    ((mapinfo.mapi_rloc_count == 0) && mapinfo.mapi_info[MAPX_RLOC]) ||
	    ((mapinfo.mapi_flags & MAPF_NEGATIVE) && (mapinfo.mapi_rloc_count || mapinfo.mapi_info[MAPX_RLOC]))) {
	       /* GgX - This is redundant but keep it by now */

#ifdef LISP_DEBUG
	        DEBUGLISP("[MAP_OUTPUT] Badly Formatted RLOCs records! \n");
#endif /* LISP_DEBUG */

		senderr(EINVAL);
	};
	  
	if (mapinfo.mapi_info[MAPX_EID] == NULL ) {

#ifdef LISP_DEBUG
	         DEBUGLISP("[MAP_OUTPUT] No EID Provided! \n");
#endif /* LISP_DEBUG */

	         senderr(EINVAL);
	};
	
	//senderr(ENOBUFS);    
	/* Checks if the eidmask is already in the radix 
	*/
	// if (mapinfo.mapi_info[MAPX_EIDMASK]) {
	        // struct radix_node *t;
		// t = rn_addmask((caddr_t) mapinfo.mapi_info[MAPX_EIDMASK], 0, 1);
		// if (t != NULL &&
		    // bcmp((char *)(void *)mapinfo.mapi_info[MAPX_EIDMASK] + 1,
			 // (char *)(void *)t->rn_key + 1,
			 // ((struct sockaddr *)t->rn_key)->sa_len - 1) == 0)
		        // mapinfo.mapi_info[MAPX_EIDMASK] = 
			  // (struct sockaddr_storage *)t->rn_key;
		// else
		        // senderr(ENOBUFS);
	// }
  
	/*
	 * Verify that the caller has the appropriate privilege; MAPM_GET
	 * is the only operation the non-superuser is allowed.
	 */
	if (mapmsg->map_type != MAPM_GET) {
	        error = priv_check(curthread, PRIV_NET_ROUTE);
		if (error)
		        senderr(error);
	}

	switch (mapmsg->map_type) {
	struct mapentry *saved_mapentry;

	case MAPM_ADD:
        
		error = maprequest(MAPM_ADD, &mapinfo, &saved_mapentry);
		
		if (error == 0 && saved_mapentry) {
		        MAP_LOCK(saved_mapentry);
			MAP_REMREF(saved_mapentry);
			MAP_UNLOCK(saved_mapentry);
		};

		break;

	case MAPM_DELETE:

	        saved_mapentry = NULL;
		error = maprequest(MAPM_DELETE, &mapinfo, &saved_mapentry);		
		if (error == 0) {
			MAP_LOCK(saved_mapentry);
			map = saved_mapentry;
			goto report;
		}
		break;
		
	case MAPM_GET:

		/*PCD*/
		if( (lispfunc == LISP_XTR) || !(mapinfo.mapi_flags & MAPF_DB) ){
			MAPTABLES(rnh, mapinfo.mapi_info[MAPX_EID]->ss_family);
		}else{
			FW_MAPTABLES(rnh,mapinfo.mapi_info[MAPX_EID]->ss_family);
		}			
		/*DPC*/
		if (rnh == NULL)
			senderr(EAFNOSUPPORT);

		RADIX_NODE_HEAD_LOCK(rnh);
		map = (struct mapentry *) rnh->rnh_lookup(mapinfo.mapi_info[MAPX_EID], mapinfo.mapi_info[MAPX_EIDMASK], rnh);
		if (map == NULL) {	/* XXX looks bogus */
			RADIX_NODE_HEAD_UNLOCK(rnh);
			senderr(ESRCH);
		}


		MAP_LOCK(map);
		MAP_ADDREF(map);
		RADIX_NODE_HEAD_UNLOCK(rnh);

                 if (mapmsg->map_type != MAPM_GET && 
                         (!map_mask(map) != !mapinfo.mapi_info[MAPX_EIDMASK])) {

		         MAP_UNLOCK(map);
                         senderr(ESRCH);

		 }
   
		 switch(mapmsg->map_type) {
 
		 case MAPM_GET:
report:
			MAP_LOCK_ASSERT(map);
			mapinfo.mapi_info[MAPX_EID] = (struct sockaddr_storage *) map_key(map);
			mapinfo.mapi_info[MAPX_EIDMASK] = (struct sockaddr_storage *) map_mask(map);
			
			mapinfo.mapi_rloc_count = map_rlocsnum(map);
			if (mapinfo.mapi_rloc_count)
			        mapinfo.mapi_info[MAPX_RLOC] = (struct sockaddr_storage *) map_rlocs(map);
			/* GgX - This is not clean since actually map_rlocs(map)
			 * points to a locator_chain struct that is the head
			 * of the rlocs list. Yet this handled correctly
			 * in map_msg2.
			 */

			if (map->map_flags & MAPF_VERSIONING) {
			        mapinfo.mapi_versioning = ntohs(map->vnum);
			};

			len = map_msg2(mapmsg->map_type, &mapinfo, NULL, NULL);
			if (len > mapmsg->map_msglen) {
				struct map_msghdr *new_mapmsg;
				R_Malloc(new_mapmsg, struct map_msghdr *, len);
				if (new_mapmsg == NULL) {
					MAP_UNLOCK(map);
					senderr(ENOBUFS);
				}
				bcopy(mapmsg, new_mapmsg, mapmsg->map_msglen);
				Free(mapmsg); 
				mapmsg = new_mapmsg;
			}

			(void)map_msg2(mapmsg->map_type, &mapinfo, (caddr_t)mapmsg, NULL);
			mapmsg->map_flags = map->map_flags;
			mapmsg->map_addrs = mapinfo.mapi_addrs;
			break;
		}
		MAP_UNLOCK(map);

		break;
	  
	default:
		senderr(EOPNOTSUPP);
	}
	
flush:	
	if (mapmsg) {		
		if (error)
			mapmsg->map_errno = error;
		else
			mapmsg->map_flags |= MAPF_DONE;
	}
	if (map)		/* XXX can this be true? */
		MAPFREE(map);		
	
	{
	struct rawcb *rp = NULL;
	/*
	 * Check to see if we don't want our own messages.
	 */
	if ((so->so_options & SO_USELOOPBACK) == 0) {
		if (map_cb.any_count <= 1) {
		        if (mapmsg)
				Free(mapmsg);
			m_freem(m);
			return (error);
		}
		/* There is another listener, so construct message */
		rp = sotorawcb(so);
	}
	if (mapmsg) {
		m_copyback(m, 0, mapmsg->map_msglen, (caddr_t)mapmsg);
		if (m->m_pkthdr.len < mapmsg->map_msglen) {
			m_freem(m);
			m = NULL;
		} else if (m->m_pkthdr.len > mapmsg->map_msglen)
			m_adj(m, mapmsg->map_msglen - m->m_pkthdr.len);
		Free(mapmsg);
	}
	if (m) {
		if (rp) {
			
			/*
			 * XXX insure we don't get a copy by
			 * invalidating our protocol
			 */
			unsigned short family = rp->rcb_proto.sp_family;
			rp->rcb_proto.sp_family = 0;
			map_dispatch(m, mapinfo.mapi_info[MAPX_EID]);
			rp->rcb_proto.sp_family = family;
		} else
			map_dispatch(m, mapinfo.mapi_info[MAPX_EID]);
	}
	}
	return (error);
#undef	sa_equal

} /* map_output */



/*
 * Extract the addresses of the passed sockaddrs.
 * Do a little sanity checking so as to avoid bad memory references.
 * This data is derived straight from userland.
 */
static int
map_xaddrs(caddr_t cp, caddr_t cplim, struct map_addrinfo *mapinfo)
{
        struct sockaddr_storage *ss, *savedss;
	int i, rlocnum;
	int maskflag = 0;

	for (i = 0; i < MAPX_MAX && cp < cplim; i++) {

	  switch ((mapinfo->mapi_addrs & (1 << i))) {
		
	  case MAPA_EIDMASK:
	        maskflag = 1;
	       /* Remember that a mask has been provided and fall through.
		*/

	  case MAPA_EID:
		ss = (struct sockaddr_storage *)cp;
		/*
		 * It won't fit.
		 */
		if (((cp + ss->ss_len) > cplim) || 
		    ((ss->ss_family != AF_INET) && 
		     (ss->ss_family != AF_INET6))) {

#ifdef LISP_DEBUG
		        DEBUGLISP("[MAP_XADDRS] EIDMASK not Valid! \n");
#endif /* LISP_DEBUG */

			return (EINVAL);

		};

		if (ss->ss_len == 0) {
			return (EINVAL); 
		}

		/* accept it */
		mapinfo->mapi_info[i] = ss;
		cp += SS_SIZE(ss);

		break;

	  case MAPA_RLOC:
	        if ((rlocnum = mapinfo->mapi_rloc_count) &&
		    (mapinfo->mapi_flags & MAPF_NEGATIVE)) 
		        return(EINVAL);
	
		savedss = (struct sockaddr_storage *)cp;
		while (rlocnum--) {
		          ss = (struct sockaddr_storage *)cp;
			  /*
			   * It won't fit.
			   */
			  if (((cp + ss->ss_len + sizeof(struct rloc_mtx)) > cplim) || 
			      ((ss->ss_family != AF_INET) && 
			       (ss->ss_family != AF_INET6))) {

#ifdef LISP_DEBUG
			          DEBUGLISP("[MAP_XADDRS] RLOC Addreess not Valid! \n");
#endif /* LISP_DEBUG */

 			          return (EINVAL);

			  };

			  if (ss->ss_len == 0) {

#ifdef LISP_DEBUG
			          DEBUGLISP("[MAP_XADDRS] ss_len field equal 0! \n");
#endif /* LISP_DEBUG */

			          return (EINVAL); 			  
			  };
			  cp += SS_SIZE(ss);
			  cp += sizeof(struct rloc_mtx); 
			                     /* to count Priority, 
					      * Weight, Flags, and
					      * MTU;
					      */
		};
		mapinfo->mapi_info[i] = savedss; 
		                             /* store rloc chain head */
		break;
	  };

	};

	return (0);

} /* map_xaddrs() */


static struct mbuf *
map_msg1(int type, struct map_addrinfo *mapinfo, struct mbuf ** mpkt)
{
	struct map_msghdr *mapm;
	struct mbuf *m;
	struct mbuf * mp = NULL; 
	int i;
	struct sockaddr_storage *ss;
	int len, dlen;

	switch (type) {
	       /* Keep this, there can be other cases in the future 
		*/

	default:
		len = sizeof(struct map_msghdr);
	};

	if (len > MCLBYTES)
		panic("map_msg1");

	m = m_gethdr(M_DONTWAIT, MT_DATA);
	if (m && len > MHLEN) {
		MCLGET(m, M_DONTWAIT);
		if ((m->m_flags & M_EXT) == 0) {
			m_free(m);
			m = NULL;
		}
	}
	if (m == NULL)
		return (m);

	m->m_pkthdr.len = m->m_len = len;
	m->m_pkthdr.rcvif = NULL;
	mapm = mtod(m, struct map_msghdr *);
	bzero((caddr_t)mapm, len);
	for (i = 0; i < MAPX_MAX; i++) {
		if ((ss = mapinfo->mapi_info[i]) == NULL)
			continue;
		mapinfo->mapi_addrs |= (1 << i);
		dlen = SS_SIZE(ss);
		m_copyback(m, len, dlen, (caddr_t)ss);
		len += dlen;
	};
	
	/* Append other information if necessary
	 */
	switch (type) {

	case MAPM_MISS_HEADER:

	  if ( (*mpkt) == NULL) {
	                m_freem(m);
			return (NULL);
		};
	  
		switch ((mapinfo->mapi_info[MAPX_EID])->ss_family) { 
	  
		case AF_INET:
	                dlen = sizeof(struct ip);
			(*mpkt) = m_pullup((*mpkt), dlen);
			m_append(m, dlen, mtod((*mpkt), c_caddr_t));
			len += dlen;
			break;
		
		};
#ifdef INET6
		case AF_INET6:
	                dlen = sizeof(struct ip6_hdr);
			(*mpkt) = m_pullup((*mpkt), dlen);
			m_append(m, dlen, mtod((*mpkt), c_caddr_t));
			len += dlen;
			break;
#endif /* INET6 */	  

		break;

	case MAPM_MISS_PACKET:

      	        mp = m_copypacket((*mpkt), M_DONTWAIT);

	        if ( ((*mpkt) == NULL) || (mp == NULL) ){
	                m_freem(m);
			return (NULL);
		};
	  
	        dlen = mp->m_pkthdr.len;
		m_cat(m, mp);
		m->m_pkthdr.len += dlen;
		len += dlen;
		break;

	};


	if (m->m_pkthdr.len != len) {
		m_freem(m);
		return (NULL);
	}
	mapm->map_msglen = len;
	mapm->map_version = MAPM_VERSION;
	mapm->map_type = type;
	mapm->map_addrs = mapinfo->mapi_addrs;

	return (m);

} /* map_msg1() */


static int
map_msg2(int type, struct map_addrinfo *mapinfo, caddr_t cp, struct walkarg *w)
{
	int i;
	int len, dlen, second_time = 0;
	caddr_t cp0;
	int rlocnum = 0;
	struct rloc_mtx * rmtxptr = NULL;

	mapinfo->mapi_addrs = 0;

again:

	len = sizeof(struct map_msghdr);

	cp0 = cp;
	if (cp0)
		cp += len;
	for (i = 0; i < MAPX_MAX; i++) {
		struct sockaddr_storage *ss;
		caddr_t * rlocmtx;
		struct locator_chain * rlocp;

		if ((ss = mapinfo->mapi_info[i]) == NULL)
			continue;

		mapinfo->mapi_addrs |= (1 << i);
		
		switch (1 << i) {
		
		case MAPA_EID:
		case MAPA_EIDMASK:
		        dlen = SS_SIZE(ss);
			if (cp) {
			       bcopy((caddr_t)ss, cp, (unsigned)dlen);
			       cp += dlen;
			}
			len += dlen;
			break;

		case MAPA_RLOC:
	                rlocnum = mapinfo->mapi_rloc_count;
		        rlocp = (struct locator_chain *) mapinfo->mapi_info[i];
 		        while (rlocnum--) {
		                ss = (struct sockaddr_storage *) rlocp->rloc.rloc_addr;
				dlen = SS_SIZE(ss);
				if (cp) {
			                bcopy((caddr_t)ss, cp, (unsigned)dlen);
					cp += dlen;
				}
				len += dlen;

				/* Metrics */
				rlocmtx = (caddr_t *) &rlocp->rloc.rloc_metrix.rlocmtx;
				dlen = sizeof(struct rloc_mtx);
				if (cp) {
			                bcopy(rlocmtx, cp, (unsigned)dlen);
				       /* Convert nonces in host byte order
					*/
					rmtxptr = (struct rloc_mtx*)cp;
					rmtxptr->tx_nonce.nvalue = ntohl(((struct rloc_mtx *)rlocmtx)->tx_nonce.nvalue) >> 8;
					rmtxptr->rx_nonce.nvalue = ntohl(((struct rloc_mtx *)rlocmtx)->rx_nonce.nvalue) >> 8;
					cp += dlen;
				}
				len += dlen;

				rlocp = rlocp->next;

			};
			break;
		};

	}
	len = ALIGN(len);
	if (cp == NULL && w != NULL && !second_time) {
		struct walkarg *rw = w;

		if (rw->w_req) {
			if (rw->w_tmemsize < len) {
				if (rw->w_tmem)
					free(rw->w_tmem, M_RTABLE);
				rw->w_tmem = (caddr_t)
					malloc(len, M_RTABLE, M_NOWAIT);
				if (rw->w_tmem)
					rw->w_tmemsize = len;
			}
			if (rw->w_tmem) {
				cp = rw->w_tmem;
				second_time = 1;
				goto again;
			}
		}
	}

	if (cp) {

		struct map_msghdr *mapmsg = (struct map_msghdr *)cp0;

		mapmsg->map_version = MAPM_VERSION;
		mapmsg->map_type = type;
		mapmsg->map_msglen = len;
		mapmsg->map_rloc_count = mapinfo->mapi_rloc_count;
		mapmsg->map_versioning = mapinfo->mapi_versioning;

	};

	return (len);

} /* map_msg2 */


void
map_notifymsg(type, mapinfo, mapping, mpkt, flags, error)
     int type;
     struct map_addrinfo *mapinfo;
     struct mapentry *mapping;
     struct mbuf ** mpkt; 
     int flags;
     int * error;
/*
 * This routine is called to generate a message from the mapping
 * socket indicating that something occured or a map lookup failed.
 * In case of MAPM_MISS type the mapping pointer is ignored.
 * In case of MAPM_EXPIRED type the mpkt pointer is ignored.
 */
{
	struct map_msghdr *mapm;
	struct mbuf *m;
	struct sockaddr_storage *ss = mapinfo->mapi_info[MAPX_EID];
	struct map_addrinfo newmapinfo;
	int len = 0;

	if (map_cb.any_count == 0) 
		return;

	switch (type) {

	case MAPM_MISS:
	  
	        switch (lispmissmsg) {
	    
		case LISP_MISSMSG_PACKET:

		  if ( (*mpkt) == NULL ) {
		                 (*error) = ENOATTR;
				 return;
			};

			type = MAPM_MISS_PACKET;

			break;

		case LISP_MISSMSG_HEADER:

		  if ( (*mpkt) == NULL ) {
		                (*error) = ENOATTR;
				return;
			};

			type = MAPM_MISS_HEADER;

			break;

		case LISP_MISSMSG_EID: 
		default:

	                type = MAPM_MISS_EID;

		};

		m = map_msg1(type, mapinfo, mpkt);

		break;

	case MAPM_DELETE:
	      
	        if (mapping == NULL) {
		        (*error) = ENOATTR;
			return;
		};

		bzero(&newmapinfo, sizeof(newmapinfo));
		
		newmapinfo.mapi_addrs |= MAPA_EID;
                newmapinfo.mapi_info[MAPX_EID] = (struct sockaddr_storage *) map_key(mapping);
		newmapinfo.mapi_addrs |= MAPA_EIDMASK;
                newmapinfo.mapi_info[MAPX_EIDMASK] = (struct sockaddr_storage *) map_mask(mapping);

                newmapinfo.mapi_rloc_count = map_rlocsnum(mapping);

                if (newmapinfo.mapi_rloc_count) {
		       newmapinfo.mapi_addrs |= MAPA_RLOC;
		       newmapinfo.mapi_info[MAPX_RLOC] = (struct sockaddr_storage *) map_rlocs(mapping);
                        /* This is not clean since actually map_rlocs(map)
			 * points to a locator_chain struct that is the head
			 * of the rlocs list. Yet this handled correctly
			 * in map_msg2.
			 */
		};

                if (mapping->map_flags & MAPF_VERSIONING) 
		        newmapinfo.mapi_versioning = ntohs(mapping->vnum);
		

		len = map_msg2(type, &newmapinfo, NULL, NULL);

		if (len > MCLBYTES)
		       panic("map_notifymsg");

		m = m_gethdr(M_DONTWAIT, MT_DATA);
		if (m && len > MHLEN) {
		        MCLGET(m, M_DONTWAIT);
			if ((m->m_flags & M_EXT) == 0) {
			        m_free(m);
				m = NULL;
			};
		};

		if (m == NULL) {
		        (*error) = ENOBUFS;
		        return;
		};

		R_Malloc(mapm, struct map_msghdr *, len);

		if (mapm == NULL) {
		        m_free(m);
		        (*error) = ENOBUFS;
		        return;
		};

		(void)map_msg2(type, &newmapinfo, (caddr_t)mapm, NULL);

                mapm->map_flags = mapping->map_flags;
                mapm->map_addrs = newmapinfo.mapi_addrs;

		if (mapm) {
		  
		        m_copyback(m, 0, mapm->map_msglen, (caddr_t)mapm);
			
			if (m->m_pkthdr.len < mapm->map_msglen) {
			        m_freem(m);
				m = NULL;
			} else if (m->m_pkthdr.len > mapm->map_msglen)
			        m_adj(m, mapm->map_msglen - m->m_pkthdr.len);
			
			Free(mapm);
		
		};

		break;

	default:

 	        m = NULL; 

	};

	if (m == NULL)
		return;

	mapm = mtod(m, struct map_msghdr *);
	mapm->map_flags |= (MAPF_DONE | flags);
	mapm->map_errno = (*error);
	map_dispatch(m, ss);

}  /* map_notifymsg() */


static void
map_dispatch(struct mbuf *m, const struct sockaddr_storage *ss)
{
	struct m_tag *tag;

	/*
	 * Preserve the family from the sockaddr, if any, in an m_tag for
	 * use when injecting the mbuf into the routing socket buffer from
	 * the netisr.
	 */
	if (ss != NULL) {
		tag = m_tag_get(PACKET_TAG_MAPSOCKFAM, sizeof(unsigned short),
		    M_NOWAIT);
		if (tag == NULL) {
			m_freem(m);
			return;
		}
		*(unsigned short *)(tag + 1) = ss->ss_family;
		m_tag_prepend(m, tag);
	}
	netisr_queue(NETISR_MAPPING, m); /* mbuf is free'd on failure. */
}



/*
 * This is used in dumping the kernel table via sysctl().
 */
static int
sysctl_dumpmapentry(struct radix_node *rn, void *vw)
{
	struct walkarg *w = vw;
	struct mapentry *map = (struct mapentry *)rn;
	int error = 0, size;
	struct map_addrinfo info;

	if (w->w_op == NET_MAPTBL_FLAGS && !(map->map_flags & w->w_arg))
		return 0;

	bzero((caddr_t)&info, sizeof(info));

	info.mapi_addrs = MAPA_EID;

	info.mapi_info[MAPX_EID] = (struct sockaddr_storage *) map_key(map);

	if ( map_mask(map) != NULL ) {
	        info.mapi_addrs |= MAPA_EIDMASK;
		info.mapi_info[MAPX_EIDMASK] = (struct sockaddr_storage *) map_mask(map);
	};

	info.mapi_rloc_count = map_rlocsnum(map);
	if (info.mapi_rloc_count) {
	        info.mapi_addrs |= MAPA_RLOC;
	        info.mapi_info[MAPX_RLOC] = (struct sockaddr_storage *) map_rlocs(map);
	};

	size = map_msg2(MAPM_GET, &info, NULL, w);
	if (w->w_req && w->w_tmem) {
		struct map_msghdr *mapmsg = (struct map_msghdr *)w->w_tmem;

		mapmsg->map_flags = map->map_flags;
		mapmsg->map_errno = mapmsg->map_pid = mapmsg->map_seq = 0;
		mapmsg->map_addrs = info.mapi_addrs;
		error = SYSCTL_OUT(w->w_req, (caddr_t)mapmsg, size);
		return (error);
	}

	return (error);

}  /* sysctl_dumpmapentry() */

static int
sysctl_mapsock(SYSCTL_HANDLER_ARGS)
{
  	int	*name = (int *)arg1;
	u_int	namelen = arg2;
	struct radix_node_head *rnh;
	int	i, j, lim, error = EINVAL;

	u_char	af;
	struct	walkarg w;
	
	name++;
	namelen--;

	if (req->newptr)
		return (EPERM);

	if (namelen != 3)
		return ((namelen < 3) ? EISDIR : ENOTDIR);

	af = name[0];
	if (af > AF_MAX) {

#ifdef LISP_DEBUG
	        DEBUGLISP("[SYSCTL_MAPSOCK] AF out of range! \n");
#endif /* LISP_DEBUG */

		return (EINVAL);
	};

	bzero(&w, sizeof(w));
	w.w_op = name[1];
	w.w_arg = name[2];
	w.w_req = req;
	
	error = sysctl_wire_old_buffer(req, 0);
	if (error)
		return (error);

	switch (w.w_op) {

	case NET_MAPTBL_DUMP:
	case NET_MAPTBL_FLAGS:
	  	if (af == 0) {			/* dump all tables */
			i = j = 0;
			lim = AF_MAX;
		} else				/* dump only one table */
			i = j = lim = af;
		
		for (error = 0; error == 0 && i < lim; i++) {
			MAPTABLES(rnh,i);
			if ( rnh != NULL) {
				RADIX_NODE_HEAD_LOCK(rnh); 
			    error = rnh->rnh_walktree(rnh,
				    sysctl_dumpmapentry, &w);
				RADIX_NODE_HEAD_UNLOCK(rnh);
			} else if (af != 0)
				error = EAFNOSUPPORT;
		};
		/*PCD*/
		if(lispfunc != LISP_XTR){
			i = j;
			for (error = 0; error == 0 && i < lim; i++) {
				FW_MAPTABLES(rnh,i);
				if ( rnh != NULL) {
					RADIX_NODE_HEAD_LOCK(rnh); 
					error = rnh->rnh_walktree(rnh,
							sysctl_dumpmapentry, &w);
					RADIX_NODE_HEAD_UNLOCK(rnh);
				} else if (af != 0)
					error = EAFNOSUPPORT;
			};
		}
		/*DPC*/
		break;
	}

	if (w.w_tmem)
	        free(w.w_tmem, M_RTABLE);

	return (error);

}  /* sysctl_mapsock() */
						
SYSCTL_NODE(_net, PF_MAP, maptbl, CTLFLAG_RD, sysctl_mapsock, "");

/*
 * Definitions of protocols supported in the MAP domain.
 */

static struct domain mapsockdomain;		
						
static struct protosw mapsw[] = {
{
	.pr_type =		SOCK_RAW,
	.pr_domain =		&mapsockdomain,
	.pr_flags =		PR_ATOMIC|PR_ADDR,
	.pr_output =		map_output,
	.pr_ctlinput =		raw_ctlinput,
	.pr_init =		raw_init,
	.pr_usrreqs =		&map_usrreqs
}
};

static struct domain mapsockdomain = {
	.dom_family =		PF_MAP,
	.dom_name =		"mapsock",
	.dom_protosw =		mapsw,
	.dom_protoswNPROTOSW =	&mapsw[sizeof(mapsw)/sizeof(mapsw[0])],
	.dom_maxrtkey =         sizeof(struct sockaddr_storage) 
	                        /* GgX - To manage both IPv4 and IPv6 key 
				 */
};

DOMAIN_SET(mapsock);


