/*- /usr/src/sys/net/lisp/maptables_xpg.c
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
 * $Id: maptables_xpg.c 176 2011-09-22 14:06:30Z ggx $
 *
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <sys/mbuf.h>
#include <sys/syslog.h>
#include <sys/callout.h>

#include <net/if.h>
#include <net/route.h>
#include <net/lisp/lisp.h>
#include <net/lisp/maptables.h>
#include <net/lisp/maptables_xpg.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>


/*
 * Default values
 */

#define CACHE_XPGTO         10*60          
#define CACHE_XPGTO_STRING "600"  /* Default Interval to check the  
				   * Cache and expunge expired entries
				   * is 10 Minutes.
				   * This must be defined as string
				   * due to initialization.
				   * The timeout is expressed in SECONDS
				   * but the values actuall value is stored
				   * in seconds.
				   * The two definition above MUST be always
				   * consistent.
				   */
#define CACHE_MINXPGTO	60        /* Minimum Interval to check the cache
				   * and expunge expired entries: 1 minute
				   */
#define CACHE_MAXXPGTO	60*60*24  /* Maximum Interval to check the cache 
				   * and expunge expired entries:24 Hours 
				   */ 
#define CACHE_XPGTO_OFF   "off"   /* Turned off string
				   */

/*
 * Expunge Timer and args
 */

struct callout maptable_xpg_timer[MAX_TABLES];

struct xpgto_args maptable_xpgto_args[MAX_TABLES];

struct maptable_xpg_arg {
	struct radix_node_head *rnh;
        int expunged;
	int expired;
	int found;
};


/*
 * Sysctl to control Expunger
 */

SYSCTL_DECL(_net_lisp);


/*
 * Cache Entries' Expunger
 */

static uint32_t  lisp_cache_xpgto = CACHE_XPGTO;
static char lisp_cache_xpgto_string[LISPMAXSTRLEN] = CACHE_XPGTO_STRING;


static int
sysctl_net_lisp_cache_xpg(SYSCTL_HANDLER_ARGS)
{
  uint32_t new = 0;
  uint32_t old = lisp_cache_xpgto;
  int error = 0;
  int i = 0;

  char tmpvalue[LISPMAXSTRLEN];

 
  strcpy(tmpvalue, lisp_cache_xpgto_string);

  error = sysctl_handle_string(oidp, lisp_cache_xpgto_string, 
			       LISPMAXSTRLEN, req);
  
  if (error || req->newptr == NULL) 
          return (error);

  if ( strcmp(lisp_cache_xpgto_string, CACHE_XPGTO_OFF) ) {

          new = (uint32_t)strtoul(lisp_cache_xpgto_string, NULL, 10); 

	  if ((!new) || (new < CACHE_MINXPGTO) || (new > CACHE_MAXXPGTO))  {

	         strcpy(lisp_cache_xpgto_string, tmpvalue);
		 return(EINVAL);

	  };
	  
  };

  lisp_cache_xpgto = new;

  if ( old && !lisp_cache_xpgto ) {
          /* Stop All Timers */
          for(i = 0; i < MAX_TABLES; i++) {

	         callout_stop(&maptable_xpg_timer[i]);
    
	  };

  } else if ( !old && lisp_cache_xpgto ) {
          /* Re-Start All Timers */
          for(i = 0; i < MAX_TABLES; i++) {

	         lisp_cache_xpg_to(&maptable_xpgto_args[i]);
    
	  };
  };
  
  return (0);

} /* sysctl_net_lisp_cachetimeout() */

SYSCTL_PROC(_net_lisp, OID_AUTO, xpgtimer, CTLTYPE_STRING | CTLFLAG_RW, 
	    0, 0, sysctl_net_lisp_cache_xpg,"A",
	   "LISP-Cache Expunger Timer");

static int  lisp_cache_expired(struct radix_node *, void *);

void
lisp_cache_xpg_to(void * xpgargs)
{
  
        struct radix_node_head *rnh = ((struct xpgto_args *)xpgargs)->rnh;
	struct maptable_xpg_arg arg;
	struct timeval atv;
	struct callout *timer;

	MAPTABLETIMER(timer,(((struct xpgto_args *)xpgargs)->af_family));

	bzero(&arg, sizeof(arg));
	arg.rnh = rnh;

	RADIX_NODE_HEAD_LOCK(rnh);
	rnh->rnh_walktree(rnh, lisp_cache_expired, &arg);
	RADIX_NODE_HEAD_UNLOCK(rnh);

#ifdef LISP_DEBUG
	log(LOG_DEBUG,"[LISP_CACHE_XPG] Expunged %d out of  %d Expired Entries (out of %d)\n",
	    arg.expunged, arg.expired, arg.found);
#endif /* LISP_DEBUG */
       
	atv.tv_usec = 0;
	atv.tv_sec = lisp_cache_xpgto;
	callout_reset(timer, tvtohz(&atv), lisp_cache_xpg_to, xpgargs);

}  /* lisp_cachexpg_to() */



static int
lisp_cache_expired(struct radix_node *rn, void * xpgarg)
{

	struct maptable_xpg_arg *argptr = xpgarg;
	struct mapentry *mapping = (struct mapentry *)rn;
	struct map_addrinfo mapinfo;
	struct timeval timenow;

	int err = 0;

	RADIX_NODE_HEAD_LOCK_ASSERT(argptr->rnh);

	if (!(mapping->map_flags & MAPF_DB)) {

		argptr->found++;

		getmicrotime(&timenow);
				
		if (!(mapping->map_flags & MAPF_STATIC) &&
		    (timenow.tv_sec - mapping->map_lastused) > lisp_cache_xpgto) {

		        argptr->expired++;

			bzero(&mapinfo, sizeof(mapinfo));
			mapinfo.mapi_addrs |= MAPA_EID;
			mapinfo.mapi_info[MAPX_EID] = (struct sockaddr_storage *) map_key(mapping);
			mapinfo.mapi_addrs |= MAPA_EIDMASK;
			mapinfo.mapi_info[MAPX_EIDMASK] = (struct sockaddr_storage *) map_mask(mapping);
			
			mapping->map_flags |= MAPF_EXPIRED;

			map_notifymsg(MAPM_DELETE, &mapinfo, mapping, NULL, 
				      0, &err);

			if (err) {
			  log(LOG_WARNING, "[LISP_CACHE_EXPIRED]: error %d sending notification through mapping socket\n", err);
				/* XXX - Should Panic? */
			  };

			err = maprequest(MAPM_DELETE, &mapinfo, NULL);

			if (err) {
			  log(LOG_WARNING, "[lisp_cache_expired]: error %d\n", err);
				/* XXX - Should Panic? */
			} else {

			  argptr->expunged++;

			};

		};


	};

	return 0;

} /* lisp_cache_expired() */


