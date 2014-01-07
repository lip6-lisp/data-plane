/*- /usr/src/sys/net/lisp/maptables_xpg.h
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
 * $Id: maptables_xpg.h 177 2011-09-22 14:33:51Z ggx $
 *
 */

#ifndef _MAPTABLES_XPG_H_
#define _MAPTABLES_XPG_H_

#include <net/lisp/maptables.h>

#define MAPTABLETIMER(m,t)					\
        if (t == AF_INET) {					\
	       m = &maptable_xpg_timer[IPv4_EIDs_TABLE];	\
	} else if (t == AF_INET6) {                             \
	       m = &maptable_xpg_timer[IPv6_EIDs_TABLE];	\
	       } else { m = NULL; }


/*
 * Expunge Timer
 */
extern struct callout maptable_xpg_timer[];

struct xpgto_args {

  struct radix_node_head *rnh;
  int af_family;

};

extern struct xpgto_args maptable_xpgto_args[];

void lisp_cache_xpg_to(void *);

#endif  /*_MAPTABLES_XPG_H_*/
