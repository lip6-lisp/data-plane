/*- /usr/src/sys/netinet/lisp/ip_lisp.h
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
 * $Id: ip_lisp.h 178 2011-09-22 14:50:11Z ggx $
 *
 */

#ifndef _IP_LISP_H_
#define _IP_LISP_H_

#define IN_ARE_MASKED_ADDR_EQUAL(a, b, c)		\
  ((a)->s_addr == ((b)->s_addr & (c)->s_addr))


int lisp_check_ip_mappings(struct mbuf **, struct sockaddr_storage *,
			   struct sockaddr_storage *, struct lispshimhdr *);

int lisp_ip_encap(struct mbuf **, int, struct in_addr *, struct in_addr *, 
		  u_char, uint16_t);

int lisp_ip_needencap(struct mbuf **);
int lisp_ip_needdecap(struct mbuf **);

int lisp_ip_mapencap(struct mbuf **, int, struct eidmap **, struct eidmap **);

void	lisp_input(struct mbuf *, int);
int     lisp_output(struct mbuf *, int, struct eidmap *, struct eidmap*);

#endif /*_IP_LISP_H_*/
