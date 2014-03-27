#- /usr/src/usr.bin/mapstat/Makefile
#
# Copyright (c) 2010 - 2011 The OpenLISP Project
#
# Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#  4. Neither the name of the University nor the names of its contributors
#     may be used to endorse or promote products derived from this software
#     without specific prior written permission.
# 
#  THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
#  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#  ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
#  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
#  OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
#  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
#  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
#  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
#  SUCH DAMAGE.
#
#  Contributors: 
#               Luigi Iannone <ggx@openlisp.org>
#
#
# $Id: Makefile 182 2011-09-22 16:11:37Z ggx $
#

.include <bsd.own.mk>

PROG=	mapstat
MAN= 	mapstat.1

SRCS=	bpf.c if.c inet.c inet6.c main.c mbuf.c mcast.c \
	mroute.c ipx.c route.c unix.c atalk.c netgraph.c \
	mroute6.c ipsec.c pfkey.c lisp.c

WARNS?=3	
NO_WERROR=

CFLAGS+=-DIPSEC -DLISP
.if !defined(NO_INET6)
CFLAGS+=-DINET6
CFLAGS+=-DFAST_IPSEC
.endif

BINGRP=	kmem
BINMODE=2555
DPADD=	${LIBKVM} ${LIBIPX} ${LIBMEMSTAT} ${LIBNETGRAPH} ${LIBUTIL}
LDADD=	-lkvm -lipx -lmemstat -lnetgraph -lutil

.include <bsd.prog.mk>
