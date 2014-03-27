#- /usr/src/sbin/mapd/Makefile
# 
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
#
#  Contributors: 
#               Luigi Iannone <ggx@openlisp.org>
#               Lorand Jakab  <ljakab@ac.upc.edu>
#
# $Id: Makefile 184 2011-09-23 09:42:39Z ggx $
#

.include <bsd.own.mk>

PROG=	mapd
MAN=	mapd.8
SRCS=	mapd.c map.c keywords.h proto-numbers.h lig.h send_map_request.c cksum.c get_my_ip_addr.c
CFLAGS+= -I. -I/usr/local/include -Wall -DNS -DLISP -L/usr/local/lib -lconfig -lutil
CFLAGS+=-DINET6 
WARNS?=	0
CLEANFILES+=keywords.h _keywords.tmp proto-numbers.h _proto-numbers.tmp

keywords.h: keywords
	sed -e '/^#/d' -e '/^$$/d' ${.CURDIR}/keywords > _keywords.tmp
	LC_ALL=C tr 'a-z' 'A-Z' < _keywords.tmp | paste _keywords.tmp - | \
	    awk '{ \
		if (NF > 1) \
			printf "#define\tM_%s\t%d\n\t{\"%s\", M_%s},\n", \
			    $$2, NR, $$1, $$2 }' \
	    > ${.TARGET}
	rm -f _keywords.tmp

proto-numbers.h: proto-numbers
	sed -e '/^#/d' -e '/^$$/d' ${.CURDIR}/proto-numbers > _proto-numbers.tmp
	LC_ALL=C tr '-' '_' < _proto-numbers.tmp | paste _proto-numbers.tmp - | \
	    awk '{ \
		if (NF > 1) \
			printf "#define\tP_%s\t%d\n\t{\"%s\"},\n", \
			    $$2, NR, $$1 }' \
	    > ${.TARGET}
	rm -f _proto-numbers.tmp

.include <bsd.prog.mk>

