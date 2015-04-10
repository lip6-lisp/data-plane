#!/bin/sh
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
#  This file performs the basic step to uninstall LISP into a FreeBSD 
#  machine (supported versions: 7.3, 7.4, 8.1, and 8.2).
#
#  Contributors: 
#               Luigi Iannone <ggx@openlisp.org>
#
#
# $Id: deinstall-lisp.sh 175 2011-09-22 13:15:35Z ggx $
#

trap "exit 1" 2

setvar OK " ------------------------------------------------> [ OK ]"
setvar KO " ------------------------------------------------> [FAIL]"


setvar KERNPATCHFILES "/sys/conf/options /sys/conf/files /sys/sys/socket.h /sys/sys/mbuf.h /sys/net/netisr.h /sys/netinet/ip_output.c /sys/netinet/ip_input.c /sys/netinet/ip_var.h /sys/netinet6/ip6_input.c /sys/netinet6/ip6_output.c /sys/netinet6/ip6_forward.c /usr/src/include/Makefile /usr/src/etc/mtree/BSD.include.dist /usr/src/sbin/Makefile /usr/src/usr.bin/Makefile"

setvar HEADERPATCHFILES "sys/socket.h sys/mbuf.h net/netisr.h "

setvar OLNEWDIRECTORIES "/sys/net/lisp /sys/netinet/lisp /sys/netinet6/lisp6 /usr/include/net/lisp"

setvar OLMAPDDIRECTORIES "/usr/local/etc/mapd /usr/src/sbin/mapd"




setvar XXXX "/usr/include/netinet/lisp /usr/include/netinet6/lisp6"




setvar MAPSTATFILES_X "Makefile atalk.c bpf.c if.c inet.c inet6.c ipsec.c ipx.c main.c mbuf.c mcast.c mroute.c mroute6.c netgraph.c netstat.h pfkey.c route.c unix.c mapstat.1 mapstat.h lisp.c"




RevertPatch()
{
    echo  "   Un-Patching: $1 "
    cp $1.orig $1
    if [ "$?" -eq "0" ] 
    then
	echo $OK
	rm $1.orig 2> /dev/null
	rm $1.rej* 2> /dev/null

    else
	echo
	echo " Original file not found!"
	echo " Sorry you need to fix this manually"
	echo $KO
	exit 1
    fi

} # RevertPatch

CheckExit()
{
if [ "$1" -eq "$2" ] 
then
    echo $OK
else
    echo $KO
    echo
    echo " (!) LISP De-installation Aborted"
    echo
    echo " Some file or directory is not where expected"
    echo " You need to continue manually"
    echo
    exit 1
fi
}  # CheckExit


IgnoreExit()
{
if [ "$1" -eq "$2" ] 
then
    echo " $3"
    echo $OK
else
    echo $KO
    echo
    echo " (!) LISP De-installation"
    echo
    echo " The following file is not where expected:"
    echo " $3"
    echo 
    echo " Error Ignored (Should be safe)"
    echo $OK
    echo 
fi
}  # IgnoreExit



echo 
echo "--------------------------------------------------------"
echo "     LISP De-Installing Script"
echo "--------------------------------------------------------"
echo

if [ $(whoami) != "root" ]
then
    echo 
    echo " You must be root to proceed!"
    echo
    exit 1
fi

echo 
echo "--------------------------------------------------------"
echo "     Finding Correct Version"
echo "--------------------------------------------------------"
echo

setvar VERSION $(uname -r)

case "$VERSION" in

#    7.3-RELEASE)
#	echo "$VERSION"
#	echo
#        break;;

#    7.2-RELEASE)
#	echo "$VERSION"
#	echo
#        break;;

#    7.1-RELEASE)
#	echo "$VERSION"
#	echo
#        break;;

#    7.0-RELEASE)
#	echo "$VERSION"
#	echo
#        break;;

#    8.0-RELEASE)
#	echo "$VERSION"
#	echo
#        break;;
#    8.0-RELEASE)
#	echo "$VERSION"
#	echo
#        break;;

#    8.1-RELEASE)
#	echo "$VERSION"
#	echo
#        break;;

    7.3-RELEASE)
	echo "$VERSION Supported"
	echo
        break;;

    7.4-RELEASE)
	echo "$VERSION Supported"
	echo
        break;;

    8.1-RELEASE)
	echo "$VERSION  Supported"
	echo
        break;;

    8.2-RELEASE)
	echo "$VERSION  Supported"
	echo
        break;;
    9.2-RELEASE)
	echo "$VERSION  Supported"
	echo
        break;;
    10.0-RELEASE)
	echo "$VERSION  Supported"
	echo
        break;;

    *) 
	echo "$VERSION"
	echo "Version Number non recognized (or not supported)"
	echo
	exit 0;;
esac



echo
echo "--------------------------------------------------------"
echo "     Un-Patching the Kernel"
echo "--------------------------------------------------------"
echo

for I in $KERNPATCHFILES
do 

RevertPatch "$I" "$VERSION"

done



echo
echo "--------------------------------------------------------"
echo "     Deleting Header Files in include directory"
echo "--------------------------------------------------------"
echo

for I in $HEADERPATCHFILES
do 

    echo " Deleting: /usr/include/$I"
    rm /usr/include/$I > /dev/null
    CheckExit "$?" "0"

done

for I in $HEADERPATCHFILES
do 

    echo " Put Back Original: /usr/include/$I"
    cp /sys/$I /usr/include/$I
    CheckExit "$?" "0"

done



echo 
echo "--------------------------------------------------------"
echo "     Deleting LISP Specific files from the Kernel"
echo "--------------------------------------------------------"
echo 

for I in $OLNEWDIRECTORIES
do 

    echo " Deleting: $I"
    rm -r $I > /dev/null
    CheckExit "$?" "0" 

done




echo 
echo "--------------------------------------------------------"
echo "     Deleting MAP Files from the Kernel"
echo "--------------------------------------------------------"
echo 

echo "   Deleting: /usr/src/sbin/map/"
rm -r /usr/src/sbin/map/ > /dev/null
CheckExit "$?" "0"

echo "   Deleting: /sbin/map/"
rm /sbin/map 2> /dev/null
IgnoreExit "$?" "0" "/sbin/map"

echo "   Deleting: map man pages"
rm /usr/share/man/cat8/map.8.gz 2> /dev/null
IgnoreExit "$?" "0" "/usr/share/man/cat8/map.8.gz"
rm /usr/share/man/man8/map.8.gz 2> /dev/null
IgnoreExit "$?" "0" "/usr/share/man/man8/map.8.gz"



echo 
echo "--------------------------------------------------------"
echo "     Deleting MAPD Files from the kernel"
echo "--------------------------------------------------------"
echo 


# Stop Running daemon if necessary
if [ -f /var/run/mapd.pid ]
then
   echo "  Stopping running daemon"
   setvar MAPDPID $(cat /var/run/mapd.pid)
   kill -s INT $MAPDPID 
   echo $OK
fi

for I in $OLMAPDDIRECTORIES
do 

    echo " Deleting: $I"
    rm -r $I > /dev/null
    CheckExit "$?" "0" 

done

echo "   Deleting: /sbin/mapd"
rm /sbin/mapd 2> /dev/null
IgnoreExit "$?" "0" "/sbin/mapd"

echo "   Deleting: /usr/local/etc/rc.d/mapd"
rm /usr/local/etc/rc.d/mapd 2> /dev/null
IgnoreExit "$?" "0" "/usr/local/etc/rc.d/mapd"

echo "   Deleting: mapd man pages"
rm /usr/share/man/cat8/mapd.8.gz 2> /dev/null
IgnoreExit "$?" "0" "/usr/share/man/cat8/mapd.8.gz"
rm /usr/share/man/man8/mapd.8.gz 2> /dev/null
IgnoreExit "$?" "0" "/usr/share/man/man8/mapd.8.gz"



echo 
echo "--------------------------------------------------------"
echo "     Deleting MAPSTAT Files"
echo "--------------------------------------------------------"
echo 

echo "   Deleting: /usr/src/usr.bin/mapstat/"
rm -r /usr/src/usr.bin/mapstat/ > /dev/null
CheckExit "$?" "0"

echo "   Deleting: /usr/bin/mapstat/"
rm /usr/bin/mapstat 2> /dev/null
IgnoreExit "$?" "0" "/usr/bin/mapstat"

echo "   Deleting: mapstat man pages/"
rm /usr/share/man/cat1/mapstat.1.gz 2> /dev/null
IgnoreExit "$?" "0" "/usr/share/man/cat1/mapstat.1.gz"
rm /usr/share/man/man1/mapstat.1.gz 2> /dev/null
IgnoreExit "$?" "0" "/usr/share/man/man1/mapstat.1.gz"



echo 
echo "--------------------------------------------------------"
echo "     Removing OpenLISP Man Pages"
echo "--------------------------------------------------------"
echo 

RevertPatch "/usr/src/share/man/man4/Makefile" 

echo " Deleting: /usr/src/share/man/man4/map.4"
rm /usr/src/share/man/man4/map.4 2> /dev/null
CheckExit "$?" "0"

rm /usr/src/share/man/man4/map.4.gz 2> /dev/null
IgnoreExit "$?" "0" "  /usr/src/share/man/man4/map.4.gz"
rm /usr/share/man/cat4/map.4.gz 2> /dev/null
IgnoreExit "$?" "0" "  /usr/share/man/cat4/map.4.gz"
rm /usr/share/man/man4/map.4.gz 2> /dev/null
IgnoreExit "$?" "0" "  /usr/share/man/man4/map.4.gz"

echo " Deleting: /usr/src/share/man/man4/lispintro.4"
rm /usr/src/share/man/man4/lispintro.4 2> /dev/null
CheckExit "$?" "0" 

rm /usr/share/man/man4/lispintro.4.gz 2> /dev/null
IgnoreExit "$?" "0" "  /usr/share/man/man4/lispintro.4.gz"
rm /usr/share/man/cat4/lispintro.4.gz > /dev/null
IgnoreExit "$?" "0" "  /usr/share/man/cat4/lispintro.4.gz"


# GgX - Ending remarks

echo 
echo "--------------------------------------------------------"
echo "     LISP Files Successfully Removed!!! (you smart) "
echo "--------------------------------------------------------"
echo 
echo "  To complete the deinstallation you have to build and install"
echo "  a new kernel. Please read README for further information."
echo



 
