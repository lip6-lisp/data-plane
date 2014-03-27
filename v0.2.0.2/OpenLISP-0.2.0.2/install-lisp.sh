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
#
#  This file performs the basic step to install LISP into a FreeBSD 
#  machine (supported versions: 7.3, 7.4, 8.1, and 8.2).
#
#  Contributors: 
#               Luigi Iannone <ggx@openlisp.org>
#
#
# $Id: install-lisp.sh 184 2011-09-23 09:42:39Z ggx $
#
trap "exit 1" 2


setvar OK " ------------------------------------------------> [ OK ]"
setvar KO " ------------------------------------------------> [FAIL]"


setvar KERNPATCHFILES "/sys/conf/options /sys/conf/files /sys/sys/socket.h /sys/sys/mbuf.h /sys/net/netisr.h /sys/netinet/ip_output.c /sys/netinet/ip_input.c /sys/netinet/ip_var.h /sys/netinet6/ip6_input.c /sys/netinet6/ip6_output.c /sys/netinet6/ip6_forward.c /usr/src/include/Makefile /usr/src/etc/mtree/BSD.include.dist /usr/src/sbin/Makefile /usr/src/usr.bin/Makefile"

setvar HEADERPATCHFILES "sys/socket.h sys/mbuf.h net/netisr.h "

setvar OLNEWDIRECTORIES "/sys/net/lisp /sys/netinet/lisp /sys/netinet6/lisp6 /usr/include/net/lisp"

setvar OLCOMMONFILES "/sys/net/lisp/maptables.h /sys/net/lisp/maptables_xpg.h /sys/net/lisp/lisp.h  /sys/net/lisp/lisp.c /sys/netinet/lisp/ip_lisp.h  /sys/netinet6/lisp6/ip6_lisp6.c /sys/netinet6/lisp6/ip6_lisp6.h"

setvar OLVERSIONSPECIFICFILES "/sys/net/lisp/mapsock.c /sys/net/lisp/maptables.c /sys/net/lisp/maptables_xpg.c /sys/netinet/lisp/ip_lisp.c"

setvar OLHEADERFILES "net/lisp/lisp.h net/lisp/maptables.h net/lisp/maptables_xpg.h"

setvar OLMAPFILES "Makefile keywords proto-numbers map.c map.8"

setvar OLMAPDDIRECTORIES "/usr/local/etc/mapd /usr/src/sbin/mapd"

setvar OLMAPDFILES "usr/local/etc/rc.d/mapd usr/local/etc/mapd/mapd.conf usr/src/sbin/mapd/Makefile usr/src/sbin/mapd/mapd.c usr/src/sbin/mapd/map.c usr/src/sbin/mapd/lig.h usr/src/sbin/mapd/send_map_request.c usr/src/sbin/mapd/cksum.c usr/src/sbin/mapd/get_my_ip_addr.c usr/src/sbin/mapd/lig-external.h usr/src/sbin/mapd/mapd.8"

setvar OLMAPDSYMLINKS "keywords proto-numbers"

setvar OLMAPSTATFILES "mapstat.1 mapstat.h lisp.c"

setvar OLMAPSTATVFILES "Makefile main.c"

setvar OLMAPSTATSYMLINKS_7_X_RELEASE "atalk.c bpf.c if.c inet.c inet6.c ipsec.c ipx.c mbuf.c mcast.c mroute.c mroute6.c netgraph.c netstat.h pfkey.c route.c unix.c"

setvar OLMAPSTATSYMLINKS_10_X_RELEASE "atalk.c bpf.c if.c inet.c inet6.c ipsec.c ipx.c mbuf.c mroute.c mroute6.c netgraph.c netstat.h pfkey.c route.c unix.c sctp.c"

setvar OLMAPSTATSYMLINKS_9_X_RELEASE "atalk.c bpf.c if.c inet.c inet6.c ipsec.c ipx.c mbuf.c mroute.c mroute6.c netgraph.c netstat.h pfkey.c route.c unix.c sctp.c"

setvar OLMAPSTATSYMLINKS_8_X_RELEASE "atalk.c bpf.c if.c inet.c inet6.c ipsec.c ipx.c mbuf.c mroute.c mroute6.c netgraph.c netstat.h pfkey.c route.c unix.c sctp.c"

#-------------------------------------------------------------------------
ReApplyPatch()
{
    setvar RETRY 1
    cp $1.orig $1
    if [ "$?" != "0" ]
    then
	echo " Original file <$1.orig> does not exist"
	echo " (!) LISP Installation Aborted"
	exit 1
    fi
    patch -cNs $1 ./code/kernel_patches/$2/$1.patch 
    if [ "$?" != "0" ]
    then
	echo " Patching on original file failed again"
	echo " (!) LISP Installation Aborted"
	echo
	exit 1 
    else
	echo
	echo " Patching on original <$1>" 
        echo $OK
	echo
    fi

} # ReApplyPatch()



#-------------------------------------------------------------------------
ApplyPatch()
{
    echo  "   Patching: $1 "
    patch -cNs $1 ./code/kernel_patches/$2/$1.patch 
    if [ "$?" -eq "0" ] 
    then
	echo $OK
    else
	echo $KO
	echo " May be the file was previously patched."
	if [ "$FFLAG" != "1" ]
	then
	    echo -n " Trying to find the original file [Y/n]? "
	    stty cbreak         # or  stty raw
	    ANSWER=`dd if=/dev/tty bs=1 count=1 2>/dev/null`
	    stty -cbreak
	    echo
	    setvar RETRY 0
	    case $ANSWER in  y*|Y*) 
		    ReApplyPatch $1 $2 ;;
	    esac
	else
	    ReApplyPatch $1 $2
	fi
	if [ "$RETRY" != "1" ]
	then 
	    echo -n " Skip this step and continue (not safe) [y/N]? " 
	    stty cbreak         # or  stty raw
	    ANSWER=`dd if=/dev/tty bs=1 count=1 2>/dev/null`
	    stty -cbreak
	    echo
	    case $ANSWER in  y*|Y*) 
		    setvar OK 1
		    ;; 
	    esac
	    if [ "$OK" != "1" ] 
	    then 
		echo " (!) LISP Installation Interrupted"
		exit 1 
	    fi
	fi
   fi
} # ApplyPatch


#-------------------------------------------------------------------------
CheckExit()
{
if [ "$1" -eq "$2" ] 
then
    echo $OK
else
    echo $KO
    echo
    echo " (!) LISP Installation Aborted"
    echo
    exit 1
fi
}  # CheckExit

# Manage Arguments
args=`getopt f $*`
if [ $? -ne 0 ]
then
    echo
    echo "Usage: sh install-lisp.sh [-f]"
    echo 
    echo "  -f : Force - force script to try to find the original"
    echo "       file when a patch seems to have been already" 
    echo "       applied."
    echo
    exit 2
fi
set -- $args
for i
do
    case "$i"
        in
        -f)
	    setvar FFLAG 1
            shift;;
        --)
            shift; break;;
    esac
done


echo 
echo "--------------------------------------------------------"
echo "     LISP Installing Script"
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
MAPSTATLIST="temp"

case "$VERSION" in

    7.3-RELEASE)
	OLMAPSTATSYMLINKS=${OLMAPSTATSYMLINKS_7_X_RELEASE}
	BRANCH="7.X-RELEASE"
	echo "$VERSION  Supported"
	echo
        break;;

    7.4-RELEASE)
	OLMAPSTATSYMLINKS=${OLMAPSTATSYMLINKS_7_X_RELEASE}
	BRANCH="7.X-RELEASE"
	echo "$VERSION  Supported"
	echo
        break;;

    8.1-RELEASE)
	OLMAPSTATSYMLINKS=${OLMAPSTATSYMLINKS_8_X_RELEASE}
	BRANCH="8.X-RELEASE"
	echo "$VERSION  Supported"
	echo
        break;;

    8.2-RELEASE)
	OLMAPSTATSYMLINKS=${OLMAPSTATSYMLINKS_8_X_RELEASE}
	BRANCH="8.X-RELEASE"
	echo "$VERSION  Supported"
	echo
        break;;
	
    9.2-RELEASE)
	OLMAPSTATSYMLINKS=${OLMAPSTATSYMLINKS_9_X_RELEASE}
	BRANCH="9.X-RELEASE"
	echo "$VERSION  Supported"
	echo
        break;;

    10.0-RELEASE)
	OLMAPSTATSYMLINKS=${OLMAPSTATSYMLINKS_10_X_RELEASE}
	BRANCH="10.X-RELEASE"
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
echo "     Patching the Kernel"
echo "--------------------------------------------------------"
echo

for I in $KERNPATCHFILES
do 

ApplyPatch "$I" "$VERSION"

done



echo
echo "--------------------------------------------------------"
echo "     Updating Header Files in include directory"
echo "--------------------------------------------------------"
echo


for I in $HEADERPATCHFILES
do 

    echo " Updating: /usr/include/$I"
    cp /sys/$I /usr/include/$I
    CheckExit "$?" "0"

done



echo 
echo "--------------------------------------------------------"
echo "     Creating New Required Directories in the Kernel"
echo "--------------------------------------------------------"
echo 

for I in $OLNEWDIRECTORIES
do 

    echo " Creating: $I"
    mkdir -p $I
    CheckExit "$?" "0" 

done



echo 
echo "--------------------------------------------------------"
echo "     Adding LISP Common Files to the Kernel"
echo "--------------------------------------------------------"
echo 

for I in $OLCOMMONFILES
do 

    echo " Installing: $I"
    cp code/src$I $I
    CheckExit "$?" "0"

done

echo 
echo "--------------------------------------------------------"
echo "     Adding LISP Version Specific Files to the Kernel"
echo "--------------------------------------------------------"
echo 

for I in $OLVERSIONSPECIFICFILES
do 

    echo " Installing: $I"
    cp code/src/$BRANCH$I $I
    CheckExit "$?" "0"

done



echo
echo "--------------------------------------------------------"
echo "     Updating Header Files in include directory"
echo "--------------------------------------------------------"
echo

for I in $OLHEADERFILES
do 
    echo " Updating: /usr/include/$I"
    cp /sys/$I /usr/include/$I
    CheckExit "$?" "0"
done



echo 
echo "--------------------------------------------------------"
echo "     Adding MAP Files to the Kernel"
echo "--------------------------------------------------------"
echo 

echo "   Creating: /usr/src/sbin/map/"
mkdir -p /usr/src/sbin/map/
CheckExit "$?" "0"

for I in $OLMAPFILES
do 

    echo " Installing: /usr/src/sbin/map/$I"
    cp code/tools/sbin/map/$I /usr/src/sbin/map/$I
    CheckExit "$?" "0"

done



echo 
echo "--------------------------------------------------------"
echo "     Adding MAPD Files to the Kernel"
echo "--------------------------------------------------------"
echo 

echo "  Searching: /usr/ports/devel/libconfig"
setvar LIBCONFIG  `pkg_info -O devel/libconfig | grep "libconfig-"`

if [ $LIBCONFIG ] 
then
    
    echo $OK

else
    
    echo $KO

fi


for I in $OLMAPDDIRECTORIES
do

    echo "   Creating: $I"
    mkdir -p $I
    CheckExit "$?" "0"

done

for I in $OLMAPDFILES
do  

    echo " Installing: /$I"
    cp code/tools/sbin/mapd/$I /$I
    CheckExit "$?" "0"

done

for I in $OLMAPDSYMLINKS
do  

    echo "   Creating: /usr/src/sbin/mapd/$I"
    ln -sF ../map/$I /usr/src/sbin/mapd/$I
    CheckExit "$?" "0"

done


echo 
echo "--------------------------------------------------------"
echo "     Adding MAPSTAT Files to the Kernel"
echo "--------------------------------------------------------"
echo 

echo "   Creating: /usr/src/usr.bin/mapstat/"
mkdir -p /usr/src/usr.bin/mapstat/
CheckExit "$?" "0"

for I in $OLMAPSTATFILES
do 

    echo " Installing: /usr/src/usr.bin/mapstat/$I"
    cp code/tools/usr.bin/mapstat/$I /usr/src/usr.bin/mapstat/$I
    CheckExit "$?" "0"

done

for I in $OLMAPSTATVFILES
do 

    echo " Installing: /usr/src/usr.bin/mapstat/$I"
    cp code/tools/usr.bin/mapstat/$BRANCH/$I /usr/src/usr.bin/mapstat/$I
    CheckExit "$?" "0"

done

for I in $OLMAPSTATSYMLINKS
do  

    echo "   Creating: /usr/src/usr.bin/mapstat/$I"
    ln -sF ../netstat/$I /usr/src/usr.bin/mapstat/$I
    CheckExit "$?" "0"

done



echo 
echo "--------------------------------------------------------"
echo "     Adding OpenLISP Man Pages"
echo "--------------------------------------------------------"
echo 

ApplyPatch "/usr/src/share/man/man4/Makefile" "$VERSION"

echo " Installing: /usr/src/share/man/man4/map.4"
cp code/tools/share/man/man4/map.4 /usr/src/share/man/man4/
CheckExit "$?" "0"

echo " Installing: /usr/src/share/man/man4/lispintro.4"
cp code/tools/share/man/man4/lispintro.4 /usr/src/share/man/man4/
CheckExit "$?" "0"


# GgX - Ending remarks

echo 
echo "--------------------------------------------------------"
echo "     LISP Files Successfully Installed!!! (you fool) "
echo "--------------------------------------------------------"
echo 
if [ ! $LIBCONFIG ]
then
    echo "  >>>>>>>>>>>>>>>>>      IMPORTANT      <<<<<<<<<<<<<<<<<<<" 
    echo "  The package /usr/ports/devel/libconfig was"
    echo "  not found. Please install it manually from the port"
    echo "  collection before continuing with OpenLISP installation."
fi
echo
echo "  To complete installation you have to build and install"
echo "  a new kernel and related tools. "
echo "  Please read README for further information."
echo
echo "  Please, before proceeding, read the COPYRIGHT note."
echo



 
