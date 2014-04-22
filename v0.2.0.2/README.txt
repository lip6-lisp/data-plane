1.  INTRODUCTION

    The OpenLISP implements the data-plane of LISP (Locator/Identifier Separation Protocol).
    Please refer to the IETF LISP drafts for a description of the LISP data plane and 
    related functionalities.	
    
    This is a modified version of OpenLISP (http://www.openlisp.org/) to support load balancing and two new functions: 
    LISP Proxy Tunnel Router (PxTR) and Reencapsulating Tunnel Router (RTR). 

    Now added support for FreeBSD 9.2 and 10.0.


2.  INSTALL

    For full guide, please refer to documents inside the source code.
    
    Following is very quick step by step to install a testbed OpenLISP (lines start with # mean command)
    
    2.1 Requirements:
        + OS: FreeBSD 8.2, 9.2 or 10.0
        + Lib: Libconfig
        + Kernel source code
        + OpenLISP-0.2.0.2
    
    2.2 Install

    a. Step 1: Install FreeBSD
	The ISO file and documents can be retrieved from http://www.freebsd.org/
    
    b. Step 2: Install Libconfig package from ports collection
        
        #cd /usr/ports/devel/libconfig/
        #make clean install
	
        Note: if libconfig does not exist in ports collection, 
        you need to update the ports collection by following theses commands 
        (take over 10 minutes, depend on the bandwidth)
            #portsnap fetch
            #portsnap extract
            #portsnap fetch
            #portsnap update

    c. Step 3: Install the complete source tree of FreeBSD 
    including man pages and utilitiesKernel source code if it does not exist. 
    The easiest way to install the full source tree is to run 
        #sysinstall
    as root, and then choosing Configure -> Distributions -> Src -> All

    d. Step 4: Install OpenLISP (Note: it could take more than 30 minutes, depend on the system)
    
    Source code and documents (version 0.2.0.2) can be retrieved 
    from https://github.com/lip6-lisp/data-plane
	
    From the source code directory, run the shell script to patch the kernel source code
        #sh install-lisp.sh

    Bellow is an example of kernel compilation. 
    The full document to compil the kernel can be retrieved 
    from: http://www.freebsd.org/doc/en_US.ISO8859-1/books/handbook/makeworld.html

        + Make a new configuration file for a new kernel
            #cd /usr/src/sys/amd64/conf
            #cp GENERIC OPENLISP_KERNEL
            #echo "options LISP" >> OPENLISP_KERNEL

        + Rebuild a new kernel with a new configuration file
            #cd /usr/src
            #make buildkernel KERNCONF=OPENLISP_KERNEL
            #make installkernel KERNCONF=OPENLISP_KERNEL
	Note: it could take more than 30 minutes, depend on the system

    e. Step 5: Installation of the OpenLISP tools
        
	+ OpenLISP map: to manage OpenLISP mapping database
            #cd /usr/src/sbin/map/
            #make depend
            #make
            #make install

        + OpenLISP mapstat: for statistical of OpenLISP
            #cd /usr/src/usr.bin/mapstat/
            #make depend
            #make
            #make install

        + OpenLISP man: man page of OpenLISP
            #cd /usr/src/share/man/man4/
            #make
            #make install

NOTE: reboot the system to load new kernel, and use some commands to start with OpenLISP
            #man lispintro
            #man 4 map
            #man mapstat
            #mapstat –Xn
            #mapstat -s -p lisp

3.  FUNCTION SWITCHING

    Two new sysctl variables "net.lisp.function" and "net.lisp.xtr_te" have been added to OpenLISP to allow switching between 
    functions and enable LISP-TE function on xTR. 
    With "net.lisp.function" there are three available values: xtr, pxtr and rtr	
