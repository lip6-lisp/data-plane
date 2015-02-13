
# Overview
The OpenLISP data plane (OpenLISP) repository https://github.com/lip6-lisp/data-plane hosts an open source data plane code for LISP (the Location/Idenfitier Separation Protocol), a protocol designed at the IETF. This is a modified version of OpenLISP (http://www.openlisp.org) to support new functions: load balancing, LISP Proxy Tunnel Router (PxTR), Reencapsulating Tunnel Router (RTR). It also supports the latest version of FreeBSD.

# For more info
http://www.lisp.ipv6.lip6.fr/


# How to install ?
For a full list of installation steps, please refer to the documentation in the source code folder. In the following there is a very synthetic set of instructions (lines starting with # gives a command)

1. Requirements:
    * OS: FreeBSD 8.2, 9.2 or 10.0
    * Libraries: Libconfig
    * Kernel source code
    * OpenLISP-0.2.0.2
    
2. Installaation
    
    a. Install FreeBSD
	
    The ISO file and documents can be retrieved from http://www.freebsd.org/
    
    b. Install the **Libconfig** package, using either ports collection:
        #cd /usr/ports/devel/libconfig/
        #make clean install

    Or use the management tools package:
        #pkg install libconfig

    Note: if **libconfig** does not exist in  ports , you need to update the ports collection by following theses commands (take over 10 minutes, depend on the bandwidth):
        #portsnap fetch
        #portsnap extract
        #portsnap fetch
        #portsnap update

    c. Install the complete source tree of FreeBSD including man pages and utilities Kernel source code if it does not exist. 
    The easiest way to install the full source tree is to run following command as root, and then to choose Configure -> Distributions -> Src -> All:
        #sysinstall
    
    Alternatively, you can download the source code that matches the version you installed, and then unpack the archive to /usr/src:
        #fetch ftp://ftp.freebsd.org/pub/FreeBSD/releases/amd64/10.0-RELEASE/src.txz
        #tar -C / -xvzf src.txz
        
    d. Install OpenLISP 
    
    Source code and documentation (version 0.2.0.2) can be retrieved from https://github.com/lip6-lisp/data-plane .
    From the source code directory, run the shell script to patch the kernel source code: 
        #sh install-lisp.sh

    Below is an example of kernel compilation. The full documentation to compile the kernel can be retrieved from: http://www.freebsd.org/doc/en_US.ISO8859-1/books/handbook/makeworld.html

    +Make a new configuration file for a new kernel:
        #cd /usr/src/sys/amd64/conf
        #cp GENERIC OPENLISP_KERNEL
        #echo "options LISP" >> OPENLISP_KERNEL

    +Rebuild a new kernel with a new configuration file:
        #cd /usr/src
        #make buildkernel KERNCONF=OPENLISP_KERNEL
        or 
        #make buildkernel KERNCONF=OPENLISP_KERNEL -j n 
        
    replace n with the number of cpu you have to speed up the compilation process.
    
        #make installkernel KERNCONF=OPENLISP_KERNEL
	
    Note: it could take more than 30 minutes, depending on your system.

    e. Installation of the OpenLISP tools
        
    +OpenLISP map: to manage OpenLISP mapping database:
	#cd /usr/src/sbin/map/
        #make depend
        #make
        #make install

    +OpenLISP mapstat: for statistical of OpenLISP:
        #cd /usr/src/usr.bin/mapstat/
        #make depend
        #make
        #make install

    +OpenLISP man: man page of OpenLISP:
        #cd /usr/src/share/man/man4/
        #make
        #make install

    Note: reboot the system to load the new kernel, and use some commands to start with OpenLISP:
        #man lispintro
        #man 4 map
        #man mapstat
        #mapstat –Xn
        #mapstat -s -p lisp
        
3. Function switching

    Two new sysctl variables "net.lisp.function" and "net.lisp.xtr_te" have been added to the legacy OpenLISP data-plane to allow switching between functions and enable LISP-TE function on xTR. With "net.lisp.function" there are three available values: xtr, pxtr and rtr
    
# Contact

Use github tracking system in case you encounter a bug.
Pull requests are welcome and should also go through the github system.

Reference
---------
Implementing the Locator/ID Separation Protocol: Design and Experience, Computer Networks, 55(4):948-958, March 2011. Url: http://inl.info.ucl.ac.be/system/files/ComNet-CRV-v3.pdf

