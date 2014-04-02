1.  INTRODUCTION

    The OpenLISP implements the data-plane of LISP (Locator/Identifier Separation Protocol).
    Please refer to the IETF LISP drafts for a description of the LISP data plane and 
    related functionalities.	
    
    This is a modified version of OpenLISP (http://www.openlisp.org/) to support load balancing and two new functions: 
    LISP Proxy Tunnel Router (PxTR) and Reencapsulating Tunnel Router (RTR). 

    Now added support for FreeBSD 9.2 and 10.0.


2.  INSTALL

    Please refer to documents inside the source code.

3.  FUNCTION SWITCHING

    Two new sysctl variables "net.lisp.function" and "net.lisp.xtr_te" have been added to OpenLISP to allow switching between 
    functions and enable LISP-TE function on xTR. 
    With "net.lisp.function" there are three available values: xtr, pxtr and rtr		
