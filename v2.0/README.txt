1.  INTRODUCTION

    The OpenLISP implements the data-plane of LISP (Locator/Identifier Separation Protocol).
    Please refer to the IETF LISP drafts for a description of the LISP data plane and 
    related functionalities.	
    
    This is a modified version of OpenLISP (http://www.openlisp.org/) to support two new functions: 
    LISP Proxy Tunnel Router (PxTR) and Reencapsulating Tunnel Router (RTR). 


2.  INSTALL

    Please refer to documents inside the tarball source code.

3.  FUNCTION SWITCHING

    A new sysctl variable "net.lisp.function" has been add to OpenLISP to allow switching between 
    functions. Three available values are xtr, pxtr and rtr		
