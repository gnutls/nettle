C Get 32-bit floating-point register from vector register
C SFP(VR)
define(`SFP',``s'substr($1,1,len($1))')

C Get 128-bit floating-point register from vector register
C QFP(VR)
define(`QFP',``q'substr($1,1,len($1))')
