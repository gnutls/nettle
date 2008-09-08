C OFFSET(i)
C Expands to 4*i, or to the empty string if i is zero
define(<OFFSET>, <ifelse($1,0,,eval(4*$1))>)
