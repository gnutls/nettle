C Register usage:
define(`RA', `%r14')
define(`SP', `%r15')

define(`STANDARD_STACK_FRAME',`160')

C Dynamic stack space allocation
C the allocated space is assigned to 'AP' general register
C the length of space must be a multiple of 8
C free_stack can be used to free the allocated space
C alloc_stack(AP, space_len)
define(`alloc_stack',
`lgr            $1,SP
    aghi           SP,-(STANDARD_STACK_FRAME+$2)
    stg            $1,0(SP)
    la             $1,STANDARD_STACK_FRAME (SP)')

C free_stack(space_len)
define(`free_stack',
`aghi           SP,STANDARD_STACK_FRAME+$1')
