changequote(<,>)dnl
changecom(!,<
>)dnl
dnl FIXME: Add some struct macros similar to the once used in Amiga assemblers
dnl Offsets in aes_ctx and aes_table
define(AES_KEYS,	0)dnl
define(AES_NROUNDS,	240)dnl

define(AES_SBOX_SIZE,	256)dnl
define(AES_IDX_SIZE,	16)dnl
define(AES_TABLE_SIZE,	1024)dnl

define(AES_SBOX,	0)dnl
define(AES_IDX1,	AES_SBOX_SIZE)dnl
define(AES_IDX2,	eval(AES_IDX1 + AES_IDX_SIZE))dnl
define(AES_IDX3,	eval(AES_IDX2 + AES_IDX_SIZE))dnl
define(AES_TABLE0,	eval(AES_IDX3 + AES_IDX_SIZE))dnl
define(AES_TABLE1,	eval(AES_TABLE0 + AES_TABLE_SIZE))dnl
define(AES_TABLE2,	eval(AES_TABLE1 + AES_TABLE_SIZE))dnl
define(AES_TABLE3,	eval(AES_TABLE2 + AES_TABLE_SIZE))dnl

dnl define(AES_SIDX1, 304)dnl
dnl define(AES_SIDX2, 320)dnl
dnl define(AES_SIDX3, 336)dnl
dnl define(AES_TABLE, 352)dnl

