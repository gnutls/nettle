changequote(<,>)dnl
changecom(!,<
>)dnl

dnl (progn (modify-syntax-entry ?< "(>") (modify-syntax-entry ?> ")<") )
dnl Struct defining macros

dnl STRUCTURE(prefix) 
define(<STRUCTURE>, <define(<SOFFSET>, 0)define(<SPREFIX>, <$1>)>)

dnl STRUCT(name, size)
define(STRUCT,
<define(SPREFIX<_>$1, SOFFSET)dnl
 define(<SOFFSET>, eval(SOFFSET + ($2)))>)

dnl UNSIGNED(name)
define(<UNSIGNED>, <STRUCT(<$1>, 4)>)

dnl Offsets in aes_ctx and aes_table
STRUCTURE(AES)
  STRUCT(KEYS, 4*60)
  UNSIGNED(NROUNDS)

define(AES_SBOX_SIZE,	256)dnl
define(AES_IDX_SIZE,	16)dnl
define(AES_TABLE_SIZE,	1024)dnl

STRUCT(AES)
  STRUCT(SBOX, AES_SBOX_SIZE)

  STRUCT(IDX1, AES_IDX_SIZE)
  STRUCT(IDX2, AES_IDX_SIZE)
  STRUCT(IDX3, AES_IDX_SIZE)

  STRUCT(SIDX1, AES_IDX_SIZE)
  STRUCT(SIDX2, AES_IDX_SIZE)
  STRUCT(SIDX3, AES_IDX_SIZE)

  STRUCT(TABLE0, AES_TABLE_SIZE)
  STRUCT(TABLE1, AES_TABLE_SIZE)
  STRUCT(TABLE2, AES_TABLE_SIZE)
  STRUCT(TABLE3, AES_TABLE_SIZE)
