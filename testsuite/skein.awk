#! /usr/bin/awk -f

# This script is used to process the Skein test vectors, from
# http://www.skein-hash.info/sites/default/files/NIST_CD_102610.zip
/^Len/ { len = $3 }
/^Msg/ { msg = $3 }
/^MD/ { md = $3;
  if (len % 8 == 0)
    printf("test_hash(&nettle_skeinxxx, /* %d octets */\nSHEX(\"%s\"),\nSHEX(\"%s\"));\n",
	   len / 8, msg, md);
}
