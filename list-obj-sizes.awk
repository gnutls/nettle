#! /usr/bin/gawk -f

# Run this filter on the output of
#
#   objdump -h libnettle.a

BEGIN {
    print "file            text-size  data-size  rodata-size";
    text_total = 0;
    data_total = 0;
    rodata_total = 0;
}

/elf32/ { name = $1; text_size = data_size = rodata_size = 0;  }
/\.text/ { text_size = $3 }
/\.data/ { data_size = $3; }
/\.rodata/ { rodata_size = $3; }
/\.comment/ {
    printf "%15s %s   %s   %s\n", name, text_size, data_size, rodata_size;
}

END {
  printf "%15s %s   %s   %s\n", "TOTAL", text_total, data_total, rodata_total;
}

