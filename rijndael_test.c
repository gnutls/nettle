
#include <stdio.h>
#include <stdlib.h>
#include "rijndael.h"

int main(void)
{
  RIJNDAEL_context ctx;
  UINT8 key[32];
  UINT8 text[16];
  int i, j;

  for (i=0; i<16; i++)
    text[i] = i;
  for (i=0; i<32; i++)
    key[i] = 0;
  key[0] = 1;

  for (j=16; j<=32; j+=8) {
    rijndael_setup(&ctx, j, key);
    printf("\nBlock Size = 128 bits, Key Size = %d bits\n", j*8);
    printf("\nPlain=   ");
    for (i=0; i<16; i++)
      printf("%2x", text[i]);
    printf("\n");
    rijndael_encrypt(&ctx, text, text);
    printf("Encrypt= ");
    for (i=0; i<16; i++)
      printf("%02x", text[i]);
    printf("\nDecrypt= ");
    rijndael_decrypt(&ctx, text, text);
    for (i=0; i<16; i++)
      printf("%2x", text[i]);
    printf("\n");
  }
  return(0);
}
