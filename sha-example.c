#include <stdio.h>
#include <stdlib.h>

#include <nettle/sha.h>

#define BUF_SIZE 1000

static void
display_hex(unsigned length, uint8_t *data)
{
  static const char digits[16] = "0123456789abcdef";
  unsigned i;

  for (i = 0; i<length; i++)
  {
    uint8_t byte = data[i];
    printf("%c%c ", digits[(byte / 16) & 0xf], digits[byte & 0xf]);
  }
  printf("\n");
}

int
main(int argc, char **argv)
{
  struct sha1_ctx ctx;
  uint8_t buffer[BUF_SIZE];
  uint8_t digest[SHA1_DIGEST_SIZE];
  
  sha1_init(&ctx);
  for (;;)
  {
    int done = fread(buffer, 1, sizeof(buffer), stdin);
    sha1_update(&ctx, done, buffer);
    if (done < sizeof(buffer))
      break;
  }
  if (ferror(stdin))
    return EXIT_FAILURE;

  sha1_digest(&ctx, SHA1_DIGEST_SIZE, digest);

  display_hex(SHA1_DIGEST_SIZE, digest);
  return EXIT_SUCCESS;  
}
