#include "testutils.h"
#include "base64.h"

int
test_main(void)
{
  test_armor(&nettle_base64, 0, "", "");
  test_armor(&nettle_base64, 1, "H", "SA==");
  test_armor(&nettle_base64, 2, "He", "SGU=");
  test_armor(&nettle_base64, 3, "Hel", "SGVs");
  test_armor(&nettle_base64, 4, "Hell", "SGVsbA==");
  test_armor(&nettle_base64, 5, "Hello", "SGVsbG8=");
  test_armor(&nettle_base64, 6, "Hello", "SGVsbG8A");
  test_armor(&nettle_base64, 4, "\377\377\377\377", "/////w==");

  SUCCESS();
}
