#include "testutils.h"
#include "sha.h"

int
test_main(void)
{
  test_hash(&nettle_sha1, 0, "",
	    H("DA39A3EE5E6B4B0D 3255BFEF95601890 AFD80709")); 

  test_hash(&nettle_sha1, 1, "a",
	    H("86F7E437FAA5A7FC E15D1DDCB9EAEAEA 377667B8")); 

  test_hash(&nettle_sha1, 3, "abc",
	    H("A9993E364706816A BA3E25717850C26C 9CD0D89D"));
  
  test_hash(&nettle_sha1, 26, "abcdefghijklmnopqrstuvwxyz",
	    H("32D10C7B8CF96570 CA04CE37F2A19D84 240D3A89"));
  
  test_hash(&nettle_sha1, 14, "message digest",
	    H("C12252CEDA8BE899 4D5FA0290A47231C 1D16AAE3")); 

  test_hash(&nettle_sha1, 62,
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "abcdefghijklmnopqrstuvwxyz0123456789",
	    H("761C457BF73B14D2 7E9E9265C46F4B4D DA11F940"));
  
  test_hash(&nettle_sha1,  80,
	    "1234567890123456789012345678901234567890"
	    "1234567890123456789012345678901234567890",
	    H("50ABF5706A150990 A08B2C5EA40FA0E5 85554732"));

  SUCCESS();
}
