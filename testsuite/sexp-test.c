#include "testutils.h"
#include "sexp.h"

int
test_main(void)
{
  struct sexp_iterator i;

  ASSERT(sexp_iterator_first(&i, LDATA("")));
  ASSERT(i.type == SEXP_END);

  ASSERT(sexp_iterator_first(&i, LDATA("()")));
  ASSERT(i.type == SEXP_LIST
	 && sexp_iterator_enter_list(&i)
	 && i.type == SEXP_END
	 && sexp_iterator_exit_list(&i)
	 && i.type == SEXP_END);

  ASSERT(sexp_iterator_first(&i, LDATA("(")));
  ASSERT(i.type == SEXP_LIST
	 && !sexp_iterator_enter_list(&i));

  ASSERT(sexp_iterator_first(&i, LDATA("3:foo0:[3:bar]1:x")));
  ASSERT(i.type == SEXP_ATOM
	 && !i.display_length && !i.display
	 && i.atom_length == 3 && MEMEQ(3, "foo", i.atom)

	 && sexp_iterator_next(&i) && i.type == SEXP_ATOM
	 && !i.display_length && !i.display
	 && !i.atom_length && i.atom

	 && sexp_iterator_next(&i) && i.type == SEXP_ATOM
	 && i.display_length == 3 && MEMEQ(3, "bar", i.display)
	 && i.atom_length == 1 && MEMEQ(1, "x", i.atom));

  {
    static const uint8_t *keys[2] = { "n", "e" };
    struct sexp_iterator v[2];
    
    ASSERT(sexp_iterator_first(&i, LDATA("((1:n2:xx3:foo)0:(1:y)(1:e))")));
    ASSERT(sexp_iterator_enter_list(&i)
	   && sexp_iterator_assoc(&i, 2, keys, v));

    ASSERT(v[0].type == SEXP_ATOM
	   && !v[0].display_length && !v[0].display
	   && v[0].atom_length == 2 && MEMEQ(2, "xx", v[0].atom)

	   && sexp_iterator_next(&v[0]) && v[0].type == SEXP_ATOM
	   && !v[0].display_length && !v[0].display
	   && v[0].atom_length == 3 && MEMEQ(3, "foo", v[0].atom)

	   && sexp_iterator_next(&v[0]) && v[0].type == SEXP_END);

    ASSERT(v[1].type == SEXP_END);

    ASSERT(sexp_iterator_first(&i, LDATA("((1:n))")));
    ASSERT(sexp_iterator_enter_list(&i)
	   && !sexp_iterator_assoc(&i, 2, keys, v));

    ASSERT(sexp_iterator_first(&i, LDATA("((1:n)(1:n3:foo))")));
    ASSERT(sexp_iterator_enter_list(&i)
	   && !sexp_iterator_assoc(&i, 2, keys, v));    
  }

  SUCCESS();
}
