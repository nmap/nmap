/*
 * Nsock regression test suite
 * Same license as nmap -- see http://nmap.org/book/man-legal.html
 */

#include "test-common.h"
#include "../src/gh_list.h"
#include <stdint.h>
#include <time.h>


#define INT2PTR(i)  ((void *)(intptr_t)(i))
#define PTR2INT(p)  ((intptr_t)(void *)(p))

#define LIST_COUNT  16


static int ghlist_stress(void *tdata) {
  gh_list lists[LIST_COUNT];
  gh_list_elem *current, *next;
  int num = 0;
  int ret;
  int i;

  for (i=0; i < LIST_COUNT; i++)
    gh_list_init(&lists[i]);

  for (num=25000; num < 50000; num++) {
    for (i=0; i < LIST_COUNT; i++) {
      gh_list_append(&lists[i], INT2PTR(num));
    }
  }

  for (num=24999; num >= 0; num--) {
    for (i=0; i < LIST_COUNT; i++) {
      gh_list_prepend(&lists[i], INT2PTR(num));
    }
  }

  for (num=0; num < 50000; num++) {
    for (i=0; i < LIST_COUNT; i++) {
      ret = PTR2INT(gh_list_pop(&lists[i]));
      if (ret != num) {
	fprintf(stderr, "prepend_test: Bogus return value %d when expected %d\n",
	                ret, num);
	return -EINVAL;
      }
    }
  }
  for (i=0; i < LIST_COUNT; i++) {
    ret = PTR2INT(gh_list_pop(&lists[i]));
    if (ret != 0) {
      fprintf(stderr, "Ret is bogus for list %d", i);
      return -EINVAL;
    }
  }

  for (num=24999; num >= 0; num--) {
    for (i=0; i < LIST_COUNT; i++) {
      gh_list_prepend(&lists[i], INT2PTR(num));
    }
  }

  for (num=25000; num < 50000; num++) {
    for (i=0; i < LIST_COUNT; i++) {
      gh_list_append(&lists[i], INT2PTR(num));
    }
  }

  for (num=0; num < 50000; num++) {
    for (i=0; i < LIST_COUNT; i++) {
      ret = PTR2INT(gh_list_pop(&lists[i]));
      if (ret != num) {
	fprintf(stderr, "prepend_test: Bogus return value %d when expected %d\n",
	        ret, num);
        return -EINVAL;
      }
    }
  }

  for (num=25000; num < 50000; num++) {
    for (i=0; i < LIST_COUNT; i++) {
      gh_list_append(&lists[i], INT2PTR(num));
    }
  }

  for (num=24999; num >= 0; num--) {
    for (i=0; i < LIST_COUNT; i++) {
      gh_list_prepend(&lists[i], INT2PTR(num));
    }
  }

  for (num=0; num < 50000; num++) {
    for (i=0; i < LIST_COUNT; i++) {
      ret = PTR2INT(gh_list_pop(&lists[i]));
      if (ret != num) {
	fprintf(stderr, "prepend_test: Bogus return value %d when expected %d\n",
	        ret, num);
	return -EINVAL;
      }
    }
  }

  for (num=24999; num >= 0; num--) {
    for (i=0; i < LIST_COUNT; i++) {
      gh_list_prepend(&lists[i], INT2PTR(num));
    }
  }

  for (num=25000; num < 50000; num++) {
    for (i=0; i < LIST_COUNT; i++) {
      gh_list_append(&lists[i], INT2PTR(num));
    }
  }

  for (i=0; i < LIST_COUNT; i++) {
    num=0;
    for (current = GH_LIST_FIRST_ELEM(&lists[i]); current;
	current = next) {
      int k;

      next = GH_LIST_ELEM_NEXT(current);
      k = PTR2INT(GH_LIST_ELEM_DATA(current));
      if (k != num) {
	fprintf(stderr, "Got %d when I expected %d\n", k, num);
        return -EINVAL;
      }
      gh_list_remove_elem(&lists[i], current);
      num++;
    }
    if (num != 50000) {
      fprintf(stderr, "Number is %d, even though %d was expected", num, 50000);
      return -EINVAL;
    }

    if (GH_LIST_COUNT(&lists[i]) != 0) {
      fprintf(stderr, "List should be empty, but instead it has %d members!\n",
              GH_LIST_COUNT(&lists[i]));
      return -EINVAL;
    }
  }

  for (i=0; i < LIST_COUNT; i++) {
    gh_list_free(&lists[i]);
  }

  return 0;
}

const struct test_case TestGHLists = {
  .t_name     = "test nsock internal ghlists",
  .t_setup    = NULL,
  .t_run      = ghlist_stress,
  .t_teardown = NULL
};

