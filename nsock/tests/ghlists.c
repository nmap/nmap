/*
 * Nsock regression test suite
 * Same license as nmap -- see https://nmap.org/book/man-legal.html
 */

#include "test-common.h"
#include "../src/gh_list.h"
/* For container_of */
#include "../src/gh_heap.h"
#include <stdint.h>
#include <time.h>


#define LIST_COUNT  16
#define ELT_COUNT   2000


struct testlist {
  unsigned int val;
  gh_lnode_t lnode;
};

static unsigned int nodeval(gh_lnode_t *lnode) {
  struct testlist *tl;

  tl = container_of(lnode, struct testlist, lnode);
  return tl->val;
}

static gh_lnode_t *mknode(unsigned int val) {
  struct testlist *tl;

  tl = calloc(1, sizeof(struct testlist));
  tl->val = val;
  return &tl->lnode;
}

static void delnode(gh_lnode_t *lnode) {
  if (lnode)
    free(container_of(lnode, struct testlist, lnode));
}

static int ghlist_stress(void *tdata) {
  gh_list_t lists[LIST_COUNT];
  gh_lnode_t *current, *next;
  int num = 0;
  int ret;
  int i;

  for (i = 0; i < LIST_COUNT; i++)
    gh_list_init(&lists[i]);

  for (num = ELT_COUNT/2; num < ELT_COUNT; num++) {
    for (i = 0; i < LIST_COUNT; i++) {
      gh_list_append(&lists[i], mknode(num));
    }
  }

  for (num = (ELT_COUNT/2 - 1); num >= 0; num--) {
    for (i = 0; i < LIST_COUNT; i++) {
      gh_list_prepend(&lists[i], mknode(num));
    }
  }

  for (num = 0; num < ELT_COUNT; num++) {
    for (i = 0; i < LIST_COUNT; i++) {
      current = gh_list_pop(&lists[i]);
      ret = nodeval(current);
      if (ret != num) {
	fprintf(stderr, "prepend_test: Bogus return value %d when expected %d\n",
	                ret, num);
	return -EINVAL;
      }
      delnode(current);
    }
  }
  for (i = 0; i < LIST_COUNT; i++) {
    current = gh_list_pop(&lists[i]);
    if (current) {
      fprintf(stderr, "Ret is bogus for list %d", i);
      return -EINVAL;
    }
  }

  for (num = (ELT_COUNT/2 - 1); num >= 0; num--) {
    for (i = 0; i < LIST_COUNT; i++) {
      gh_list_prepend(&lists[i], mknode(num));
    }
  }

  for (num = ELT_COUNT/2; num < ELT_COUNT; num++) {
    for (i = 0; i < LIST_COUNT; i++) {
      gh_list_append(&lists[i], mknode(num));
    }
  }

  for (num = 0; num < ELT_COUNT; num++) {
    for (i=0; i < LIST_COUNT; i++) {
      current = gh_list_pop(&lists[i]);
      ret = nodeval(current);
      if (ret != num) {
	fprintf(stderr, "prepend_test: Bogus return value %d when expected %d\n",
	        ret, num);
        return -EINVAL;
      }
      delnode(current);
    }
  }

  for (num = ELT_COUNT/2; num < ELT_COUNT; num++) {
    for (i = 0; i < LIST_COUNT; i++)
      gh_list_append(&lists[i], mknode(num));
  }

  for (num = ELT_COUNT/2 - 1; num >= 0; num--) {
    for (i = 0; i < LIST_COUNT; i++)
      gh_list_prepend(&lists[i], mknode(num));
  }

  for (num = 0; num < ELT_COUNT; num++) {
    for (i = 0; i < LIST_COUNT; i++) {
      current = gh_list_pop(&lists[i]);
      ret = nodeval(current);
      if (ret != num) {
	fprintf(stderr, "prepend_test: Bogus return value %d when expected %d\n",
	        ret, num);
	return -EINVAL;
      }
      delnode(current);
    }
  }

  for (num = ELT_COUNT/2 - 1; num >= 0; num--) {
    for (i = 0; i < LIST_COUNT; i++)
      gh_list_prepend(&lists[i], mknode(num));
  }

  for (num = ELT_COUNT/2; num < ELT_COUNT; num++) {
    for (i=0; i < LIST_COUNT; i++)
      gh_list_append(&lists[i], mknode(num));
  }

  for (i = 0; i < LIST_COUNT; i++) {
    num = 0;

    for (current = gh_list_first_elem(&lists[i]); current; current = next) {
      int k;

      next = gh_lnode_next(current);
      k = nodeval(current);
      if (k != num) {
	fprintf(stderr, "Got %d when I expected %d\n", k, num);
        return -EINVAL;
      }
      gh_list_remove(&lists[i], current);
      delnode(current);
      num++;
    }
    if (num != ELT_COUNT) {
      fprintf(stderr, "Number is %d, even though %d was expected", num, ELT_COUNT);
      return -EINVAL;
    }

    if (gh_list_count(&lists[i]) != 0) {
      fprintf(stderr, "List should be empty, but instead it has %d members!\n",
              gh_list_count(&lists[i]));
      return -EINVAL;
    }
  }

  for (i = 0; i < LIST_COUNT; i++) {
    while ((current = gh_list_pop(&lists[i])) != NULL)
      delnode(current);

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

