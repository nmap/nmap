/*
 * Nsock regression test suite
 * Same license as nmap -- see https://nmap.org/book/man-legal.html
 */

#include "test-common.h"
#include "../src/gh_heap.h"
#include <stdint.h>
#include <time.h>


#define HEAP_COUNT  3

struct testitem {
  int val;
  gh_hnode_t  node;
};

static int hnode_int_cmp(gh_hnode_t *n1, gh_hnode_t *n2) {
  struct testitem *a;
  struct testitem *b;

  a = container_of(n1, struct testitem, node);
  b = container_of(n2, struct testitem, node);

  return (a->val < b->val);
}

static gh_hnode_t *mknode(int val) {
  struct testitem *item;

  item = calloc(1, sizeof(struct testitem));
  assert(item != NULL);
  item->val = val;
  gh_hnode_invalidate(&item->node);
  return &item->node;
}

static int node2int(gh_hnode_t *hnode) {
  struct testitem *item;

  item = container_of(hnode, struct testitem, node);
  return item->val;
}

static int ghheap_ordering(void *tdata) {
  gh_heap_t heap;
  int i, n, k;

  gh_heap_init(&heap, hnode_int_cmp);

  for (i = 25000; i < 50000; i++)
    gh_heap_push(&heap, mknode(i));

  for (i = 24999; i >= 0; i--)
    gh_heap_push(&heap, mknode(i));

  for (i = 25000; i < 50000; i++)
    gh_heap_push(&heap, mknode(i));

  n = -1;
  do {
    gh_hnode_t *current;

    current = gh_heap_pop(&heap);
    assert(!gh_hnode_is_valid(current));
    k = node2int(current);

    if (k < n)
      return -EINVAL;

    n = k;
    free(container_of(current, struct testitem, node));
  } while (gh_heap_count(&heap) > 0);

  gh_heap_free(&heap);
  return 0;
}

static int ghheap_stress(void *tdata) {
  gh_heap_t heaps[HEAP_COUNT];
  int i, num;

  for (i = 0; i < HEAP_COUNT; i++)
    gh_heap_init(&heaps[i], hnode_int_cmp);

  for (num = 25000; num < 50000; num++) {
    for (i = 0; i < HEAP_COUNT; i++) {
      gh_heap_push(&heaps[i], mknode(num));
    }
  }

  for (num = 24999; num >= 0; num--) {
    for (i = 0; i < HEAP_COUNT; i++) {
      gh_heap_push(&heaps[i], mknode(num));
    }
  }

  for (num = 0; num < 50000; num++) {
    for (i = 0; i < HEAP_COUNT; i++) {
      int r_min, r_pop;
      gh_hnode_t *hnode;

      r_min = node2int(gh_heap_min(&heaps[i]));
      hnode = gh_heap_pop(&heaps[i]);
      r_pop = node2int(hnode);

      if (r_min != r_pop) {
        fprintf(stderr, "Bogus min/pop return values (%d != %d)\n", r_min, r_pop);
        return -EINVAL;
      }

      if (r_min != num) {
	fprintf(stderr, "Bogus return value %d when expected %d\n", r_min, num);
	return -EINVAL;
      }

      free(container_of(hnode, struct testitem, node));
    }
  }

  for (i = 0; i < HEAP_COUNT; i++) {
    void *ret;

    ret = gh_heap_pop(&heaps[i]);
    if (ret != NULL) {
      fprintf(stderr, "Ret is bogus for heap %d\n", i);
      return -EINVAL;
    }
  }

  for (i = 0; i < HEAP_COUNT; i++)
    gh_heap_free(&heaps[i]);

  return 0;
}


const struct test_case TestGHHeaps = {
  .t_name     = "test nsock internal ghheaps",
  .t_setup    = NULL,
  .t_run      = ghheap_stress,
  .t_teardown = NULL
};

const struct test_case TestHeapOrdering = {
  .t_name     = "test heaps conditions",
  .t_setup    = NULL,
  .t_run      = ghheap_ordering,
  .t_teardown = NULL
};
