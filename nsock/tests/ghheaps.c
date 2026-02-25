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

void gh_heap_verify(gh_heap_t *heap) {
  gh_hnode_t *a, *b, *c;
  unsigned int bi, ci;
  unsigned int count = gh_heap_count(heap);
  unsigned int i;
  for (i=0; i < heap->count; i++) {
    a = gh_heap_find(heap, i);
    bi = (i << 1) + 1;
    assert(a->index == i);
    if (bi < count) {
      b = gh_heap_find(heap, bi);
      assert(b->index == bi);
      assert(node2int(a) <= node2int(b));
      ci = bi + 1;
      if (ci < count) {
        c = gh_heap_find(heap, ci);
        assert(c->index == ci);
        assert(node2int(a) <= node2int(c));
      }
    }
  }
}

static int ghheap_ordering(void *tdata) {
  gh_heap_t heap;
  int i, n, k;

  gh_heap_init(&heap, hnode_int_cmp);

  for (i = 25000; i < 50000; i++)
    gh_heap_push(&heap, mknode(i));

  gh_heap_verify(&heap);

  for (i = 24999; i >= 0; i--)
    gh_heap_push(&heap, mknode(i));

  gh_heap_verify(&heap);

  for (i = 0; i < 5000; i++) {
    gh_hnode_t *current = gh_heap_find(&heap, rand() % gh_heap_count(&heap));
    gh_heap_remove(&heap, current);
    free(container_of(current, struct testitem, node));
  }

  gh_heap_verify(&heap);

  for (i = 25000; i < 50000; i++)
    gh_heap_push(&heap, mknode(i));

  gh_heap_verify(&heap);

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
  for (i = 0; i < HEAP_COUNT; i++)
    gh_heap_verify(&heaps[i]);

  for (num = 24999; num >= 0; num--) {
    for (i = 0; i < HEAP_COUNT; i++) {
      gh_heap_push(&heaps[i], mknode(num));
    }
  }
  for (i = 0; i < HEAP_COUNT; i++)
    gh_heap_verify(&heaps[i]);

  for (num = 0; num < 50000; num++) {
    for (i = 0; i < HEAP_COUNT; i++) {
      gh_heap_t *heap = &heaps[i];
      gh_hnode_t *hnode;
      if (num % 0x7f == 0) {
        size_t count = gh_heap_count(heap);
        hnode = gh_heap_find(heap, count-1);
        if (hnode == NULL) {
          fprintf(stderr, "Failed to find node at index %lu (count-1)\n", count-1);
          return -EINVAL;
        }
        gh_heap_remove(heap, hnode);
        free(container_of(hnode, struct testitem, node));
        gh_heap_verify(heap);
      }
      else if (num % 0x1fff == 0 && num < gh_heap_count(heap)) {
        hnode = gh_heap_find(heap, num);
        if (hnode == NULL) {
          fprintf(stderr, "Failed to find node at index %d (count = %lu)\n", num, gh_heap_count(heap));
          return -EINVAL;
        }
        gh_heap_remove(heap, hnode);
        free(container_of(hnode, struct testitem, node));
        gh_heap_verify(heap);
      }
      else {
        int r_min, r_pop;

        r_min = node2int(gh_heap_min(heap));
        hnode = gh_heap_pop(heap);
        r_pop = node2int(hnode);

        if (r_min != r_pop) {
          fprintf(stderr, "Bogus min/pop return values (%d != %d)\n", r_min, r_pop);
          return -EINVAL;
        }

        if (r_min > num) {
          fprintf(stderr, "Bogus return value %d when expected <=%d\n", r_min, num);
          return -EINVAL;
        }

        free(container_of(hnode, struct testitem, node));
      }
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
