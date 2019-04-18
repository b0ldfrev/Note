nb为传入的分配size大小参数。

```c
if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
{
  idx = fastbin_index (nb);
  mfastbinptr *fb = &fastbin (av, idx);
  mchunkptr pp = *fb;
  do
    {
      victim = pp;
      if (victim == NULL)
        break;
    }
  while ((pp = catomic_compare_and_exchange_val_acq (fb, victim->fd, victim))
         != victim);
  if (victim != 0)
    {
      if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))
        {
          errstr = "malloc(): memory corruption (fast)";
        errout:
          malloc_printerr (check_action, errstr, chunk2mem (victim), av);
          return NULL;
        }
      check_remalloced_chunk (av, victim, nb);
      void *p = chunk2mem (victim);
      alloc_perturb (p, bytes);
      return p;
    }
}
```

如果所需的 chunk 大小小于等于 fast bins 中的最大 chunk 大小，首先尝试从 fast bins 中
分配 chunk

```c
if (in_smallbin_range (nb))
    {
      idx = smallbin_index (nb);
      bin = bin_at (av, idx);

      if ((victim = last (bin)) != bin)
        {
          if (victim == 0) /* initialization check */
            malloc_consolidate (av);
          else
            {
              bck = victim->bk;
	if (__glibc_unlikely (bck->fd != victim))
                {
                  errstr = "malloc(): smallbin double linked list corrupted";
                  goto errout;
                }
              set_inuse_bit_at_offset (victim, nb);
              bin->bk = bck;
              bck->fd = bin;

              if (av != &main_arena)
                victim->size |= NON_MAIN_ARENA;
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
        }
    }
```

如果分配的 chunk 属于 small bin，首先查找 chunk 所对应 small bins 数组的 index，然后
根据 index 获得某个 small bin 的空闲 chunk 双向循环链表表头，然后将最后一个 chunk 赋值
给 victim，如果 victim 与表头相同，表示该链表为空，不能从 small bin 的空闲 chunk 链表中
分配，这里不处理，等后面的步骤来处理。

```c
else
{
  idx = largebin_index (nb);
  if (have_fastchunks (av))
    malloc_consolidate (av);
}
```

所需 chunk 不属于 small bins，那么就一定属于 large bins，首先根据 chunk 的大小获得
对应的 large bin 的 index，接着判断当前分配区的 fast bins 中是否包含 chunk，如果存在，调用 malloc_consolidate()函数合并 fast bins 中的 chunk，并将这些空闲 chunk 加入 unsorted bin
中。

```c
while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
{
  bck = victim->bk;
  if (__builtin_expect (victim->size <= 2 * SIZE_SZ, 0)
      || __builtin_expect (victim->size > av->system_mem, 0))
    malloc_printerr (check_action, "malloc(): memory corruption",
                     chunk2mem (victim), av);
  size = chunksize (victim);

  /*
     If a small request, try to use last remainder if it is the
     only chunk in unsorted bin.  This helps promote locality for
     runs of consecutive small requests. This is the only
     exception to best-fit, and applies only when there is
     no exact fit for a small chunk.
   */

  if (in_smallbin_range (nb) &&
      bck == unsorted_chunks (av) &&
      victim == av->last_remainder &&
      (unsigned long) (size) > (unsigned long) (nb + MINSIZE))
    {
      /* split and reattach remainder */
      remainder_size = size - nb;
      remainder = chunk_at_offset (victim, nb);
      unsorted_chunks (av)->bk = unsorted_chunks (av)->fd = remainder;
      av->last_remainder = remainder;
      remainder->bk = remainder->fd = unsorted_chunks (av);
      if (!in_smallbin_range (remainder_size))
        {
          remainder->fd_nextsize = NULL;
          remainder->bk_nextsize = NULL;
        }

      set_head (victim, nb | PREV_INUSE |
                (av != &main_arena ? NON_MAIN_ARENA : 0));
      set_head (remainder, remainder_size | PREV_INUSE);
      set_foot (remainder, remainder_size);

      check_malloced_chunk (av, victim, nb);
      void *p = chunk2mem (victim);
      alloc_perturb (p, bytes);
      return p;
    }

  /* remove from unsorted list */
  unsorted_chunks (av)->bk = bck;
  bck->fd = unsorted_chunks (av);

  /* Take now instead of binning if exact fit */

  if (size == nb)
    {
      set_inuse_bit_at_offset (victim, size);
      if (av != &main_arena)
        victim->size |= NON_MAIN_ARENA;
      check_malloced_chunk (av, victim, nb);
      void *p = chunk2mem (victim);
      alloc_perturb (p, bytes);
      return p;
    }

  /* place chunk in bin */

  if (in_smallbin_range (size))
    {
      victim_index = smallbin_index (size);
      bck = bin_at (av, victim_index);
      fwd = bck->fd;
    }
  else
    {
      victim_index = largebin_index (size);
      bck = bin_at (av, victim_index);
      fwd = bck->fd;

      /* maintain large bins in sorted order */
      if (fwd != bck)
        {
          /* Or with inuse bit to speed comparisons */
          size |= PREV_INUSE;
          /* if smaller than smallest, bypass loop below */
          assert ((bck->bk->size & NON_MAIN_ARENA) == 0);
          if ((unsigned long) (size) < (unsigned long) (bck->bk->size))
            {
              fwd = bck;
              bck = bck->bk;

              victim->fd_nextsize = fwd->fd;
              victim->bk_nextsize = fwd->fd->bk_nextsize;
              fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
            }
          else
            {
              assert ((fwd->size & NON_MAIN_ARENA) == 0);
              while ((unsigned long) size < fwd->size)
                {
                  fwd = fwd->fd_nextsize;
                  assert ((fwd->size & NON_MAIN_ARENA) == 0);
                }

              if ((unsigned long) size == (unsigned long) fwd->size)
                /* Always insert in the second position.  */
                fwd = fwd->fd;
              else
                {
                  victim->fd_nextsize = fwd;
                  victim->bk_nextsize = fwd->bk_nextsize;
                  fwd->bk_nextsize = victim;
                  victim->bk_nextsize->fd_nextsize = victim;
                }
              bck = fwd->bk;
            }
        }
      else
        victim->fd_nextsize = victim->bk_nextsize = victim;
    }

  mark_bin (av, victim_index);
  victim->bk = bck;
  victim->fd = fwd;
  fwd->bk = victim;
  bck->fd = victim;

#define MAX_ITERS       10000
  if (++iters >= MAX_ITERS)
    break;
}
```

* 走到了这一步，也就是从 `fast bins` , `small bins` , `large bins`的链表中均没有找到合适的chunk，反向遍历 `unsorted bin` 的双向循环链表中的`unsorted bin chunk`,并检查当前遍历的 chunk 是否合法，不合法则抛出`malloc_printerr` 
*  如果需要分配一个 `small bin chunk`，在上面的 `small bins` 中没有匹配到合适的chunk，并且 `unsorted bin` 中只有一个 chunk，并且这个 chunk 为 `last remainder chunk`，并且这个 chunk 的大小大于所需 chunk 的大小加上 `MINSIZE`，在满足这些条件的情况下，用这个chunk切分出需要的`small bin chunk`,将内存指针返回给应用层，退出`_int_malloc()`。这是唯一的从`unsorted bin`中分配`small bin chunk`的情况
*  如果没有上面直接从`unsorted bin`中切割分配`small bin chunk`这一步，就将双向循环链表中的最后一个 chunk 移除，如果当前遍历的 `unsorted bin chunk` 与所需的 chunk 大小一致，就将当前 chunk 返回。
*  到这一步，说明已经把`unsorted bin`中最后一个chunk移除了，接下来就是 如果该chunk大小属于`small bins`那就将其链入合适的`small bins`；如果该chunk大小属于`large bins`那就将其链入合适的`large bins`。`large bin`和`small bin`不一样，将其链入`large bins`时会被填入`fd_nextsize`,`bk_nextsize`项，指向下一个堆地址。
* 循环上面步骤，如果 unsorted bin 中的 chunk 超过了 10000 个，最多遍历 10000 个就退出，避免长时间
处理 unsorted bin 影响内存分配的效率。


接下来的源码我就不贴出来了，这里简单说一下接下来的步骤：当将 unsorted bin 中的空闲 chunk 加入到相应的 small bins 和 large bins 后，将使用最佳匹配法分配chunk,找到合适的`small bin chunk` 或者 `large bin chunk`,然后切割该chunk，返回给用户，切割的剩余部作为一个新的 chunk 加入到 unsorted bin 中（如果切割剩余部分的大小小于 MINSIZE(32B)，将整个 chunk 分配给应用层）.......

当然如果从所有的 bins 中都没有获得所需的 chunk，可能的情况为 bins 中没有空闲 chunk，
或者所需的 chunk 大小很大，下一步将尝试从 top chunk 中分配所需 chunk.......



