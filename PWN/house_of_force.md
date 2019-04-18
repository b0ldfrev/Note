---
layout:     post
title:      "House of Force"
subtitle:   "笔记"
date:       2018-11-24 12:00:00
author:     "Chris"
catalog: true
tags:
    - 笔记
 
---

利用条件：

* 能够以溢出等方式控制到 top chunk 的 size 域
* 能够自由地控制堆分配尺寸的大小
* 可泄露堆(top chunk)地址

House Of Force 产生的原因在于 glibc 对 top chunk 的处理，进行堆分配时，如果所有空闲的块都无法满足需求，那么就会从 top chunk 中分割出相应的大小作为堆块的空间。若 top chunk 的 size 值是由用户控制的任意的值且很大时 (如0xffffffffffffffff),可以使得 top chunk 指向我们期望的任何位置，这就相当于一次任意地址写.

调用`_int_malloc`时，对用户请求的大小和 top chunk 现有的 size 的验证代码如下:

```c
// 获取当前的top chunk，并计算其对应的大小
victim = av->top;
size   = chunksize(victim);
// 若 top chunk 的size 大于 请求大小+32Byte 就可以直接进行分割
if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE)) 
{
    remainder_size = size - nb;
    remainder      = chunk_at_offset(victim, nb); 
    // #define chunk_at_offset(p, s) ((mchunkptr)(((char *) (p)) + (s)))
    av->top        = remainder;  
    //更新 main_arena 中 topchunk 地址 ，new_topchunk_addr=topchunk_addr+请求大小nb
    set_head(victim, nb | PREV_INUSE |
            (av != &main_arena ? NON_MAIN_ARENA : 0));
    // 设置分配chunk的头
    set_head(remainder, remainder_size | PREV_INUSE);
    // 设置topchunk的头
    check_malloced_chunk(av, victim, nb);
    void *p = chunk2mem(victim);
    alloc_perturb(p, bytes);
    return p;
}

```
这里存在漏洞利用，比如如果此时我们已经将top_chunk的size改成了 -1 (进行比较时会把 size 转换成无符号数，因此 -1 也就是说 unsigned long 中最大的数0xffffffffffffffff) ,那我们就能从topchunk分配任意大小

若我们的请求大小 nb 是精心构造的数值， 如 `nb = attack_addr - topchunk_addr` ,分配结束后，根据代码，那新的top_chunk地址就会被替换成 `topchunk_addr+nb = topchunk_addr+attack_addr - topchunk_addr = attck_addr`  ，更改 top chunk 的位置到我们想要的地方,之后我们分配的堆块就会出现在 attack_addr+0x10 的位置，便可以控制该内存的内容。

与此同时，我们需要注意的是，topchunk 的 size 也会更新，如果我们想要下次在指定位置分配大小为 x 的 chunk，我们需要确保 remainder_size 不小于 x+ MINSIZE。


这里说一下请求大小 nb 为负数的情况，用户申请的内存大小，一旦进入申请内存的函数中就变成了无符号整数。

```c
void *__libc_malloc(size_t bytes)
```

如果想要用户输入的大小经过内部的 checked_request2size可以得到这样的大小，即

```python

#define REQUEST_OUT_OF_RANGE(req)                                              \
    ((unsigned long) (req) >= (unsigned long) (INTERNAL_SIZE_T)(-2 * MINSIZE))

//MALLOC_ALIGN_MASK = 2 * SIZE_SZ -1

#define request2size(req)                                                      \
    (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)                           \
         ? MINSIZE                                                             \
         : ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)

#define checked_request2size(req, sz)                                          \
    if (REQUEST_OUT_OF_RANGE(req)) {                                           \
        __set_errno(ENOMEM);                                                   \
        return 0;                                                              \
    }                                                                          \
    (sz) = request2size(req);

```
>下面内容转自ctf——wiki


一方面，我们需要绕过 REQUEST_OUT_OF_RANGE(req) 这个检测，即我们传给 malloc 的值在负数范围内，不得大于 -2 * MINSIZE，这个一般情况下都是可以满足的。

另一方面，在满足对应的约束后，我们需要使得 request2size正好转换为对应的大小，假如算出的offset为-4112，我们需要使得 `((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK `恰好为 - 4112。首先，很显然，-4112 是 chunk 对齐的，那么我们只需要将其分别减去 SIZE_SZ，MALLOC_ALIGN_MASK 就可以得到对应的需要申请的值。其实我们这里只需要减 SIZE_SZ 就可以了，因为多减的` MALLOC_ALIGN_MASK` 最后还会被对齐掉。而如果 -4112 不是` MALLOC_ALIGN` 的时候，我们就需要多减一些了。当然，我们最好使得分配之后得到的 chunk 也是对齐的，因为在释放一个 chunk 的时候，会进行对齐检查。所以最后是malloc(-4120)。