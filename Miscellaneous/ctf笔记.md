>随心情笔记，不定期更新

## one_gadgets笔记：

1.改malloc_hook为one_gadgets,一般malloc触发的方式，one_gadgets由于限制条件不满足，执行都不会成功，可以考虑free两次造成double free，调用malloc_printerr触发，恰好[esp+0x50]=0(当向非标准IO函数向缓冲流输出或输入的数据过大时，往往会先预先给数据分配内存。比如printf/scanf-打印/输入字符串过长时会触发malloc)


2.在地址上__malloc_hook与__realloc_hook是相邻的，在攻击malloc_hook我们没有能够成功执行one_gadgets，但是我们可以通过将__malloc_hook更改为_libc_realloc+0x14,将__realloc_hook更该为one_gadgets。
这样的好处在于，我们能够控制__malloc_hook指向的代码的内容，规避掉_libc_realloc中部分指令，从而更改在执行one_gadgets时的占空间，创建能够成功执行one_gadgets的栈空间。这是一个很巧妙的点

3.虽然`__free_hook`上方几乎是"\x00"，无可用size，但是我们可以先用 unsorted attack 攻击`__free_hook`上方，在其上方踩出 size，再去劫持 __free_hook。


4.使用`tcache stashing attack`或`unsorted_bin_attack`，将`_IO_2_1_stdin_->_IO_buf_end`改成`main_arena+x`(我这里是+352)，从而可以在scanf的时候输入数据到`realloc_hook`和`malloc_hook`，改成one_gadget，调节下偏移即可。



5.利用house of husk ,覆写`__printf_function_table`表为heap地址(让其不为空)，覆写`__printf_arginfo_table`表为heap地址且heap['s']被覆写为了one_gadget，在调用格式化字符带有`%s`printf()函数时，即可get shell。

6.写exit函数在ld.so中的`_rtld_global._dl_rtld_lock_rescursive` 为one_gadget

7.当程序开启full relor时，可写libc中puts函数开头的strlen的got表

## 无leak函数的利用笔记：

* 没开PIE的情况

1.可申请或者构造非fastbin chunk情况，能够修改free_got --> puts_plt,下次释放一个unsorted_bin chunk(入链)或者fastbin chunk(入链)  ,程序调用链 free->free_got->puts_plt->puts 以此泄露libc地址或者heap地址。

2.只能存在fastbin chunk情况，修改 free_got 为 printf，释放一个有格式化字符串的chunk，利用构造格式化字符串漏洞 打印栈中的 libc 地址。 

* 开启PIE的情况

利用IO_write_base实现leak，详细见[https://b0ldfrev.gitbook.io/note/pwn/iofile-li-yong-si-lu-zong-jie#li-yong-iowritebase-shi-xian-leak](https://b0ldfrev.gitbook.io/note/pwn/iofile-li-yong-si-lu-zong-jie#li-yong-iowritebase-shi-xian-leak)

* 无须泄露，全程爆破的方式(不实用)

[House_of_Roman](https://b0ldfrev.gitbook.io/note/pwn/house_of_roman)

## IO_FILE笔记
程序调用exit 后会遍历 `_IO_list_all`,调用 `_IO_2_1_stdout_` 下的vatable中`_setbuf` 函数.

## glibc缺陷

glibc缺陷 : 对于未开启tcache版本来说，只要释放chunk大小在fastbin范围，那就不检查当前释放这个chunk是否已经free（通常检测下一个相邻chunk的prev_size位），就直接将其放入fastbin；

对于开启tcache版本来说，只要tcache中有空，那就不检查当前释放这个chunk是否已经free（通常检测下一个相邻chunk的prev_size位），并直接将其放入tcache中。对于开启tcache这种情况，相对来说就会更危险，我们很容易构造堆风水来实现进一步利用。

## malloc_consolidate笔记

`malloc_consolidate()`函数用于将 fast bins 中的 chunk 合并，并加入 unsorted bin 中。 ptmalloc中会有以下几种情况会调用`malloc_consolidate()`

1. 在`_int_malloc`的while循环之前，分配的 chunk 属于 small bin,如果 small bin 还没有初始化为双向循环链表，则调用`malloc_consolidate()`函数将 fast bins中的 chunk 合并.

2. 在`_int_malloc`的while循环之前，分配的 chunk 属于 large bin，判断当前分配区的 fast bins 中是否包含 chunk，如果存在，调用 `malloc_consolidate()`函数合并 fast bins 中的 chunk

3. 在分配chunk时 假如最后 top chunk 也不能满足分配要求，就会查看 fast bins 中是否有空闲 chunk ，若存在就调用malloc_consolidate()函数，并重新设置当前 bin 的 index，并转到最外层的循环，尝试重新分
配 chunk。

4. 在释放chunk时，遇到相邻空闲chunk合并或者与topchunk合并，如果合并后的 chunk 大小大于 64KB，并且 fast bins 中存在空闲 chunk，则会调用malloc_consolidate()函数合并 fast bins 中的空闲 chunk 到 unsorted bin 中

一些能触发`malloc_consolidate`的 trick

* scanf时可输入很长一段字符串 "1"*0x1000,这样可以导致scanf内部扩充缓冲区，从而调用init_malloc来分配更大的空间，从而导致malloc_consolidate，合并fast_bin中的空闲chunk。调用栈如图：

![](../pic/Miscellaneous/3.jpg)

* 如果程序没有setbuf(stdin,0)也就是没有关闭stdin的缓冲区。getchar() 会开辟一个很大的堆块形成缓冲区，也就是申请0x400的chunk,此时fast_bin中存在chunk，就会调用`malloc_consolidate`合并

```c
pwndbg> bt

#0  __GI___libc_malloc (bytes=1024) at malloc.c:2902
#1  0x00007ffff7a7a1d5 in __GI__IO_file_doallocate (fp=0x7ffff7dd18e0 <_IO_2_1_stdin_>) at filedoalloc.c:127
#2  0x00007ffff7a88594 in __GI__IO_doallocbuf (fp=fp@entry=0x7ffff7dd18e0 <_IO_2_1_stdin_>) at genops.c:398
#3  0x00007ffff7a8769c in _IO_new_file_underflow (fp=0x7ffff7dd18e0 <_IO_2_1_stdin_>) at fileops.c:556
#4  0x00007ffff7a8860e in __GI__IO_default_uflow (fp=0x7ffff7dd18e0 <_IO_2_1_stdin_>) at genops.c:413
#5  0x00007ffff7a83255 in getchar () at getchar.c:37


```

## 程序退出

1.程序会执行到libc里面`__GI___call_tls_dtors`函数
```python

   0x7ffff7a475d0 <__GI___call_tls_dtors>:	  push   rbp
   0x7ffff7a475d1 <__GI___call_tls_dtors+1>:	push   rbx
   0x7ffff7a475d2 <__GI___call_tls_dtors+2>:	sub    rsp,0x8
   0x7ffff7a475d6 <__GI___call_tls_dtors+6>:	mov    rbp,QWORD PTR [rip+0x3897a3]        # 0x7ffff7dd0d80
=> 0x7ffff7a475dd <__GI___call_tls_dtors+13>:	mov    rbx,QWORD PTR fs:[rbp] # rbp=-0x40
   0x7ffff7a475e2 <__GI___call_tls_dtors+18>:	test   rbx,rbx
   0x7ffff7a475e5 <__GI___call_tls_dtors+21>:	je     0x7ffff7a4762e <__GI___call_tls_dtors+94>
   0x7ffff7a475e7 <__GI___call_tls_dtors+23>:	nop    WORD PTR [rax+rax*1+0x0]
   0x7ffff7a475f0 <__GI___call_tls_dtors+32>:	mov    rdx,QWORD PTR [rbx+0x18]
   0x7ffff7a475f4 <__GI___call_tls_dtors+36>:	mov    rax,QWORD PTR [rbx]
   0x7ffff7a475f7 <__GI___call_tls_dtors+39>:	mov    rdi,QWORD PTR [rbx+0x8]
   0x7ffff7a475fb <__GI___call_tls_dtors+43>:	ror    rax,0x11
   0x7ffff7a475ff <__GI___call_tls_dtors+47>:	xor    rax,QWORD PTR fs:0x30
   0x7ffff7a47608 <__GI___call_tls_dtors+56>:	mov    QWORD PTR fs:[rbp+0x0],rdx
   0x7ffff7a4760d <__GI___call_tls_dtors+61>:	call   rax
   0x7ffff7a4760f <__GI___call_tls_dtors+63>:	mov    rax,QWORD PTR [rbx+0x10]

```

观察看出，`__GI___call_tls_dtors+18`也就是rbx不为零时，程序会执行到下面的`call rax`，且参数是由rbx控制，再看`__GI___call_tls_dtors+13`,rbx是fs:[-0x40]，也就是当前线程栈的TLS结构体的上方0x40处，若能覆盖到此处，就能控制程序执行流程。在最终`call rax`之前，还有一次`ror rax,0x11`和`xor rax, fs:[0x30]`，需要leak出TLS的pointer_guard成员.

```c
typedef struct {   
void *tcb;        /* Pointer to the TCB.  Not necessarily the thread descriptor used by libpthread.  */   
dtv_t *dtv;   
void *self;       /* Pointer to the thread descriptor.  */   
int multiple_threads;   
int gscope_flag;   
uintptr_t sysinfo;   
uintptr_t stack_guard;   #canary  offset=fs:0x28
uintptr_t pointer_guard;   
... } tcbhead_t; 


```

2.程序在执行退出流程时，最终会在ld.so这个动态装载器里面调用_dl_fini函数，这个函数，利用方式见下图：

![](../pic/Miscellaneous/4.png)



## calloc绕过 leak

2.23及 以上libc都适用

```c
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

typedef long *longptr;

int main()

{
longptr v[7];
long *a,*b,*c;

a=malloc(20);
b=malloc(20);

memset(b,'A',20);
/*
for (int i=0;i<7;i++)
{
v[i]=malloc(20);
}

for (int i=0;i<7;i++)
{
free(v[i]);
}
*/
free(b);
b[-1] |= 2;

c=calloc(1,20);

for (int i=0;i<20;i++)
{
printf("%.2x",((char *)c)[i]);

}
putchar("\n");
exit(0);

}

```

给fastbin_chunk的size的IS_MAPPED域置1.通过calloc分配到时，不会被清空。

```python
chris@ubuntu:~$ ./calloc
00000000000000004141414141414141414141419


```

## stack_povit

栈迁移到.bss段时，若栈上方(低地址处)有大约0x200字节的空白空间，则执行system函数就不会报错；但我们通常使用onegadget获取shell


## fd相关 close(1)


* 对于有write函数调用的情况下.

write函数直接能够将输出重定位到0或2描述符.

```c
#include<stdio.h>
void main()
{
close(1);
write(0,"123",3);
return 0;
}

```

这时能打印123.原因是0，1，2文件描述符都指向同一个tty文件，如下：

```python
[master●]#~ file /proc/8642/fd/0
/proc/8942/fd/0: symbolic link to /dev/pts/18
[master●]#~ file /proc/8642/fd/1
/proc/8942/fd/1: symbolic link to /dev/pts/18
[master●]#~ file /proc/8642/fd/2
/proc/8942/fd/2: symbolic link to /dev/pts/18

```

* 无write函数调用情况下.

由于程序只关闭了文件描述符1，却没有关闭文件描述符0，所以我们可以修改stdout的文件描述符_fileno为0或2，则可以使得程序再次拥有了输出的能力，这时再调用printf或者puts就能输出了

* close(1)后，格式化字符串最多只能写0x2000字节，这种情况下在利用时可修改程序.bss段中的stdout指针地址为stderr指针，由源码分析，在vprintf的check时刚好能通过，这使得printf再次拥有输出能力

* close(1)时获取服务器端flag，利用重定向"cat flag >&0"

* 再调用scanf时，会取到`_IO_2_1_stdin_`结构的`fileno`,最终汇到底层系统调用read`（_IO_2_1_stdin_.fileno，buf，nbytes）`。所以有些时候如果我们能够控制`IO_stdin`结构的fileno为其它fd，再去调用scanf函数时就可以实现从其它fd读数据。



## off-by-one 构造思路

* 方法一

![](../pic/Miscellaneous/off-by-one1.jpg)

* 方法二

![](../pic/Miscellaneous/off-by-one2.jpg)

* 方法三(非特殊情况不推荐)
 
原理与方法一类似，在能泄露heap地址前提下，直接构造fake_chunk,填好指针，绕过unlink

![](../pic/Miscellaneous/off-by-one3.jpg)


## realloc

简化版的realloc，非mmapped分配方式

```c
__libc_realloc (void *oldmem, size_t bytes)

{

checked_request2size (bytes, nb_szie);
old_size = chunksize (oldmem);

// 如果bytes为零，相当于free
if (bytes = 0) 
{ 
	free(oldmem); 
	return 0;
}

//  如果old_size大于请求size，那就缩减old_size,如果缩减的size小于当前arch最小chunk的大小(不能切割出一个chunk)，那就直接返回原来的oldmem，剩下的交给用户处理，不多管.
if (old_size > nb_size)  
{ 

if (old_size - nb_size >= 4 * SIZE_SZ) 
{
  free( oldmem + nb_size );
}  
old_size=nb_size; 
return oldmem; 
}


// 如果old_size小于请求size，glibc2.23是按照常规malloc分配，2.27是从直接从topchunk分配
if (old_size < nb_size ) 
{

	if (glibc==2.23)
	 {
		p=malloc(bytes);
		free(oldmem);
		return p;
	 }

	if(glibc==2.27)
	 {
		p=malloc(bytes); // no_tcache 的_int_malloc不会分配tcache里面的chunk
		free(oldmem);
		return p;
	 }

}

}

```

## tcache相关

tcache_perthread_struct结构体是用来管理tcache链表：
这个结构体位于heap段的起始位置，且有size：0x251

```c
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];//数组长度64，每个元素最大为0x7，仅占用一个字节（对应64个tcache链表）
  tcache_entry *entries[TCACHE_MAX_BINS];//entries指针数组（对应64个tcache链表，cache bin中最大为0x400字节
  //每一个指针指向的是对应tcache_entry结构体的地址。
} tcache_perthread_struct;

```

一个tcache链表的结构，单个tcache bins默认最多包含7个块。tcache_entry：
2.26

```c
typedef struct tcache_entry
{
  struct tcache_entry *next;//指向的下一个chunk的fd字段
} tcache_entry;

```

2.28存在bk字段所有的bk都指向tcache_perthread_struct的fd

```c
typedef struct tcache_entry
{
 //指向tcache的下一个chunk，
  struct tcache_entry *next;
  /* 这个字段是用来检测双重free释放的  */
  struct tcache_perthread_struct *key;
} tcache_entry;

```

放入tcache bin的情况:

* 释放时，`_int_free`中在检查了size合法后(小于0x400)，放入fastbin之前，它先尝试将其放入tcache
* 在`_int_malloc`中，若fastbins中取出块则将对应bin中其余chunk填入tcache对应项直到填满（smallbins中也是如此）
* 当进入unsorted bin(同时发生堆块合并）中找到精确的大小时，并不是直接返回而是先加入tcache中，直到填满：

取tcache bin中的chunk：

* 在`__libc_malloc`，`_int_malloc`之前，如果tcache中存在满足申请需求大小的块，就从对应的tcache中返回chunk
* 在遍历完unsorted bin(同时发生堆块合并）之后，若是tcache中有对应大小chunk则取出并返回：
* 在遍历unsorted bin时，大小不匹配的chunk将会被放入对应的bins，若达到`tcache_unsorted_limit`限制且之前已经存入过chunk则在此时取出（默认无限制）：


## tcache struct攻击

* tcache初始化

```c
tcache_init(void)
{
  mstate ar_ptr;
  void *victim = 0;
  const size_t bytes = sizeof (tcache_perthread_struct);
  if (tcache_shutting_down)
    return;
  arena_get (ar_ptr, bytes);
  victim = _int_malloc (ar_ptr, bytes);
  if (!victim && ar_ptr != NULL)
    {
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      victim = _int_malloc (ar_ptr, bytes);
    }
  if (ar_ptr != NULL)
    __libc_lock_unlock (ar_ptr->mutex);
  /* In a low memory situation, we may not be able to allocate memory
     - in which case, we just keep trying later.  However, we
     typically do this very early, so either there is sufficient
     memory, or there isn't enough memory to do non-trivial
     allocations anyway.  */
  if (victim)
    {
      tcache = (tcache_perthread_struct *) victim;
      memset (tcache, 0, sizeof (tcache_perthread_struct));
    }
}

```

在程序需要进行动态分配时，如果是使用TCACHE机制的话，会先对tcache进行初始化。跟其他bins不一样的是，tcache是用_int_malloc函数进行分配内存空间的，因此tcache结构体是位于heap段，而不是main_arena。通常
tcache结构体位于堆首的chunk.

```c
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];//0x40
  tcache_entry *entries[TCACHE_MAX_BINS];//0x40
} tcache_perthread_struct;
```

tcache的结构是由0x40字节数量数组（每个字节代表对应大小tcache的数量）和0x200(0x40*8)字节的指针数组组成（每8个字节代表相应tache_entry链表的头部指针）。因此整个tcache_perthread_struct结构体大小为0x240。


* tcache free

```c
#if USE_TCACHE
  {
    size_t tc_idx = csize2tidx (size);
    if (tcache
        && tc_idx < mp_.tcache_bins
        && tcache->counts[tc_idx] < mp_.tcache_count)//<7
      {
        tcache_put (p, tc_idx);
        return;
      }
  }
#endif

```

在将chunk放入tcahce的时候会检查tcache->counts[tc_idx] < mp_.tcache_count（无符号比较），也就是表示在tacha_entry链表中的tache数量是否小于7个。但值得注意的是，tcache->counts[tc_idx]是放在堆上的，因此如果可以修改堆上数据，可以将其改为较大的数，这样就不会将chunk放入tache了。


* tcache malloc

```c
#if USE_TCACHE
  /* int_free also calls request2size, be careful to not pad twice.  */
  size_t tbytes;
  checked_request2size (bytes, tbytes);
  size_t tc_idx = csize2tidx (tbytes);
  MAYBE_INIT_TCACHE ();
  DIAG_PUSH_NEEDS_COMMENT;
  if (tc_idx < mp_.tcache_bins
      /*&& tc_idx < TCACHE_MAX_BINS*/ /* to appease gcc */
      && tcache
      && tcache->entries[tc_idx] != NULL)
    {
      return tcache_get (tc_idx);
    }
  DIAG_POP_NEEDS_COMMENT;
#endif

```

而在tcache分配时，不会检查`tcache->counts[tc_idx]`的大小是否大于0，会造成下溢。且没有检测entries处chunk的合法性，我们若能伪造`tcache->entries[tc_idx]`的`tcache_entry`指针，那我们就能实现从tcache任意地址分配chunk。


## 关于glibc 2.29及以上一些check的绕过

1.在unlink操作前增加了prevsize的检查机制：在合并的时候会判断prev_size和要合并chunk的size是否相同。
```c
/* consolidate backward */
if (!prev_inuse(p)) {
  prevsize = prev_size (p);
  size += prevsize;
  p = chunk_at_offset(p, -((long) prevsize));
  if (__glibc_unlikely (chunksize(p) != prevsize))
    malloc_printerr ("corrupted size vs. prev_size while consolidating");
  unlink_chunk (av, p);
}

```

这样导致了常规off-by-null的构造方式失效，但可利用残余在 large bin 上的 fd_nextsize / bk_nextsize 指针，smallbin残留的bk指针，以及fastbin的fd指针 来构造出一个天然的chunk链来绕过size检测与双向链表检测。具体见[https://bbs.pediy.com/thread-257901.htm](https://bbs.pediy.com/thread-257901.htm)



2.增加了`tcache_double_free`的检测，2.29将每个放入tcache中的chunk->bk(也是tcache entries结构的key位)设置为tcache。


```c

void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  assert (tc_idx < TCACHE_MAX_BINS);

  /* Mark this chunk as "in the tcache" so the test in _int_free will
     detect a double free.  */
  e->key = tcache;

  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}


```
在释放tcache中的chunk时，只根据相应的tc_idx检测重复chunk

```c
/* This test succeeds on double free.  However, we don't 100%
    trust it (it also matches random payload data at a 1 in
    2^<size_t> chance), so verify it's not an unlikely
    coincidence before aborting.  */
if (__glibc_unlikely (e->key == tcache))
  {
    tcache_entry *tmp;
    LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
    for (tmp = tcache->entries[tc_idx];
    tmp;
    tmp = tmp->next)
      if (tmp == e)
  malloc_printerr ("free(): double free detected in tcache 2");
    /* If we get here, it was a coincidence.  We've wasted a
        few cycles, but don't abort.  */
  }
```

绕过方式：可以将同一个tcache_chunk放入不同的tcache_bin或其他bin中来重新实现利用（这种方式见House_of_botcake）；也可以篡改chunk->key，使其e->key != tcache来绕过。

也可以利用fastbin的double free，待fastbin形成double_free链后再malloc重分配清空tchache预留位置，最后一次malloc使得剩余fastbin进入tcache，实现堆块复用。详细可参见[glibc2.31下的新double free手法/字节跳动pwn题gun题解](https://blog.csdn.net/chennbnbnb/article/details/109284780)



3.`_int_malloc`中，使用`unsortedbin_attack`时，增加了对unsortedbin双向链表的完整性检测，导致`unsortedbin_attack`不可用.

```c
/* remove from unsorted list */
if (__glibc_unlikely (bck->fd != victim))
  malloc_printerr ("malloc(): corrupted unsorted chunks 3");
unsorted_chunks (av)->bk = bck;
bck->fd = unsorted_chunks (av);

```

但有另外的地方可利用，`unsortedbin_attack`无非就是往一个地址写一个值，如果只是为了改例如`global_max_fast`,那`largebin_attack`完全可以替代，只不过写入的是堆地址，只是和`largebin_attack`配套的`house of strom`来实现任意地址分配不能用了。

```
          if (__glibc_unlikely (size <= 2 * SIZE_SZ)
              || __glibc_unlikely (size > av->system_mem))
            malloc_printerr ("malloc(): invalid size (unsorted)");
          if (__glibc_unlikely (chunksize_nomask (next) < 2 * SIZE_SZ)
              || __glibc_unlikely (chunksize_nomask (next) > av->system_mem))
            malloc_printerr ("malloc(): invalid next size (unsorted)");
          if (__glibc_unlikely ((prev_size (next) & ~(SIZE_BITS)) != size))
            malloc_printerr ("malloc(): mismatching next->prev_size (unsorted)");
          if (__glibc_unlikely (bck->fd != victim)
              || __glibc_unlikely (victim->fd != unsorted_chunks (av)))
            malloc_printerr ("malloc(): unsorted double linked list corrupted");
          if (__glibc_unlikely (prev_inuse (next)))
            malloc_printerr ("malloc(): invalid next->prev_inuse (unsorted)");
```

如果要达到写libc地址，也可以，有师傅把它叫做**tcache stash unlink attack plus**，

```c
  if (in_smallbin_range (nb))
    {
      idx = smallbin_index (nb);
      bin = bin_at (av, idx);

      if ((victim = last (bin)) != bin)
        {
          bck = victim->bk;
	  if (__glibc_unlikely (bck->fd != victim))
	    malloc_printerr ("malloc(): smallbin double linked list corrupted");
          set_inuse_bit_at_offset (victim, nb);
          bin->bk = bck;  
          bck->fd = bin;

          if (av != &main_arena)
	    set_non_main_arena (victim);
          check_malloced_chunk (av, victim, nb);
#if USE_TCACHE
	  /* While we're here, if we see other chunks of the same size,
	     stash them in the tcache.  */
	  size_t tc_idx = csize2tidx (nb);
	  if (tcache && tc_idx < mp_.tcache_bins)
	    {
	      mchunkptr tc_victim;

	      /* While bin not empty and tcache not full, copy chunks over.  */
	      while (tcache->counts[tc_idx] < mp_.tcache_count
		     && (tc_victim = last (bin)) != bin)
		{
		  if (tc_victim != 0)
		    {
		      bck = tc_victim->bk;
		      set_inuse_bit_at_offset (tc_victim, nb);
		      if (av != &main_arena)
			set_non_main_arena (tc_victim);
		      bin->bk = bck;
		      bck->fd = bin;

		      tcache_put (tc_victim, tc_idx);
	            }
		}
	    }
#endif
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
    }

```


前置条件是：对应tcache中预留2个chunk位（至少）(除非你能伪造fd，绕过双向链表检测)

small bin中存在2个chunk，我们修改small bin头部chunk的bk为`target`，fd不变（ 不修改small bin尾部chunk是为了绕过分配时的`smallbin double linked list corrupted`检测 ）,且`target->bk`( `target+3*size_t` )必须是一个可写地址，记作`target->bk = attack_addr`


原理是`_int_malloc`中,当从small bin中申请出chunk时，small bin尾部chunk在经过双向链表检测后会被分配出去，启用tcache会遍历small bin中剩余的chunk放入到对应tcache中，但此时的small bin链表已经被破坏，` (tc_victim = last (bin)) != bin` 这个条件恒成立直到abort，为了beak那个while循环，我们才在tcache中预留2个chunk位，直到tcache被填满`tcache->counts[tc_idx] = mp_.tcache_count`以此来跳出循环。

同时在最后一次unlink过程中会往`attack_addr -> fd `写入一个`main_arena`的地址，**实现任意地址写**。(当然这个洞在引入tcache时的glibc版本就已经存在)。

```c
static void *
_int_malloc (mstate av, size_t bytes)


/* While bin not empty and tcache not full, copy chunks over.  */
while (tcache->counts[tc_idx] < mp_.tcache_count
  && (tc_victim = last (bin)) != bin)
{
	if (tc_victim != 0)
	    {
	      bck = tc_victim->bk;
	      set_inuse_bit_at_offset (tc_victim, nb);
	      if (av != &main_arena)
		set_non_main_arena (tc_victim);
	      bin->bk = bck;
	      bck->fd = bin;
	      tcache_put (tc_victim, tc_idx);
        }
}

```


这时tcache已满，且tcache顶部刚好是我们伪造那个`target_chunk`


4.在使用top chunk的时候增加了检查：size要小于等于system_mems，因为House of Force需要控制top chunk的size为-1，不能通过这项检查，所以House of Force不可用

5.从glibc 2.30开始，常规large bin attack方法也被封堵



```c
  if ((unsigned long) size
              == (unsigned long) chunksize_nomask (fwd))
                        /* Always insert in the second position.  */
                        fwd = fwd->fd;
                      else
                        {
                          victim->fd_nextsize = fwd;
                          victim->bk_nextsize = fwd->bk_nextsize;
                          if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))
                            malloc_printerr ("malloc(): largebin double linked list corrupted (nextsize)");
                          fwd->bk_nextsize = victim;
                          victim->bk_nextsize->fd_nextsize = victim;
                        }
                      bck = fwd->bk;
                      if (bck->fd != fwd)
                        malloc_printerr ("malloc(): largebin double linked list corrupted (bk)");

```

查看相关代码，发现其中只增加了对 size 大于最小 size 的时候做了
检查，但是小于最小 size 却没有进行检查，因此我们可以利用这一点来完成 libc2.30 及以上的`largebin attack`。

具体做法是，往 `largebin` 中放一个堆块，并在 `unsorted bin` 中放一个比 `large bin` 中小但是在同一个 index的堆块，利用 `uaf` 修改 `large bin` 的 `bk_nextsize = 目标地址`，申请一个比 `unsorted bin` 中小的 `chunk` 触发攻击，此时 `largebin->bk_nextsize->fd_nextsize` 写入堆地址。


## tcache相关冷门漏洞(任意地址写与任意地址分配)


1.small bin
```c
  if (in_smallbin_range (nb))
    {
      idx = smallbin_index (nb);
      bin = bin_at (av, idx);

      if ((victim = last (bin)) != bin)
        {
          bck = victim->bk;
	  if (__glibc_unlikely (bck->fd != victim))
	    malloc_printerr ("malloc(): smallbin double linked list corrupted");
          set_inuse_bit_at_offset (victim, nb);
          bin->bk = bck;  
          bck->fd = bin;

          if (av != &main_arena)
	    set_non_main_arena (victim);
          check_malloced_chunk (av, victim, nb);
#if USE_TCACHE
	  /* While we're here, if we see other chunks of the same size,
	     stash them in the tcache.  */
	  size_t tc_idx = csize2tidx (nb);
	  if (tcache && tc_idx < mp_.tcache_bins)
	    {
	      mchunkptr tc_victim;

	      /* While bin not empty and tcache not full, copy chunks over.  */
	      while (tcache->counts[tc_idx] < mp_.tcache_count
		     && (tc_victim = last (bin)) != bin)
		{
		  if (tc_victim != 0)
		    {
		      bck = tc_victim->bk;
		      set_inuse_bit_at_offset (tc_victim, nb);
		      if (av != &main_arena)
			set_non_main_arena (tc_victim);
		      bin->bk = bck;
		      bck->fd = bin;

		      tcache_put (tc_victim, tc_idx);
	            }
		}
	    }
#endif
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
    }

```


前置条件是：对应tcache中预留2个chunk位（至少）(除非你能伪造fd，绕过双向链表检测)

small bin中存在2个chunk，我们修改small bin头部chunk的bk为`target`，fd不变（ 不修改small bin尾部chunk是为了绕过分配时的`smallbin double linked list corrupted`检测 ）,且`target->bk`( `target+3*size_t` )必须是一个可写地址，记作`target->bk = attack_addr`


原理是`_int_malloc`中,当从small bin中申请出chunk时，small bin尾部chunk在经过双向链表检测后会被分配出去，启用tcache会遍历small bin中剩余的chunk放入到对应tcache中，但此时的small bin链表已经被破坏，` (tc_victim = last (bin)) != bin` 这个条件恒成立直到abort，为了beak那个while循环，我们才在tcache中预留2个chunk位，直到tcache被填满`tcache->counts[tc_idx] = mp_.tcache_count`以此来跳出循环。

同时在最后一次unlink过程中会往`attack_addr -> fd `写入一个`main_arena`的地址，实现任意地址写。


```c
static void *
_int_malloc (mstate av, size_t bytes)


/* While bin not empty and tcache not full, copy chunks over.  */
while (tcache->counts[tc_idx] < mp_.tcache_count
  && (tc_victim = last (bin)) != bin)
{
	if (tc_victim != 0)
	    {
	      bck = tc_victim->bk;
	      set_inuse_bit_at_offset (tc_victim, nb);
	      if (av != &main_arena)
		set_non_main_arena (tc_victim);
	      bin->bk = bck;
	      bck->fd = bin;
	      tcache_put (tc_victim, tc_idx);
        }
}

```


这时tcache已满，且tcache顶部刚好是我们伪造那个`target_chunk`


由于smallbin摘链后chunk全部进入tcache，且已满，这时tcache对应idx入口处的chunk是`target_chunk`。如果再次调用malloc申请chunk，得益于从tcache分配时未仔细检查`chunk_head`，这时便会从tcache中将这个`target_chunk`分配出来，实现任意地址分配内存。


demo代码可参考V1me师傅写的
```c
#include<stdio.h>
#include<stdlib.h>
int main() {
    char buf[0x100];
    long *ptr1 = NULL, *ptr2 = NULL;
    int i = 0;

    memset(buf, 0, sizeof(buf));
    *(long *)(buf + 8) = (long)buf + 0x40;

    // put 5 chunks in tcache[0x90]
    for (i = 0; i < 5; i++) {
        free(calloc(1, 0x88));
    }

    // put 2 chunks in small bins
    ptr1 = calloc(1, 0x168);
    calloc(1, 0x18);
    ptr2 = calloc(1, 0x168);

    for (i = 0; i < 7; i++) {
        free(calloc(1, 0x168));
    }

    free(ptr1);
    ptr1 = calloc(1, 0x168 - 0x90);

    free(ptr2);
    ptr2 = calloc(1, 0x168 - 0x90);

    calloc(1, 0x108);

    // ptr1 and ptr2 point to the small bin chunks [0x90]
    ptr1 += (0x170 - 0x90) / 8;
    ptr2 += (0x170 - 0x90) / 8;

    // vuln
    ptr2[1] = (long)buf - 0x10;

    // trigger
    calloc(1, 0x88);

    // malloc from tcache
    ptr1 = malloc(0x88);
    strcpy((char *)ptr1, "Ohhhhhh! you are pwned!");
    printf("%s\n", buf);
    return 0;
}


```

2.fast bin

当从fastbin中分配出chunk时(比如调用calloc->_int_malloc)，如果fastbin中还有剩余chunk且相对应idx的tcache有空闲位置，这时就会根据fd指针将剩余的fastbin_chunk链入tcache中，且在这个过程中并没有检查剩余`fastbin_chunk`的完整性。


```c
static void *
_int_malloc (mstate av, size_t bytes)

#if USE_TCACHE
	      /* While we're here, if we see other chunks of the same size,
		 stash them in the tcache.  */
	      size_t tc_idx = csize2tidx (nb);
	      if (tcache && tc_idx < mp_.tcache_bins)
		{
		  mchunkptr tc_victim;

		  /* While bin not empty and tcache not full, copy chunks.  */
		  while (tcache->counts[tc_idx] < mp_.tcache_count
			 && (tc_victim = *fb) != NULL)
		    {
		      if (SINGLE_THREAD_P)
			*fb = tc_victim->fd;
		      else
			{
			  REMOVE_FB (fb, pp, tc_victim);
			  if (__glibc_unlikely (tc_victim == NULL))
			    break;
			}
		      tcache_put (tc_victim, tc_idx);
		    }
		}
#endif



```

如果我们通过UAF能修改fastbin链表尾部chunk的fd指针为一个`target_addr`，当这个`target_chunk`最后被滑入tcache中时，`target_chunk`做为tcache的头部，若tcache中存在其他chunk，则`target_chunk -> fd` 就被写入一个堆地址，实现任意地址写。

与此同时，如果再次调用malloc申请chunk，得益于从tcache分配时未仔细检查`chunk_head`，这时便会从tcache中将这个`target_chunk`分配出来，实现任意地址分配内存。（任意地址分配内存在这种情况下是个鸡肋，因为我们完全可以不清空tcache,利用UAF+calloc也就是`fastbin_attck`来实现任意地址分配）

## glibc 2.28及以上堆利用的栈转移

1.在2.29中vtable是可写的

2.setcontext函数中gadget指令可控寄存器变成了rdx，非rdi

#### 1.利用FSOP控制程序流程

在libc-2.29下`_IO_strfile`没有了像libc-2.24下的`fp->_s._allocate_buffer()`这类函数操作，都被修改为了标准函数(malloc...)，所以没办法直接直接像libc-2.24那样直接劫持程序流。因此不能使用以前的`io_file`攻击手法来劫持流程，但是我们看到在`_IO_str_overflow`函数中有很多函数,并且参数我们都可以控制，因此我们可以利用这一点来完成新版的io_file攻击

```c
int
_IO_str_overflow (FILE *fp, int c)
{
int flush_only = c == EOF;
size_t pos;
if (fp->_flags & _IO_NO_WRITES)
return flush_only ? 0 : EOF;
if ((fp->_flags & _IO_TIED_PUT_GET) && !(fp->_flags &
_IO_CURRENTLY_PUTTING))
{
fp->_flags |= _IO_CURRENTLY_PUTTING;
fp->_IO_write_ptr = fp->_IO_read_ptr;
fp->_IO_read_ptr = fp->_IO_read_end;
}
pos = fp->_IO_write_ptr - fp->_IO_write_base;
if (pos >= (size_t) (_IO_blen (fp) + flush_only))

{
if (fp->_flags & _IO_USER_BUF) /* not allowed to enlarge */
return EOF;
else
{
char *new_buf;
char *old_buf = fp->_IO_buf_base;
size_t old_blen = _IO_blen (fp);
size_t new_size = 2 * old_blen + 100;
if (new_size < old_blen)
return EOF;
new_buf = malloc (new_size);
if (new_buf == NULL)
{
/* __ferror(fp) = 1; */
return EOF;
}
if (old_buf)
{
memcpy (new_buf, old_buf, old_blen);
free (old_buf);
/* Make sure _IO_setb won't try to delete _IO_buf_base. */
fp->_IO_buf_base = NULL;
}
memset (new_buf + old_blen, '\0', new_size - old_blen);
_IO_setb (fp, new_buf, new_buf + new_size, 1);
fp->_IO_read_base = new_buf + (fp->_IO_read_base - old_buf);
fp->_IO_read_ptr = new_buf + (fp->_IO_read_ptr - old_buf);
fp->_IO_read_end = new_buf + (fp->_IO_read_end - old_buf);
fp->_IO_write_ptr = new_buf + (fp->_IO_write_ptr - old_buf);
fp->_IO_write_base = new_buf;
fp->_IO_write_end = fp->_IO_buf_end;
}
}
if (!flush_only)
*fp->_IO_write_ptr++ = (unsigned char) c;
if (fp->_IO_write_ptr > fp->_IO_read_end)
fp->_IO_read_end = fp->_IO_write_ptr;
return c;
}
```

看`_IO_str_overflow`对应的汇编代码：


```c
.text:00007FFFF7E73AEB                 mov     rdx, [rdi+28h]      
.text:00007FFFF7E73AEF 
.text:00007FFFF7E73AEF loc_7FFFF7E73AEF:                       ; CODE XREF: _IO_str_overflow+175↓j 
.text:00007FFFF7E73AEF                 mov     r12, [rdi+38h] 
.text:00007FFFF7E73AF3                 mov     r15, [rdi+40h] 
.text:00007FFFF7E73AF7                 xor     eax, eax 
.text:00007FFFF7E73AF9                 mov     ebp, esi 
.text:00007FFFF7E73AFB                 mov     rbx, rdi 
.text:00007FFFF7E73AFE                 sub     r15, r12 
.text:00007FFFF7E73B01                 cmp     esi, 0FFFFFFFFh 
.text:00007FFFF7E73B04                 mov     rsi, rdx 
.text:00007FFFF7E73B07                 setz    al 
.text:00007FFFF7E73B0A                 sub     rsi, [rdi+20h] 
.text:00007FFFF7E73B0E                 add     rax, r15 
.text:00007FFFF7E73B11                 cmp     rax, rsi 
.text:00007FFFF7E73B14                 ja      loc_7FFFF7E73BF0 
.text:00007FFFF7E73B1A                 and     ecx, 1 
.text:00007FFFF7E73B1D                 jnz     loc_7FFFF7E73C50 
.text:00007FFFF7E73B23                 lea     r14, [r15+r15+64h] 
.text:00007FFFF7E73B28                 cmp     r15, r14 
.text:00007FFFF7E73B2B                 ja      loc_7FFFF7E73C50 
.text:00007FFFF7E73B31                 mov     rdi, r14 
.text:00007FFFF7E73B34                 call    j_malloc


```
可看到调用malloc之前rdx可控制为[rdi+28h]

攻击方式：

* 劫持`IO_list_all`指向我们伪造的`io_file`

* 劫持`malloc_hook`为setcontext+61

* `io_str_overflow`里面会调用malloc,调用malloc之前`rdx=rdi+0x28`  `rdi=&fake_IO_FILE` ,此时rdi可控，执行srop


还一种情况是不能分配到理想大小的tcache，无法通过常规方式劫持free或`malloc_hook`项。（参见TCTF2020 duet）

在执行FSOP前布置好一条tcache bin：`chunk A-> ptr`
构造好三个IO_FILE: `X.chain -> Y.chain -> Z.chain`

调用malloc前rdx=rdi+0x28  rdi=&fake_IO_FILE ,此时rdi可控。

这样就可以利用FSOP在`_IO_flush_all_lockp`时三次进入`_IO_str_overflow`；第一次控制malloc参数将chunk A分配出来；第二次的时候调用malloc就会分配到ptr，而后memcpy（参见`_IO_str_overflow` C源码），即可进行任意地址写（通常将`_malloc_hook`写成setcontext+61，用于第三次刷新IO用）；第三次调用malloc，即可setcontext实现orw。

#### 2.利用`_free_hook`控制程序流程

* **方法 I ：**

然而在我们控了free_hook以后，我们发现libc-2.29中没有可以利用rdi控制rsp进行迁栈的gadget，所以使用了其它方法。`IO_wfile_sync`函数可以利用rdi控制rdx，函数setcontext+0x35处可以用rdx控rsp，两个搭配使用就可以进行迁栈。在`IO_wfile_sync+0x6d`处有call [r12+0x20]，这里的r12也是可以用rdi控制的，所以可以利用这条指令调用setcontext+0x35，实现`free_hook -> IO_wfile_sync -> setcontext+0x35`


```python
.text:0000000000089460 _IO_wfile_sync  proc near               ; DATA XREF: LOAD:0000000000010230↑o
.text:0000000000089460                                         ; __libc_IO_vtables:00000000001E5F00↓o ...
.text:0000000000089460
.text:0000000000089460 var_20          = qword ptr -20h
.text:0000000000089460
.text:0000000000089460 ; __unwind {
.text:0000000000089460                 push    r12
.text:0000000000089462                 push    rbp
.text:0000000000089463                 push    rbx
.text:0000000000089464                 mov     rbx, rdi
.text:0000000000089467                 sub     rsp, 10h
.text:000000000008946B                 mov     rax, [rdi+0A0h]
.text:0000000000089472                 mov     rdx, [rax+20h]
.text:0000000000089476                 mov     rsi, [rax+18h]
.text:000000000008947A                 cmp     rdx, rsi
.text:000000000008947D                 jbe     short loc_894AD
.text:000000000008947F                 mov     eax, [rdi+0C0h]
.text:0000000000089485                 test    eax, eax
.text:0000000000089487                 jle     loc_89590
.text:000000000008948D                 sub     rdx, rsi
.text:0000000000089490                 sar     rdx, 2
.text:0000000000089494                 call    _IO_wdo_write
.text:0000000000089499                 test    eax, eax
.text:000000000008949B                 setnz   al
.text:000000000008949E                 test    al, al
.text:00000000000894A0                 jnz     loc_895AD
.text:00000000000894A6
.text:00000000000894A6 loc_894A6:                              ; CODE XREF: _IO_wfile_sync+147↓j
.text:00000000000894A6                 mov     rax, [rbx+0A0h]
.text:00000000000894AD
.text:00000000000894AD loc_894AD:                              ; CODE XREF: _IO_wfile_sync+1D↑j
.text:00000000000894AD                 mov     rsi, [rax]
.text:00000000000894B0                 mov     rax, [rax+8]
.text:00000000000894B4                 cmp     rsi, rax
.text:00000000000894B7                 jz      short loc_89532
.text:00000000000894B9                 sub     rsi, rax
.text:00000000000894BC                 mov     r12, [rbx+98h]
.text:00000000000894C3                 sar     rsi, 2
.text:00000000000894C7                 mov     rbp, rsi
.text:00000000000894CA                 mov     rdi, r12
.text:00000000000894CD                 call    qword ptr [r12+20h]
```

* **方法 II :**

利用libc中的这段gadget

```
sub rsp,0x18
mov rbp,[rdi+0x48]
mov rax,[rbp+0x18]
lea r13,[rbp+0x10]
mov dword ptr [rbp+0x10],0
mov rdi,r13
call qword ptr [rax+0x28]
```

将`free_hook`写成这个gadget，可控制rbp寄存器，call时跳转到`leave_ret`指令实现栈迁移

或者glibc2.31中的这一段

```
0x7fcab86497a0 <getkeyserv_handle+576>    mov    rdx, qword ptr [rdi + 8]
0x7fcab86497a4 <getkeyserv_handle+580>    mov    qword ptr [rsp], rax
0x7fcab86497a8 <getkeyserv_handle+584>    call   qword ptr [rdx + 0x20] <0x7fcab854d0dd>

```


#### 3.利用fclose（特殊条件）

fclose的源码，其核心函数是位于/libio/iofclose.c的`_IO_new_fclose`函数，其大致流程是：首先检查文件结构体指针，之后使用`_IO_un_link`将文件结构体从`_IO_list_all`链表取下，`_IO_file_close_it`里会最终调用`IO_SYSCLOSE(fp)`关闭文件描述符，之后返回fclose函数会调用到vtable里面的函数`_IO_FINISH(fp)`，如果并非stdin/stdout/stderr最后调用free(fp)释放结构体指针。


在`_IO_file_close_it`里调用`IO_SYSCLOSE(fp)`，或是在fclose里调用`_IO_FINISH(fp)`的时候，rdx的寄存器值都是`_IO_helper_jumps`，所以只要我们能控制`_IO_helper_jumps`的值就能控制rdx（2.29以上`jumps_table`可写）.

利用方式：

我们可以将`IO_file_jumps`+0x88(sysclose)（0x10(finish)）的位置覆盖为setcontext+53并且在`IO_helper_jumps`上布置setcontext参数，或者将vtable直接覆盖为`IO_helper_jumps`，然后直接在`IO_helper_jumps`布置所有的值。

## House-of-Corrosion 任意地址写

1. 可以分配较大的堆块（size <=0x3b00)
2. 通过爆破4bit,改写bk进行unsortedbin attack 改写global_max_fast变量
3. 通过分配释放特定大小的堆块,记为A **(chunk size = (offset * 2) + 0x20 ，offset为target_addr与fastbinY的差值)**
`pwndbg>    p (mfastbinptr (*)[10])target_addr - &main_arena.fastbinsY ` **target_addr**为攻击地址



![](../pic/Miscellaneous/5.jpg)

所以我们至少可实现任意地址写null,存在UAF时可写任意value.


## seccomp 没禁用架构

大致思路：

1. 调用mmap申请地址，调用read读入32位shellcode
2. 同时构造用retfq切换到32位模式，跳转到32位shellcode 位置
3. 按照32位规则调用fp = open("flag")
4. 保存open函数返回的fp指针，再次调用retfq切换回64模式，跳转到64位shellcode位置
5. 执行read,write打印flag

注意点：

cs = 0x23代表32位模式，cs = 0x33代表64位模式，retfq有两步操作，ret以及set cs，所以执行retfq会跳转到rsp同时将cs设置为[rsp+0x8]，我们只需要事先在ret位置写入32位的shellcode就可以执行了，但retfq跳转过去的时候程序已经切换成了32位模式，所以地址解析也是以32位的规则来的，所以原先的rsp = 0x7ffe530d01b8会被解析成esp = 0x530d01b8，所以跳过去之后再执行push/pop的指令就会报错，所以在跳转过去后要先平衡好esp的地址，比如执行mov esp,im

