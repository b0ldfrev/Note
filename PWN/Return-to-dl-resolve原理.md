---
layout:     post
title:      "Return-to-dl-resolve原理"
subtitle:   "Lazy binding 延迟绑定细节"
date:       2018-11-27 12:00:00
author:     "Chris"
catalog: true
tags:
    - 笔记
    - Linux
    - Pwn
 
---

>前言：初学Pwn的时候，是从栈溢出开始，在网上找了很多介绍Return-to-dl-resolve技术的文章，但还是云里雾里，不懂其中精髓,于是就放一边去。最近发现网上有一篇博文对该技术介绍的很细致，我怕博主换域名，于是Copy一份到我的博客。

## About GOT and PLT

为了了解`GOT`和`PLT`，首先要知道关于`PIC`的知识，`Position Independent Code(PIC)`是为了是为了重定位动态链接库的`symbols`，现代操作系统不允许修改代码段，只能修改数据段，而使用了动态链接库后函数地址只有在执行时才能确定，所以程序内调用的库中的函数地址在编译时不知道，所以，编译时将函数调用返回`.data`段，而包含`PIC`的程序在运行时需要更改`.data`段中的`GOT`和`PLT`来重定位全局变量。

`Global Offset Table`，也就是`GOT`表为每个全局变量保存了入口地址，在调用全局变量时，会直接调用对应`GOT`表条目中保存的地址，而不调用绝对地址。

`Procedural Linkage Table`，也就是`PLT`是过程链接表，为每个全局变量保存了一段代码，第一次调用一个函数会调用形如`function@PLT`的函数，这就是跳到了函数对应的`PLT`表开头执行，会解析出函数真正的地址填入`GOT`表中，以后调用时会从`GOT`表中取出函数真正的起始地址执行，下面会说具体的细节。

## Environment

```python
root@VirtualBox:~/Desktop$ uname -a
Linux VirtualBox 3.13.0-32-generic #57~precise1-Ubuntu SMP Tue Jul 15 03:50:54 UTC 2014 i686 i686 i386 GNU/Linux
 
root@VirtualBox:~/Desktop$ lsb_release -a
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 12.04.5 LTS
Release:    12.04
Codename:   precise
 
root@VirtualBox:~/Desktop$ gcc -v
gcc version 4.6.3 (Ubuntu/Linaro 4.6.3-1ubuntu5)
```

测试代码:

```c
//test.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {

        printf("aaa");
        char* s = (char *)malloc(300);
        char* s1 = (char*)malloc(248);
        void* a = malloc(0x20);
        free(a);
        free(s);
        free(s1);
        malloc(100);
        malloc(200);
        return 0;
}

```

编译链接:

```python
root@VirtualBox:~/Desktop$ gcc -g test.c -o test
```

## Something about .dynamic

ELF的`.dynamic section`里包含了和重定位有关的很多信息，完整的`.dynamic`段:

```python
root@VirtualBox:~/Desktop$ readelf -d test

Dynamic section at offset 0xf28 contains 20 entries:
  Tag        Type                         Name/Value
 0x00000001 (NEEDED)                     Shared library: [libc.so.6]
 0x0000000c (INIT)                       0x80482f4
 0x0000000d (FINI)                       0x804857c
 0x6ffffef5 (GNU_HASH)                   0x80481ac
 0x00000005 (STRTAB)                     0x804823c
 0x00000006 (SYMTAB)                     0x80481cc
 0x0000000a (STRSZ)                      88 (bytes)
 0x0000000b (SYMENT)                     16 (bytes)
 0x00000015 (DEBUG)                      0x0
 0x00000003 (PLTGOT)                     0x8049ff4
 0x00000002 (PLTRELSZ)                   40 (bytes)
 0x00000014 (PLTREL)                     REL
 0x00000017 (JMPREL)                     0x80482cc
 0x00000011 (REL)                        0x80482c4
 0x00000012 (RELSZ)                      8 (bytes)
 0x00000013 (RELENT)                     8 (bytes)
 0x6ffffffe (VERNEED)                    0x80482a4
 0x6fffffff (VERNEEDNUM)                 1
 0x6ffffff0 (VERSYM)                     0x8048294
 0x00000000 (NULL)                       0x0

```

`GOT`表分成两部分`.got`和`.got.plt`，前一个保存全局变量引用位置，后一个保存函数引用位置，通常说的`GOT`指后面一个，下文GOT即代表`.got.plt`。

`GOT`表的起始地址:

```python
root@VirtualBox:~/Desktop$ readelf -d test | grep GOT
 0x00000003 (PLTGOT)                     0x8049ff4
```

`GOT`表的前三项有特殊含义:

```python
gdb-peda$ x/3x 0x8049ff4
0x8049ff4 <_GLOBAL_OFFSET_TABLE_>:  0x08049f28  0xb7fff918  0xb7ff2650
gdb-peda$ x/i 0xb7ff2650
   0xb7ff2650 <_dl_runtime_resolve>:    push   eax
gdb-peda$ x/x 0x08049f28
0x8049f28 <_DYNAMIC>:   0x00000001
gdb-peda$ x/x 0xb7fff918
0xb7fff918: 0x00000000

```

第一项是`.dynamic`段的地址，第二个是`link_map`的地址，第三个是`_dl_runtime_resolve`函数的地址，第四项开始就是函数的`GOT`表了，第一项就是`printf`条目:

```python
gdb-peda$ x/x 0x8049ff4+0xc
0x804a000 <printf@got.plt>: 0x08048346
```

`PLTRELSZ`指定了`.rel.plt`大小，`RELENT`指定每一项大小，`PLTREL`指定条目类型为`REL`，`JMPREL`对应`.rel.plt`地址，保存了重定位表，保存的是结构体信息:

```python
root@VirtualBox:~/Desktop$ readelf -d test | grep REL
 0x00000002 (PLTRELSZ)                   40 (bytes)
 0x00000014 (PLTREL)                     REL
 0x00000017 (JMPREL)                     0x80482cc
 0x00000011 (REL)                        0x80482c4
 0x00000012 (RELSZ)                      8 (bytes)
 0x00000013 (RELENT)                     8 (bytes)

```

`REL`的数据结构为:

```c
typedef struct
{
  Elf32_Addr    r_offset;               /* Address */
  Elf32_Word    r_info;                 /* Relocation type and symbol index */
} Elf32_Rel;
#define ELF32_R_SYM(val)                ((val) >> 8)
#define ELF32_R_TYPE(val)               ((val) & 0xff)

```

`r_offset`就是对应函数`GOT`表地址，看看`.rel.plt`第一项和第二项:

```python
gdb-peda$ x/2x 0x80482cc
0x80482cc:  0x0804a000  0x00000107
gdb-peda$ x/2x 0x80482cc+0x8
0x80482d4:  0x0804a004  0x00000207

```

再看:

```python
root@VirtualBox:~/Desktop$ readelf -r test

Relocation section '.rel.dyn' at offset 0x2c4 contains 1 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
08049ff0  00000406 R_386_GLOB_DAT    00000000   __gmon_start__

Relocation section '.rel.plt' at offset 0x2cc contains 5 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
0804a000  00000107 R_386_JUMP_SLOT   00000000   printf
0804a004  00000207 R_386_JUMP_SLOT   00000000   free
0804a008  00000307 R_386_JUMP_SLOT   00000000   malloc
0804a00c  00000407 R_386_JUMP_SLOT   00000000   __gmon_start__
0804a010  00000507 R_386_JUMP_SLOT   00000000   __libc_start_main

```

分别和`printf`与`free`对应，`0x0804a000`处就是`printf`的`GOT`表地址。

根据宏定义，由`r_info=0x107`可以知道`ELF32_R_TYPE(r_info)=7`，对应于`R_386_JUMP_SLOT`；其`symbol index`则为`RLF32_R_SYM(r_info)=1`

还有一个需要注意的就是字符串表，保存了一些符号表，在重定位时会用到:

```python
root@VirtualBox:~/Desktop$ readelf -d test | grep STRTAB
 0x00000005 (STRTAB)                     0x804823c
```
查看:

```python
gdb-peda$ x/10s 0x804823c
0x804823c:   ""
0x804823d:   "__gmon_start__"
0x804824c:   "libc.so.6"
0x8048256:   "_IO_stdin_used"
0x8048265:   "printf"
0x804826c:   "malloc"
0x8048273:   "__libc_start_main"
0x8048285:   "free"
0x804828a:   "GLIBC_2.0"
0x8048294:   ""

```

## How ELF relocation works

在第一次`call 0x8048340 <printf@plt>`时会跳到`PLT`段中，第一句会跳到`GOT`条目指向的地址:

```python
gdb-peda$ x/x 0x804a000
0x804a000 <printf@got.plt>: 0x08048346
gdb-peda$ b *0x08048346
Breakpoint 2 at 0x8048346
gdb-peda$ c

```

第一次调用函数时，`GOT`表中的地址为`PLT`表的第二句地址:

```nasm
   0x8048340 <printf@plt>:  jmp    DWORD PTR ds:0x804a000
=> 0x8048346 <printf@plt+6>:    push   0x0
   0x804834b <printf@plt+11>:   jmp    0x8048330
↓
=> 0x804834b <printf@plt+11>:   jmp    0x8048330
 | 0x8048350 <free@plt>:    jmp    DWORD PTR ds:0x804a004
 | 0x8048356 <free@plt+6>:  push   0x8
 | 0x804835b <free@plt+11>: jmp    0x8048330
 | 0x8048360 <malloc@plt>:  jmp    DWORD PTR ds:0x804a008
 |->   0x8048330:   push   DWORD PTR ds:0x8049ff8
       0x8048336:   jmp    DWORD PTR ds:0x8049ffc
       0x804833c:   add    BYTE PTR [eax],al
       0x804833e:   add    BYTE PTR [eax],al
↓
=> 0x8048336:   jmp    DWORD PTR ds:0x8049ffc
 | 0x804833c:   add    BYTE PTR [eax],al
 | 0x804833e:   add    BYTE PTR [eax],al
 | 0x8048340 <printf@plt>:  jmp    DWORD PTR ds:0x804a000
 | 0x8048346 <printf@plt+6>:    push   0x0
 |->   0xb7ff2650 <_dl_runtime_resolve>:       push   eax

```

先push `reloc_offset`，这里是0，再push `link_map`，也就是`GOT`表的第二项，再调用`_dl_runtime_resolve`函数。

`_dl_runtime_resolve`根据`reloc_offset`找到`.rel.plt`段中的结构体:

```python

Elf32_Rel * p = JMPREL + rel_offset;

p的内容:
0x80482cc:  0x0804a000  0x00000107
```

`r_info`为`0x107`。

然后根据`ELF32_R_SYM(r_info)`找到`.dynsym`中对应的结构体:

```python
Elf32_Sym *sym = SYMTAB[ELF32_R_SYM(p->r_info)]
=> sym = SYMTAB[1]
```

`.dynsym`有关的信息为:

```python
root@VirtualBox:~/Desktop$ readelf -d test | grep SYM
 0x00000006 (SYMTAB)                     0x80481cc
 0x0000000b (SYMENT)                     16 (bytes)
```

其实地址为`0x80481cc`，每个结构体大小为`16bytes`，

结构体为:

```c
typedef struct
{
  Elf32_Word    st_name;                /* Symbol name (string tbl index) */
  Elf32_Addr    st_value;               /* Symbol value */
  Elf32_Word    st_size;                /* Symbol size */
  unsigned char st_other;               /* Symbol visibility */
  Elf32_Section st_shndx;               /* Section index */
} Elf32_Sym;

```

所以`SYMTAB[1]`为`0x80481cc+16`:

```python
gdb-peda$ x/5wx 0x80481cc+16
0x80481dc:  0x00000029  0x00000000  0x00000000    0x00000012
0x80481ec:  0x00000049

```

然后根据`sym->st_name`=0x29在`.dynstr`中，也就是`STRTAB`找到函数对应的字符串:

```python
gdb-peda$ x/s 0x804823c+0x29
0x8048265:   "printf"
```
根据函数名字找到对应的地址，填入`GOT`表对应的位置，跳到函数起始地址执行，执行完后，`printf`对应的`GOT`表处已经填上了函数真正的地址:

```python
gdb-peda$ x/x 0x0804a000
0x804a000 <printf@got.plt>: 0xb7e6b8a0

```

## 相关链接

下面是我收集的一些关于`Return-to-dl-resolve`的好文章

[如何在32位系统中使用ROP+Return-to-dl来绕过ASLR+DEP](https://www.freebuf.com/articles/system/149214.html)

[在64位系统中使用ROP+Return-to-dl-resolve来绕过ASLR+DEP](https://www.freebuf.com/articles/system/149364.html)

[return to dl-resolve之roputils库使用](https://sirhc.xyz/2018/06/16/return-to-dl-resolve%E5%88%A9%E7%94%A8/)

[roputils.pyc文件](https://github.com/yxshyj/project/tree/master/pwn/Return-to-dl-resolve)