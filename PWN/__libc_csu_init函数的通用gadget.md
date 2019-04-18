---
layout:     post
title:      "64位通用gadget"
subtitle:   "x64 ROP 笔记"
date:       2018-06-03 12:00:00
author:     "Chris"
catalog: true
tags:
    - Pwn
    - 笔记
    - Linux
 
---

# 简介

x86中参数都是保存在栈上,但在x64中前六个参数依次保存在RDI, RSI, RDX, RCX, R8和 R9寄存器里，如果还有更多的参数的话才会保存在栈上。这样传参就有点难受，但是程序在编译过程中会加入一些通用函数用来进行初始化操作（比如加载libc.so的初始化函数），所以虽然很多程序的源码不同，但是初始化的过程是相同的，因此针对这些初始化函数，我们可以提取一些通用的gadgets加以使用，从而达到我们想要达到的效果。

## _\_libc\_csu\_init函数(1-3参数)

### 3参数

输入 **objdump -d 文件名** ：反汇编文件中的需要执行指令的那些section

找到 <__libc_csu_init>  -- 有以下代码

1.执行gad1

```nasm
	.text:000000000040089A                 pop     rbx  #必须为0
	.text:000000000040089B                 pop     rbp  #必须为1
	.text:000000000040089C                 pop     r12  #call（由于下面call指令的寻址方式为间接寻址，所以此处应为got表地址） 
	.text:000000000040089E                 pop     r13  #arg3
	.text:00000000004008A0                 pop     r14  #arg2
	.text:00000000004008A2                 pop     r15  #arg1
	.text:00000000004008A4                 retn  ——>  #to gad2
```
2.再执行gad2

```nasm
	.text:0000000000400880                 mov     rdx, r13
	.text:0000000000400883                 mov     rsi, r14
	.text:0000000000400886                 mov     edi, r15
	.text:0000000000400889                 call    qword ptr [r12+rbx*8] call 
	.text:000000000040088D                 add     rbx, 1
	.text:0000000000400891                 cmp     rbx, rbp
	.text:0000000000400894                 jnz     short loc_400880
	.text:0000000000400896                 add     rsp, 8
	.text:000000000040089A                 pop     rbx
	.text:000000000040089B                 pop     rbp
	.text:000000000040089C                 pop     r12
	.text:000000000040089E                 pop     r13
	.text:00000000004008A0                 pop     r14
	.text:00000000004008A2                 pop     r15
	.text:00000000004008A4                 retn ——>  #构造一些垫板(7*8=56byte)就返回了
```
这样的话

```nasm
	r13 =rdx =arg3
	r14 =rsi =arg2
	r15 =edi =arg1
	r12 =call address
```

### 1-2参数

还有一个老司机才知道的x64 gadgets，就是 pop rdi，ret的gadgets。这个gadgets还是在这里，但是是由opcode错位产生的。

如上的例子中4008A2、4008A4两句的字节码如下

	0x41 0x5f 0xc3

意思是pop r15，ret，但是恰好pop rdi，ret的opcode如下

	0x5f 0xc3

因此如果我们指向0x4008A3就可以获得pop rdi，ret的opcode，从而对于单参数函数可以直接获得执行，这是1个参数的情况。

 

与此类似的，还有0x4008A1处的 

	pop rsi，pop r15，ret

那么这个有什么用呢？我们知道x64传参顺序是rdi,rsi,rdx,rcx。

所以rsi是第二个参数，我们可以在rop中配合pop rdi,ret来使用pop rsi，pop r15,ret，这样就可以轻松的调用2个参数的函数。


## \_dl\_runtime\_resolve(6参数)

我们把`_dl_runtime_resolve`反编译可以得到：

```nasm
	0x7ffff7def200 <_dl_runtime_resolve>:   sub    rsp,0x38
	0x7ffff7def204 <_dl_runtime_resolve+4>: mov    QWORD PTR [rsp],rax
	0x7ffff7def208 <_dl_runtime_resolve+8>: mov    QWORD PTR [rsp+0x8],rcx
	0x7ffff7def20d <_dl_runtime_resolve+13>:    mov    QWORD PTR [rsp+0x10],rdx
	0x7ffff7def212 <_dl_runtime_resolve+18>:    mov    QWORD PTR [rsp+0x18],rsi
	0x7ffff7def217 <_dl_runtime_resolve+23>:    mov    QWORD PTR [rsp+0x20],rdi
	0x7ffff7def21c <_dl_runtime_resolve+28>:    mov    QWORD PTR [rsp+0x28],r8
	0x7ffff7def221 <_dl_runtime_resolve+33>:    mov    QWORD PTR [rsp+0x30],r9
	0x7ffff7def226 <_dl_runtime_resolve+38>:    mov    rsi,QWORD PTR [rsp+0x40]
	0x7ffff7def22b <_dl_runtime_resolve+43>:    mov    rdi,QWORD PTR [rsp+0x38]
	0x7ffff7def230 <_dl_runtime_resolve+48>:    call   0x7ffff7de8680 <_dl_fixup>
	0x7ffff7def235 <_dl_runtime_resolve+53>:    mov    r11,rax
	0x7ffff7def238 <_dl_runtime_resolve+56>:    mov    r9,QWORD PTR [rsp+0x30]
	0x7ffff7def23d <_dl_runtime_resolve+61>:    mov    r8,QWORD PTR [rsp+0x28]
	0x7ffff7def242 <_dl_runtime_resolve+66>:    mov    rdi,QWORD PTR [rsp+0x20]
	0x7ffff7def247 <_dl_runtime_resolve+71>:    mov    rsi,QWORD PTR [rsp+0x18]
	0x7ffff7def24c <_dl_runtime_resolve+76>:    mov    rdx,QWORD PTR [rsp+0x10]
	0x7ffff7def251 <_dl_runtime_resolve+81>:    mov    rcx,QWORD PTR [rsp+0x8]
	0x7ffff7def256 <_dl_runtime_resolve+86>:    mov    rax,QWORD PTR [rsp]
	0x7ffff7def25a <_dl_runtime_resolve+90>:    add    rsp,0x48
	0x7ffff7def25e <_dl_runtime_resolve+94>:    jmp    r11
```
从0x7ffff7def235开始，就是这个通用gadget的地址了。通过这个gadget我们可以控制rdi，rsi，rdx，rcx， r8，r9的值。但要注意的是`_dl_runtime_resolve`()在内存中的地址是随机的。所以我们需要先用information leak得到`_dl_runtime_resolve`()在内存中的地址。那么`_dl_runtime_resolve`()的地址被保存在了哪个固定的地址呢？

通过反编译level5程序我们可以看到[email protected]()这个函数使用PLT [0] 去查找write函数在内存中的地址，函数jump过去的地址*0x600ff8其实就是`_dl_runtime_resolve`()在内存中的地址了。所以只要获取到0x600ff8这个地址保存的数据，就能够找到`_dl_runtime_resolve`()在内存中的地址：

```nasm
	0000000000400420 <[email protected]>:
	  400420:   ff 35 ca 0b 20 00       pushq  0x200bca(%rip)        # 600ff0 <_GLOBAL_OFFSET_TABLE_+0x8>
	  400426:   ff 25 cc 0b 20 00       jmpq   *0x200bcc(%rip)        # 600ff8 <_GLOBAL_OFFSET_TABLE_+0x10>
	  40042c:   0f 1f 40 00             nopl   0x0(%rax)
	
	gdb-peda$ x/x 0x600ff8
	0x600ff8 <_GLOBAL_OFFSET_TABLE_+16>:    0x00007ffff7def200
	
	gdb-peda$ x/21i 0x00007ffff7def200
	   0x7ffff7def200 <_dl_runtime_resolve>:    sub    rsp,0x38
	   0x7ffff7def204 <_dl_runtime_resolve+4>:  mov    QWORD PTR [rsp],rax
	   0x7ffff7def208 <_dl_runtime_resolve+8>:  mov    QWORD PTR [rsp+0x8],rcx
	   0x7ffff7def20d <_dl_runtime_resolve+13>: mov    QWORD PTR 
	[rsp+0x10],rdx
	
```

另一个要注意的是，想要利用这个gadget，我们还需要控制rax的值，因为gadget是通过rax跳转的：

```nasm
	0x7ffff7def235 <_dl_runtime_resolve+53>:    mov    r11,rax
	……
	0x7ffff7def25e <_dl_runtime_resolve+94>:    jmp    r11
```
所以我们接下来用ROPgadget查找一下libc.so中控制rax的gadget：

```nasm
	ROPgadget --binary libc.so.6 --only "pop|ret" | grep "rax"
	0x000000000001f076 : pop rax ; pop rbx ; pop rbp ; ret
	0x0000000000023950 : pop rax ; ret
	0x000000000019176e : pop rax ; ret 0xffed
	0x0000000000123504 : pop rax ; ret 0xfff0
```

0x0000000000023950刚好符合我们的要求。有了pop rax和_dl_runtime_resolve这两个gadgets，我们就可以很轻松的调用想要的调用的函数了。

