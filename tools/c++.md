---
layout:     post
title:      "C++ 虚表分析"
subtitle:   "非多继承，虚继承"
date:       2018-07-25 12:00:00
author:     "Chris"
catalog: true
tags:
    - 笔记
    - Linux
 
---

>自己捣鼓了一下C++的虚表，随便写点东西

**在C++中，每一个含有虚函数的类都会有一个虚函数表，简称虚表。与之对应的，每一个对象都会有其专属的虚表指针指向这个虚表。**

## 0x00 测试代码

```c++
#include <iostream>
#include <cstring>
#include <cstdlib>
using namespace std;

class A{
public:
int a;
virtual void  print()
{
cout<<"This is class A"<<endl;
}
};


class B : public A{
public:
int b;
virtual void  print()
{
cout<<"This is class B"<<endl;
}
};

int main()

{
A *a=new A;
A *b=new B;
a->print();
b->print();
return 0;
}
```

## 0x01 GDB调试

```nasm
   0x8048791 <main+4>     and    esp, 0xfffffff0
   0x8048794 <main+7>     sub    esp, 0x20
   0x8048797 <main+10>    mov    dword ptr [esp], 8    #参数 8字节
   0x804879e <main+17>    call   0x8048660          #先开辟 8 byte 空间
 
   0x80487a3 <main+22>    mov    ebx, eax
   0x80487a5 <main+24>    mov    dword ptr [esp], ebx
   0x80487a8 <main+27>    call   A::A() <0x80488aa>    #再调用构造函数
 
 ► 0x80487ad <main+32>    mov    dword ptr [esp + 0x18], ebx
   0x80487b1 <main+36>    mov    dword ptr [esp], 0xc
   0x80487b8 <main+43>    call   0x8048660
 
   0x80487bd <main+48>    mov    ebx, eax
```
执行完 **call   A::A() <0x80488aa>** 也就是分配好空间，调用完构造函数 我们再看一下返回值eax地址单元的内容：

```nasm
pwndbg> x/4xw $eax
0x804b008:	0x080489a8	0x00000000	0x00000000	0x00020ff1
```

这里 **0x080489a8** 就是a对象的虚表地址（vfptr）,**0x00000000** 是int a变量值（这里构造函数里面未对其赋值，所以为零） ，至于**0x00000000 与	0x00020ff1** 是top chunk 不用管。

接下来我们再看看 **0x080489a8** 虚表里面的内容

```nasm
pwndbg> x/4xw 0x080489a8
0x80489a8 <_ZTV1A+8>:	0x08048852	0x00004231	0x0804a128	0x080489ac

pwndbg> x/5i 0x08048852
   0x8048852 <_ZN1A5printEv>:	push   ebp
   0x8048853 <_ZN1A5printEv+1>:	mov    ebp,esp
   0x8048855 <_ZN1A5printEv+3>:	sub    esp,0x18
   0x8048858 <_ZN1A5printEv+6>:	mov    DWORD PTR [esp+0x4],0x8048970
   0x8048860 <_ZN1A5printEv+14>:	mov    DWORD PTR [esp],0x804a080
```
很容易看出来了，虚表里第一个地址就是A类里面的print函数

```c
A *a=new A;
a->print();
```

当执行以上代码的时候实际上是这样一个流程 **a - > 0x08048852 - > 0x08048852** 来执行print（）

===========================================================================================

同理，我们分析一下b对象，我们GDB继续往下跟。

```nasm
   0x80487b1 <main+36>    mov    dword ptr [esp], 0xc
   0x80487b8 <main+43>    call   0x8048660
 
   0x80487bd <main+48>    mov    ebx, eax
   0x80487bf <main+50>    mov    dword ptr [esp], ebx
   0x80487c2 <main+53>    call   B::B() <0x80488b8>
 
 ► 0x80487c7 <main+58>    mov    dword ptr [esp + 0x1c], ebx
   0x80487cb <main+62>    mov    eax, dword ptr [esp + 0x18]
   0x80487cf <main+66>    mov    eax, dword ptr [eax]
```

箭头指向处 **A \*b=new B** 已经执行完，我们看看回值eax地址单元的内容：

```nasm
pwndbg> x/4xw $eax
0x804b018:	0x08048998	0x00000000	0x00000000	0x00020fe1

pwndbg> x/4w 0x08048998
0x8048998 <_ZTV1B+8>: 0x0804887e	0x00000000	0x00000000	0x080489c0

pwndbg> x/5i 0x0804887e
   0x804887e <_ZN1B5printEv>:	push   ebp
   0x804887f <_ZN1B5printEv+1>:	mov    ebp,esp
   0x8048881 <_ZN1B5printEv+3>:	sub    esp,0x18
   0x8048884 <_ZN1B5printEv+6>:	mov    DWORD PTR [esp+0x4],0x8048980
   0x804888c <_ZN1B5printEv+14>:	mov    DWORD PTR [esp],0x804a080
```
同理 b对象的虚表里面有它自己的print函数，地址异于a的，这就是c++多态性的实现。

## 0x02 总结

这里再总结一下： 

如果是调用 **A \*b = new B;** 生成的是子类的对象，在构造时，子类对象的虚指针指向的是子类的虚表，接着由B\*到A\*的转换并没有改变虚表指针，所以这时候b->print，实际上是p->vfptr->print，它在构造的时候就已经指向了子类的print，所以调用的是子类的虚函数，这就是多态了。




>[文件下载](https://github.com/yxshyj/project/tree/master/other/C%2B%2B%20%E8%99%9A%E8%A1%A8%E5%88%86%E6%9E%90)



