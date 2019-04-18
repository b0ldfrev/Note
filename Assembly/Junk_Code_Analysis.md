---
layout:     post
title:      "Junk Code Analysis"
subtitle:   "花指令 反调试笔记——转"
date:       2018-11-12 10:00:00
author:     "Chris"
catalog: true
tags:
    - Junk Code
 
---

>本文转自看雪Adventure大佬的一篇外文翻译。


本次实验我们会分析一个特别准备好的二进制文件（非恶意文件），但是里面使用了各种反-反汇编技术

首先使用IDA打开antidisasm.exe：

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/1.jpg)

你可以看到这里有一组函数调用，每一个函数使用了不同的反反汇编技术，并把返回值保存在eax寄存器。本次任务是通过静态分析找出每个函数的返回值是什么？

## 1)  分析Loc_40101A函数

首先进入到0x40101A函数

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/2.jpg)

看上去IDA并没有识别出这是一个函数，而且这个函数看上去也没有返回值，因为在CALL EAX指令后面有一些垃圾指令，而loc_401045标签位置是下一个函数的开始。

注意 在loc_40101A开始的地方有一个奇怪的call( call $+5).

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/3.jpg)

这个有趣的CALL的调用地址是下一条指令（0x401022）。它这样调用的目的是为了把返回地址(0x401022)PUSH到栈上，然后通过执行POP EAX指令把刚才的地址加载到EAX。

然后EAX+10被加10后，CALL向了这个新的EAX的值。

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/4.jpg)

现在你知道EAX的值是0x401032（0x401022+0x10）。不幸的是，这个地址的位置是垃圾代码中间的位置，并且看上去这个地址的位置并没有指令。


![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/5.jpg)

很明显这些垃圾代码是因为反汇编引擎解析某些指令时出现了错位导致的。因为在IDA解析CALL EAX这条指令，IDA并不知道它CALL的地址是多少，所以尝试反汇编CALL EAX的下一条指令。

要修复这个问题，首先选中所有的垃圾代码，然后右键选择undefined(或者按U键)：

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/6.jpg)

下一步，选中0x401032位置的第一个字节，按下C键把这个位置的字节转换成代码。可以看到CALL EAX指令后面出现了一个字符串”Fintastic!”。

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/7.jpg)

现在代码比刚才清晰多了，你可以看到`loc_40101A`函数的返回值是0x1337

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/8.jpg)

总结一下，在这个函数中学到了两种反反汇编技术，第一这里有个间接调用到动态计算的地址。IDA不知道这个被调用的地址是多少，因此它尝试解析这个CALL后面在行内嵌入的字符串(第二种反反汇编技术)。最终导致解析出了一些垃圾指令，而不是一个有效的汇编指令。

## 2)  分析loc_401045函数

本次我们将分析位于`loc_401045`的函数。

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/9.jpg)

第一眼看上去尽管IDA并没有识别出这里的代码是一个正常的函数，但是这里有一个经典的函数开始和结束retn指令。你也可以高亮EAX寄存器来找到它在哪里被赋值的。

看上去EAX第一次被赋值成了0x11EB，然后增加了0x1000。即使如此，我们应该把注意力放在跳转指令（jz），jz看上去是跳转到了另一条汇编指令的中间位置。同样注意到这里有个有条红色交叉引用，看上去这里貌似出现了什么问题。

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/10.jpg)

在分析jz将要跳转到哪里之前，先来看看什么条件它才会跳转。最后一条指令导致零标志位ZF被置1的指令是jz跳转指令前面的XOR EAX EAX，它会清空EAX寄存器，并设置ZF标志为1。这表示跳转一定会被执行。

由于跳转到了一条汇编指令中间，选中这条指令并把它转换成数据（使用Undefine 或 按U键）。


![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/11.jpg)

IDA可能会转换比你预期等多的代码，但没关系，因为你知道jz跳转的目标地址是0x40104B，原始的jz指令位于0x401050。

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/12.jpg)

现在选中0x40104B处的一字节，按下C转换成代码，同样操作来转换jz指令的位置，0x401050。做完这些操作后，你应该能看到类似下面这样的代码：

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/13.jpg)

这表示在PUSH指令中间隐藏了另一个跳转指令jmp。

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/14.jpg)

正如你所见，这条被隐藏的跳转指令的目的地址是0x40105E（另一条汇编指令0x40105D的中间位置）。但是这次看上去是一个正常的汇编错位解析指令。

为了继续进行，把0x40105D转换成数据，然后把0x40105E位置转成代码，转换完成后，你看到的代码应该是这个样子：

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/15.jpg)

现在你可以清楚的看到返回值被设置成了0x4096。注意在返回指令retn后面的这几个垃圾字节，是曾经被用来阻止IDA反汇编EAX被赋值这条指令的。

下面截图展示了在没有做任何修改之前，这个函数的执行流程：

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/16.jpg)

总结一下通过这个函数你学习到的一些反-反汇编技术。最明显的一个就是跳转到另一条指令中间。在这种情况下PUSH指令被用来隐藏另一个跳转指令。你还看到把jz条件跳转变成了无条件跳转，以及一些垃圾字节来阻止IDA反汇编。

## 3)  分析sub_401065函数

下一个要分析的函数是`sub_401065`。但是这次IDA把它识别成一个正常的函数了。


![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/17.jpg)

可以看到EAX开始被清空了，然后调用了sub_40107D函数(传入参数0x1000)，最终EAX又增加了0x1000。问题是不知道`sub_40107D`函数的返回值EAX有没有被修改。

来看一下`sub_40107D`函数：

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/18.jpg)

看上去这个函数做的唯一一件事就是把参数0x1000赋值给了EAX，然后又加了0x1000，当这个函数返回时EAX应该是0x2000。难道sub_401065函数的返回值是0x3000（0x2000+0x1000）？

正如你所怀疑，并不是那么简单。来看一下sub_40107D返回前发生了什么：

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/19.jpg)

首先把第一个参数的地址传给了EDX，然后把EDX减去4。还知道现在EDX保存的指针指向哪里么？看一下堆栈的结构：

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/20.jpg)

在EDX减去4后指向了栈上返回地址的位置，然后，在第三行，给返回地址增加了0x2B。这表示当前函数sub_40107D的返回地址被修改了，它将跳转到代码的其他地方。

为了检查它会跳转到哪里，返回来看一下sub_401065:

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/21.jpg)

原始的返回地址是0x401074。但是你知道它被增加了0x2B。所以`sub_40107D`将会返回到0x40109F(0x401074+0x2B)。切换到下一个视图找到这个返回地址的位置。

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/22.jpg)

一点也不意外返回地址的位置出现了花指令，按U转换成数据，然后在0x40109F的位置按C再转成代码：

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/23.jpg)

我们看到了最终EAX的值是0xC0DE！

总结一下，通过刚才分析，我们学习到了一种比较流行的反-反汇编技术叫做返回地址替换。因为恶意代码欺骗了IDA，将调用函数中的返回地址替换掉了，导致IDA解析出来的返回地址并不是它原版真实的返回地址。

## 4)  分析sub_4010B2函数

现在我们来看一个不完整的sub_4010B2函数

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/24.jpg)

中间代码忽略

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/25.jpg)

如果你进入到这个函数看反汇编代码，你将看到很多的反汇编代码在用各种指令来操作EAX寄存器。尽管如此，如果你仔细看就会发现，有一些组合指令都在执行一些无意义的操作。

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/26.jpg)

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/27.jpg)

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/28.jpg)

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/29.jpg)

这是一种比较简单的混淆技术，这些被嵌入在正常代码中间的花指令除了让手动分析变得更难以外，对程序的执行流程不会有任何影响。

处理这种花指令的唯一方法就是在它们当中找到规律，如果你找到了花指令的规律，你才可以尝试编写脚本来用NOP指令来覆盖这些花指令，或者使用某种颜色来高亮它们。但是编写脚本不在本篇教程范围之内。

如果你再仔细分析一下这些花指令，你会发现只有3条指令会映像最终EAX的值：

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/30.jpg)

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/31.jpg)

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/32.jpg)

这表示最终EAX的值是0x1500。

## 5)  分析sub_40116D函数

最后一个要分析的函数是sub_40116D.

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/33.jpg)

在这个程序中EAX的返回值看上去是0xEBFE。即使如此，你应该马上能注意到

`MOV FS:0,ESP`这条指令告诉我们它正在安装一个SHE（标准化异常处理程序）。

异常处理程序被保存成一个单向链表结构，每个节点是`EXCEPTION_REGISTRATION`的结构：

	_EXCEPTION_REGISTRATION struc
	
	prev     dd ?
	
	handler dd ?
	
	_EXCEPTION_REGISTRATION ends

这个结构由两个字段组成，第一个字段prev是指向下一个`EXCEPTION_REGISTRATION`结构的指针，第二个字段handler指向异常处理函数。

指向第一个`EXCEPTION_REGISTRATION`结构永远被保存在TIB的第一个DWORD字节中。在Win32平台TIB的地址被保存在FS寄存器中，因此指向MOV FS:0,ESP这条指令等于把栈顶的保存的值，设置成了第一个异常处理结构`EXCEPTION_REGISTRATION`。

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/34.jpg)

在sub_40116D这个函数中，栈的结构应该是这样的（安装SHE之后）：

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/35.jpg)

那么问题来了，在这个函数中是否有异常被触发了？答案是肯定的，先来看看ECX寄存器，它被设置成0了，然后程序尝试写入一个DWORD到ECX保存的地址。因为ECX指向了一个未申请内存地址0x00000000，所以一定会触发非法内存访问异常(`STATUS_ACCESS_VIOLATION-0xC0000005`)。

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/36.jpg)

但是异常处理函数的地址是多少呢？在这个例子中，你看到0x15232A1被push到栈上了，但是它并不是一个有效的函数地址。注意上图中的XOR指令将0x1122300与异常处理函数的地址异或。表示真正的地址是0x15232A1 xor 0x1122300 = 0x4011A1

你也可以使用IDA中的计算器来计算，（View->Calculator 或者按下SHIFT+/键）:

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/40.jpg)

现在切换视图到0x4011A1的位置：

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/38.jpg)

重复我们之前的套路，把0x4011A1位置的数据转换成代码：

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/junk_code/39.jpg)

你可以看到EAX被赋值了0x512，其他指令只是恢复栈帧并跳转到sub_40116D的函数尾部。

总结一下，在这个函数中我们学到了使用SEH来改变程序的执行流程。SHE通常用来反-反汇编和反调试技术。另外异常处理程序的地址也被XOR混淆了。









