32位程序调用64位函数

首先，先从宏观分析一下，32位程序的运行需要软硬件两个大方面的支持：

1）硬件上，CPU的解码模式需要是32位模式。64位CPU（我只熟悉INTEL的）是通过GDT表中CS段所对应的表项中L标志位来确定当前解码模式的。这里不展开描述GDT表与CPU运行模式的关系

2）软件上，操作系统需要提供32位的用户态运行时环境（C库，WINDOWS API）对32位程序支持，其次因为win64内核是64位模式的，所以32位运行时环境在与64位内核交互时需要有状态转换。

## 1.模式切换

参考看雪文章[https://bbs.pediy.com/thread-221236.htm](https://bbs.pediy.com/thread-221236.htm)

32位模式切换为64位模式 借助retf将CS寄存器从0x23设置为0x33。

```c
push 0x33     // cs = 0x33
call L1   
L1: 
add [esp], 5
retf    	 // far ret，切换CPU状态

/*此时CPU处于64位模式*/

```


```c
call L2: 
L2:
mov [esp + 4], 0x23    	  // cs = 0x23
add [esp], 0xd     
retf

/*此时CPU处于32位模式*/

```

retf 远返回指令。当它执行时，处理器先从栈中弹出一个字到IP，再弹出一个字到CS。

$表示当前地址,call $+5表示,调用用 本地址+5字节后的 子程序

## 2.查找目标函数地址

思想是 目标函数从动态库（ntdll）中获得，我们需要从LDR中匹配动态库，LDR可以在PEB中找到，PEB可以在TEB中找到，WOW64进程中的R12寄存器指向其64位的TEB结构（线程环境块），所以TEB可以通过R12寄存器获得。

找到模块基地址以后，我们就可以通过PE文件结构去获得我们需要的函数了

具体实现参考这里[https://sirhc.gitbook.io/note/windows_operating_system/windows-xia-tong-yong-shellcode-yuan-li](https://sirhc.gitbook.io/note/windows_operating_system/windows-xia-tong-yong-shellcode-yuan-li),只是PE文件从32到32+，要做部分修改。

## 3.自实现传参

我们得到函数地址以后，不能直接调用 
需要通过X64Call执行。 X64调用约定前4个参数通过rcx,rdx,r8,r9来传递，之后通过堆栈传递。











