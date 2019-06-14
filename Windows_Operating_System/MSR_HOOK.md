32 位下 HOOk SYSENTER 实现进程保护。

OpenProcess的调用过程如下：

 **kernel32.OpenProcess -> kernelBa.OpenProcess -> ntdll.ZwOpenProcess -> ntdll.KiFastSystemCall ->(Ring0) _KiFastCallEntry -> (Ring0)NtOpenProcess**

ZwOpenProcess中的代码如下:

```c
mov eax,0xeb  //调用号
mov edx,KUSER_SHARED_SYSCALL 
// cpu初始化时，根据架构不同，KUSER_SHARED_SYSCALL里面的实现的内核函数指针接口也不同,可能是 KiIntSystemCall中断式系统调用 也可能是 KiFastSystemCall快速系统调用
call [edx]
ret 0x10

```
这里edx保存的是KiFastSystemCall函数，继续跟进KiFastSystemCall函数

```c
mov edx,esp
sysenter 
retn

```

简单的三条指令，mov edx,esp 因为下一条指令SYSENTER就是进入内核层，由于每个线程都有一套线程上下文，都有一个独立的栈.。进入到内核后，内核也会使用自己的内核栈，所以这里先用edx保存栈顶esp。

SYSENTER 执行的时候，会读取三个特殊寄存器,从这三个特殊寄存器中取出内核栈的栈顶( esp ) ，内核代码段段选择子( cs ) ，以及代码的首地址( eip )，保存这三个值得寄存器是MSR寄存器组。这组寄存器没有名字，只有编号，由于没有名字，无法通过正常的汇编指令来存取值，Intel提供了两条指令来读写这些寄存器:

* rdmsr 读取MSR寄存器 其中高32位存放在EDX 低32位存放在EAX(64位和32位是一样，只是64位时rdx和rcx的高32位会被清零),使用ECX传递寄存器编号
* wrmsr 写入MSR寄存器，和读取一样写入时是用EDX表示高32位,EAX表示低32位，使用ECX传递寄存器编号

也就是说, Windows在启动,进行初始化的时候会将内核栈栈顶,内核CS段选择子,以及代码段地址（KiFastCallEntry 函数）的地址一一存放到MSR寄存器组的这几个编号的寄存器中。当 SYSENTER 被执行,，CPU就直接使用这些寄存器的值来初始化真正的CS , EIP , ESP 寄存器。因此, SYSENTER 执行之后, 就跑到内核的 KiFastCallEntry 函数中执行代码了。

 
而进行SYSENTER-HOOK时我们只需要关注代码的地址( SYSENTER_EIP_MSR )即可，它的编号是0x176。用类似于3环的Inline-Hook的方法，直接把该地址改为我们自己的函数地址，过滤检查传入的参数，这样就能实现HOOK保护进程了。具体用法如下：

```
#include <ntddk.h>


ULONG OldAddr;
VOID DriverUnload(PDRIVER_OBJECT pDriver_Object);
VOID OnHook();
UINT32 g_Pid = 2652;

void _declspec(naked) MyKiFastCallEntry()  //过滤参数
{
	__asm
	{
		cmp eax, 0xbe;//对比是否是NtOpenProcess的调用号
		jne _End;     //不是则不处理
		push eax;     //保存寄存器
		mov eax, [edx + 0x14];//获取第4个参数PCLIENT_ID
		mov eax, [eax];//获取PCLIENT_ID第一个字段PID
		//PCLIENT_ID->UniqueProcess的值       
		cmp eax, g_Pid;//判断是否是要保护的进程
		pop eax;
		jne _End;
		cmp[edx + 0xc], 1;//判断是否是关闭操作
		jne _End;
		mov[edx + 0xc], 0;//是就把访问权限设为无
	_End:
		jmp OldAddr;//调用原来的_KiFastCallEntry函数
	}
}

VOID OnHook(){
	KAFFINITY ActiveProcessors, CurrentAffinity;
	ActiveProcessors = KeQueryActiveProcessors();
	for (CurrentAffinity = 1; ActiveProcessors; CurrentAffinity <<= 1)  //考虑多核同步下，msr逻辑分离，所以修改每个内核的msr
	{
		if (ActiveProcessors & CurrentAffinity)
		{
			ActiveProcessors &= ~CurrentAffinity;
			KeSetSystemAffinityThread(CurrentAffinity);
			_asm
			{
				cli      // 锁，防止中断
					push ecx
					push eax
					mov ecx, 0x176
					rdmsr
					mov OldAddr, eax //保存原来的 SYSENTER_EIP_MSR中的_KiFastCallEntry
					xor eax, eax
					mov eax, MyKiFastCallEntry // 将 SYSENTER_EIP_MSR寄存器的值设置为我们的过滤函数
					wrmsr
					xor eax, eax
					xor ecx, ecx
					pop eax
					pop ecx
					sti
			}
		}
	}
	DbgPrint("NewKiFastCallEntry Addr:%08x\n", MyKiFastCallEntry);
	
}


VOID DriverUnload(PDRIVER_OBJECT pDriver_Object)  //恢复HOOK
{
	KAFFINITY ActiveProcessors, CurrentAffinity;
	ActiveProcessors = KeQueryActiveProcessors();
	for (CurrentAffinity = 1; ActiveProcessors; CurrentAffinity <<= 1)
	{
		if (ActiveProcessors & CurrentAffinity)
		{
			ActiveProcessors &= ~CurrentAffinity;
			KeSetSystemAffinityThread(CurrentAffinity);
			_asm
			{
				cli
					push ecx
					push eax
					mov ecx, 0x176
					mov eax, OldAddr
					wrmsr
					xor ecx, ecx
					xor eax, eax
					pop eax
					pop ecx
					sti
			}
		}
	}
	DbgPrint("驱动卸载成功\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver_Object, PUNICODE_STRING pRegstryString)
{
	OnHook();
	pDriver_Object->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;

}
```