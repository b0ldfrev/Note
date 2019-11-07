由 SSDT HOOk 实现的进程保护框架

```c
#include <ntddk.h>
#include<ntstatus.h>

//1.找到系统服务表的函数地址表

//定义一个全局变量用来存放之前的NtOpenProcess地址
ULONG uOldNtOpenProcess;


//有了地址还需要一个函数NtOpenProcess指针，用于调用原来的NtOpenProcess
typedef NTSTATUS(*NTOPENPROCESS)(
    __out PHANDLE  ProcessHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in POBJECT_ATTRIBUTES  ObjectAttributes,
    __in_opt PCLIENT_ID  ClientId
    );

typedef struct _KSYSTEM_SERVICE_TABLE
{
    PULONG  ServiceTableBase;               // SSDT (System Service Dispatch Table)的基地址 
    PULONG  ServiceCounterTableBase;        // 用于 checked builds, 包含 SSDT 中每个服务被调用的次数
    ULONG   NumberOfService;               // 服务函数的个数, NumberOfService * 4 就是整个地址表的大小  
    PULONG   ParamTableBase;               // SSPT(System Service Parameter Table)的基地址  
} KSYSTEM_SERVICE_TABLE, *PKSYSTEM_SERVICE_TABLE;

typedef struct _KSERVICE_TABLE_DESCRIPTOR
{
    KSYSTEM_SERVICE_TABLE   ntoskrnl;                       // ntoskrnl.exe 的服务函数  
    KSYSTEM_SERVICE_TABLE   win32k;                         // win32k.sys 的服务函数(GDI32.dll/User32.dll 的内核支持)  
    KSYSTEM_SERVICE_TABLE   notUsed1;
    KSYSTEM_SERVICE_TABLE   notUsed2;
}KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;


//导出由 ntoskrnl所导出的 SSDT
extern PKSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTable;//这个是导出的，要到内核文件找，所以名字不能瞎起

//准备用于替换的函数
NTSTATUS NTAPI MyNtOpenProcess(__out PHANDLE  ProcessHandle,
    __in ACCESS_MASK  DesiredAccess,
    __in POBJECT_ATTRIBUTES  ObjectAttributes,
    __in_opt PCLIENT_ID  ClientId
)
{
    NTSTATUS Status;
    Status = STATUS_SUCCESS;
    if (ClientId->UniqueProcess == (HANDLE)916)//指定保护的进程ID
        {
            return STATUS_ABANDONED;
        }
    //打开原来的函数，因为这个函数也要实现原来的功能，不然就乱套了，除非你自己在自己业务里实现了
    return ((NTOPENPROCESS)uOldNtOpenProcess)(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

void PageProtectOff() {

    __asm { //关闭内存保护
        push eax;
        mov eax, cr0;
        and eax, ~0x10000;
        mov cr0, eax;
        pop eax;
    }
}

void PageProtectOn() {

    __asm { //恢复内存保护
        push eax;
        mov eax, cr0;
        or eax, 0x10000;
        mov cr0, eax;
        pop eax;
    }
}

//3.修改函数地址,准备个函数用来修改函数地址
void HookNtOpenProcess() {
    NTSTATUS Status;
    Status = STATUS_SUCCESS;
    PageProtectOff();
    uOldNtOpenProcess = KeServiceDescriptorTable->ntoskrnl.ServiceTableBase[0xBE];
    KeServiceDescriptorTable->ntoskrnl.ServiceTableBase[0xBE] = (ULONG)MyNtOpenProcess;
    PageProtectOn();
}

//4.恢复
void UnHookNtOpenProcess() {
    PageProtectOff();
    KeServiceDescriptorTable->ntoskrnl.ServiceTableBase[0xBE] = (ULONG)uOldNtOpenProcess;
    PageProtectOn();
}

VOID DriverUnload(PDRIVER_OBJECT pDriver) {
    UNREFERENCED_PARAMETER(pDriver);
    UnHookNtOpenProcess();

    KdPrint(("My Dirver is unloading..."));

}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pPath) {
    UNREFERENCED_PARAMETER(pPath);
    KdPrint(("->%x \n", KeServiceDescriptorTable->ntoskrnl.ServiceTableBase[0xBE]));//得到函数地址表

    HookNtOpenProcess();

    pDriver->DriverUnload = DriverUnload;
    return STATUS_SUCCESS;
}

```


参见[进程隐藏与进程保护（SSDT Hook 实现）](https://www.cnblogs.com/DuanLaoYe/p/5476950.html)