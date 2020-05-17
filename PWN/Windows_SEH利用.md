>windows栈溢出部分关于SEH的利用
>（本文不探究safeSEH相关机制，不绕过safeSEH机制对SEH异常处理函数指针的检查，也就是不讨论覆盖SEH函数指针的情况；而是去绕过`__except_handler4`异常处理函数内部的检测，实现伪造`__except`或`__finally`函数）

先看一个编译好的程序main函数入口处代码。SEH 的使用范围是线程相关的，每个线程都有自己的函数（SEH链表是局部链表，在堆栈中）

```python

.text:004010B0                 push    ebp
.text:004010B1                 mov     ebp, esp
.text:004010B3                 push    0FFFFFFFEh      // ebp-4
.text:004010B5                 push    offset _EH4_SCOPETABLE_addr // ebp-8 
.text:004010BA                 push    offset __except_handler4 // ebp-c
.text:004010BF                 mov     eax, large fs:0
.text:004010C5                 push    eax             // ebp-10
.text:004010C6                 add     esp, 0FFFFFF40h
.text:004010CC                 mov     eax, ___security_cookie
.text:004010D1                 xor     [ebp-8], eax // 加密scopeTable
.text:004010D4                 xor     eax, ebp
.text:004010D6                 mov     [ebp-1Ch], eax // 放入GS
.text:004010D9                 push    ebx
.text:004010DA                 push    esi
.text:004010DB                 push    edi
.text:004010DC                 push    eax
.text:004010DD                 lea     eax, [ebp-10h]
.text:004010E0                 mov     large fs:0, eax

```

先看`push    offset _EH4_SCOPETABLE_addr`这条指令，在main函数入口处被压入栈中。`_EH4_SCOPETABLE`为SEH的scope table结构，它保存了**当前函数**中`__try`块相匹配的 `__except` 或 `__finally`的地址值.

`_EH4_SCOPETABLE`通常被保存在程序的.rdata段。

```python
.rdata:00403688 _EH4_SCOPETABLE_addr dd 0FFFFFFE4h           ; GSCookieOffset
.rdata:00403688                                         ; DATA XREF: _main+5↑o
.rdata:00403688                 dd 0                    ; GSCookieXOROffset ; SEH scope table for function 4010B0
.rdata:00403688                 dd 0FFFFFF20h           ; EHCookieOffset
.rdata:00403688                 dd 0                    ; EHCookieXOROffset
.rdata:00403688                 dd 0FFFFFFFEh           ; ScopeRecord.EnclosingLevel
.rdata:00403688                 dd offset loc_401348    ; ScopeRecord.FilterFunc
.rdata:00403688                 dd offset loc_40134E    ; ScopeRecord.HandlerFunc
.rdata:004036A4                 align 8

```

细看`_EH4_SCOPETABLE`，它的C结构如下：

```c
struct _EH4_SCOPETABLE {
        DWORD GSCookieOffset;
        DWORD GSCookieXOROffset;
        DWORD EHCookieOffset;
        DWORD EHCookieXOROffset;
        _EH4_SCOPETABLE_RECORD ScopeRecord[1];
};

struct _EH4_SCOPETABLE_RECORD {
        DWORD EnclosingLevel;
        long (*FilterFunc)();
            union {
            void (*HandlerAddress)();
            void (*FinallyFunc)(); 
    };
};


```

其中`FilterFunc`与`FinallyFunc`就是我们自定义的`__except` 或 `__finally`函数的地址。


紧接着下面三条指令，作用是在栈中为当前线程添加异常处理。

```python
 push    offset __except_handler4 // ebp-c
 mov     eax, large fs:0
 push    eax  // ebp-0x10

 ......

 lea     eax, [ebp-10h]
 mov     large fs:0, eax

```

**科普**：

1.TIB结构
TIB，又称线程信息块，是保存线程基本信息的数据结构，它位于TEB的头部。TEB是操作系统为了保存每个线程的私有数据创建的，每个线程都有自己的TEB。

TIB结构如下：

```c
typedef struct _NT_TIB{
    struct _EXCEPTION_REGISTRATION_RECORD *Exceptionlist;//指向异常处理链表
    PVOID StackBase;//当前进程所使用的栈的栈底
    PVOID StackLimit;//当前进程所使用的栈的栈顶
    PVOID SubSystemTib;
    union {
        PVOID FiberData;
        ULONG Version;
    };
    PVOID ArbitraryUserPointer;
    struct _NT_TIB *Self;//指向TIB结构自身
} NT_TIB;

```

在这个结构中与异常处理有关的第一个成员：指向`_EXCEPTION_REGISTRATION_RECORD`结构的Exceptionlist指针

2.`EXCEPTION_REGISTRATION_RECORD` 结构

该结构主要用于描述线程异常处理过程的地址，多个该结构的链表描述了多个线程异常处理过程的嵌套层次关系

结构如下：

```c
typedef struct _EXCEPTION_REGISTRATION_RECORD{
    struct _EXCEPTION_REGISTRATION_RECORD *Next;//指向下一个结构的指针
    PEXCEPTION_ROUTINE Handler;//当前异常处理回调函数的地址
}EXCEPTION_REGISTRATION_RECORD;
```

结构如图所示：

![异常处理过程](https://s2.ax1x.com/2019/10/09/uI9Auq.png)

>fs寄存器指向TEB结构

所以 上面`lea eax, [ebp-10h]`与`mov large fs:0, eax`指令也就是在栈中插入一个SEH异常处理结构体到TIB顶部, `__except_handler4`就是添加的系统默认异常处理回调函数，当发生异常时会首先执行它。

我们跟进`__except_handler4`中


```c
int __cdecl _except_handler4(int a1, int a2, int a3, int a4)
{
  return except_handler4_common((int)&__security_cookie, (int)__security_check_cookie, a1, a2, a3, a4);
}


```

里面又嵌套调用了`except_handler4_common`函数

```c

void __cdecl ValidateLocalCookies(void (__fastcall *cookieCheckFunction)(unsigned int), _EH4_SCOPETABLE *scopeTable, char *framePointer)
{
    unsigned int v3; // esi@2
    unsigned int v4; // esi@3

    if ( scopeTable->GSCookieOffset != -2 )
    {
        v3 = *(_DWORD *)&framePointer[scopeTable->GSCookieOffset] ^ (unsigned int)&framePointer[scopeTable->GSCookieXOROffset];
        __guard_check_icall_fptr(cookieCheckFunction);
        ((void (__thiscall *)(_DWORD))cookieCheckFunction)(v3);
    }
    v4 = *(_DWORD *)&framePointer[scopeTable->EHCookieOffset] ^ (unsigned int)&framePointer[scopeTable->EHCookieXOROffset];
    __guard_check_icall_fptr(cookieCheckFunction);
    ((void (__thiscall *)(_DWORD))cookieCheckFunction)(v4);
}

int __cdecl _except_handler4_common(unsigned int *securityCookies, void (__fastcall *cookieCheckFunction)(unsigned int), _EXCEPTION_RECORD *exceptionRecord, unsigned __int32 sehFrame, _CONTEXT *context)
{
    // 异或解密 scope table
    scopeTable_1 = (_EH4_SCOPETABLE *)(*securityCookies ^ *(_DWORD *)(sehFrame + 8));

    // sehFrame 等于 主函数 ebp - 10h 位置, framePointer 等于主函数 ebp 的位置
    framePointer = (char *)(sehFrame + 16);
    scopeTable = scopeTable_1;

    // 验证 GS
    ValidateLocalCookies(cookieCheckFunction, scopeTable_1, (char *)(sehFrame + 16));
    __except_validate_context_record(context);

    if ( exceptionRecord->ExceptionFlags & 0x66 )
    {
        ......
    }
    else
    {
        exceptionPointers.ExceptionRecord = exceptionRecord;
        exceptionPointers.ContextRecord = context;
        tryLevel = *(_DWORD *)(sehFrame + 12);
        *(_DWORD *)(sehFrame - 4) = &exceptionPointers;
        if ( tryLevel != -2 )
        {
            while ( 1 )
            {
                v8 = tryLevel + 2 * (tryLevel + 2);
                filterFunc = (int (__fastcall *)(_DWORD, _DWORD))*(&scopeTable_1->GSCookieXOROffset + v8);
                scopeTableRecord = (_EH4_SCOPETABLE_RECORD *)((char *)scopeTable_1 + 4 * v8);
                encloseingLevel = scopeTableRecord->EnclosingLevel;
                scopeTableRecord_1 = scopeTableRecord;
                if ( filterFunc )
                {
                    // 调用 FilterFunc
                    filterFuncRet = _EH4_CallFilterFunc(filterFunc);
                    ......
                    if ( filterFuncRet > 0 )
                    {
                        ......
                        // 调用 FilterFunc
                        _EH4_TransferToHandler(scopeTableRecord_1->HandlerFunc, v5 + 16);
                        ......
                    }
                }
                ......
                tryLevel = encloseingLevel;
                if ( encloseingLevel == -2 )
                    break;
                scopeTable_1 = scopeTable;
            }
            ......
        }
    }
  ......
}

```


里面会检查栈中放入的GS值，会根据securityCookies解密`_EH4_SCOPETABLE`的地址,最终会调用到`_EH4_SCOPETABLE`里面的FilterFunc与FilterFunc函数，也就是我们自定义的`__except` 或 `__finally`函数的地址。

如果我们能够查询伪造一个`_EH4_SCOPETABLE`结构，里面的FilterFunc函数指针写成自己的，其他字段不改变，覆盖栈中的`_EH4_SCOPETABLE_addr`为伪造地址，就能实现任意地址函数调用。

不过由于

```python
mov     eax, ___security_cookie  
xor     [ebp-8], eax
``` 

指令中的[ebp-8]是`_EH4_SCOPETABLE_addr`, 所以我们还需要计算`new_EH4_SCOPETABLE_addr=fake__EH4_SCOPETABLE_addr ^ ___security_cookie`才行，`___security_cookie`的实际值需要leak。

由于

```python
mov     eax, ___security_cookie
xor     eax, ebp
mov     [ebp-1Ch], eax  //GS

```

覆盖存入栈ebp-0x1c的GS值时也应该注意这点， 也需要先leak出ebp与`___security_cookie`值后 再计算`new_GS=___security_cookie ^ ebp`的值 再进行覆盖。

所以要实现这种SEH利用，要泄露的地方其实挺多的。