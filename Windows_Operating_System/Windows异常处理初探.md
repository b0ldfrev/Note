>by Knocked 看雪

异常机制，就是为了让计算机能够更好的处理程序运行期间产生的错误，从编程的角度来看，能够将错误的处理与程序的逻辑分隔开。使得我们可以集中精力开发关键功能，而把程序可能出现的异常统一管理。
 
Windows提供了异常处理的机制，使得你有机会挽救自己即将崩溃的程序，大体上来说它提供了以下处理异常的机制：
* SEH-结构化异常处理
* VEH-向量化异常处理
* VCH-向量化异常处理


## 结构化异常处理

Structed Exception Handler(结构化异常处理)简称SEH，是微软提供的一种处理异常的机制。
 
在VC++中，通过提供四个微软关键字使得程序员能够良好的使用这一机制，分别是：
 
__try、 __finally、 __except、 __leave
 
接下来简要说明一下用法。


#### 终结处理器

由 __try、 __finally 和 __leave构成。能够保证无论 __try 块中的指令以何种方式退出，都必然会执行 __finally 块。[不会进行异常处理，只进行清理操作]
 
SEH 的使用范围是线程相关的，每个线程都有自己的函数（SEH链表是局部链表，在堆栈中）

```c
__try
{
    // 被检查的代码块，通常是程序的逻辑部分
    printf("__try { ... }\n");
 
    // 使用 __leave 跳出当前的 __try
    __leave;
}
__finally
{
    // 终结处理块，通常用于清理当前程序
    // 无论 __try 以何种方式退出，都会执行这里的指令
    printf("__finally { ... }\n");
 
    // 使用 AbnormalTermination 判断 __try 的退出方式
    // 正常退出，返回值是 false
    if (AbnormalTermination())
        printf("异常退出\n");
    else
        printf("正常退出\n");
}

```

执行结果

```
__try { ... }
__finally { ... }
正常退出

```

使用 goto 退出（return 、 break 同理）：

```c
__try
{
    printf("__try { ... }\n");
    goto tag;
}
__finally
{
    printf("__finally { ... }\n");
    if (AbnormalTermination())
        printf("异常退出\n");
    else
        printf("正常退出\n");
}
tag:
return 0;

```



执行结果

```
__try { ... }
__finally { ... }
异常退出

```


#### 异常处理器

由关键字 __try 、 __except 构成，能够保证 __try 中如果产生了异常，会执行过滤表达式中的内容，应该在过滤表达式提供的过滤函数中处理想要处理的异常

* EXCEPTION_EXECUTE_HANDLER(1)：表示该异常被处理，从异常处下一条指令继续执行
* EXCEPTION_CONTINUE_SEARCH(0)：表示异常不能被处理，交给下一个SEH
* EXCEPTION_CONTINUE_EXECUTION(-1)：表示异常被忽略，从异常处继续执行


```c
// 异常处理器: 由关键字 __try 和 __except 构成
// 如果 __try 中产生了异常，会执行过滤表达式中的内容
// 应该在过滤表达式提供的过滤函数中处理想要处理的异常
 
// 异常过滤表达式中最常见的情况就是编写一个异常过滤函数，对异常进行处理
DWORD ExceptionFilter(DWORD ExceptionCode, PEXCEPTION_POINTERS ExceptionInfo)
{
    printf("ExceptionCode: %X\n", ExceptionCode);
 
    // 如果当前产生的异常是除零异常，那么就通过修改寄存器处理异常
    if (ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO)
    {
        // 在这里对寄存器执行的所有修改都会直接被应用到程序中
        ExceptionInfo->ContextRecord->Eax = 1;
        ExceptionInfo->ContextRecord->Ecx = 1;
 
        // 如果异常被处理了，那么就返回重新执行当前的代码
        return EXCEPTION_CONTINUE_EXECUTION;
    }
 
    // 如果不是自己能够处理的异常，就不处理只报告
    return EXCEPTION_EXECUTE_HANDLER;
}
 
int main()
{
    int number = 0;
 
    __try
    {
        // __try 中的是可能产生异常的代码
        // idiv eax, ecx
        number /= 0;
    }
 
    // 通常会为异常过滤表达式提供一个异常处理函数用于处理异常，并返回处理结果
    // GetExceptionCode: 用于获取异常的类型，能在过滤表达式和异常处理器中使用
    // GetExceptionInformation: 用于获取异常的信息，只能写在过滤表达式中
 
    // 异常过滤表达式
    __except (ExceptionFilter(GetExceptionCode(), GetExceptionInformation()))
    {
        // 异常处理器，只有 __except 返回 EXCEPTION_EXECUTE_HANDLER 才会执行
        printf("__try 中产生了异常，但是并没有处理异常 %X\n", GetExceptionCode());
    }
 
    printf("numebr = %d\n", number);
 
    return 0;
}

```

执行结果

```
ExceptionCode: C0000094
numebr = 1

```

## 顶层异常处理器

TopLevelEH 全称顶层异常处理器(UEF)，这个函数只能有一个，被保存在全局变量中。
 
由于只会被系统默认的最底层 SEH 调用，所以又会被称作是 SEH 的一种，是整个异常处理的最后一环。所以通常都不会再此执行异常处理操作，而是进行内存 dump ，将消息发送给服务器，进行异常分析。
 
在 win7 之后，只有在非调试模式下才会被调用，可以用来反调试。

```c
LONG WINAPI TopLevelExceptionFilter(PEXCEPTION_POINTERS ExceptionInfo)
{
    printf("ExceptionCode: %X\n", ExceptionInfo->ExceptionRecord->ExceptionCode);
 
    // 如果当前的异常是除零异常，那么就通过修改寄存器处理异常
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO)
    {
        ExceptionInfo->ContextRecord->Eax = 1;
        ExceptionInfo->ContextRecord->Ecx = 1;
 
        // 异常如果被处理了，那么就返回重新执行当前的代码
        return EXCEPTION_CONTINUE_EXECUTION;
    }
 
    // 如果不是自己能够处理的异常，就不处理只报告
    return EXCEPTION_EXECUTE_HANDLER;
}
 
 
int main()
{
    int number = 0;
 
    // 通过一个函数可以直接的安装 UEF
    SetUnhandledExceptionFilter(TopLevelExceptionFilter);
 
    __try
    {
        number /= 0;
    }
    // 异常一旦被 SEH 处理，就不会再传递给 UEF
    __except (EXCEPTION_CONTINUE_SEARCH)
    {
        printf("不会被执行\n");
    }
 
    printf("number = %d\n", number);
 
    system("pause");
    return 0;
}

```


执行结果

```
ExceptionCode: C0000094
numebr = 1

```

## 向量化异常处理


#### 向量异常VEH

Vectored Exception Handler 向量化异常处理的一种，被保存在一个全局的链表中，进程内的所有线程都可以使用这个函数，是第一个处理异常的函数。

```c
LONG WINAPI VectoredExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    printf("ExceptionCode: %X\n", ExceptionInfo->ExceptionRecord->ExceptionCode);
 
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO)
    {
        ExceptionInfo->ContextRecord->Eax = 1;
        ExceptionInfo->ContextRecord->Ecx = 1;
 
        return EXCEPTION_CONTINUE_EXECUTION;
    }
 
    return EXCEPTION_EXECUTE_HANDLER;
}
 
int main()
{
    int number = 0;
 
    // 通过一个API可以直接安装VEH
    // 参数一是布尔值，如果为 TRUE，就将当前的函数添加到全局 VEH 函数的链表头部
    // 否则则为尾部
    AddVectoredExceptionHandler(TRUE, VectoredExceptionHandler);
 
    __try
    {
        number /= 0;
    }
    // 异常首先被 VEH 接收到，如果无法处理才会传递给 SEH
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        printf("永远不会被执行\n");
    }
 
    printf("number = %d\n", number);
 
    system("pause");
    return 0;
}

```

执行结果

```
ExceptionCode: C0000094
numebr = 1

```

#### 向量化异常处理VCH

VCH：和 VEH 类似，但是只会在异常被处理的情况下最后调用。

## 异常的传递过程

```c
LONG WINAPI VectoredExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo)
{
    printf("VEH: ExceptionCode: %X\n", ExceptionInfo->ExceptionRecord->ExceptionCode);
 
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO)
    {
        ExceptionInfo->ContextRecord->Eax = 1;
        ExceptionInfo->ContextRecord->Ecx = 1;
 
        return EXCEPTION_CONTINUE_SEARCH;
    }
 
    return EXCEPTION_EXECUTE_HANDLER;
}
 
DWORD StructedExceptionFilter(PEXCEPTION_POINTERS ExceptionInfo)
{
    printf("SEH: ExceptionCode: %X\n", ExceptionInfo->ExceptionRecord->ExceptionCode);
 
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO)
    {
        ExceptionInfo->ContextRecord->Eax++;
        ExceptionInfo->ContextRecord->Ecx = 1;
 
        return EXCEPTION_CONTINUE_SEARCH;
    }
 
    return EXCEPTION_EXECUTE_HANDLER;
}
 
LONG WINAPI TopLevelExceptionFilter(PEXCEPTION_POINTERS ExceptionInfo)
{
    printf("UEF: ExceptionCode: %X\n", ExceptionInfo->ExceptionRecord->ExceptionCode);
 
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO)
    {
        ExceptionInfo->ContextRecord->Eax++;
        ExceptionInfo->ContextRecord->Ecx = 1;
 
        return EXCEPTION_CONTINUE_EXECUTION;
    }
 
    return EXCEPTION_EXECUTE_HANDLER;
}
 
LONG WINAPI VectoredContinueHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    // VCH 不会对异常进行处理，调用的时机和异常处理的情况有关
    printf("VCH: ExceptionCode: %X\n", ExceptionInfo->ExceptionRecord->ExceptionCode);
 
    return EXCEPTION_CONTINUE_SEARCH;
}
 
int main()
{
    int number = 0;
 
    AddVectoredExceptionHandler(TRUE, VectoredExceptionHandler);
    AddVectoredContinueHandler(TRUE, VectoredContinueHandler);
    SetUnhandledExceptionFilter(TopLevelExceptionFilter);
 
    __try
    {
        number /= 0;
    }
    __except (StructedExceptionFilter(GetExceptionInformation()))
    {
        printf("SEH: 异常处理器\n");
    }
 
    printf("number = %d\n", number);
 
    system("pause");
    return 0;
}

```


执行结果

```
VEH: ExceptionCode: C0000094
SEH: ExceptionCode: C0000094
UEF: ExceptionCode: C0000094
VCH: ExceptionCode: C0000094
number = 3

```

可以得出，异常的传递过程：VEH -> SEH -> UEH -> VCH


## 探究SEH


```c
// 带有异常处理函数的函数
void test1()
{
    // 在 VS 的同一个函数中无论编写了多少个 SEH， 编译器
    // 实际上只会安装一个叫做 except_handler4 的函数
    __try
    {
        printf("__try { ... }\n");
        __try
        {
            printf("__try { ... }\n");
        }
        __except (1)
        {
            printf("__except (1) { ... }\n");
        }
    }
    __except (1)
    {
        printf("__except (1) { ... }\n");
    }
}
 
// 没有异常处理函数的函数
void test2() { }
 
// 遍历当前程序中已经存在的异常处理函数
void ShowSEH()
{
    // 定义一个结构体指针，用于保存 SEH 链表的头节点
    PEXCEPTION_REGISTRATION_RECORD header = nullptr;
 
    // 通过 FS:[0] 找到 ExceptionList 的头节点
    __asm push fs:[0]
    __asm pop header
 
    // 遍历异常处理链表，链表以 -1 结尾
    while (header != (EXCEPTION_REGISTRATION_RECORD*)-1)
    {
        printf("function: %08X\n", header->Handler);
        header = header->Next;
    }
 
    printf("\n");
}
 
EXCEPTION_DISPOSITION NTAPI ExceptionRoutine(
    // 产生的异常信息
    _Inout_ struct _EXCEPTION_RECORD* ExceptionRecord,
    _In_ PVOID EstablisherFrame,
    // 产生异常时的线程上下文
    _Inout_ struct _CONTEXT* ContextRecord,
    _In_ PVOID DispatcherContext
)
{
    printf("自定义SEH: ExceptionCode: %X\n", ExceptionRecord->ExceptionCode);
 
    if (EXCEPTION_INT_DIVIDE_BY_ZERO == ExceptionRecord->ExceptionCode)
    {
        ContextRecord->Eax = 1;
        ContextRecord->Ecx = 1;
 
        return ExceptionContinueExecution;
    }
 
    return ExceptionContinueSearch;
}
 
int main()
{
    test1();
    test2();
 
    PEXCEPTION_REGISTRATION_RECORD ExceptionList = nullptr;
 
    __asm push fs : [0]
    __asm pop ExceptionList
 
    // 遍历异常处理函数
    ShowSEH();
 
    // 手动安装一个异常处理函数，操作 FS:[0]
    __asm push ExceptionRoutine
    __asm push fs : [0]
    __asm mov fs : [0], esp
 
    ShowSEH();
 
    int number = 0;
    number /= 0;
 
    printf("\n");
 
    __asm mov eax, ExceptionList
    __asm mov fs : [0], eax
    __asm add esp, 0x08
 
    ShowSEH();
 
    return 0;
}
```

执行结果

```
__try { ... }
__try { ... }
function: 002F1FE0
function: 77A89F80
function: 77A98F1F

function: 002F1311
function: 002F1FE0
function: 77A89F80
function: 77A98F1F

自定义SEH: ExceptionCode: C0000094

function: 002F1FE0
function: 77A89F80
function: 77A98F1F
```


