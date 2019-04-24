```
char *lpText1;
ULONG my_esp;
__declspec(naked) void MyMessageBoxA(
HWND hWnd,
LPCTSTR lpText,
LPCTSTR lpCaption,
UINT uType)
{

_asm
{
//pop hWnd
//pop lpText
//pop lpCaption
//pop uType
mov my_esp,esp; //先保存下需要用到的参数
pushad//然后保存整个堆栈
pushfd
push eax
mov eax, my_esp
add eax, 8
mov eax,[eax] //不能直接 mov给变量，编译通不过 ， 需要用eax 中转一下，听说是编译器的问题。
mov lpText1,eax;
pop eax;
}

printf("MyMessageBoxA lpText: %s \r\n",lpText1); //lpText1已经是地址了 不需要&度地址赋。

_asm
{
popfd
popad //把堆栈还原掉。
RETN 16; //把参数废除掉 4*n 屏蔽掉MessageBoxA ,此处就要直接退出messagebox了。
}

//此处是若要hook后执行原函数流程
_asm
{
PUSH EBP   //执行以下被HOOK掉的 头5个字节。
MOV EBP,ESP
JMP newbark;   //然后调回去
}

}

```


在0环 hook ， 禁止和开启系统写保护，实现底层的hook。

```c
  _asm
  {
    push eax;
    mov eax, cr0;
    mov uAttr, eax;
    and eax, 0FFFEFFFFh; // CR0 16 BIT = 0   禁用写保护
    mov cr0, eax;
    pop eax;
    cli
  };
  g_uCr0 = uAttr; //保存原有的 CRO 屬性
}
```

```c
VOID WPON()
{
  _asm
  {
    sti
      push eax;
    mov eax, g_uCr0; //恢復原有 CR0 屬性
    mov cr0, eax;
    pop eax;
  };
}
```