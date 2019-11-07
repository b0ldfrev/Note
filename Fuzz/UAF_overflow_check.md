根据fuzz工具asan源码，对于UAF和堆溢出漏洞，这个工具对malloc与free做了如下HOOK：

## UAF

```c
#include <stdio.h>
#include <memory.h>
#include <stdlib.h>
#include <execinfo.h>
#include <signal.h>
#define STORESIZE sizeof(size_t)

void show_stack()
{
    int i;
    void *buffer[1024];
    int n = backtrace(buffer, 1024);
    char **symbols = backtrace_symbols(buffer, n);
    for (i = 0; i < n; i++) {
        printf("%s\n", symbols[i]);
    }
}
void signal_handler(int sig) {
    if(SIGSEGV==sig)
    {
        show_stack();
        exit(-1);
    }
    else{
        printf("signal with %d\n",sig);
    }
}
void my_free(void* addr){
    printf("free addr:%p size:%d append_size:%d\n",addr,*(size_t*)((size_t)addr-STORESIZE),STORESIZE);
    memset(addr,0xFF,*(size_t*)((size_t)addr-STORESIZE));
    free((void*)((size_t)addr-STORESIZE));
}
void* my_malloc(size_t len){
    void* addr=malloc(len+STORESIZE);
    printf("malloc addr:%p size:%d app_size:%d\n",(void*)((size_t)addr+STORESIZE),len,STORESIZE);
    *(size_t*)addr=len;
    return (void*)((size_t)addr+STORESIZE);
}

void main()

{
 signal(SIGSEGV, signal_handler);
 //do();
}

```

在malloc的时候多分配一个size_t大小用于存储malloc的buffer大小，并放置在buffer前。

在free的时候获取存储的buffer大小进行memset，后在释放。

如果有重用 释放堆块里面的指针行为，程序崩溃Segmentation fault: 的时候打印堆栈。（为测试代码添加了signal处理函数）

## overflow

```c
#include <stdio.h>
#include <memory.h>
#include <stdlib.h>
#include <execinfo.h>
#include <signal.h>
#define STORESIZE sizeof(size_t)

void my_free(void* addr){
    printf("free addr:%p size:%d append_size:%d\n",addr,*(size_t*)((size_t)addr-STORESIZE),2*STORESIZE);
    memset(addr,0xFF,*(size_t*)((size_t)addr-STORESIZE));
    if(*(size_t*)((size_t)addr-STORESIZE)!=((size_t)addr+*(size_t*)((size_t)addr-STORESIZE)))
    {
        printf("heap over_flow!\n");
        show_stack();
        exit(-1);
    }
    free((void*)((size_t)addr-STORESIZE));
}
void* my_malloc(size_t len){
    void* addr=malloc(len+2*STORESIZE);
    printf("malloc addr:%p size:%d app_size:%d\n",(void*)((size_t)addr+STORESIZE),len,2*STORESIZE);
    *(size_t*)addr=len;
    *(size_t*)((size_t)addr+len+STORESIZE)=len;
    return (void*)((size_t)addr+STORESIZE);
}

```

溢出的检测是在malloc的buffer前后分别添加一个buffer的size 类似[len][buffer][len]，在free的时候检测头尾的len是否相等。如不相等则溢出。