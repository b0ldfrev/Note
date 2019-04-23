House of Roman 实现了开启PIE没有leak地址功能的程序的利用，这个技巧说简单点其实就是 fastbin attack 和 Unsortbin attachk 结合，还有严密的堆布局，我学习了一下，做个简单的分享与记录。

## aslr

PIE和系统的aslr，对于一个32bit的binary，它的高20bit会被随机化的，而最后的12bit不会被随机化(64位同样)，如果漏洞触发，我们能够恰好覆盖最后的12bit，实际上也能在一定的范围内劫持程序的控制流

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/House_of_Roman/3.jpg)


## 大致思路

通过`fastbin_attack`控制`malloc_hook`地址空间，再通过`Unsortedbin_attack`将`malloc_hook`内容改写成`main_arena+0x58`，编辑`malloc_hook`地址空间内容的后几位，改成one_gadget,实现利用，但是这里通常有几bit需要爆破。

## 1 首先构造一个非fastbin chunk

暂且命名为chunk 0，释放掉它再重新分配它，这样就将它的mem空间填充了main_arena地址

再编辑该chunk，将fd指针的后8字节 覆盖成libc中 `malloc_hook - 0x23`偏移的后8字节,因为通常main_arean地址在`__malloc_hook`的下面不远处，算偏移一般都不会超过FF 无需进位。

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/House_of_Roman/2.jpg)

所以这里编辑chunk 0的内容就为 `\x1d`覆盖后 chunk 0 的 fd 中的内容就刚刚好是`malloc_hook - 0x23`

还有必要利用Off-By-One将该chunk 0的size大小改成fastbin范围，最后的chunk 0如下：

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/House_of_Roman/1.jpg)

## 2 构造fastbin链，进行fastbin_attack

构造如图：

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/House_of_Roman/4.jpg)

连续三次分配0x70大小的chunk之后，我们就能分配得到`malloc_hook_chunk`，便可以随意往`malloc_hook`写东西 ( 注意：该操作结束之后要修复 fastbin链表 )

## 3 进行UnsortedBin_attack

修改`malloc_hook`为`main_arena+0x58`

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/House_of_Roman/5.jpg)

## 4 编辑`malloc_hook_chunk`内容

将main_arena覆盖成one_gadget.这里由于onegadget在代码段，在libc中代码段的偏移量通常比数据段的`malloc_hook`少4bit，他们实际地址相差甚远，所以就给覆盖造成了困难,在我本地测试的环境中： 比如main_arena+0x58 的地址是 0x7fffffxxx123 ，one_gadget的偏移是 0xe9456 ,由于后12bit未被随机化，所以 main_arena+0x58 肯定是被覆盖为 0x7fffffxxx456，但xxx这三位在我本机环境就不一样了，需要爆破xxx这12bit，才能找到正确的one_gadget地址。

## 5 触发方式

根据调用execve时的rsp指向微调，直接malloc触发或者double free 抛出malloc_printerr触发

>相关链接

[House of Roman 实战-hac425](https://www.cnblogs.com/hac425/p/9416913.html)

[House of Roman-ctf-wiki](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/house_of_roman/)