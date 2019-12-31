>懒人玩reverse

## intel-pin

之前玩了angr之后发现有点局限性，后来接触了 intel-pin 这个动态插桩工具，当时发现对于一些加密字节关联度不大的题目，尤其是代码混淆比较严重的题目，可以编写 pintool 统计指令数等信息，多快好省的通过侧信道的方法逐位爆破出 flag。

## 安装

在[官网](https://software.intel.com/en-us/articles/pin-a-binary-instrumentation-tool-downloads)下载即可,解压后根目录下pin程序直接可使用。

## 使用1

在 source/tools/ManualExamples 中有一些现成的 pintool 可以使用，基本涵盖了各个模块的用法。

下面就说说指令计数的功能。

`make obj-intel64/inscount0.so TARGET=intel64` 编译生成64位的pintool
`make obj-ia32/inscount00.so ` 编译生成32位的pintool
`pin -t your_pintool -- your_binary <arg>` 使用基本命令 或者喂给输入在后面加 <<< "flag{dsada}"

通常在make前，我们可以改一改fini函数

```c
VOID Fini(INT32 code, VOID *v)
{
    // Write to a file since cout and cerr maybe closed by the application
    // OutFile.setf(ios::showbase);
   // OutFile << "Count " << icount << endl;
   // OutFile.close();
   std::cout<< "Count " << icount << std::endl;
 
}

```

注释掉OutFile部分，不让输出文件，直接cout输出结果到命令行。

## 使用2

对于一些相同的输入但是指令数不固定的程序，我们可以找到关键校验地址，对 inscount1 的 docount 函数做如下更改

```c
更改前：
VOID docount() { icount++; }

更改后：
VOID docount(void *ip) 
{
  	// .text:000000000047B96E  cmp al, cl; 
	if ((long long int)ip == 0x000000000047B96E)
	 icount++; 
}

```

需要注意的是 `INS_InsertCall` 是一个变参函数，前三个参数分别为指令(ins)，插入的实际(IPOINT_BEFORE，表示在指令运行之前插入 docount 函数)，函数指针(docount，转化为了 AFUNPTR 类型)，之后的参数为传递给 docount 函数的参数，以 IARG_END 结尾，所以这里还要继续修改`INS_InsertCall`函数的参数。


```c
更改前：
INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_END);

更改后：
INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_INST_PTR, IARG_END);

```

这样再运行，只有运行到 0x47B96E 一句才会计数，这样我们就可以根据 pintool 的结果来逐位爆破 flag 了

## 一些脚本

猜长度

```python
from subprocess import Popen, PIPE
from sys import argv
import string
import time

def Read():
	f = open('./inscount.out','r')
	file  = f.read().strip('\n')
	f.close()
	return file


pinPath = "/home/b0ldfrev/pin/pin"
pinInit = lambda tool, elf: Popen([pinPath, '-t', tool, '--', elf],stdin = PIPE, stdout = PIPE)
pinWrite = lambda cont: pin.stdin.write(cont)
pinRead = lambda : pin.communicate()[0]

if __name__ == "__main__":
    last = 0
    for i in range(1, 33):
        pin = pinInit("./inscount0.so", "./test")
        pinWrite("a" * i + '\n')
        # time.sleep(0.5)
        v=pinRead().split(" ")[1]

        now = int(v,10)
        
        print ( "inputLen({:2d}) -> ins({}) -> delta({})".format(i, now, now - last) )
        last = now

```

猜结果

```python

from subprocess import Popen, PIPE
from sys import argv
import string
import pdb
import time

pinPath = "/home/boldfrev/pin/pin"
pinInit = lambda tool, elf: Popen([pinPath, '-t', tool, '--', elf], stdin = PIPE, stdout = PIPE)
pinWrite = lambda cont: pin.stdin.write(cont)
pinRead = lambda : pin.communicate()[0]

def Read():
    f = open('./inscount.out','r')
    file  = f.read().strip('\n')
    f.close()
    return file

if __name__ == "__main__":

    last = 0
    length=8  # flag length
    diff=1000  # instruction difference
    dic = "\x01"+string.ascii_letters + string.digits + "+_ "+"{}"
    pwd = '?' *length
    dicIdx = 0
    pwdIdx = 0

    while True:
	
        pwd = pwd[: pwdIdx] + dic[dicIdx] + pwd[pwdIdx + 1: ]
        
        pin = pinInit("./inscount1.so","./crackme")
        pinWrite(pwd + '\n')
        #time.sleep(0.2)
        try:
        	now = int(pinRead().split("Count ")[1])
	    except:
			time.sleep(0.2)
			now = int(pinRead().split("Count ")[1])
        print "input({}) -> now({}) -> delta({})".format(pwd, now, abs(now - last))

        if abs(now - last) > diff and dicIdx:
            pwdIdx += 1
            dicIdx = -1
            last = 0
            if pwdIdx >= len(pwd):
                print "Found pwd: {}".format(pwd)
                break

        dicIdx += 1
        last = now

```