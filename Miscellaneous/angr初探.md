
## 什么是angr

angr是一个用于分析二进制文件的python框架。它专注于静态和符号分析，使其适用于各种任务。其项目地址是，[https://github.com/angr](https://github.com/angr).

## 什么是符号执行

符号执行 （Symbolic Execution）是一种程序分析技术。其可以通过分析程序来得到让特定代码区域执行的输入。使用符号执行分析一个程序时，该程序会使用符号值作为输入，而非一般执行程序时使用的具体值。在达到目标代码时，分析器可以得到相应的路径约束，然后通过约束求解器来得到可以触发目标代码的具体值。[1]
符号模拟技术（symbolic simulation）则把类似的思想用于硬件分析。符号计算（Symbolic computation）则用于数学表达式分析。

## angr安装踩坑

1，首先`apt-get update` 一下

2，安装依赖环境

	sudo apt-get install python-dev libffi-dev build-essential

3，安装virtualenvwrapper

建议使用 `pip install virtualenvwrapper `安装virtualenvwrapper，安装地点默认在/usr/local/bin/ ，如果以其他方式安装virtualvwrapper则可能找不到安装地址。

4，添加`mkvirutalenv`环境变量

首先设置一个环境变量WORKON_HOME

` export WORKON_HOME=$HOME/Python-workhome`

这里的`HOME/Python-workhome`就是准备放置虚拟环境的地址。 
然后`source /usr/local/bin/virtualenvwrapper.sh`启动virtualenvwrapper.sh脚本 
为方便操作，将上述语句直接写入到~/.bash_profile


5，新建一个python的虚拟机环境

	mkvirutalenv angr

6，在刚才新建的虚拟环境里面

	pip install angr

7，之后要启动虚拟环境： `workon [虚拟环境名称]`

   离开虚拟环境: `deactivate`

8，上面的`mkvirutalenv`环境变量如果始终设置不成功，可以用麻烦一点的方法，先找到`virtualenv.py`的位置

```shell
find / -name 'virtualenv.py'

----------------------------------------------------

root@ubuntu:/home/chris# find / -name 'virtualenv.py'
/usr/lib/python2.7/dist-packages/virtualenv.py
/usr/local/lib/python2.7/dist-packages/virtualenv.py
```

9，然后进入所在目录,手动执行py脚本创建虚拟环境
    
```shell
    cd /usr/local/lib/python2.7/dist-packages/
	# venvName为创建的虚拟环境名,这一步等效于第5步
	python virtualenv.py venvName(angr)
```

10，之后就在虚拟环境里正常安装angr

	pip install angr

11，这样的话启动方式就和配好环境变量的启动方式不同，离开方式一样。

```shell
cd ENV
# ENV为之前创建的虚拟环境文件夹路径
source ./bin/activate

-----------------------------------------------------------------------------------

root@ubuntu:~#    cd /usr/local/lib/python2.7/dist-packages/angr
root@ubuntu:/usr/local/lib/python2.7/dist-packages/angr#    source ./bin/activate
(angr) root@ubuntu:/usr/local/lib/python2.7/dist-packages/angr#    cd ~
(angr) root@ubuntu:~#    deactivate
root@ubuntu:~#  
```
后期可以自己写个shell脚本一条命令进入angr环境


## 拿一个Re开刀

2018 网鼎杯线上赛第二场 Reverse 的 Martricks

贴IDA代码：

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/angr/1.jpg)

好吧流程其实挺简单的，但是分析算法就有点耗时间了，以前我都是人脑分析，撸py解密脚本，现在我们直接上angr

```python
import angr

def main():
    p = angr.Project("martricks")
    simgr = p.factory.simulation_manager(p.factory.full_init_state())
    simgr.explore(find=0x400A84, avoid=0x400A90)

    return simgr.found[0].posix.dumps(0).strip('\0\n')

if __name__ == '__main__':
   print main()
```

Explorer这个方法可以设定说要找到哪个程式执行的位址，可以用find=(addr1)来找，和使用avoid=(addr2)来避免找到某位址。设定find=(addr1)有点像是在下断点，但注意位址必须是基本区块（basic block）的开头 ，否则angr并不会找到该位址，导致最后该路径会被归类成deadended而不是found。

给虚拟机分了1个cpu，20秒跑出flag

![](https://raw.githubusercontent.com/yxshyj/yxshyj.github.io/master/img/pic/angr/2.jpg)

>[下载链接](https://github.com/yxshyj/project/tree/master/reverse/angr)
















