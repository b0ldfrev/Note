>环境Ubuntu 16.04 amd64 
>本文主要以MIPS架构为主，ARM架构的搭建同理


## 安装qemu

```ruby

sudo apt-get install qemu 
sudo apt-get install qemu-user-static
sudo apt-get install qemu-system
sudo apt-get install uml-utilities
sudo apt-get install bridge-utils

```


## 安装交叉编译环境

##### 使用buildroot

安装依赖环境

```ruby
sudo apt-get install libncurses5-dev
```

在[buildroot.org](https://buildroot.org)下载buildroot

```ruby
tar -zxvf buildroot-2019.02.5.tar.gz
cd buildroot-2019.02.5
make clean
make menuconfig
```
之后会出来个GUI

在`target options->target arch`选项里面选择自己要编译的架构，我这里选的MIPS(little endian)

在`toolchain-->Kernel Headers`选择自己主机的内核版本或者更低的版本，保存退出

```ruby
sudo make
```

编译时间有点长，中间还会下载一些库，输出文件在output目录。闲麻烦的我这里有个编译好的，将output文件夹打包放在百度云。

自取[https://pan.baidu.com/s/16GIXyYoag4eGuvMhaqqAZg](https://pan.baidu.com/s/16GIXyYoag4eGuvMhaqqAZg) 提取码：[vceh]()

编译完成之后，写个demo测试一下，用file查看编译好的mips架构文件。

```ruby
output/host/usr/bin/mipsel-linux-gcc demo.c -o demo

rooth@ubuntu:~$ file demo
hello: ELF 32-bit LSB executable, MIPS, MIPS32 version 1 (SYSV), dynamically linked, interpreter /lib/ld-, not stripped

```

LSB，可以看到是小端序的MIPS程序

为了方便，后期可以将程序写入环境变量

```python
vi ~/.bashrc
#里面加入
export  PATH=$PATH:/home/bldfrev/arm_little_gcc/output/host/usr/bin/

```
之后就可以直接使用`mipsel-linux-gcc`命令

##### 使用mipsel-gcc软件包

使用`apt search "mipsel-linux"`搜索，找到相关软件包`gcc-mipsel-linux-gnu`，安装即可

安装好后，即可直接使用`mipsel-linux-gnu-gcc`命令，同时它的相关lib库文件在系统的`/usr`目录下的`mipsel-linux-gnu`文件中。

## 交叉编译静态socat或gdbserver



>这里以编译gdbserver为例

若后期要进入qemu系统模式调试，网上又找不到理想匹配的静态链接的程序，就只能自己动手编译。

去下载gdb源码[http://ftp.gnu.org/gnu/gdb/](http://ftp.gnu.org/gnu/gdb/)

下载解压后进入“ gdb-<version>/gdb/gdbserver ”目录，使用如下命令编译安装：

```ruby
root@ubuntu:~$ CC="mipsel-linux-gcc"  ./configure --target=mipsel-linux --host="mipsel-linux" --prefix="/home/b0ldfrev/gdbserver_setup" --disable-build-with-cxx CFLAGS='-fPIC -static'

root@ubuntu:~$ make install 
```
这将使用标准的C构建过程`CC="mipsel-linux-gcc"`，也可以在配置时关闭g++`--disable-build-with-cxx`。

CC选项尽量使用buildroot编译出来的`mipsel-linux-gcc`，因为它的内核版本较老;若使用`mipsel-gcc`软件包编译出来的`mipsel-linux-gnu-gcc`来编译gdbserver，这会导致编译出来的gdbserver只能在内核版本较高的系统中运行。

然后，在你通过“ --prefix ”选项指定的路径下，就可以找到编译完成的 gdbserver 了。




## 用qemu运行编译出的程序

>这里与buildroot为例

尝试运行

```ruby
qemu-mipsel demo
```
mipsel这里代表小端序的mips，但是这里可能会报错,这是因为没有对应架构的链接库的问题

定位到buildroot交叉编译出的uclibc链接库

在`output/host/mipsel-buildroot-linux-uclibc/sysroot/lib/`目录，敲以下命令：

```ruby

sudo cp ld-uClibc-1.0.31.so /lib/
sudo chown -R root:root /lib/ld-uClibc-1.0.31.so
sudo ln -s /lib/ld-uClibc-1.0.31.so /lib/ld-uClibc.so.0

sudo cp libuClibc-1.0.31.so /lib/
sudo chown -R root:root /lib/libuClibc-1.0.31.so
sudo ln -s /lib/libuClibc-1.0.31.so /lib/libc.so.0

```

运行成功

```ruby
root@ubuntu:~$ qemu-mipsel demo
hello world !

```

PS: 如果不想把编译出的libc与ld移入主机的/lib文件夹，也可以在qemu-mipsel后面加参数 `-L "output/host/mipsel-buildroot-linux-uclibc/sysroot/"` 指定环境变量的路径。

## 使用qemu用户模式调试

1.GDB插件尽量用gef(pwndbg也行)

2.先安装`gdb-multiarch`

```ruby
sudo apt-get install gdb-multiarch

```
若找不到`gdb-multiarch`软件包可以在`/etc/apt/sources.list` 添加源

```ruby
deb http://cz.archive.ubuntu.com/ubuntu cosmic main universe
```
完成后执行`sudo apt-get update`再重新安装


3.在一个窗口通过`qemu-mipsel -g [port] [binname]`来指定监听的端口启动程序，然后在另一个终端使用`gdb-multiarch biname`连接该端口进行调试

```ruby
root@ubuntu:~$ qemu-mipsel -g 9999 demo

```

```ruby
root@ubuntu:~$ gdb-multiarch demo
......
......
pwndbg> set arch mips
The target architecture is assumed to be mips
pwndbg> set endian little 
The target is assumed to be little endian
pwndbg> target remote 127.0.0.1:9999
Remote debugging using 127.0.0.1:9999

....

```

4.调试一些其它程序(非本地buildroot环境编译)

ctf当中有些时候会给so库

所以可以使用chroot，把根目录设置到给出的so库目录下，这样就能加载到题目给的libc库了。不过需要注意的是，如果在这里使用qemu-mips的话还是会报错，因为qemu-mips不是静态编译的，它的运行依赖于本地的其他so库，chroot之后便找不到这些so库了，虽然可以通过ldd查看它所需要的库，并拷贝到相对当前目录下的对应路径下，但是这样太麻烦了，可以直接使用静态编译的版本qemu-mips-static：

```ruby
sudo chroot . ./qemu-mips-static binname 

```

5.exp脚本利用+调试

使用命令`socat tcp-l:9999,fork exec:"qemu-mipsel -g 8888 demo"` 创建qemu调试模式I/O的socat端口映射

必须先执行exp脚本再用gdb-multiarch去attach，顺序不能乱。

exp脚本中执行完`p=remote("127.0.0.1",9999)`后就应该调用个input()暂停一下，等待喂给数据；

紧接着再去`gdb-multiarch demo`，附加远程调试`target remote 127.0.0.1:8888`,这时gdb调试窗口停在start函数处；这时可以设置断点，gdb窗口按下c继续执行程序，再去运行exp脚本的shell窗口按下回车，通过脚本进行数据的交互，最后gdb窗口中在断点处断下。

这样其实有点鸡肋，因为只能从头开始调试，不能从进程中间附加上去调试，但这样也解决了的交互数据存在不可见字符的问题，所以还算比较实用的方法。

当然还有更简单的方法，可以直接在python脚本里面 `p=process(["qemu-mipsel","-g","8888","-L","./","./demo"])` ，这样也可以直接通过pwntools映射I/O流，解决调试时数据交互问题。


## 使用qemu系统模式调试

1.配置本机网络
 
写个source文件

```ruby
sudo brctl addbr virbr0
sudo ifconfig virbr0 192.168.122.1/24 up

sudo tunctl -t tap0
sudo ifconfig tap0 192.168.122.11/24 up
sudo brctl addif virbr0 tap0
```

2.[下载](https://people.debian.org/~aurel32/qemu/mipsel/)并启动qemu镜像(通常只需下载readme.txt提示的几个配套文件)

```ruby
sudo qemu-system-mipsel -M malta -kernel vmlinux-3.2.0-4-4kc-malta -hda debian_wheezy_mipsel_standard.qcow2 -append "root=/dev/sda1 console=tty0" -netdev tap,id=tapnet,ifname=tap0,script=no -device rtl8139,netdev=tapnet -nographic

```
输入root/root进入虚拟机，设置ip：

```ruby
ifconfig eth0 192.168.122.12/24 up
```
接着就可以看到qemu虚拟机和外面的网络互通了

也可以这样启动镜像：
```
qemu-system-mips64el -M malta -kernel vmlinux-3.2.0-4-5kc-malta -hda debian_wheezy_mipsel_standard.qcow2 -append "root=/dev/sda1" -netdev user,id=net0 -device e1000,netdev=net0,id=net0,mac=52:54:00:c9:18:27 -redir tcp:11022::22 -redir tcp:11000::11000  -nographic```

这样就可以与guest虚拟机ssh连接了，而且guest虚拟机可以连接互联网

`ssh -p 11022 root@127.0.0.1`


2.如需从主机传输数据，使用

```ruby
scp -r ./data  root@192.168.122.12:/root/

```
3.qemu系统模式调试

可以[下载](https://github.com/yxshyj/embedded-toolkit)各个架构静态编译的gdbserver，使用gdbserver启动要调试的程序或附加到需要调试的进程上。

```ruby
# 启动要调试的程序
root@debian-mips:~# ./gdbserver 0.0.0.0:9999 demo 
Process demo created; pid = 2379
Listening on port 9999

# 附加到要调试的进程
root@debian-mips:~# ./gdbserver 0.0.0.0:9999 --attach $(pid of demo)
Attached; pid = 2790
Listening on port 9999

```

接着就可以在qemu外使用gdb-mutiarch来连接该端口进行调试了,同上面——使用qemu用户模式调试

```ruby
root@ubuntu:~$ gdb-multiarch demo
......
......
pwndbg> set arch mips
The target architecture is assumed to be mips
pwndbg> set endian little 
The target is assumed to be little endian
pwndbg> target remote 192.168.122.12:9999
Remote debugging using 192.168.122.12:9999

....

```

4.解决调试中的数据发送问题

现在已经能够用系统模式和用户模式来模拟运行mips程序了，并且可以使用gdbserver来启动或附加到我们要调试的程序上。但是这里还是存在一个问题，就是不能像做正常pwn题那样方便的往程序中输入数据，虽然可以在qemu中手动的输入，但是输入的数据中难免会有不可见字符。

在[https://github.com/darkerego/mips-binaries](https://github.com/darkerego/mips-binaries)(大端)或者[https://github.com/hypn/misc-binaries](https://github.com/hypn/misc-binaries)(小端)下载静态编译的socat程序，因为socat可以用来做数据转发，而且很久之前的pwn题也有用socat部署过。把下载好的socat拷贝到qemu虚拟机中，然后使用如下命令：

```ruby
./socat tcp-l:9999,fork exec:./demo
```

然后使用pwntools连接该端口，发现能够正常的与该程序进行交互

但此时不能调试该程序，执行socat命令后qemu的终端就被占用了

可以创建一个sh文件，把socat命令写到该文件中，然后以后台方式&运行该sh文件，主机连接到socat后在脚本raw_input()处停下，这时就可以在qemu系统中查看pid，`gdbserver 0.0.0.0：[port] --attach [pid]`附加上去。在主机就可以使用gdb-multiarch调试了

## 模拟设备

解固件包，若有加密，参照[路由器加密固件的解密](https://mp.weixin.qq.com/s?__biz=MzI0MDY1MDU4MQ==&mid=2247498141&idx=2&sn=2fd0ab42f93f5ec5a438ea613c40d80f&chksm=e91529a7de62a0b1c6ea7988aa6d536130f013955f92c781158fb88af7d04534777d59892fee&mpshare=1&scene=24&srcid=0826BqAwKL49eUcT1z43Xbrj&sharer_sharetime=1598408704438&sharer_shareid=f04a963f2d52f62a108ba2405d28bd38#rd)

解密后在binwalk提取出文件系统，将设备文件目录拖入对应的qemu系统模式，在文件目录执行chroot . /bin/sh。根据服务的报错信息，通过`LD_RELOAD` hook对应函数。

