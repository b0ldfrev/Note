>环境Ubuntu 16.04 amd64


## 安装qemu

```javascript
sudo apt-get install qemu 
sudo apt-get install qemu-user-static
sudo apt-get install qemu-system
sudo apt-get install uml-utilities
sudo apt-get install bridge-utils

```


## 安装buildroot交叉编译环境

安装依赖环境

```javascript
sudo apt-get install libncurses5-dev
```

在[buildroot.org](https://buildroot.org)下载buildroot

```javascript
tar -zxvf buildroot-2019.02.5.tar.gz
cd buildroot-2019.02.5
make clean
make menuconfig
```
之后会出来个GUI

在`target options->target arch`选项里面选择自己要编译的架构，我这里选的MIPS(little endian)

在`toolchain-->Kernel Headers`选择自己主机的内核版本或者更低的版本，保存退出

```javascript
sudo make
```

编译时间有点长，中间还会下载一些库，输出文件在output目录。闲麻烦的我这里有个编译好的，将output文件夹打包放在百度云。

自取[https://pan.baidu.com/s/16GIXyYoag4eGuvMhaqqAZg](https://pan.baidu.com/s/16GIXyYoag4eGuvMhaqqAZg) 提取码：[vceh]()

编译完成之后，写个demo测试一下，用file查看编译好的mips架构文件。

```javascript
output/host/usr/bin/mipsel-linux-gcc demo.c -o demo

rooth@ubuntu:~$ file demo
hello: ELF 32-bit LSB executable, MIPS, MIPS32 version 1 (SYSV), dynamically linked, interpreter /lib/ld-, not stripped

```

LSB，可以看到是小端序的MIPS程序

## 用qemu运行编译出的程序

```javascript
qemu-mipsel demo
```
mipsel这里代表小端序的mips，但是这里可能会报错,这是因为没有对应架构的链接库的问题

在`output/host/mipsel-buildroot-linux-uclibc/sysroot/lib/`目录，敲以下命令：

```javascript
sudo cp ld-uClibc-1.0.31.so /lib/
sudo chown -R root:root /lib/ld-uClibc-1.0.31.so
sudo ln -s /lib/ld-uClibc-1.0.31.so /lib/ld-uClibc.so.0

sudo cp libuClibc-1.0.31.so /lib/
sudo chown -R root:root /lib/libuClibc-1.0.31.so
sudo ln -s /lib/libuClibc-1.0.31.so /lib/libc.so.0

```

运行成功

```javascript
root@ubuntu:~$ qemu-mipsel demo
hello world !

```

## 使用qemu用户模式调试

1.GDB插件尽量用pwndbg

2.先安装`gdb-multiarch`

```javascript
sudo apt-get install gdb-multiarch

```
若找不到`gdb-multiarch`软件包可以在`/etc/apt/sources.list` 添加源

```javascript
deb http://cz.archive.ubuntu.com/ubuntu cosmic main universe
```
完成后执行`sudo apt-get update`再重新安装


3.在一个窗口通过`qemu-mipsel -g [port] [binname]`来指定监听的端口启动程序，然后在另一个终端使用`gdb-multiarch biname`连接该端口进行调试

```javascript
root@ubuntu:~$ qemu-mipsel -g 9999 demo

```

```javascript
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

```javascript
sudo chroot . ./qemu-mips-static binname 

```

## 使用qemu系统模式调试

1.配置本机网络
 
写个source文件

```javascript
sudo brctl addbr virbr0
sudo ifconfig virbr0 192.168.122.1/24 up

sudo tunctl -t tap0
sudo ifconfig tap0 192.168.122.11/24 up
sudo brctl addif virbr0 tap0
```

2.[下载](https://people.debian.org/~aurel32/qemu/mipsel/)并启动qemu镜像(通常只需下载readme.txt提示的几个配套文件)

```javascript
sudo qemu-system-mips -M malta -kernel vmlinux-3.2.0-4-4kc-malta -hda debian_wheezy_mipsel_standard.qcow2 -append "root=/dev/sda1 console=tty0" -netdev tap,id=tapnet,ifname=tap0,script=no -device rtl8139,netdev=tapnet -nographic

```
输入root/root进入虚拟机，设置ip：

```javascript
ifconfig eth0 192.168.122.12/24 up
```
接着就可以看到qemu虚拟机和外面的网络互通了

2.如需从主机传输数据，使用

```javascript
scp -r ./data  root@192.168.122.12:/root/

```
3.qemu系统模式调试

可以[下载](https://github.com/yxshyj/embedded-toolkit)各个架构静态编译的gdbserver，使用gdbserver启动要调试的程序或附加到需要调试的进程上。

```javascript
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

```javascript
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

在[https://github.com/darkerego/mips-binaries](https://github.com/darkerego/mips-binaries)下载静态编译的socat程序，因为socat可以用来做数据转发，而且很久之前的pwn题也有用socat部署过。把下载好的socat拷贝到qemu虚拟机中，然后使用如下命令：

```javascript
./socat tcp-l:9999,fork exec:./demo
```

然后使用pwntools连接该端口，发现能够正常的与该程序进行交互

但此时不能调试该程序，执行socat命令后qemu的终端就被占用了

可以创建一个sh文件，把socat命令写到该文件中，然后以后台方式&运行该sh文件，主机连接到socat后在脚本raw_input()处停下，这时就可以在qemu系统中查看pid，`gdbserver 0.0.0.0：[port] --attach [pid]`附加上去。在主机就可以使用gdb-multiarch调试了


