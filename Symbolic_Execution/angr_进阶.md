## 喂参数给程序

创建init_state之前生成位向量符号argv1 ，作为程序的参数。

```python
argv1 = claripy.BVS("argv1",100*8)
initial_state = project.factory.entry_state(args=["./crackme1",argv1])
```

## 正常输入

早期版本的angr是使用`init_state.posix.files[0].read_from(1)`逐字节读取喂给的参数，并且进行约束。

现在几乎都是使用新版本的angr，在创建`init_state`时使用  
```python
  p = angr.Project("test")
  initial_state = project.factory.entry_state(
            args=['./test'],
            stdin=flag,
    )
```

args是程序文件，flag是使用claripy的 BVS() 方法生成的位向量符号，做为stdin输入。

对于C++的程序，state时需要使用full_init_state方法并，设置unicorn引擎

```python

initial_state = p.factory.full_init_state(
            args=['./cplus'],
            add_options=angr.options.unicorn,
            stdin=flag,
    )

```

## 一些约束

直接使用claripy创建向量，bit_chars是一个BVS类型的list，这样创建便于对每字节数据做约束

bit用了Concat方法将list转化成一个完整的BVS向量，并在末尾加换行符。

```python
    bit_chars = [claripy.BVS('argv_%d' % i, 8) for i in range(32)]
    bit = claripy.Concat(*argv_chars+ [claripy.BVV(b'\n')])

```
添加约束，提高数据的生成效率：

可使用`initial_state.add_constraints（）`也可使用`initial_state.solver.add()`

```python
for k in flag_chars:
        cond_0 = k >= ord('0')
        cond_1 = k <= ord('9')
        cond_2 = k >= ord('a')
        cond_3 = k <= ord('f')
        cond_4 = initial_state.solver.And(cond_0, cond_1)
        cond_5 = initial_state.solver.And(cond_2, cond_3)
        cond_6 = initial_state.solver.Or(cond_4, cond_5)
        initial_state.solver.add(cond_6)

```



## 任意位置加载程序

1.有些时候程序的输入数据被分类很多组，或者程序获取输入的逻辑实现的很复杂，严重干扰了angr分析，这时候就要跳过那些输入指令，加载程序，提高符号执行效率。

创建`initial_state`时，使用factory的blank_state方法，传入地址，表示从该地址的状态开始。

```python
start_address = 0x40083E  
initial_state = p.factory.blank_state(addr=start_address)

```

2.之后就可以对寄存器，地址，做hook设置。

**initial_state.memory.store(addr_in ,  bvs ,  endness='Iend_BE') ** 将你创建的BVS符号向量载入addr内存地址,第三个参数可以不用加，默认是大端的方式。

```python
Variables:  
LE – little endian, least significant byte is stored at lowest address
BE – big endian, most significant byte is stored at lowest address
ME – Middle-endian. Yep.

```

 **recv = initial_state.memory.load(addr_out, size)**  将addr地址处的数据取出size字节放到recv对象

**   initial_state.regs.rax = 0x1122334455667788 ** 给寄存器赋值，或者取出寄存器的值。

**initial_state.stack_push(0x1234) ** 往栈中压入一个值

**initial_state.mem[initial_state.regs.esp+12:].dword = 0x25** 在一个内存地址处 载入一个dword类型的数
 ......

3.修复程序并执行

手动修复，给缺失的内存数据填入BVS符号。

比如我们的输入是在栈中

```python
lea     rax, [rbp-70h]
mov     rsi, rax
mov     edi, offset aS  ; "%s"
mov     eax, 0
call    ___isoc99_scanf

```

我们将程序入口设置到scanf下方，现在我们需要了解，我们跳过的那些指令是如何调整栈空间的，我们要注入的符号位向量的确切的位置。从前面的分析可知，我们要注入的位置是 [RBP - 0x70] ，因此在压栈前我们我要填充栈，但是我们首先应当告诉 ebp 它应该是指向内存的什么位置。因此我们要用angr处理函数开头（我们跳过的部分）： MOV RBP, RSP 。之后我们需要减小帧指针的值（模拟 sub esp, XXX），并将BVS写到RBP-0x70的位置

修复函数如下：

```python
initial_state.regs.rbp = initial_state.regs.rsp
bind_addr = initial_state.regs.rsp-0x70
initial_state.regs.rsp-=0x70
initial_state.memory.store(bind_addr, data)


```

对于更复杂的情况，比如当前位置的一个子函数加载程序后，涉及到从子函数中退出，会用到返回地址，栈帧，我们就必需要手动构造一个完整的栈结构。


## hook反调试

将ptrace函数hook返回0

`p.hook_symbol('ptrace', angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained'](return_value=0))`

另外，对于代码自修改程序，需要使用如下的方式

`p = angr.Project("crackme", support_selfmodifying_code=True) `

hook到一些关键函数上，达到控制效果。

比如控制scanf就可以达到和控制返回值类似的效果。

```python
flag_chars = [claripy.BVS('flag_%d' % i, 32) for i in range(13)]
    class my_scanf(angr.SimProcedure):
        def run(self, fmt, ptr): # pylint: disable=arguments-differ,unused-argument
            self.state.mem[ptr].dword = flag_chars[self.state.globals['scanf_count']]
            self.state.globals['scanf_count'] += 1

    proj.hook_symbol('__isoc99_scanf', my_scanf(), replace=True)

    sm = proj.factory.simulation_manager()
    sm.one_active.options.add(angr.options.LAZY_SOLVES)
    sm.one_active.globals['scanf_count'] = 0

    # search for just before the printf("%c%c...")
    # If we get to 0x402941, "Wrong" is going to be printed out, so definitely avoid that.
    sm.explore(find=0x4028E9, avoid=0x402941)

    # evaluate each of the flag chars against the constraints on the found state to construct the flag
    flag = ''.join(chr(sm.one_found.solver.eval(c)) for c in flag_chars)
    return flag

```

## 路径探索

最后通过传入参数 initial_state 调用 simgr 函数创建 Simulation Manager 对象,在通过simulation执行explore方法找路径。

```python 

simulation = project.factory.simgr(initial_state)
simulation.explore(find=addr1,void=addr2) 

```

地址可传入list的形式

```python
yes=[0x400567,0x400756,0x400835]
no=[0x400435,0x400342,0x400526]

simulation.explore(find=yes,void=no)

```

如果路径很多的情况下可这样处理

```python

def is_successful(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    if b'Good Job.' in stdout_output:
    	return True  
    else :
    	return False

def should_abort(state):
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    if b'Try again.' in  stdout_output:
    	return True  
    else :
    	return False

simulation.explore(find=is_successful, avoid=should_abort)


```


## 打印值


```python

if simulation.found:
    solution_state = simulation.found[0]
    print solution_state.posix.dumps(sys.stdin.fileno()).strip('\0\n') //打印输入的值
    print solution_state.solver.eval(flag, cast_to=bytes)  //打印定义的BVS的值

else:
    raise Exception('Could not find the solution')


```


## 过滤输出

过滤found后结果的输出

found的地址刚好设置在puts函数打印正确结果处，
此时的状态时，put将要打印edi寄存器的值.
取出edi里面的地址，暂且命名为flag_addr
取出flag_addr地址处的40字节的数据到flag对象，再进行约束

```python
found = simulation.found[0] 
flag_addr = found.regs.rdi

found.add_constraints(found.memory.load(flag_addr, 5) == int(binascii.hexlify(b"flag{"), 16))

flag = found.memory.load(flag_addr, 40)

for i in range(5, 5+32):
        cond_0 = flag.get_byte(i) >= ord('0')
        cond_1 = flag.get_byte(i) <= ord('9')
        cond_2 = flag.get_byte(i) >= ord('a')
        cond_3 = flag.get_byte(i) <= ord('f')
        cond_4 = found.solver.And(cond_0, cond_1)
        cond_5 = found.solver.And(cond_2, cond_3)
        found.add_constraints(found.solver.Or(cond_4, cond_5))

        found.add_constraints(flag.get_byte(32+5) == ord('}'))

```
最后将结果通过eval输出即可.
`flag_str = found.solver.eval(flag, cast_to=bytes)`