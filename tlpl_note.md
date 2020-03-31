# 第2章  基  本  概  念 
## 2.1    操作系统的核心—内核

#### 内核的职责:
   - 进程调度
   - 内存管理
   - 提供了文件系统
   - 创建和终止进程
   - 对设备的访问
   - 联网
   - 提供系统调用应用编程接口（API）

#### 内核态和用户态

#### 以进程及内核视角检视系统
- 信号的传递和进程间通信事件的触发由内核统一协调，对进程而言，随时可能发生。诸如此类，进程都一无所知。进程不清楚自己在 RAM 中的位置。也不知道访问的文件在硬盘哪里，只是通过名称来引用文件而已。进程也不能与计算机外接的输入输出设备直接通信。 进程本身无法创建出新进程，哪怕“自行了断”都不行
- 内核对于系统的一切无所不知，无所不能。
- “某进程可创建另一个进程”、“某进程可创建管道”、“某进程可将数据写入文件”，以及“调用 exit()以终止某进程”。以上所有动作都是由内核来居中“调停”，上面的说法不过是“某进程可以请求内核创建另一个进程”的缩略语

## 2.2    shell 
shell 是一种具有特殊用途的程序，主要用于读取用户输入的命令，并执行相应的程序以
响应命令。

## 2.3    用户和组

系统会对每个用户的身份做唯一标识，用户可隶属于多个组。 
组 
一个用户可以同时属于多个组

## 2.4    单根目录层级、目录、链接及文件

#### 文件类型 

对文件类型标记，进行分类：普通文件、设备、管道、套接字、目录以及符号链接

#### 路径和链接

目录是一种特殊类型的文件，内容采用表格形式，数据项包括文件名以及对相应文件的
引用。这一“文件名+引用”的组合被称为链接。每个文件都可以有多条链接，因而也可以有多个名称，在相同或不同的目录中出现。 

#### 符号链接
符号链接给文件起了一个“别号（alternative name）”
普通链接是内容为“文件名+指针”的一条记录，一个符号链接对应着目录中内容为“文件名+指针”的一条记录，指针指向的文件内容为另一个文件名的字符串。我理解其实就是C语言的指针。系统查找的时候也是递归查下去。
硬链接（hard link）或软链接（soft link）这样的术语来指代正常链接和符号链接。


#### 文件名
文件名最长可达 255 个字符。文件名可以包含除“/”和空字符（\0）外的所有字符。

#### 路径名
路径名是由一系列文件名组成的字符串，彼此以“/”分隔

#### 文件的所有权和权限
系统把用户分为 3 类：属主、属组成员用户、其他用户。
目录权限： 读权限允许列出目录内容，写权限允许对目录内容进行更改（比如，添加、修改或删除文件名），执行（有时也称为搜索）权限允许对目录中的文件进行访问（但需受文件自身访问权限的约束）。

## 2.5    文件 I/O 模型
UNIX 系统 I/O 模型最为显著的特性之一是其 I/O 通用性概念。也就是说，同一套系统调
用（open()、read()、write()、close()等）所执行的 I/O 操作，可施之于所有文件类型，包括设备文件在内。

## 2.6    程序

## 2.7    进程
进程是正在执行的程序实例

#### 进程的内存布局
逻辑上将一个进程划分为以下几部分（也称为段）。 
    文本：程序的指令。 
    数据：程序使用的静态变量。 
    堆：程序可从该区域动态分配额外内存。 
    栈：随函数调用、返回而增减的一片内存，用于为局部变量和函数调用链接信息分配存储空间。

#### 创建进程和执行程序
进程可使用系统调用 fork()来创建一个新进程。调用 fork()的进程被称为父进程，新创建
的进程则被称为子进程。
内核通过对父进程的复制来创建子进程。子进程从父进程处继承数
据段、栈段以及堆段的副本后，可以修改这些内容，不会影响父进程的“原版”内容。

!! linux下启动进程都是通过PID为1的进程fork来的，那fork来的子进程系统资源是怎么申请的？

#### 进程终止和终止状态
两种方法终止进程：1. 进程可使用_exit()  2. 向进程传递信号，将其“杀死”

#### 进程的用户和组标识符（凭证）
     真实用户 ID 和组 ID：用来标识进程所属的用户和组。
    有效用户 ID 和组 ID：进程在访问受保护资源（比如，文件和进程间通信对象）
    时，会使用这两个 ID（并结合下述的补充组 ID）来确定访问权限。
     补充组 ID：用来标识进程所属的额外组。

#### 特权进程
特权进程是指有效用户 ID 为 0（超级用户）的进程。

#### 能力（Capabilities）
赋予某进程部分能力，使得其既能够执行某些特权级操作，又防止其执行其他特权级操作。

#### init 进程
所有进程之父，进程号为1
系统的所有进程由 init（使用 frok()）“亲自”创建，或由其后代进程创建。

#### 守护进程
    “长生不老”。守护进程通常在系统引导时启动，直至系统关闭前，会一直“健在”。 
     守护进程在后台运行，且无控制终端供其读取或写入数据。 
守护进程中的例子有 syslogd（在系统日志中记录消息）和 httpd（利用 HTTP 分发 Web 页面）。 

#### 环境列表

#### 资源限制
 
ulimit 命令查看

## 2.8    内存映射 

调用系统函数 mmap()的进程，会在其虚拟地址空间中创建一个新的内存映射。 

映射分为两类:
- 文件映射：将文件的部分区域映射入调用进程的虚拟内存。映射一旦完成，对文件映射内容的访问则转化为对相应内存区域的字节操作。映射页面会按需自动从文件中加载。 
- 相映成趣的是并无文件与之相对应的匿名映射，其映射页面的内容会被初始化为 0。

!! 内存映射到底是什么，没有明白，先看下后面的章节

## 2.9    静态库和共享库
目录库：将（通常是逻辑相关的）一组函数代码加以编译，并置于一个文件中，供其他应用程序调用。

#### 静态库
要使用静态库中的函数，需要在创建程序的链接命令中指定相应的库。主程序会对静态库中隶属于各目标模块的不同函数加以引用。链接器在解析了引用情况后，会从库中抽取所需目标模块的副本，将其复制到最终的可执行文件中，这就是所谓静态链接。

缺点：
- 在不同的可执行文件中，可能都存有相同目标代码的副本，这是对磁盘空间的浪费。
- 调用同一库函数的程序，若均以静态链接方式生成，且又于同时加以执行，这会造成内存浪费
- 如果对库函数进行了修改，需要重新加以编译、生成新的静态库，而所有需要调用该函数“更新版”的应用，都必须与新生成的静态库重新链接。 

#### 共享库
设计共享库的目的是为了解决静态库所存在的问题。 
共享库在运行时将可执行文件载入内存，一款名为“动态链接器”的程序会确保将可执行文件所需的动态库找到，并载入内存，随后实施运行时链接，解析可执行文件中的函数调用，将其与共享库中相应的函数定义关联起来。在运行时，共享库代码在内存中只需保留一份，且可供所有运行中的程序使用。 
经过编译处理的函数仅在共享库内保存一份，从而节约了磁盘空间。另外，这一设计还
能确保各类程序及时使用到函数的最新版本，功莫大焉，只需将带有函数新定义体的共享库重新加以编译即可，程序会在下次执行时自动使用新函数。 


## 2.10    进程间通信及同步

通信方式：
- 信号（signal），用来表示事件的发生。 
- 管道（亦即 shell 用户所熟悉的“|”操作符）和 FIFO，用于在进程间传递数据。 
- 套接字，供同一台主机或是联网的不同主机上所运行的进程之间传递数据。 
- 文件锁定，为防止其他进程读取或更新文件内容，允许某进程对文件的部分区域加以锁定。 
- 消息队列，用于在进程间交换消息（数据包）。 
- 信号量（semaphore），用来同步进程动作。 
- 共享内存，允许两个及两个以上进程共享一块内存。当某进程改变了共享内存的内容时，其他所有进程会立即了解到这一变化。 

## 2.11    信号 
内核、其他进程（只要具有相应的权限）或进程自身均可向进程发送信号。

## 2.12    线程
线程的主要优点在于协同线程之间的数据共享（通过全局变量）更为容易，
多线程应用能从多处理器硬件的并行处理中获益匪浅。 

## 2.13    进程组和 shell 任务控制
shell 执行的每个程序都会在一个新进程内发起。

## 2.14    会话、控制终端和控制进程 
对于由交互式 shell 所创建的会话，这恰恰是用户的登录终端。断开了与终端的连接，控制进程将会收到 SIGHUP 信号。 会话中运行的进程会退出， "&"后台运行 的进程也会退出。

## 2.15    伪终端
最知名的要数 telnet 和 ssh 之类提供网络登录服务

## 2.16    日期和时间

- 真实时间： unix时间戳
- 进程时间：亦称为 CPU 时间，细分为：系统 CPU 时间和用户 CPU 时间

## 2.17    客户端/服务器架构 

客户端：向服务器发送请求消息，请求服务器执行某些服务。 
服务器：分析客户端的请求，执行相应的动作，然后，向客户端回发响应消息。 

## 2.18    实时性

实时性应用程序是指那些需要对输入做出及时响应的程序。

!! 没搞懂这个实时性是什么意思

## 2.19    /proc 文件系统

/proc 文件系统是一种虚拟文件系统，以文件系统目录和文件形式，提供一个指向内核数
据结构的接口。这为查看和改变各种系统属性开启了方便之门。此外，还能通过一组以/ 
proc/PID 形式命名的目录（PID 即进程 ID）查看系统中运行各进程的相关信息。 


# 第3 章 系统编程概念 

## 3.1    系统调用 
系统调用是受控的内核入口，进程可以请求内核以自己的名义去执行某些动作。

程序调用步骤：

1. 应用程序通过调用 C 语言函数库中的外壳（wrapper）函数，来发起系统调用。 
2. 对系统调用中断处理例程（稍后介绍）来说，外壳函数必须保证所有的系统调用参数可用。通过堆栈，这些参数传入外壳函数，但内核却希望将这些参数置入特定寄存器。因此，外壳函数会将上述参数复制到寄存器。
3. 由于所有系统调用进入内核的方式相同，内核需要设法区分每个系统调用。为此，外壳函数会将系统调用编号复制到一个特殊的 CPU 寄存器（%eax）中。 
4. 外壳函数执行一条中断机器指令（int 0x80），引发处理器从用户态切换到核心态，并执行系统中断 0x80 (十进制数 128)的中断矢量所指向的代码。
5. 为响应中断 0x80，内核会调用 system_call()例程（位于汇编文件 arch/i386/entry.S 中）来
处理这次中断，具体如下。 
a） 在内核栈中保存寄存器值（参见 6.5 节）。 
b） 审核系统调用编号的有效性。 
c） 以系统调用编号对存放所有调用服务例程的列表（内核变量 sys_call_table）进行索引，发现并调用相应的系统调用服务例程。若系统调用服务例程带有参数，那么将首先检
查参数的有效性。例如，会检查地址指向用户空间的内存位置是否有效。随后，该服
务例程会执行必要的任务，这可能涉及对特定参数中指定地址处的值进行修改，以及
在用户内存和内核内存间传递数据（比如，在 I/O 操作中）。最后，该服务例程会将结
果状态返回给 system_call()例程。 
d） 从内核栈中恢复各寄存器值，并将系统调用返回值置于栈中。 
e） 返回至外壳函数，同时将处理器切换回用户态。 
6. 若系统调用服务例程的返回值表明调用有误，外壳函数会使用该值来设置全局变量 errno。然后，外壳函数会返回到调用程序，并同时返回一个整型值，以表明系统调用是否成功。

## 3.2    库函数 

## 3.3    标准 C 语言函数库；GNU C 语言函数库（glibc）

查看了 glibc 的版本号
```
root@archlinux ~$ /lib/libc.so.6                                                     
GNU C Library (GNU libc) stable release version 2.30.
Copyright (C) 2019 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 9.2.0.
libc ABIs: UNIQUE IFUNC ABSOLUTE
For bug reporting instructions, please see:
<https://bugs.archlinux.org/>.

```
## 3.4    处理来自系统调用和库函数的错误
几乎每个系统调用和库函数都会返回某类状态值，用以表明调用成功与否。

## 3.5    关于本书示例程序的注意事项
## 3.6    可移植性问题
## 3.7    总结 
系统调用允许进程向内核请求服务。与用户空间的函数调用相比，哪怕是最简单的系统调用都会产生显著的开销，其原因是为了执行系统调用，系统需要临时性地切换到核心态，此外，内核还需验证系统调用的参数、用户内存和内核内存之间也有数据需要传递。

## 3.8    练习
使用 Linux 专有的 reboot()系统调用重启系统时，必须将第二个参数 magic2 定义为一组 magic 号之一（例如，LINUX_REBOOT_MAGIC2）。这些 magic 号有何意义？（将 magic 号转换为十六进制数，对解题会有所帮助。） 

```
man 2 reboot 或cat /usr/include/linux/reboot.h

#define LINUX_REBOOT_MAGIC2  672274793
```

转为16进制:
```
printf %x 672274793   结果为28121969 （Linus生日，哈哈！）
```

# 第4章  文件 I/O：通用的 I/O 模型 

## 4.1    概述 

所有执行 I/O 操作的系统调用都以文件描述符，一个非负整数（通常是小整数），来指代打开的文件。
文件描述符用以表示所有类型的已打开文件，包括管道（pipe）、FIFO、socket、终端、设备和普通文件。针对每个进程，文件描述符都自成一套。 

常见的三类:
| 文件描述符  | 用途 | POSIX名称 |stdio 流 |
| :------| ------: | :------: |:------: |
| 0 | 标准输入 | STDIN_FILENO  | stdin  |
| 1 | 标准输出 | STDOUT_FILENO | stdout |
| 2 | 标准错误 | STDERR_FILENO | stderr |


4个IO操作调用函数:
- fd = open(pathname, flags, mode)
- numread = read(fd, buffer, count)
- numwritten = write(fd, buffer, count)
- status = close(fd)

使用上面4个调用函数实现一个copy:

fileio/copy.c

```
#include <sys/stat.h>
#include <fcntl.h>
#include "tlpi_hdr.h"

#ifndef BUF_SIZE
#define BUF_SIZE 1024
#endif

int main(int argc, char *argv[]){
    int inputFd, outputFd, openFlags;
    mode_t filePerms;
    ssize_t numRead;
    char buf[BUF_SIZE];

    if (argc !=3 || strcmp(argv[1], "--help") == 0){
        usageErr("111");
    }

    inputFd = open(argv[1], O_RDONLY);
    if(inputFd == -1){
        errExit("opening file %s", argv[1]);
    }

    openFlags = O_CREAT|O_WRONLY | O_TRUNC;
    filePerms = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP |
        S_IROTH | S_IWOTH;

    outputFd = open(argv[2], openFlags, filePerms);
    if (outputFd == -1) {
        errExit("opening file %s", argv[2]);
    }

    while ((numRead = read(inputFd, buf, BUF_SIZE)) > 0) {
      if (write(outputFd, buf, numRead) != numRead) {
          fatal("could't write whole buffer");
      }
    }

    if (numRead == -1) {
        errExit("read");
    }

    if (close(inputFd) == -1) {
        errExit("close input");
    }

    if (close(outputFd) == -1) {
        errExit("close output");
    }
    exit(EXIT_SUCCESS);
}

```

## 4.2 通过I/O

UNIX I/O 模型的显著特点之一是其输入/输出的通用性概念。这意味着使用 4 个同样的系
统调用 open()、read()、write()和 close()可以对所有类型的文件执行 I/O 操作，包括终端之类的
设备。

## 4.3 打开一个文件：open() 
open()调用既能打开一个业已存在的文件，也能创建并打开一个新文件。

```
int open(const char *pathname, int flags, ... /* mode_t mode */);
```

调用成功，open()将返回一文件描述符，若发生错误，则返回−1，并将 errno 置为相应的错误标志。 

pathname:
  文件路径，如果是符号链接，会对期解引用。

flags:

| 访问模式| 描述| 数字标识|
| :----| ----: | ---- |
| O_RDONLY |以只读方式打开文件 | 0  |
| O_WRONLY | 以只写方式打开文件| 1  |
| O_RDWR | 以读写方式打开文件  | 2  |

mode:
当需要创建新文件时，mode表示文件权限

**open()调用所返回的文件描述符数值**

```
#include <stdio.h>

int main(int argc, char *argv[]) {
    int fd;
    // close(STDIN_FILENO);    # 取消注释，fd会打印0
    fd = open("test", O_RDONLY);
    printf("%d", fd);
}
```

如果调用 open()成功，必须保证其返回值为进程未用文件描述符中数值最小者。(切记，是进程，而不是系统全局)
一个open会有一个文件描述符，这个也是linux中要把ulimit中的open files(-n)值设置的更大一点。

### 4.3.1    open()调用中的 flags 参数

多个flags以`|` 连接。 比如 `open('/tmp/text.txt', O_WRONLY | O_CREAT )`

flags参数介绍:

| 标志      | 用途                                          | 统一 UNIX 规范版本 |
| :---      | -------------------------------:             | ----------------- |
| O_RDONLY  |以只读方式打开文件                             |   v3  |
| O_WRONLY  |以只写方式打开文件                             |   v3  |
| O_RDWR    |以读写方式打开文件                             |   v3  |
|O_CLOEXEC  |设置 close-on-exec 标志                       |   v4  |
|O_CREAT    |若文件不存在则创建之                           |   v3  |
|O_DIRECT   |无缓冲的输入/输出                              |       |
|O_DIRECTORY|如果 pathname 不是目录，则失败                 |   v4  | 
|O_EXCL     |结合 O_CREAT 参数使用，专门用于创建文件,文件存在会报错|  v3   | 
|O_LARGEFILE|在 32 位系统中使用此标志打开大文件              |       | 
|O_NOATIME  |调用 read()时，不修改文件最近访问时间(Linux 2.6.8开始)|| 
|O_NOCTTY   |不要让 pathname（所指向的终端设备）成为控制终端  |  v3  | 
|O_NOFOLLOW |对符号链接不予解引用                           |   v4  | 
|O_TRUNC    |截断已有文件，使其长度为零                      |  v3  |
|O_APPEND   |总在文件尾部追加数据                           |   v3  | 
|O_ASYNC    |当 I/O 操作可行时，产生信号（signal）通知进程   |       |
|O_DSYNC    |提供同步的 I/O 数据完整性（自 Linux 2.6.33 版本开始）| v3| 
|O_NONBLOCK |以非阻塞方式打开                               |   v3  | 
|O_SYNC     |以同步方式写入文件                             |   v3  | 


### 4.3.2   open()函数的错误 

open()将返回−1，错误号 errno 标识错误原因

- EACCES    权限错误
- EISDIR    是个目录
- EMFILE    进程打开文件描述符已到上限
- ENFILE    文件打开数达到系统允许上限
- ENOENT    文件不存在
- EROFS     只读文件系统，企图写入
- ETXTBSY   所指定的文件为可执行文件（程序），且正在运行

其它的可以通过`main 2 open`查看

### 4.3.3    creat()系统调用 

早期，open只有两个参数，不能创建文件， 需要使用`creat`。
现在安心用open就行。
```
#include <fcntl.h>
int creat(const char *pathname, mode_t mode);
```

`creat`相当于`open(pathname, O_CREAT|O_WRONLY|O_TRUNC, mode)`


## 4.4  读取文件内容：read() 

read()系统调用从文件描述符 fd 所指代的打开文件中读取数据。 

```
#include <unistd.h>

ssize_t read(int fd, void *buf, size_t count);

```

count 参数指定最多能读取的字节数。（size_t 数据类型属于无符号整数类型。）buffer 参数
提供用来存放输入数据的内存缓冲区地址。缓冲区至少应有 count 个字节。 

如果 read()调用成功，将返回实际读取的字节数，如果遇到文件结束（EOF）则返回 0，
如果出现错误则返回-1。ssize_t 数据类型属于有符号的整数类型，用来存放（读取的）字节数
或-1（表示错误）。 
一次 read()调用所读取的字节数可以小于请求的字节数。对于普通文件而言，这有可能是
因为当前读取位置靠近文件尾部。 
当 read()应用于其他文件类型时，比如管道、FIFO、socket 或者终端，在不同环境下也会
出现 read()调用读取的字节数小于请求字节数的情况。例如，默认情况下从终端读取字符，一
遇到换行符（\n），read()调用就会结束。

## 4.5   数据写入文件：write() 
write()系统调用将数据写入一个已打开的文件中。 
```
#include <unistd.h>
ssize_t write(int fd, const void *buf, size_t count);
```

buffer 参数为要写入文件中数据的内存地址，count参数为欲从 buffer 写入文件的数据字节数，fd 参数为一文件描述符，指代数据要写入的文件。 

如果 write()调用成功，将返回实际写入文件的字节数，该返回值可能小于 count 参数值。
这被称为“部分写”。对磁盘文件来说，造成“部分写”的原因可能是由于磁盘已满，或是因
为进程资源对文件大小的限制。

write()调用成功并不能保证数据已经写入磁盘。因为为了减少磁盘活动量和加快 write()系统调用，内核会缓存磁盘的 I/O 操作。

## 4.6    关闭文件：close() 
close()系统调用关闭一个打开的文件描述符，并将其释放回调用进程，供该进程继续使用。
**当一进程终止时，将自动关闭其已打开的所有文件描述符。**

```
#include <unistd.h>

int close(int fd);
```
文件描述符属于有限资源，因此文件描述符关闭失败可能会导致一个进程将文件描述符资源消耗殆尽。

## 4.7    改变文件偏移量：lseek() 

对于每个打开的文件，系统内核会记录其文件偏移量，有时也将文件偏移量称为读写偏
移量或指针。文件偏移量是指执行下一个 read()或 write()操作的文件起始位置，会以相对于文
件头部起始点的文件当前位置来表示。文件第一个字节的偏移量为 0。 


```
#include <sys/types.h>
#include <unistd.h>

off_t lseek(int fd, off_t offset, int whence);

```

offset 参数指定了一个以`字节`为单位的数值。（SUSv4 规定 off_t 数据类型为有符号整型数。）whence 参数则表明应参照哪个基点来解释 offset 参数，应为下列其中之一：

- SEEK_SET 文件头部起始点。
- SEEK_CUR 相对于当前文件偏移量
- SEEK_END 起始于文件尾部的 offset个字节

*如果 whence 参数值为 SEEK_CUR 或 SEEK_END，offset 参数可以为正数也可以为负数； 如果 whence 参数值为 SEEK_SET，offset 参数值必须为非负数*

**几个实例**
```
lseek(fd, 0, SEEK_SET)    /* 文件开头 */
lseek(fd, 0, SEEK_END)    /* 文件结尾 */
lseek(fd, -1, SEEK_END)    /* 文件最后一个字节 */
lseek(fd, -10, SEEK_CUR)    /* 当前位置往前10个字节 */
lseek(fd, 10000, SEEK_END)    /* 文件结尾后的10001个字节 */
```

**注意点**

- lseek()调用只是调整内核中与文件描述符相关的文件偏移量记录，并没有引起对任何物理 设备的访问。
- 不允许将 lseek()应用于管道、FIFO、socket 或者终端
- 只要合情合理，也可以将 lseek() 应用于设备。例如，在磁盘或者磁带上查找一处具体位置。 

**文件空洞**
如果程序的文件偏移量已然跨越了文件结尾，然后再执行 I/O 操作, read()调用将返回 0，表示文件结尾。write()函数可以在文件结尾后的任意位置写入数据, 从文件结尾后到新写入数据间的这段空间被称为文件空洞。 
文件空洞中 是存在字节的，读取空洞将返回以 0（空字节）填充的缓冲区。 但是不占用任何磁盘空间。
空洞的存在意味着一个文件名义上的大小可能要比其占用的磁盘存储总量要大。

**示例程序**

```c
#include <stdio.h>
#include <fcntl.h>
#include <ctype.h>
#include "tlpi_hdr.h"

int main(int argc, char *argv[]) {
    size_t len;
    off_t offset;
    int fd, ap, j;
    char *buf;
    ssize_t numRead, numWritten;

    if(argc <3 || strcmp(argv[1], "--help") == 0)
        usageErr("%s file {r<length>|R<length>|w<string}|s<offset>...\n", argv[0]);

    fd = open(argv[1], O_RDWR|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
    if(fd == -1)
        errExit("open");

    for (ap = 2; ap < argc; ap++) {
      switch (argv[ap][0]) {
      case 'r':
      case 'R':
          len = getLong(&argv[ap][1],GN_ANY_BASE , argv[ap]);
          buf = malloc(len);
          if(buf== NULL)
              errExit("malloc");
          numRead = read(fd, buf, len);
          if (numRead == -1)
              errExit("read");

          if (numRead == 0) {
              printf("%s: end-of-file\n", argv[ap]);
          } else {
              printf("%s: ", argv[ap]);
              for (j = 0; j < numRead; j++) {
                  if(argv[ap][0] == 'r')
                      printf("%c", isprint((unsigned char) buf[j]) ? buf[j] : '?');
                  else
                      printf("%02x ", (unsigned int) buf[j]);
              }
              printf("\n");
          }
          free(buf);
          break;

      case 'w':
          numWritten = write(fd, &argv[ap][1], strlen(&argv[ap][1]));
          if(numWritten == -1)
              errExit("write");
          printf("%s: wrote %ld bytes\n", argv[ap], (long) numWritten);
          break;
      case 's':
          offset = getLong(&argv[ap][1], GN_ANY_BASE, argv[ap]);
          if(lseek(fd, offset, SEEK_SET) == -1)
              errExit("lseek");
          printf("%s: seek succeeded\n", argv[ap]);
          break;
      default:
          cmdLineErr("Argument must start with [rRws]: %s\n", argv[ap]);
      }
    }
    exit(EXIT_SUCCESS);
}

```

## 4.8 通用 I/O 模型以外的操作：ioctl() 

ioctl()系统调用又为执行文件和设备操作提供了一种多用途机制。

```
#include <sys/ioctl.h>

int ioctl(int fd, unsigned long request, ...);
```

具体怎么用，后面会有介绍

## 4.9 总结
I/O操作核心：open、文件偏移量(read、write)、close

## 4.10 练习

4-1.  tee 命令是从标准输入中读取数据，直至文件结尾，随后将数据写入标准输出和命令行参数所指定的文件。（44.7 节讨论 FIFO 时，会展示使用 tee 命令的一个例子。）请使用I/O 系统调用实现 tee 命令。默认情况下，若已存在与命令行参数指定文件同名的文件，tee 命令会将其覆盖。如文件已存在，请实现-a 命令行选项（tee-a  file）在文件结尾处追加数据。（请参考附录 B 中对 getopt()函数的描述来解析命令行选项。） 