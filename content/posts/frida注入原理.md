+++
title='frida'
draft = false
+++
## 1.spawn模式注入so的实现原理
核心思想是先向zygote进程注入一个mon.so，这样它运行在zygote进程，就可以轻而易举的实现对zygote进程中函数的hook，通过hook fork系列函数，在fork触发之后再安装对setArgV0的hook，在setArgV0函数触发时判断是否是目标app，从而确定是否dlopen需要注入的so，

## 2.**远程读写：**

当前frida采用直接读写`/proc/<zygote>/mem`的形式进行远程读写(这个操作挂圈好像用的很多)。`/proc/[pid]/mem`是通过文件系统接口暴露的进程虚拟内存空间的直接读写通道，它像一个窗户，窗户内部是进程的完整虚拟地址空间，那么要如何精准的在这块空间里找到我们想要的东西呢？那就需要先去读`/proc/[pid]/maps`，map翻译过来是地图的意思，事实也的确如此，`maps`就像是这块空间的一张地图，通过它就可以定位到我们想要的位置
## 3.改进点-如何修改java函数entry_point进行hook
因为setArgV0函数是用于设置进程名的，在app启动时它会被稳定触发，所以完全可以跳过对fork函数的hook，直接hook setArgV0。其次就是zygote里驻留的so不是很好清理，以及selinux的问题处理的也很粗糙.
setArgV0函数这是一个JNI函数，对于JNI函数，它在java层就会有一个对应的java函数，那我们直接hook对应的java函数就好了。这个就很熟悉了，直接修改对应java函数的ArtMethod的`entry_point`即可，完全不需要inline hook了
问题
1. 如何定位目标函数的`entry_point`并修改
2. 我们的hook函数该如何注入到zygote进程
第一个问题解决办法
1.Frida找到 JNI 函数`android_os_Process_setArgV0`的符号地址 
2.在内存中搜索指向该地址的指针
Frida 通过读取 zygote 进程的堆内存，搜索包含这个地址的位置：
```
// src/linux/linux-host-session.vala:1007-1027
uint pointer_size = ("/lib64/" in libc_path) ? 8 : 4;

var original_ptr = new uint8[pointer_size];
var replaced_ptr = new uint8[pointer_size];

// 将地址编码为字节数组
(new Buffer (new Bytes.static (original_ptr), ByteOrder.HOST, pointer_size))
    .write_pointer (0, set_argv0_address);
(new Buffer (new Bytes.static (replaced_ptr), ByteOrder.HOST, pointer_size))
    .write_pointer (0, payload_base);

var fd = open_process_memory (pid);

uint64 art_method_slot = 0;
bool already_patched = false;

// 遍历堆内存区域
foreach (var candidate in heap_candidates) {
    var heap = new uint8[candidate.size];
    var n = fd.pread (heap, candidate.base_address);
    
    // 在堆内存中搜索这个指针值
    void * p = memmem (heap, original_ptr);
    if (p == null) {
        p = memmem (heap, replaced_ptr);
        already_patched = p != null;
    }
    
    if (p != null) {
        // 找到了，计算 ArtMethod 的 entry_point 字段地址
        art_method_slot = candidate.base_address + ((uint8 *) p - (uint8 *) heap);
        break;
    }
}
```
这样就拿到了`art_method_slot`的地址，即存储了指向`android_os_Process_setArgV0`地址的字段的地址，接下来通过上面提到的，读写`/proc/<zygote>/mem`来实现修改该字段，但在修改之前，需要备份一下原始指向的函数地址，后面注入成功/失败之后需要unhook，会用到原本的值
## 3.改进点-注入到zygote由so改为机器码
![[aa9f52acb7fa7654216dd3219cfa598b.jpg]]