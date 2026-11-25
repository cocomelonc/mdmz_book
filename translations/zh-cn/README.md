# MD MZ 恶意软件开发（第二版）—— 简体中文译本

本目录为 [MD MZ Book](https://github.com/cocomelonc/mdmz_book) 第二版（`mdmz2/`）的**简体中文**翻译。

- **原文**：[MD MZ Book second version (2024)](https://cocomelonc.github.io/book/2024/11/29/mybook-2.html)
- **章节数**：101 章，章号与原书目录逐一对应
- **翻译性质**：AI 辅助翻译（AI-assisted translation）＋人工技术审校

## 章节对照

| 文件 | 章节 |
|---|---|
| [1-intro.md](1-intro.md) | 第 1 章 引言 |
| [2-malwdev.md](2-malwdev.md) | 第 2 章 什么是恶意软件开发？ |
| [3-revsh.md](3-revsh.md) | 第 3 章 反向 shell |
| [4-malware-tricks-1.md](4-malware-tricks-1.md) | 第 4 章 经典代码注入：简单的 C++ 恶意软件 |
| [5-malware-tricks-2.md](5-malware-tricks-2.md) | 第 5 章 经典 DLL 注入：简单的 C++ 恶意软件 |
| [6-dll-hijacking.md](6-dll-hijacking.md) | 第 6 章 Windows 中的 DLL 劫持：简单的 C 示例 |
| [7-findproc.md](7-findproc.md) | 第 7 章 按名称查找进程 ID 并向其注入：简单的 C++ 示例 |
| [8-linux-shellcoding-1.md](8-linux-shellcoding-1.md) | 第 8 章 Linux shellcode 编写：示例 |
| [9-linux-shellcoding-2.md](9-linux-shellcoding-2.md) | 第 9 章 Linux shellcode 编写：反向 TCP shellcode |
| [10-windows-shellcoding-1.md](10-windows-shellcoding-1.md) | 第 10 章 Windows shellcode 编写（第 1 部分）：简单示例 |
| [11-windows-shellcoding-2.md](11-windows-shellcoding-2.md) | 第 11 章 Windows shellcode 编写（第 2 部分）：查找 kernel32 地址 |
| [12-windows-shellcoding-3.md](12-windows-shellcoding-3.md) | 第 12 章 Windows shellcode 编写（第 3 部分）：PE 文件格式 |
| [13-malware-tricks-3.md](13-malware-tricks-3.md) | 第 13 章 APC 注入技术：简单的 C++ 恶意软件 |
| [14-malware-tricks-4.md](14-malware-tricks-4.md) | 第 14 章 通过 NtTestAlert 进行 APC 注入：简单的 C++ 恶意软件 |
| [15-malware-tricks-5.md](15-malware-tricks-5.md) | 第 15 章 通过可警报线程进行 APC 注入：简单的 C++ 恶意软件 |
| [16-malware-tricks-6.md](16-malware-tricks-6.md) | 第 16 章 通过线程劫持进行代码注入：简单的 C++ 恶意软件 |
| [17-malware-tricks-7.md](17-malware-tricks-7.md) | 第 17 章 通过 SetWindowsHookEx 进行经典 DLL 注入：简单的 C++ 恶意软件 |
| [18-malware-tricks-8.md](18-malware-tricks-8.md) | 第 18 章 通过 Windows 纤程进行代码注入：简单的 C++ 恶意软件 |
| [19-basic-hooking.md](19-basic-hooking.md) | 第 19 章 Windows API 挂钩：简单的 C++ 示例 |
| [20-inline-asm.md](20-inline-asm.md) | 第 20 章 通过内联汇编运行 shellcode：简单的 C++ 示例 |
| [21-malware-tricks-9.md](21-malware-tricks-9.md) | 第 21 章 通过未文档化的 NtCreateThreadEx 进行 DLL 注入：简单的 C++ 示例 |
| [22-malware-tricks-10.md](22-malware-tricks-10.md) | 第 22 章 通过未文档化的 NtAllocateVirtualMemory 进行代码注入：简单的 C++ 示例 |
| [23-malware-tricks-11.md](23-malware-tricks-11.md) | 第 23 章 通过未文档化的原生 API 函数进行代码注入：简单的 C++ 示例 |
| [24-malware-tricks-12.md](24-malware-tricks-12.md) | 第 24 章 通过内存节进行代码注入：简单的 C++ 示例 |
| [25-malware-tricks-13.md](25-malware-tricks-13.md) | 第 25 章 通过 ZwCreateSection 进行代码注入：简单的 C++ 恶意软件示例 |
| [26-malware-tricks-14.md](26-malware-tricks-14.md) | 第 26 章 通过内存节与 ZwQueueApcThread 进行代码注入：简单的 C++ 恶意软件示例 |
| [27-malware-tricks-15.md](27-malware-tricks-15.md) | 第 27 章 通过 KernelCallbackTable 进行进程注入：简单的 C++ 恶意软件示例 |
| [28-malware-tricks-16.md](28-malware-tricks-16.md) | 第 28 章 通过 RWX 内存搜寻进行进程注入：简单的 C++ 示例 |
| [29-basic-hooking-2.md](29-basic-hooking-2.md) | 第 29 章 Windows API 挂钩（第 2 部分）：简单的 C++ 示例 |
| [30-malware-tricks-17.md](30-malware-tricks-17.md) | 第 30 章 通过 FindWindow 进行进程注入：简单的 C++ 示例 |
| [31-malware-tricks-18.md](31-malware-tricks-18.md) | 第 31 章 恶意软件开发技巧：以汇编方式查找 kernel32.dll 基址（C++ 示例） |
| [32-malware-tricks-19.md](32-malware-tricks-19.md) | 第 32 章 恶意软件开发技巧：下载并注入逻辑（C++ 示例） |
| [33-malware-tricks-20.md](33-malware-tricks-20.md) | 第 33 章 恶意软件开发技巧：通过 EnumDesktopsA 运行 shellcode（C++ 示例） |
| [34-malware-tricks-21.md](34-malware-tricks-21.md) | 第 34 章 恶意软件开发技巧：通过 EnumChildWindows 运行 shellcode（C++ 示例） |
| [35-malware-tricks-22.md](35-malware-tricks-22.md) | 第 35 章 恶意软件开发技巧：像 Lazarus Group 那样运行 shellcode（C++ 示例） |
| [36-malware-tricks-23.md](36-malware-tricks-23.md) | 第 36 章 恶意软件开发技巧：父进程 PID 欺骗（简单的 C++ 示例） |
| [37-malware-tricks-24.md](37-malware-tricks-24.md) | 第 37 章 恶意软件开发技巧：Listplanting（C++ 示例） |
| [38-malware-tricks-25.md](38-malware-tricks-25.md) | 第 38 章 恶意软件开发技巧：EnumerateLoadedModules（C++ 示例） |
| [39-malware-tricks-26.md](39-malware-tricks-26.md) | 第 39 章 恶意软件开发技巧：互斥体（C++ 示例） |
| [40-malware-tricks-27.md](40-malware-tricks-27.md) | 第 40 章 恶意软件开发技巧：WinAPI LoadLibrary 实现（简单的 C++ 示例） |
| [41-malware-tricks-28.md](41-malware-tricks-28.md) | 第 41 章 恶意软件开发技巧：转储 lsass.exe（简单的 C++ 示例） |
| [42-malware-tricks-29.md](42-malware-tricks-29.md) | 第 42 章 恶意软件开发技巧：在注册表中存储二进制数据（简单的 C++ 示例） |
| [43-malware-tricks-30.md](43-malware-tricks-30.md) | 第 43 章 恶意软件开发技巧：通过 NtGetNextProcess 查找 PID（简单的 C++ 示例） |
| [44-malware-tricks-31.md](44-malware-tricks-31.md) | 第 44 章 恶意软件开发技巧：通过 SetTimer 运行 shellcode（简单的 C++ 示例） |
| [45-malware-tricks-34.md](45-malware-tricks-34.md) | 第 45 章 恶意软件开发技巧：通过 WTSEnumerateProcesses 查找 PID（简单的 C++ 示例） |
| [46-malware-tricks-35.md](46-malware-tricks-35.md) | 第 46 章 恶意软件开发技巧：在备用数据流中存储载荷（简单的 C++ 示例） |
| [47-malware-tricks-36.md](47-malware-tricks-36.md) | 第 47 章 恶意软件开发技巧：枚举进程模块（简单的 C++ 示例） |
| [48-malware-tricks-37.md](48-malware-tricks-37.md) | 第 48 章 恶意软件开发技巧：通过 VirtualQueryEx 枚举进程模块（简单的 C++ 示例） |
| [49-malware-tricks-38.md](49-malware-tricks-38.md) | 第 49 章 恶意软件开发技巧：RWX 搜寻（第 2 部分）——目标进程调查技巧（简单的 C/C++ 示例） |
| [50-malware-tricks-39.md](50-malware-tricks-39.md) | 第 50 章 恶意软件开发技巧：通过 EnumDesktopsA 运行载荷（简单的 Nim 示例） |
| [51-malware-tricks-40.md](51-malware-tricks-40.md) | 第 51 章 恶意软件开发技巧：通过合法的 Telegram API 窃取数据（简单的 C 示例） |
| [52-malware-tricks-41.md](52-malware-tricks-41.md) | 第 52 章 恶意软件开发技巧：通过合法的 VirusTotal API 窃取数据（简单的 C 示例） |
| [53-malware-tricks-42.md](53-malware-tricks-42.md) | 第 53 章 恶意软件开发技巧：通过合法的 Discord Bot API 窃取数据（简单的 C 示例） |
| [54-malware-av-evasion-1.md](54-malware-av-evasion-1.md) | 第 54 章 针对简单 C++ 恶意软件的 AV 引擎规避 |
| [55-malware-av-evasion-2.md](55-malware-av-evasion-2.md) | 第 55 章 针对简单 C++ 恶意软件的 AV 引擎规避（第 2 部分） |
| [56-malware-av-evasion-3.md](56-malware-av-evasion-3.md) | 第 56 章 AV 引擎规避技术（第 3 部分）：简单的 C++ 示例 |
| [57-malware-av-evasion-4.md](57-malware-av-evasion-4.md) | 第 57 章 AV 引擎规避技术（第 4 部分）：简单的 C++ 示例 |
| [58-malware-av-evasion-5.md](58-malware-av-evasion-5.md) | 第 58 章 AV 引擎规避技术（第 5 部分）：简单的 C++ 示例 |
| [59-malware-av-evasion-6.md](59-malware-av-evasion-6.md) | 第 59 章 AV/VM 引擎规避技术（第 6 部分）：简单的 C++ 示例 |
| [60-malware-av-evasion-7.md](60-malware-av-evasion-7.md) | 第 60 章 恶意软件 AV 规避（第 7 部分）：禁用 Windows Defender（简单的 C++ 示例） |
| [61-malware-av-evasion-8.md](61-malware-av-evasion-8.md) | 第 61 章 恶意软件 AV 规避（第 8 部分）：通过 Z85 算法编码载荷（C++ 示例） |
| [62-malware-av-evasion-9.md](62-malware-av-evasion-9.md) | 第 62 章 恶意软件 AV 规避（第 9 部分）：通过 RC4 加密 Base64 编码的载荷（C++ 示例） |
| [63-malware-av-evasion-10.md](63-malware-av-evasion-10.md) | 第 63 章 恶意软件 AV/VM 规避（第 10 部分）：反调试之 NtGlobalFlag（简单的 C++ 示例） |
| [64-malware-av-evasion-11.md](64-malware-av-evasion-11.md) | 第 64 章 恶意软件 AV/VM 规避（第 11 部分，博客第 15 篇）：WinAPI GetModuleHandle 实现（简单的 C++ 示例） |
| [65-malware-av-evasion-12.md](65-malware-av-evasion-12.md) | 第 65 章 恶意软件 AV/VM 规避（第 12 部分，博客第 16 篇）：WinAPI GetProcAddress 实现（简单的 C++ 示例） |
| [66-malware-av-evasion-13.md](66-malware-av-evasion-13.md) | 第 66 章 恶意软件 AV/VM 规避（第 13 部分，博客第 17 篇）：通过 fodhelper.exe 绕过 UAC（简单的 C++ 示例） |
| [67-malware-pers-1.md](67-malware-pers-1.md) | 第 67 章 恶意软件开发：持久化（第 1 部分）——注册表运行项（C++ 示例） |
| [68-malware-pers-2.md](68-malware-pers-2.md) | 第 68 章 恶意软件开发：持久化（第 2 部分）——屏幕保护程序劫持（C++ 示例） |
| [69-malware-pers-3.md](69-malware-pers-3.md) | 第 69 章 恶意软件开发：持久化（第 3 部分）——COM DLL 劫持（简单的 C++ 示例） |
| [70-malware-pers-4.md](70-malware-pers-4.md) | 第 70 章 恶意软件开发：持久化（第 4 部分）——Windows 服务（简单的 C++ 示例） |
| [71-malware-pers-5.md](71-malware-pers-5.md) | 第 71 章 恶意软件开发：持久化（第 5 部分）——AppInit_DLLs（简单的 C++ 示例） |
| [72-malware-pers-6.md](72-malware-pers-6.md) | 第 72 章 恶意软件开发：持久化（第 6 部分）——Windows netsh 辅助 DLL（简单的 C++ 示例） |
| [73-malware-pers-7.md](73-malware-pers-7.md) | 第 73 章 恶意软件开发：持久化（第 7 部分）——Winlogon（简单的 C++ 示例） |
| [74-malware-pers-8.md](74-malware-pers-8.md) | 第 74 章 恶意软件开发：持久化（第 8 部分）——端口监视器（简单的 C++ 示例） |
| [75-malware-pers-9.md](75-malware-pers-9.md) | 第 75 章 恶意软件开发：持久化（第 9 部分）——默认文件扩展名劫持（简单的 C++ 示例） |
| [76-malware-pers-10.md](76-malware-pers-10.md) | 第 76 章 恶意软件开发：持久化（第 10 部分）——使用映像文件执行选项（简单的 C++ 示例） |
| [77-malware-pers-11.md](77-malware-pers-11.md) | 第 77 章 恶意软件开发：持久化（第 11 部分）——PowerShell 配置文件（简单的 C++ 示例） |
| [78-malware-pers-12.md](78-malware-pers-12.md) | 第 78 章 恶意软件开发：持久化（第 12 部分）——辅助功能（简单的 C++ 示例） |
| [79-malware-pers-13.md](79-malware-pers-13.md) | 第 79 章 恶意软件开发：持久化（第 13 部分）——劫持应用程序的卸载逻辑（简单的 C++ 示例） |
| [80-malware-pers-14.md](80-malware-pers-14.md) | 第 80 章 恶意软件开发：持久化（第 14 部分）——事件查看器帮助链接（简单的 C++ 示例） |
| [81-malware-pers-15.md](81-malware-pers-15.md) | 第 81 章 恶意软件开发：持久化（第 15 部分）——Internet Explorer（简单的 C++ 示例） |
| [82-malware-pers-16.md](82-malware-pers-16.md) | 第 82 章 恶意软件开发：持久化（第 16 部分）——加密注册表项（简单的 C++ 示例） |
| [83-malware-pers-17.md](83-malware-pers-17.md) | 第 83 章 恶意软件开发：持久化（第 17 部分）——APT 技术：通过 UpdateProcThreadAttribute 窃取令牌（简单的 C++ 示例） |
| [84-malware-pers-18.md](84-malware-pers-18.md) | 第 84 章 恶意软件开发：持久化（第 18 部分）——Windows 错误报告（简单的 C++ 示例） |
| [85-malware-pers-19.md](85-malware-pers-19.md) | 第 85 章 恶意软件开发：持久化（第 19 部分）——磁盘清理实用工具（简单的 C++ 示例） |
| [86-malware-pers-20.md](86-malware-pers-20.md) | 第 86 章 恶意软件开发：持久化（第 20 部分）——UserInitMprLogonScript（登录脚本）（简单的 C++ 示例） |
| [87-malware-pers-21.md](87-malware-pers-21.md) | 第 87 章 恶意软件开发：持久化（第 21 部分）——回收站、我的文档 COM 扩展处理程序（简单的 C++ 示例） |
| [88-malware-pers-22.md](88-malware-pers-22.md) | 第 88 章 恶意软件开发：持久化（第 22 部分）——Windows 安装程序（简单的 C++ 示例） |
| [89-malware-pers-23.md](89-malware-pers-23.md) | 第 89 章 恶意软件开发：持久化（第 23 部分）——LNK 文件（简单的 PowerShell 示例） |
| [90-malware-pers-24.md](90-malware-pers-24.md) | 第 90 章 恶意软件开发：持久化（第 24 部分）——StartupApproved（简单的 C 示例） |
| [91-malware-pers-25.md](91-malware-pers-25.md) | 第 91 章 恶意软件开发：持久化（第 25 部分）——从合法程序创建指向恶意程序的符号链接（简单的 C 示例） |
| [92-malware-cryptography-1.md](92-malware-cryptography-1.md) | 第 92 章 恶意软件与密码学研究（第 1 部分，第 29 篇）：LOKI 载荷加密（简单的 C 示例） |
| [93-malware-cryptography-2.md](93-malware-cryptography-2.md) | 第 93 章 恶意软件与密码学研究（第 2 部分，第 30 篇）：Khufu 载荷加密（简单的 C 示例） |
| [94-malware-cryptography-3.md](94-malware-cryptography-3.md) | 第 94 章 恶意软件与密码学研究（第 3 部分，第 31 篇）：CAST-128 载荷加密（简单的 C 示例） |
| [95-maware-cryptography-4.md](95-maware-cryptography-4.md) | 第 95 章 恶意软件与密码学研究（第 4 部分，第 32 篇）：通过 FEAL-8 算法加密载荷（简单的 C 示例） |
| [96-malware-cryptography-5.md](96-malware-cryptography-5.md) | 第 96 章 恶意软件与密码学研究（第 5 部分，第 33 篇）：通过 Lucifer 算法加密载荷（简单的 C 示例） |
| [97-malware-cryptography-6.md](97-malware-cryptography-6.md) | 第 97 章 恶意软件与密码学研究（第 6 部分，第 34 篇）：通过 DFC 算法加密载荷（简单的 C 示例） |
| [98-intro-to-linux-hacking-1.md](98-intro-to-linux-hacking-1.md) | 第 98 章 Linux 恶意软件开发 1：内核黑客技术入门（简单的 C 示例） |
| [99-intro-to-linux-hacking-2.md](99-intro-to-linux-hacking-2.md) | 第 99 章 Linux 恶意软件开发 2：按名称查找进程 ID（简单的 C 示例） |
| [100-intro-to-linux-hacking-3.md](100-intro-to-linux-hacking-3.md) | 第 100 章 Linux 恶意软件开发 3：使用 ptrace 进行 Linux 进程注入（简单的 C 示例） |
| [101-finall.md](101-finall.md) | 第 101 章 结语 |

## 构建 PDF

与仓库根目录 README 相同的方式（pandoc）：

```bash
pandoc -f markdown-implicit_figures --pdf-engine=xelatex \
  -V mainfont="Amiri" -V colorlinks=true -V linkcolor=blue \
  -o "MD MZ 2nd edition-zh-cn.pdf" 1-intro.md 2-malwdev.md 3-revsh.md 4-malware-tricks-1.md 5-malware-tricks-2.md 6-dll-hijacking.md 7-findproc.md 8-linux-shellcoding-1.md 9-linux-shellcoding-2.md 10-windows-shellcoding-1.md 11-windows-shellcoding-2.md 12-windows-shellcoding-3.md 13-malware-tricks-3.md 14-malware-tricks-4.md 15-malware-tricks-5.md 16-malware-tricks-6.md 17-malware-tricks-7.md 18-malware-tricks-8.md 19-basic-hooking.md 20-inline-asm.md 21-malware-tricks-9.md 22-malware-tricks-10.md 23-malware-tricks-11.md 24-malware-tricks-12.md 25-malware-tricks-13.md 26-malware-tricks-14.md 27-malware-tricks-15.md 28-malware-tricks-16.md 29-basic-hooking-2.md 30-malware-tricks-17.md 31-malware-tricks-18.md 32-malware-tricks-19.md 33-malware-tricks-20.md 34-malware-tricks-21.md 35-malware-tricks-22.md 36-malware-tricks-23.md 37-malware-tricks-24.md 38-malware-tricks-25.md 39-malware-tricks-26.md 40-malware-tricks-27.md 41-malware-tricks-28.md 42-malware-tricks-29.md 43-malware-tricks-30.md 44-malware-tricks-31.md 45-malware-tricks-34.md 46-malware-tricks-35.md 47-malware-tricks-36.md 48-malware-tricks-37.md 49-malware-tricks-38.md 50-malware-tricks-39.md 51-malware-tricks-40.md 52-malware-tricks-41.md 53-malware-tricks-42.md 54-malware-av-evasion-1.md 55-malware-av-evasion-2.md 56-malware-av-evasion-3.md 57-malware-av-evasion-4.md 58-malware-av-evasion-5.md 59-malware-av-evasion-6.md 60-malware-av-evasion-7.md 61-malware-av-evasion-8.md 62-malware-av-evasion-9.md 63-malware-av-evasion-10.md 64-malware-av-evasion-11.md 65-malware-av-evasion-12.md 66-malware-av-evasion-13.md 67-malware-pers-1.md 68-malware-pers-2.md 69-malware-pers-3.md 70-malware-pers-4.md 71-malware-pers-5.md 72-malware-pers-6.md 73-malware-pers-7.md 74-malware-pers-8.md 75-malware-pers-9.md 76-malware-pers-10.md 77-malware-pers-11.md 78-malware-pers-12.md 79-malware-pers-13.md 80-malware-pers-14.md 81-malware-pers-15.md 82-malware-pers-16.md 83-malware-pers-17.md 84-malware-pers-18.md 85-malware-pers-19.md 86-malware-pers-20.md 87-malware-pers-21.md 88-malware-pers-22.md 89-malware-pers-23.md 90-malware-pers-24.md 91-malware-pers-25.md 92-malware-cryptography-1.md 93-malware-cryptography-2.md 94-malware-cryptography-3.md 95-maware-cryptography-4.md 96-malware-cryptography-5.md 97-malware-cryptography-6.md 98-intro-to-linux-hacking-1.md 99-intro-to-linux-hacking-2.md 100-intro-to-linux-hacking-3.md 101-finall.md --mathjax
```

图片使用仓库 `mdmz2/images/` 下的原始素材（与其他语言译本做法一致）。

## 翻译约定

- 代码块、命令行、注册表路径、标识符按原文保留，不作翻译。
- 技术术语遵循统一术语表，一词一译。
- 段落划分较原 Markdown 更细，内容完全覆盖原文。
