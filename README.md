# BlindEDR-TCP

本程序通过调用底层 NtDeviceIoControlFile 向 \\.\Nsi 网络堆栈接口发送控制命令，结合自定义结构体 NSI_SET_PARAMETERS_EX 和硬编码 TCP 模块 GUID，可精准关闭指定 PID 的 ESTABLISHED 状态连接。利用 GetTcpTable2 获取 TCP 表，搭配 CreateToolhelp32Snapshot 枚举进程，配合 NSI 接口实现免驱动断连，使用go的概念性实现

原文链接：https://mp.weixin.qq.com/s/HuYc8sUzZsYjMdTliItX_Q

📦 使用方法

`go build -ldflags "-s -w" -o NetConnWatch.exe main.go`

该程序将持续运行并扫描默认配置中指定的进程名，一旦检测到其存在活动 TCP 会话，将尝试释放连接。

⚙️ 自定义
你可以编辑 main() 函数中的 targetProcs 列表，添加或删除需监控的进程名：

`targetProcs := []string{"chrome.exe", "myApp.exe"}`

![image](https://github.com/user-attachments/assets/9745037b-1148-4cd4-b642-f3e1a2d6018e)
