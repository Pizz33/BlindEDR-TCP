# BlindEDR-TCP

- 使用 Go 调用 `NtDeviceIoControlFile` 操作 `\\.\Nsi` 网络设备接口
- 构造 `NSI_SET_PARAMETERS_EX` 与 TCP GUID 实现连接控制
- 通过 `GetTcpTable2` 获取 TCP 表，筛选 ESTABLISHED 状态
- 利用 `CreateToolhelp32Snapshot` 动态获取指定进程 PID
- 全流程基于合法 API，绕过用户态防护与驱动签名限制
- 无需驱动加载，具备较强隐蔽性与免杀特性

原文链接：https://mp.weixin.qq.com/s/HuYc8sUzZsYjMdTliItX_Q

📦 使用方法

`go build -ldflags "-s -w" -o NetConnWatch.exe main.go`

该程序将持续运行并扫描默认配置中指定的进程名，一旦检测到其存在活动 TCP 会话，将尝试释放连接。

⚙️ 自定义
你可以编辑 main() 函数中的 targetProcs 列表，添加或删除需监控的进程名：

`targetProcs := []string{"chrome.exe", "myApp.exe"}`

![image](https://github.com/user-attachments/assets/9745037b-1148-4cd4-b642-f3e1a2d6018e)
