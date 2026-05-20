## 调试 Windows 10 DHCP 广播接收问题

**当前状态分析：**
- ✅ 抓包工具能收到 255.255.255.255 的包
- ✅ tftpd32 监听在 UDP 0.0.0.0:67
- ❌ tftpd32 收不到包
- ❌ 没有任何调试日志输出

---

## 代码审查发现的 Bug

### Bug 1（关键）：`recvfrom` 回退路径不填充 `SockTo`

**位置**: [`ListenDhcpMessage`](src/_services/bootpd.c:1559) 主循环

**问题**: 当 `WSARecvMsg` 失败（返回 -1）时，代码回退到 `recvfrom`。但 `recvfrom` 只填充 `SockFrom`（来源地址），**不会**填充 `SockTo`（接收接口地址）。`SockTo` 保持为全零。

**后果**:
1. 如果配置了 `szDHCPLocalIP`（非空），第 1604 行的检查会将 `SockTo.sin_addr.s_addr`(=0) 与配置的 IP 比较，结果永远不匹配 → **所有包被静默丢弃**
2. 即使 `szDHCPLocalIP` 为空，`ProcessDHCPMessage` 收到零化的 `receivingAddress`，导致 DHCP 响应中的服务器 IP 地址错误

**修复**: 在 `recvfrom` 回退后使用 `getsockname()` 获取绑定的本地地址来填充 `SockTo`。

```c
// 修复前（原始代码）:
if (Rc==-1)
{
    Rc = recvfrom(tThreads[TH_DHCP].skt, ...);
    // SockTo 仍然是全零！
}

// 修复后:
if (Rc==-1)
{
    Rc = recvfrom(tThreads[TH_DHCP].skt, ...);
    if (Rc > 0)
    {
        int toLen = sizeof SockTo;
        getsockname(tThreads[TH_DHCP].skt, (struct sockaddr *)&SockTo, &toLen);
    }
}
```

### Bug 2（关键）：`WSARecvMsg` 成功但 `IP_PKTINFO` 未找到时 `SockTo` 未填充

**位置**: [`SktRcvAndGetAddrOfIncomingIf`](src/_services/bootpd.c:1375)

**问题**: 当 `WSARecvMsg` 成功接收数据，但控制消息中没有 `IP_PKTINFO` 时（第 1423 行），函数直接返回 `BytesRecv`（正值，表示成功），但 `to` 参数（即 `SockTo`）**从未被填充**。

**后果**: 同 Bug 1，`SockTo` 为零导致包被静默丢弃或服务器 IP 错误。

**修复**: 当 `IP_PKTINFO` 未找到时，使用 `getsockname()` 作为回退。

```c
// 修复前:
if (pMsgHdr==NULL)  return BytesRecv;

// 修复后:
if (pMsgHdr==NULL)
{
    int toLen = sizeof *to;
    getsockname(skt, (struct sockaddr *)to, &toLen);
    return BytesRecv;
}
```

### Bug 3（诊断）：缺少调试日志

**位置**: [`ListenDhcpMessage`](src/_services/bootpd.c:1497)

**问题**: 函数启动时没有任何日志输出，无法确认：
- 线程是否启动
- Socket 是否有效
- 是否进入了主接收循环
- 使用了哪种接收方式（WSARecvMsg / recvfrom）

**修复**: 添加了以下关键日志点：
- `"DHCP: Thread started successfully"` — 线程启动
- `"DHCP: Socket handle=XX, gRunning=1"` — Socket 状态
- `"DHCP: Entering main receive loop"` — 进入主循环
- `"DHCP: Received N bytes from X, SockTo=Y (method=M)"` — 收到包
- `"DHCP: WSARecvMsg failed, error N"` — WSARecvMsg 失败
- `"DHCP: recvfrom fallback, SockTo=X via getsockname"` — 回退路径

---

## 数据流分析

```
DHCP 客户端发送广播 (255.255.255.255:68 → 0.0.0.0:67)
    │
    ▼
Socket (bind 0.0.0.0:67, SO_BROADCAST, IP_PKTINFO)
    │
    ▼
SktRcvAndGetAddrOfIncomingIf()
    ├── WSARecvMsg() 成功?
    │   ├── YES → 解析 IP_PKTINFO → 填充 SockTo
    │   │         ├── IP_PKTINFO 找到? → ✅ SockTo 正确
    │   │         └── IP_PKTINFO 未找到? → ⚠️ [Bug 2] SockTo=0
    │   └── NO → return -1
    │              └── recvfrom() 回退 → ⚠️ [Bug 1] SockTo=0
    │
    ▼
SockTo 检查 (szDHCPLocalIP 配置时)
    ├── SockTo == 配置IP? → ✅ 继续
    └── SockTo == 0? → ❌ 包被丢弃！
```

---

## 已实施的代码改动

### 文件: `src/_services/bootpd.c`

1. **`ListenDhcpMessage` 函数** (行 ~1497):
   - 添加线程启动日志
   - 添加 Socket 状态日志
   - 添加 "Entering main receive loop" 日志
   - 主循环中初始化 `SockFrom`、`SockTo` 为零（`memset`）
   - 添加 `nRecvMethod` 变量追踪接收方式
   - **修复**: `recvfrom` 回退后用 `getsockname()` 填充 `SockTo`
   - 增强接收成功/失败的日志（包含 method 信息）
   - 增强接口过滤日志（显示期望 IP 和实际 SockTo）

2. **`SktRcvAndGetAddrOfIncomingIf` 函数** (行 ~1375):
   - 添加 `WSARecvMsg` 失败日志
   - **修复**: `IP_PKTINFO` 未找到时用 `getsockname()` 填充 `to` 参数
   - 添加回退日志

---

## 验证步骤

### 1. 重新编译
```cmd
cd E:\develop\tftpd64\src
msbuild tftpd32.sln /t:Rebuild /p:Configuration=Release
```

### 2. 检查日志输出
启动 tftpd32 后，在 Log/Status 窗口或 DebugView 中应看到：
```
DHCP: Thread started successfully
DHCP: Socket handle=XXX, gRunning=1
DHCP: Entering main receive loop
```

如果**这些都没有出现** → 编译失败或运行了旧版 exe。

### 3. 发送测试 DHCP 包
当收到 DHCP 包时，应看到：
```
DHCP: Received N bytes from 0.0.0.0, SockTo=192.168.x.x (method=1)
```
- `method=1` = WSARecvMsg 成功
- `method=2` = recvfrom 回退

### 4. 如果仍然收不到包
检查是否有以下错误日志：
- `"DHCP: WSARecvMsg failed, error N"` → WSARecvMsg 不可用
- `"Recv error N (method=2)"` → recvfrom 也失败
- `"Can add broadcast capability"` → Socket 选项设置失败
- `"Can add PKTINFO capability"` → IP_PKTINFO 不支持

如果完全没有日志 → 代码未编译或 exe 未更新。
