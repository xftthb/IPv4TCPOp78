IPV4TCPOP78  
==============  
在本地指定端口上**透明地插入 / 解析 TCP Option 78** 的实验工具。  
把本机当成“中继”：  
- 发出去的 SYN/ACK/PSH… 报文会被动态塞入 Option 78（时间戳 + 四元组）。  
- 收到的报文如果携带 Option 78，则立即在 stdout 打印其内容。  

整个过程对应用层零侵入，仅在内核 netfilter/iptables 层完成。

---

1  实现原理（给“使用者”看的白话版）
----------------------------------
1. 程序启动后自动在 iptables 里创建两条规则：  
   OUTPUT/INPUT → 自定义链 → NFQUEUE。  
   NFQUEUE 会把匹配的报文“拉”到用户态，由本程序接管。  

2. 每个 NFQUEUE 队列绑定一个 worker 线程（可配置 N 个线程并行）。  

3. worker 拿到报文后：  
   - 判断方向：  
     ‑ sport == local_port ⇒ **出站**，尝试插入 Option 78；  
     ‑ dport == local_port ⇒ **入站**，尝试解析 Option 78。  

4. **插入 Option 78** 的细节：  
   - 先看 TCP 头里还剩多少空间（`60 – doff*4`）。  
   - 至少 6 字节才能插（kind+len+4 字节时间戳）。  
   - 能塞多少塞多少，最多 18 字节（时间戳 4 + 四元组 14）。  
   - 不足 4 字节对齐时补 NOP(0)。  
   - 调整 `tot_len`、`doff`、IP/TCP 校验和，再丢回内核。  

5. **解析 Option 78** 的细节：  
   - 扫描 TCP Options 直到遇到 kind==78；  
   - 按实际收到的长度打印字段（可能只收到 4 字节时间戳，也可能完整 18 字节）。  

6. **退出时** 通过 `atexit` + 信号处理器保证：  
   - iptables 规则、自定义链全部自动清理。  

---

2  环境依赖
------------
- Linux ≥ 3.6（需要 NFQUEUE）  
- gcc ≥ 7 或 clang ≥ 6（必须支持 C++17）  
- root 权限（需要改 iptables 和打开 raw socket）  
- 安装开发包：  
  Debian/Ubuntu：  
  ```bash
  sudo apt-get install build-essential libnetfilter-queue-dev libnfnetlink-dev iptables
  ```  
  CentOS/RHEL：  
  ```bash
  sudo yum install gcc-c++ libnfnetlink-devel libnetfilter_queue-devel iptables-services
  ```

---

3  编译
-------
```bash
g++ -O2 -Wall -Wextra -std=c++17 IPV4TCPOP78.cpp -o IPV4TCPOP78 -lnetfilter_queue -lpthread
```

---

4  使用方法
-----------
```bash
sudo ./IPV4TCPOP78 <local_port> [worker_threads=4]
```

示例  
- 监听本机 8080 端口，用 8 个线程：  
  ```bash
  sudo ./IPV4TCPOP78 8080 8
  ```

运行期间所有经 8080 的 TCP 报文都会被处理。  
在另一终端执行 `curl http://127.0.0.1:8080`，即可看到打印的 Option 78 信息。

---

5  注意事项
-----------
1. **必须 root**；否则无法修改 iptables、无法打开 NFQUEUE。  
2. **不要** 在同一端口并行启动多个实例；随机链名仍可能冲突。  
3. 如果系统已有 `conntrack` 或 `docker` 等复杂规则，建议先：  
   `iptables -I OUTPUT 1 -p tcp --sport 8080 -j NFQUEUE --queue-balance 0:3`  
   手动验证队列正常工作，再运行本程序。  
4. Option 78 属于 **实验保留** 选项，互联网上绝大多数中间设备会**直接丢弃**或**剥离**未知 TCP Option，因此仅适合实验室/内网测试。  
5. 内核发送缓存满时 `recv()` 会返回 -1；程序遇到非 `EINTR` 错误即退出。  
6. **MTU 限制**：插入后报文 +18 字节，若原报文 ≥ 1462 字节可能被丢弃（需要本地设备支持 MTU 1500+18）。  

---

6  常见问题 FAQ
---------------
**Q1  启动时报 “nfq_open: Protocol not supported”**  
→ 内核未编译 `CONFIG_NETFILTER_NETLINK_QUEUE`；换内核或加载模块：  
```bash
sudo modprobe nfnetlink_queue
```

**Q2  终端没有任何打印**  
- 确认流量真的经过本机端口。  
- 确认 iptables 规则已生效：`sudo iptables -L | grep TCPOPT78`。  
- 确认对端未丢弃 Option 78（抓包：`tcpdump -i any -nn -X tcp and port 8080`）。

**Q3  如何验证 Option 78 真的被插入？**  
抓包：  
```bash
sudo tcpdump -i any -nn -XX tcp and port 8080
```
在 TCP 头里应看到类似 `4e 12 aa bb cc dd ...`（kind=0x4e, len=0x12=18）。

**Q4  想同时监控多个端口？**  
目前只支持单端口。可起多个进程，或自行改代码把规则改为 multiport：  
```bash
iptables -A TCPOPT78_xxx -p tcp -m multiport --sports 80,443 -j NFQUEUE ...
```

**Q5  如何彻底清理残留规则？**  
程序异常退出后手动执行：  
```bash
sudo iptables -F TCPOPT78_<port>_xxxxx 2>/dev/null
sudo iptables -X TCPOPT78_<port>_xxxxx 2>/dev/null
```

---

7  协议格式速查
---------------
Option 78 布局（网络字节序）  
```
0      1      2      3
+------+------+------+------+
| kind=78 | len=N | 时间戳 4B |
+------+------+------+------+
| 源地址 4B | 源端口 2B |
+------+------+------+------+
| 目的地址 4B | 目的端口 2B |（可选）
```
- len 最小 6（kind+len+时间戳），最大 20。  
- 如果空间不足，程序会截断，只保证时间戳 4B 存在。

---

8  许可证
---------
MIT — 可随意修改，但请保留原作者署名。
