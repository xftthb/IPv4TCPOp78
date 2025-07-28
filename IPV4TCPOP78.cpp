// IPV4TCPOP78.cpp
// ------------------------------------------------------------
// 功能：
//   1. 拦截本地 <local_port> 的出入口 TCP 报文
//   2. 对出站报文动态插入/截断 Option 78（时间戳+四元组）
//   3. 对入站报文解析并打印收到的 Option 78
//
// 用法：
//   ./IPV4TCPOP78 <local_port> [worker_threads=4]
//
// 编译：
//   调试: g++ -O0 -g -Wall -Wextra -std=c++17 -DDEBUG=1 ... -lnetfilter_queue -lpthread
//   发行: g++ -O2 -Wall -Wextra -std=c++17 ... -lnetfilter_queue -lpthread
//
// 清理：
//   Ctrl-C、SIGTERM 或程序退出时会自动删除 iptables 规则与链
//
// ------------------------------------------------------------

// ===================== 头文件 =====================
#include <arpa/inet.h>                      // 字节序、地址转换
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/ip.h>                       // struct iphdr
#include <linux/netfilter.h>                // NF_ACCEPT ...
#include <linux/tcp.h>                      // struct tcphdr
#include <signal.h>
#include <unistd.h>

#include <cassert>
#include <chrono>
#include <cstring>
#include <iostream>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace std;

// ===================== 调试宏 =====================
#ifdef DEBUG
#define DBG(fmt, ...) \
    fprintf(stderr, "[DEBUG %s:%d] " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)
#else
#define DBG(...)
#endif

// ===================== 常量 =====================
constexpr uint8_t  OPT_KIND_78      = 254;     // 自定义 Option 类型
constexpr size_t   OPT_78_FIXED_LEN = 16;     // 时间戳(4) + saddr(4) + sport(2) + daddr(4) + dport(2)
constexpr size_t   TCP_HDR_MAX      = 60;     // TCP 头最大长度（字节）
constexpr size_t   IP_HDR_MAX       = 60;     // IP 头最大长度（字节）
constexpr size_t   ETH_MTU          = 1500;   // 以太网 MTU（含头）

// ===================== 校验和工具 =====================
// 通用 16 位 1 的补码和
static uint16_t csum16(const void *data, size_t len) {
    const uint16_t *p = reinterpret_cast<const uint16_t *>(data);
    uint32_t sum = 0;
    while (len >= 2) {
        sum += *p++;
        len -= 2;
    }
    if (len) {                      // 剩余 1 字节
        sum += *reinterpret_cast<const uint8_t *>(p);
    }
    while (sum >> 16) {             // 处理溢出
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return static_cast<uint16_t>(sum);
}

// 计算 IP 头校验和（仅 IP 头）
static uint16_t ip_checksum(struct iphdr *iph) {
    iph->check = 0;
    size_t ip_hdr_len = iph->ihl * 4;  // ihl 单位是 32-bit 字
    assert(ip_hdr_len <= IP_HDR_MAX);
    uint16_t sum = csum16(iph, ip_hdr_len);
    uint16_t csum = static_cast<uint16_t>(~sum);
    DBG("ip_checksum=0x%04x", csum);
    return csum;
}

// 计算 TCP 校验和（含伪首部）
/*static uint16_t tcp_checksum(struct iphdr *iph, struct tcphdr *tcph, uint16_t tcp_len_host) {
    struct __attribute__((packed)) {
        uint32_t saddr, daddr;
        uint8_t  zero;
        uint8_t  protocol;
        uint16_t tcp_len_net;
    } ph = {
        iph->saddr,
        iph->daddr,
        0,
        IPPROTO_TCP,
        htons(tcp_len_host)
    };

    uint32_t sum = csum16(&ph, sizeof(ph));

    tcph->check = 0;
    sum += csum16(tcph, tcp_len_host);

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    uint16_t csum = static_cast<uint16_t>(~sum);
    DBG("tcp_checksum=0x%04x (len=%u)", csum, tcp_len_host);
    return csum;
}*/
static uint16_t tcp_checksum(struct iphdr *iph, struct tcphdr *tcph, uint16_t tcp_len_host) {
    // 创建正确的伪首部（确保字节序正确）
    struct {
        uint8_t  saddr[4];
        uint8_t  daddr[4];
        uint8_t  zero;
        uint8_t  protocol;
        uint16_t tcp_len;
    } ph;
    
    // 显式复制IP地址（保持网络字节序）
    memcpy(ph.saddr, &iph->saddr, 4);
    memcpy(ph.daddr, &iph->daddr, 4);
    ph.zero = 0;
    ph.protocol = IPPROTO_TCP;
    ph.tcp_len = htons(tcp_len_host);
    
    uint32_t sum = csum16(&ph, sizeof(ph));
    tcph->check = 0;
    sum += csum16(tcph, tcp_len_host);
    
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    
    uint16_t csum = static_cast<uint16_t>(~sum);
    DBG("tcp_checksum=0x%04x (len=%u)", csum, tcp_len_host);
    return csum;
}



// ===================== Option 78 处理 =====================
// 判断 TCP 选项区是否已存在 Option 78
static bool hasOpt78(const uint8_t *opt, int len) {
    while (len > 0) {
        if (len < 2) break;
        uint8_t kind = opt[0];
        if (kind == 0) break;               // EOL
        if (kind == 1) { ++opt; --len; continue; } // NOP
        uint8_t optlen = opt[1];
        if (optlen < 2 || optlen > len) break;
        if (kind == OPT_KIND_78) return true;
        opt += optlen;
        len -= optlen;
    }
    return false;
}

// 向 TCP 头插入 Option 78
static bool insertOpt78(struct iphdr *iph, struct tcphdr *tcph) {
    // 当前 TCP 头长度（字节）
    const int tcp_hdrlen = tcph->doff * 4;
    if (tcp_hdrlen < (int)sizeof(struct tcphdr) || tcp_hdrlen > (int)TCP_HDR_MAX) {
        DBG("TCP header length invalid: %d", tcp_hdrlen);
        return false;
    }
    // IP 头长度
    const int ip_hdrlen = iph->ihl * 4;
    if (ip_hdrlen < 20 || ip_hdrlen > (int)IP_HDR_MAX) {
        DBG("IP header length invalid: %d", ip_hdrlen);
        return false;
    }

    // 负载长度
    const int payload_len = ntohs(iph->tot_len) - ip_hdrlen - tcp_hdrlen;
    assert(payload_len >= 0);

    // 剩余空间
    const int remain = (int)TCP_HDR_MAX - tcp_hdrlen;
    if (remain < 6) {   // kind+len+最少4字节
        DBG("No room for option 78");
        return false;
    }

    uint8_t *opt_start = reinterpret_cast<uint8_t *>(tcph + 1);
    int optlen = tcp_hdrlen - sizeof(struct tcphdr);
    if (hasOpt78(opt_start, optlen)) {
        DBG("Option 78 already present");
        return false;
    }

    // 构造 16 字节数据
    uint8_t buf[OPT_78_FIXED_LEN];
    uint32_t ts = static_cast<uint32_t>(
        chrono::duration_cast<chrono::milliseconds>(
            chrono::steady_clock::now().time_since_epoch()).count());
    memcpy(buf + 0,  &ts,          4);      // 时间戳
    memcpy(buf + 4,  &iph->saddr,  4);      // src ip
    memcpy(buf + 8,  &tcph->source, 2);     // src port
    memcpy(buf + 10, &iph->daddr,  4);      // dst ip
    memcpy(buf + 14, &tcph->dest,  2);      // dst port

    int avail = remain - 2;                 // 去掉 kind+len
    int copy  = std::min(avail, (int)OPT_78_FIXED_LEN);
    if (copy < 4) {
        DBG("Cannot even fit timestamp");
        return false;
    }

    int needed = 2 + copy;                  // kind+len+data
    int pad    = (4 - (needed & 3)) & 3;    // 4 字节对齐
    needed += pad;

    const int new_tot = ntohs(iph->tot_len) + needed;
    if (new_tot > ETH_MTU) {
        DBG("New packet length %d > MTU", new_tot);
        return false;
    }

    // 负载后移
    uint8_t *payload = reinterpret_cast<uint8_t *>(iph) + ip_hdrlen + tcp_hdrlen;
    memmove(payload + needed, payload, payload_len);

    // 写入选项
    uint8_t *opt = reinterpret_cast<uint8_t *>(tcph) + tcp_hdrlen;
    opt[0] = OPT_KIND_78;
    opt[1] = 2 + copy;
    memcpy(opt + 2, buf, copy);
    //if (pad) memset(opt + 2 + copy, 0, pad); // NOP/EOL 填充
    if (pad > 0) {
        for (int i = 0; i < pad - 1; ++i) {
        opt[2 + copy + i] = 1; // NOP
        }
        opt[2 + copy + pad - 1] = 0; // EOL
    }
    tcph->doff = (tcp_hdrlen + needed) / 4;

    // 更新 IP 总长度（网络序）
    iph->tot_len = htons(static_cast<uint16_t>(new_tot));
    iph->check   = ip_checksum(iph);

    // 重算 TCP 校验和（主机字节序长度）
    //uint16_t new_tcp_len_host = htons(iph->tot_len) - iph->ihl * 4;
    //tcph->check = tcp_checksum(iph, tcph, new_tcp_len_host);
    // 计算新的 TCP 长度（含 TCP 头 + 选项 + 负载）
    uint16_t tcp_len_host = new_tot - iph->ihl * 4;
    tcph->check = tcp_checksum(iph, tcph, tcp_len_host);  
    //tcph->check = htons(tcp_checksum(iph, tcph, tcp_len_host));

    DBG("Option 78 inserted, new_tot=%d, doff=%u, tcp_check=0x%04x",
        new_tot, tcph->doff, tcph->check);
    return true;
}

// 解析收到的 Option 78
static void parseOpt78(const uint8_t *opt, int len) {
    while (len > 0) {
        if (len < 2) break;
        uint8_t kind = opt[0];
        if (kind == 0) break;
        if (kind == 1) { ++opt; --len; continue; }
        uint8_t optlen = opt[1];
        if (optlen < 2 || optlen > len) break;

        if (kind == OPT_KIND_78) {
            const uint8_t *p = opt + 2;
            uint32_t ts   = (optlen >= 6) ? *(uint32_t *)(p + 0) : 0;
            uint32_t saddr= (optlen >= 10) ? *(uint32_t *)(p + 4) : 0;
            uint16_t sport= (optlen >= 12) ? *(uint16_t *)(p + 8) : 0;
            uint32_t daddr= (optlen >= 16) ? *(uint32_t *)(p + 10) : 0;
            uint16_t dport= (optlen >= 18) ? *(uint16_t *)(p + 14) : 0;

            cout << "RECV OPT78"
                 << " ts=" << ts
                 << " src=" << ((saddr >> 0) & 0xFF) << "."
                             << ((saddr >> 8) & 0xFF) << "."
                             << ((saddr >> 16) & 0xFF) << "."
                             << ((saddr >> 24) & 0xFF)
                 << ":" << ntohs(sport)
                 << " dst=" << ((daddr >> 0) & 0xFF) << "."
                             << ((daddr >> 8) & 0xFF) << "."
                             << ((daddr >> 16) & 0xFF) << "."
                             << ((daddr >> 24) & 0xFF)
                 << ":" << ntohs(dport) << '\n';
        }
        opt += optlen;
        len -= optlen;
    }
}

// ===================== NFQUEUE 工作线程 =====================
static void worker(int queue_num, uint16_t local_port) {
    struct nfq_handle *h = nfq_open();
    if (!h) { perror("nfq_open"); return; }
    if (nfq_bind_pf(h, AF_INET) < 0) { perror("nfq_bind_pf"); nfq_close(h); return; }

    struct nfq_q_handle *qh = nfq_create_queue(
        h, queue_num,
        [](struct nfq_q_handle *qh, struct nfgenmsg *,
           struct nfq_data *nfa, void *port_ptr) -> int {
            uint32_t id = 0;
            struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
            if (ph) id = ntohl(ph->packet_id);

            unsigned char *pkt;
            int len = nfq_get_payload(nfa, &pkt);
            if (len < (int)(sizeof(struct iphdr) + sizeof(struct tcphdr))) {
                DBG("Payload too small");
                return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
            }

            struct iphdr *iph = reinterpret_cast<struct iphdr *>(pkt);
            if (iph->ihl < 5 || iph->ihl > 15 ||
                len < (int)(iph->ihl * 4 + sizeof(struct tcphdr))) {
                DBG("IP header invalid");
                return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
            }

            struct tcphdr *tcph = reinterpret_cast<struct tcphdr *>(pkt + iph->ihl * 4);
            uint16_t local = *static_cast<uint16_t *>(port_ptr);

            int tcp_hdrlen = tcph->doff * 4;
            if (tcp_hdrlen < (int)sizeof(struct tcphdr) || tcp_hdrlen > (int)TCP_HDR_MAX) {
                DBG("TCP header length invalid");
                return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
            }

            bool outbound = (ntohs(tcph->source) == local);
            bool inbound  = (ntohs(tcph->dest)  == local);

            // 握手/拆除报文：出方向尝试插入选项，否则仅重算校验和
            if (tcph->syn || tcph->rst || tcph->fin) {
                if (outbound && insertOpt78(iph, tcph)) {
                    return nfq_set_verdict(qh, id, NF_ACCEPT, ntohs(iph->tot_len), pkt);
                } else {
                    //uint16_t tcp_len = ntohs(iph->tot_len) - iph->ihl * 4;
                    //tcph->check = tcp_checksum(iph, tcph, tcp_len);
                    //return nfq_set_verdict(qh, id, NF_ACCEPT, len, pkt);
                    // 仅重算校验和
                    //uint16_t tcp_len_host = ntohs(iph->tot_len) - iph->ihl * 4;
                    //tcph->check = tcp_checksum(iph, tcph, tcp_len_host); 
                    return nfq_set_verdict(qh, id, NF_ACCEPT, len, pkt);
                }
            }
            
            if (outbound) {
                if (insertOpt78(iph, tcph))
                    return nfq_set_verdict(qh, id, NF_ACCEPT, ntohs(iph->tot_len), pkt);
                else
                    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
            } else if (inbound) {
                int optlen = tcp_hdrlen - sizeof(struct tcphdr);
                if (optlen > 0)
                    parseOpt78(reinterpret_cast<uint8_t *>(tcph + 1), optlen);
                return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
            }
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
        },
        &local_port);

    if (!qh) { perror("nfq_create_queue"); nfq_close(h); return; }
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        perror("nfq_set_mode"); nfq_close(h); return;
    }

    int fd = nfq_fd(h);
    char buf[64 * 1024] __attribute__((aligned(16)));
    while (true) {
        int rv = recv(fd, buf, sizeof(buf), 0);
        if (rv <= 0) {
            if (errno != EINTR) perror("recv");
            break;
        }
        nfq_handle_packet(h, buf, rv);
    }
    nfq_destroy_queue(qh);
    nfq_close(h);
}

// ===================== iptables 规则管理 =====================
static string g_chain;
static uint16_t g_port;

static bool run_cmd(const string &cmd) {
    DBG("exec: %s", cmd.c_str());
    int rc = system(cmd.c_str());
    if (rc != 0) cerr << "cmd failed: " << cmd << " (exit=" << rc << ")\n";
    return rc == 0;
}

static bool chain_exists(const string &c) {
    return system(("iptables -L " + c + " -n >/dev/null 2>&1").c_str()) == 0;
}

static string make_chain(uint16_t port) {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<uint32_t> dist(10000, 99999);
    string base = "TCPOPT78_" + to_string(port) + "_";
    for (;;) {
        string c = base + to_string(dist(gen));
        if (!chain_exists(c)) return c;
    }
}

static void install_rules(uint16_t port, int threads) {
    g_chain = make_chain(port);
    run_cmd("iptables -N " + g_chain);
    run_cmd("iptables -F " + g_chain);
    run_cmd("iptables -A " + g_chain + " -p tcp --sport " + to_string(port) +
            " -j NFQUEUE --queue-balance 0:" + to_string(threads - 1));
    run_cmd("iptables -A " + g_chain + " -p tcp --dport " + to_string(port) +
            " -j NFQUEUE --queue-balance 0:" + to_string(threads - 1));
    run_cmd("iptables -I OUTPUT -j " + g_chain);
    run_cmd("iptables -I INPUT  -j " + g_chain);
}

static void cleanup() {
    if (g_chain.empty()) return;
    run_cmd("iptables -D OUTPUT -j " + g_chain);
    run_cmd("iptables -D INPUT  -j " + g_chain);
    run_cmd("iptables -F " + g_chain);
    run_cmd("iptables -X " + g_chain);
}

// ===================== 主函数 =====================
int main(int argc, char *argv[]) {
    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <local_port> [threads=4]\n";
        return 1;
    }
    uint16_t port  = static_cast<uint16_t>(stoi(argv[1]));
    int threads    = (argc >= 3) ? stoi(argv[2]) : 4;

    if (threads < 1 || threads > 65535) {
        cerr << "threads must be 1..65535\n";
        return 1;
    }
    g_port = port;

    install_rules(port, threads);
    atexit(cleanup);
    signal(SIGINT,  [](int){ exit(0); });
    signal(SIGTERM, [](int){ exit(0); });

    vector<thread> pool;
    for (int i = 0; i < threads; ++i)
        pool.emplace_back(worker, i, port);
    for (auto &t : pool) t.join();
    return 0;
}
