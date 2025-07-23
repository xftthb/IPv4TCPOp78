// IPV4TCPOP78.cpp
// 编译：g++ -O2 -Wall -Wextra -std=c++17 IPV4TCPOP78.cpp -o IPV4TCPOP78 -lnetfilter_queue -lpthread
//
// 功能：
//   1. 拦截本地 <local_port> 的出入口 TCP 报文
//   2. 对出站报文动态插入/截断 Option 78（时间戳+四元组）
//   3. 对入站报文解析并打印收到的 Option 78
//
// 用法：
//   ./IPV4TCPOP78 <local_port> [worker_threads=4]
//
// 清理：
//   Ctrl-C、SIGTERM 或程序退出时会自动删除 iptables 规则与链

#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/tcp.h>
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

//====================== 校验和计算工具 ======================
static uint16_t csum16(const void *data, size_t len) {
    const uint16_t *p = reinterpret_cast<const uint16_t *>(data);
    uint32_t sum = 0;
    while (len >= 2) { sum += *p++; len -= 2; }
    if (len) sum += *reinterpret_cast<const uint8_t *>(p);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

static uint16_t ip_checksum(struct iphdr *iph) {
    iph->check = 0;
    return csum16(iph, iph->ihl * 4);
}

static uint16_t tcp_checksum(struct iphdr *iph, struct tcphdr *tcph, uint16_t tcp_len) {
    struct {
        uint32_t saddr, daddr;
        uint8_t  zero;
        uint8_t  protocol;
        uint16_t tcp_len;
    } __attribute__((packed)) ph = {
        iph->saddr, iph->daddr, 0, IPPROTO_TCP, htons(tcp_len)
    };
    uint32_t sum = csum16(&ph, sizeof(ph));
    tcph->check = 0;
    sum += csum16(tcph, tcp_len);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

//====================== Option 78 处理 ======================
static bool hasOpt78(const uint8_t *opt, int len) {
    while (len > 0) {
        if (len < 2) break;
        uint8_t kind = opt[0];
        if (kind == 0) break;
        if (kind == 1) { ++opt; --len; continue; }
        uint8_t optlen = opt[1];
        if (optlen < 2 || optlen > len) break;
        if (kind == 78) return true;
        opt += optlen;
        len -= optlen;
    }
    return false;
}

/* 动态插入 Option 78（剩余多少空间插多少，最小 4 字节时间戳） */
static bool insertOpt78(struct iphdr *iph, struct tcphdr *tcph) {
    constexpr int MAX_TCP_HDR = 60;
    const int tcp_hdrlen = tcph->doff * 4;
    if (tcp_hdrlen < (int)sizeof(struct tcphdr) || tcp_hdrlen > MAX_TCP_HDR)
        return false;
    if (iph->ihl < 5 || iph->ihl > 15) return false;

    const int hdr_len = iph->ihl * 4 + tcp_hdrlen;
    const int payload_len = ntohs(iph->tot_len) - hdr_len;
    assert(payload_len >= 0);
    if (payload_len < 0) return false;

    uint8_t *payload = reinterpret_cast<uint8_t *>(iph) + hdr_len;
    const uint16_t old_tcp_len = ntohs(iph->tot_len) - iph->ihl * 4;

    int remain = MAX_TCP_HDR - tcp_hdrlen;
    if (remain < 6) return false; // kind+len+至少4字节数据

    uint8_t *opt_start = reinterpret_cast<uint8_t *>(tcph + 1);
    int optlen = tcp_hdrlen - sizeof(struct tcphdr);
    if (hasOpt78(opt_start, optlen)) return false;

    uint8_t buf[16];
    uint32_t ts = static_cast<uint32_t>(
        chrono::duration_cast<chrono::milliseconds>(
            chrono::steady_clock::now().time_since_epoch()).count());
    memcpy(buf + 0,  &ts,          4);
    memcpy(buf + 4,  &iph->saddr,  4);
    memcpy(buf + 8,  &tcph->source, 2);
    memcpy(buf + 10, &iph->daddr,  4);
    memcpy(buf + 14, &tcph->dest,  2);

    int avail = remain - 2;          // 去掉 kind+len
    int copy  = std::min(avail, 16); // 最大 16
    if (copy < 4) return false;      // 连时间戳都放不下

    int needed = 2 + copy;
    int pad    = (4 - (needed & 3)) & 3;
    needed += pad;

    const int new_tot = ntohs(iph->tot_len) + needed;
    if (new_tot > 1500) return false;

    memmove(payload + needed, payload, payload_len);

    uint8_t *opt = reinterpret_cast<uint8_t *>(tcph) + tcp_hdrlen;
    opt[0] = 78;
    opt[1] = 2 + copy;
    memcpy(opt + 2, buf, copy);
    if (pad) memset(opt + 2 + copy, 0, pad);

    tcph->doff  = (tcp_hdrlen + needed) / 4;
    iph->tot_len = htons(static_cast<uint16_t>(new_tot));
    iph->check   = ip_checksum(iph);
    uint16_t new_tcp_len = old_tcp_len + needed;
    tcph->check  = tcp_checksum(iph, tcph, new_tcp_len);
    return true;
}

/* 解析 Option 78（支持截断数据） */
static void parseOpt78(const uint8_t *opt, int len) {
    while (len > 0) {
        if (len < 2) break;
        uint8_t kind = opt[0];
        if (kind == 0) break;
        if (kind == 1) { ++opt; --len; continue; }
        uint8_t optlen = opt[1];
        if (optlen < 2 || optlen > len) break;

        if (kind == 78) {
            const uint8_t *p = opt + 2;
            int left = optlen - 2;

            uint32_t ts = 0;
            if (left >= 4) { memcpy(&ts, p, 4); }

            uint32_t saddr = 0;
            if (left >= 8) { memcpy(&saddr, p + 4, 4); }

            uint16_t sport = 0;
            if (left >= 12) { memcpy(&sport, p + 8, 2); }

            uint32_t daddr = 0;
            if (left >= 16) { memcpy(&daddr, p + 12, 4); }

            uint16_t dport = 0;
            if (left >= 18) { memcpy(&dport, p + 14, 2); }

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

//====================== NFQUEUE 工作线程 ======================
static void worker(int queue_num, uint16_t local_port) {
    struct nfq_handle *h = nfq_open();
    if (!h) { perror("nfq_open"); return; }
    if (nfq_bind_pf(h, AF_INET) < 0) { perror("nfq_bind_pf"); nfq_close(h); return; }

    struct nfq_q_handle *qh = nfq_create_queue(
        h, queue_num,
        [](struct nfq_q_handle *qh, struct nfgenmsg *, struct nfq_data *nfa, void *port_ptr) -> int {
            uint32_t id = 0;
            struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
            if (ph) id = ntohl(ph->packet_id);

            unsigned char *pkt;
            int len = nfq_get_payload(nfa, &pkt);
            if (len < (int)(sizeof(struct iphdr) + sizeof(struct tcphdr)))
                return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);

            struct iphdr *iph = reinterpret_cast<struct iphdr *>(pkt);
            if (iph->ihl < 5 || iph->ihl > 15 ||
                len < (int)(iph->ihl * 4 + sizeof(struct tcphdr)))
                return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);

            struct tcphdr *tcph = reinterpret_cast<struct tcphdr *>(pkt + iph->ihl * 4);
            uint16_t port = *static_cast<uint16_t *>(port_ptr);

            int tcp_hdrlen = tcph->doff * 4;
            if (tcp_hdrlen < (int)sizeof(struct tcphdr) || tcp_hdrlen > 60)
                return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);

            bool outbound = (ntohs(tcph->source) == port);
            bool inbound  = (ntohs(tcph->dest) == port);

            if (outbound) {
                if (insertOpt78(iph, tcph))
                    return nfq_set_verdict(qh, id, NF_ACCEPT, ntohs(iph->tot_len), pkt);
            } else if (inbound) {
                int optlen = tcp_hdrlen - sizeof(struct tcphdr);
                if (optlen > 0)
                    parseOpt78(reinterpret_cast<uint8_t *>(tcph + 1), optlen);
            }
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
        },
        &local_port);

    if (!qh) { perror("nfq_create_queue"); nfq_close(h); return; }
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) { perror("nfq_set_mode"); nfq_close(h); return; }

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

//====================== iptables 规则管理 ======================
static string g_chain;
static uint16_t g_port;

static bool run_cmd(const string &cmd) {
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
    run_cmd("iptables -D OUTPUT -j " + g_chain);
    run_cmd("iptables -D INPUT  -j " + g_chain);
    run_cmd("iptables -F " + g_chain);
    run_cmd("iptables -X " + g_chain);
}

//====================== 主函数 ======================
int main(int argc, char *argv[]) {
    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <local_port> [threads=4]\n";
        return 1;
    }
    uint16_t port = static_cast<uint16_t>(stoi(argv[1]));
    int threads   = (argc >= 3) ? stoi(argv[2]) : 4;

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
