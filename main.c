/*
 * main.cxx
 *
 *  Created on: 2012年4月20日
 *      Author: Fifi Lyu
 */

#include "issue.h"
#include "common/file.h"
#include "common/host.h"
#include "common/misc.h"
#include "common/network.h"
#include <linux/version.h>  // for LINUX_VERSION_CODE KERNEL_VERSION
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
#include <linux/in.h>  // for IPPROTO_TCP
#endif
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter_ipv4.h>

MODULE_LICENSE(LICENSE);
MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESCRIPTION);

static char         *g_hosts = NULL;
static loff_t       g_hosts_size = 0;

static network_t    *g_net_array = NULL;
static size_t       g_net_array_size = 0;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,24)
unsigned int nf_hook_func(
        unsigned int hooknum, struct sk_buff *skb, const struct net_device *in,
        const struct net_device *out, int (*okfn)(struct sk_buff *)) {
    struct sk_buff   *skb_ = skb;
#else
unsigned int nf_hook_func(
        unsigned int hooknum, struct sk_buff **skb, const struct net_device *in,
        const struct net_device *out, int (*okfn)(struct sk_buff *)) {
    struct sk_buff   *skb_ = *skb;
#endif
    struct iphdr     *ip_header_ = NULL;
    struct tcphdr    *tcp_header_ = NULL;
    unsigned char    *tcp_data_ = NULL;

    if (!skb_)
        return NF_ACCEPT;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
    ip_header_ = ip_hdr(skb_);
#else
    ip_header_ = skb_->h.ipiph;
#endif

    // 仅仅过滤 TCP 协议
    if (!ip_header_ || ip_header_->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    // 已知在 2.6.18/3.19.2 上，tcp_hdr(skb_) 会返回预期的 tcp 头偏移量。
    // 已知在 2.6.32 上，tcp_hdr(skb_) 与 ip_hdr(skb_) 会返回相同的指针地址。
    //
    // 2.6.32:
    // TCP 包来自 1/2 层，netfilter/ipv4 钩子会在第 3 层被注入。
    // 因此，此时使用 tcp_hdr 函数不会获得预期的 tcp 头偏移量。
    // 直接根据 IP 头偏移量计算 TCP 头偏移量是最合适的
    tcp_header_ = (struct tcphdr *)((__u32 *)ip_header_ + ip_header_->ihl);

    // 仅仅过滤指定的 HTTP 端口
    if (htons(tcp_header_->dest) != HTTP_PORT)
        return NF_ACCEPT;

    // 如果是信任的网络，则放行。不做任何过滤
    // 因此，如果本机作为转发网关，必须添加内网网段，内网网络才能访问公网。
    if (check_net(ip_header_->saddr, g_net_array, g_net_array_size))
        return NF_ACCEPT;

    //    GET / HTTP/1.1\r\n
    //    User-Agent: curl/7.41.0\r\n
    //    Host: abc.com\r\n
    //    Accept: */*\r\n
    //    \r\n
    tcp_data_ = get_tcp_data(skb_, ip_header_, tcp_header_);

    // 跳过非 HTTP 头相关包
    if (!check_http_header(tcp_data_))
        return NF_ACCEPT;

    // 如果是信任的主机，则放行
    if (check_host(tcp_data_, g_hosts, g_hosts_size))
        return NF_ACCEPT;

    return NF_DROP;
}

static struct nf_hook_ops g_nf_hook = {
        .hook = (nf_hookfn*) nf_hook_func,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
        .hooknum = NF_INET_PRE_ROUTING,
#else
        .hooknum = NF_IP_PRE_ROUTING,
#endif
        .pf = PF_INET,
        .priority = NF_IP_PRI_FIRST
};

int init_module() {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
    pr_err("[%s] Linux Kernel Version does not supported.\n", MODOUBLE_NAME);
    return -1;
#endif

    pr_info("Loading module \"%s\"\n", MODOUBLE_NAME);

    if (!init_host_str(&g_hosts, &g_hosts_size)) {
        pr_err("Cannot initialize host whitelist.\n");
        pr_err("Cannot load module \"%s\"\n", MODOUBLE_NAME);
        return -1;
    }

    if (!init_net_array(&g_net_array, &g_net_array_size)) {
        pr_err("Cannot initialize network whitelist.\n");
        pr_err("Cannot load module \"%s\"\n", MODOUBLE_NAME);
        return -1;
    }

    if (nf_register_hook(&g_nf_hook) < 0) {
        pr_err("Cannot register netfilter hook.\n");
        pr_err("Cannot load module \"%s\"\n", MODOUBLE_NAME);
        return -1;
    }

    return 0;
}

void cleanup_module() {
    pr_info("Unloading module \"%s\"\n", MODOUBLE_NAME);
    if (g_hosts) kfree(g_hosts);
    if (g_net_array) kfree(g_net_array);
    nf_unregister_hook(&g_nf_hook);
}

