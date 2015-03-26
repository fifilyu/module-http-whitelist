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

unsigned int nf_hook_func(
        unsigned int hooknum, struct sk_buff *skb, const struct net_device *in,
        const struct net_device *out, int (*okfn)(struct sk_buff *)) {
    struct sk_buff   *skb_ = skb;
    struct iphdr     *ip_header_ = NULL;
    struct tcphdr    *tcp_header_ = NULL;
    unsigned char    *tcp_data_ = NULL;

    if (!skb_)
        return NF_ACCEPT;

    ip_header_ = ip_hdr(skb_);

    // 仅仅过滤 TCP 协议
    if (!ip_header_ || ip_header_->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    tcp_header_ = tcp_hdr(skb_);

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
        .hooknum = NF_INET_PRE_ROUTING,
        .pf = PF_INET,
        .priority = NF_IP_PRI_FIRST
};

int init_module() {
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

