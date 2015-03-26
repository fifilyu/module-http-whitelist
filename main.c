/*
 * main.cxx
 *
 *  Created on: 2012年4月20日
 *      Author: Fifi Lyu
 */

#include "issue.h"
#include "common/domain.h"
#include "common/file.h"
#include "common/host.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include "common/misc.h"

MODULE_LICENSE(LICENSE);
MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESCRIPTION);

static char* g_domains = NULL;
static loff_t g_domains_len = 0;

static char* g_nets = NULL;
static loff_t g_nets_len = 0;

static wlist_ip_t* g_wlist_ips = NULL;
static size_t g_wlist_ip_count = 0;

unsigned int nf_hook_func(
        unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff*));

unsigned int nf_hook_func(
        unsigned int hooknum, struct sk_buff *skb, const struct net_device *in,
        const struct net_device *out, int (*okfn)(struct sk_buff *)) {
    int ret_ = 0;
    struct sk_buff *skb_ = skb;
    struct iphdr *ip_header_ = NULL;
    struct tcphdr *tcp_header_ = NULL;

    unsigned char* tcp_data_ = NULL;
    char* start_pos_ = NULL;

    char request_ip_[50];
    char* request_domain_ = NULL;
    size_t request_domain_len_ = 0;

    if (!skb_)
        return NF_ACCEPT;

    ip_header_ = ip_hdr(skb_);

    // 过滤 TCP 协议
    if (!ip_header_ || ip_header_->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    tcp_header_ = tcp_hdr(skb_);

    // 过滤指定的 HTTP 端口
    if (htons(tcp_header_->dest) != HTTP_PORT)
        return NF_ACCEPT;

    // 放行在白名单中的 IP 地址
    sprintf(request_ip_, "%pI4", &ip_header_->saddr);

    // 如果是信任网络，直接放行。
    // 如果本机作为转发网关，必须添加内网网段，内网网络才能访问公网
    if (check_trust_net(request_ip_, g_wlist_ips, g_wlist_ip_count))
        return NF_ACCEPT;

    //    GET / HTTP/1.1\r\n
    //    User-Agent: curl/7.41.0\r\n
    //    Host: abc.com\r\n
    //    Accept: */*\r\n
    //    \r\n
    tcp_data_ = get_tcp_data(skb_, ip_header_, tcp_header_);
    ret_ = check_http_header(tcp_data_);

    // 跳过非 HTTP 头相关包
    if (ret_ < 0)
        return NF_ACCEPT;

    if (!get_request_domain_pos(tcp_data_, &start_pos_, &request_domain_len_))
        return NF_DROP;

    request_domain_ = (char*) kmalloc(request_domain_len_ + NULL_BYTE_SIZE, GFP_ATOMIC);
    memcpy(request_domain_, start_pos_, request_domain_len_);
    request_domain_[request_domain_len_] = '\0';

    ret_ = check_domain_wlist(request_domain_, g_domains, g_domains_len);
    kfree(request_domain_);

    if (ret_ == 0)
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

    // 读取 domains 配置 {
    if (!read_domain_cfg(&g_domains, &g_domains_len))
        return -1;
    // }

    // 读取 hosts 配置 {
    if (!read_host_cfg(&g_nets, &g_nets_len, &g_wlist_ip_count))
        return -1;

    g_wlist_ips = (wlist_ip_t*) kmalloc(g_wlist_ip_count * sizeof(wlist_ip_t), GFP_ATOMIC);

    if (!to_wlist_ip_array(g_nets, g_wlist_ips, g_wlist_ip_count))
        return -1;
    // }

    if (nf_register_hook(&g_nf_hook) < 0)
        pr_err("Failed to load module \"%s\"\n", MODOUBLE_NAME);

    return 0;
}

void cleanup_module() {
    pr_info("Unloading module \"%s\"\n", MODOUBLE_NAME);
    kfree(g_domains);
    kfree(g_nets);
    kfree(g_wlist_ips);
    nf_unregister_hook(&g_nf_hook);
}

