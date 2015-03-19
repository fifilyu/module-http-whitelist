/*
 * common.h
 *
 *  Created on: 2015年3月16日
 *      Author: Fifi Lyu
 */

#ifndef COMMON_COMMON_H_
#define COMMON_COMMON_H_

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter_ipv4.h>

int read_list(const char* path, char** data, loff_t* len);
int write_list(const char* path, char* data, loff_t len);

unsigned char* get_tcp_data(
        struct sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph);

int get_request_domain_pos(unsigned char* tcp_header, char** start_pos, size_t* len);

int check_http_header(unsigned char* haystack);

int check_ip_wlist(
        char* request_ip, char* wlist, size_t wlist_len);

int cmp_domain(char* request_domain, char* wlist_domain);
int check_domain_wlist(
        char* request_domain, char* wlist, size_t wlist_len);

#endif /* COMMON_COMMON_H_ */
