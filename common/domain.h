/*
 * domain.h
 *
 *  Created on: 2015年3月16日
 *      Author: Fifi Lyu
 */

#ifndef COMMON_DOMAIN_H_
#define COMMON_DOMAIN_H_

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/netfilter_ipv4.h>

bool read_domain_cfg(char** data, loff_t* len);

bool get_request_domain_pos(unsigned char* tcp_header, char** start_pos, size_t* len);

int check_http_header(unsigned char* haystack);

int check_domain_wlist(
        char* request_domain, char* wlist, size_t wlist_len);


#endif /* COMMON_DOMAIN_H_ */
