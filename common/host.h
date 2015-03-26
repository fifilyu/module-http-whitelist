/*
 * misc.h
 *
 *  Created on: 2015年3月16日
 *      Author: Fifi Lyu
 */

#ifndef COMMON_HOST_H_
#define COMMON_HOST_H_

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/netfilter_ipv4.h>
#include "misc.h"

#define MAX_IP_CIDR_SIZE 18
#define MIN_IP_SIZE 7
#define MAX_IP_SIZE 15

#define MIN_CIDR 0
#define MAX_CIDR 32
#define MAX_CIDR_PREFIX_SIZE 32
#define DEFAULT_CIDR 32

typedef struct {
    char ip_cidr[MAX_IP_CIDR_SIZE + NULL_BYTE_SIZE];
    char ip[MAX_IP_SIZE + NULL_BYTE_SIZE];
    int cidr;
    char cidr_prefix[MAX_CIDR_PREFIX_SIZE + NULL_BYTE_SIZE];
} wlist_ip_t;

bool read_host_cfg(char** data, loff_t* len, size_t* line_count);

bool to_wlist_ip_array(char* cfg, wlist_ip_t* array, size_t array_count);

bool check_trust_net(
        const char* request_ip, wlist_ip_t* array, const size_t array_size);

#endif /* COMMON_HOST_H_ */
