/*
 * network.h
 *
 *  Created on: 2015年3月16日
 *      Author: Fifi Lyu
 */

#ifndef COMMON_NETWORK_H_
#define COMMON_NETWORK_H_

#include "misc.h"
#include <linux/types.h>

#define MAX_IP_CIDR_SIZE 18
#define MAX_IP_SIZE 15

#define MIN_CIDR 0
#define MAX_CIDR 32
#define MAX_CIDR_PREFIX_SIZE 32
#define DEFAULT_CIDR 32

typedef struct {
    char ip_cidr[MAX_IP_CIDR_SIZE + NULL_BYTE_SIZE];
    char ip[MAX_IP_SIZE + NULL_BYTE_SIZE];
    int  cidr;
    char cidr_prefix[MAX_CIDR_PREFIX_SIZE + NULL_BYTE_SIZE];
} network_t;

bool init_net_array(network_t **array, size_t *array_size);

bool check_net(__be32 src_addr, network_t *array, const size_t array_size);

#endif /* COMMON_NETWORK_H_ */
