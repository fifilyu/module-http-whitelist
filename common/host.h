/*
 * host.h
 *
 *  Created on: 2015年3月16日
 *      Author: Fifi Lyu
 */

#ifndef COMMON_HOST_H_
#define COMMON_HOST_H_

#include <linux/types.h>

bool init_host_str(char **data, loff_t *size);

bool check_http_header(unsigned char *tcp_data);

bool check_host(unsigned char *tcp_data, char *hosts, size_t hosts_size);

#endif /* COMMON_HOST_H_ */
