/*
 * issue.h
 *
 *  Created on: 2015年3月16日
 *      Author: Fifi Lyu
 */

#ifndef ISSUE_H_
#define ISSUE_H_

#include <linux/stddef.h>

// 0 off
// 1 on
#define DEBUG 0

#define HTTP_PORT 80

#define WL_HOST  "/etc/http_whitelist/host"
#define WL_NETWORK  "/etc/http_whitelist/network"

#define MODOUBLE_NAME "http_whitelist"
#define LICENSE "Dual MIT/GPL";
#define AUTHOR "Fifi Lyu";
#define DESCRIPTION "HTTP Whitelist";

#endif /* ISSUE_H_ */
