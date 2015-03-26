/*
 * domain.c
 *
 *  Created on: 2015年3月16日
 *      Author: Fifi Lyu
 */

#include "domain.h"
#include "misc.h"

#include "file.h"
#include "../issue.h"
#include <asm/segment.h>
#include <linux/buffer_head.h>
#include <asm-generic/fcntl.h>
#include <linux/inet.h>

bool read_domain_cfg(char** data, loff_t* len) {
    if (read_list(WL_DOMAINS, data, len) < 0)
        return false;

    tok_str(data, '\n');

    return true;
}

// 此代码不会修改 tcp_header 指针指向的值
bool get_request_domain_pos(unsigned char* tcp_header, char** start_pos, size_t* len) {
    static const char* HEADER_HOST_TITLE_ = "\nHost: ";
    static size_t HEADER_HOST_TITLE_SIZE_ = 7;
    char* end_pos_ = NULL;
    char* host_ = NULL;
    char* start_pos_ = NULL;

    // [:端口号] 表示可能会出现

    //    \n
    //    Host: abc.com[:80]\r\n
    //    Accept: */*\r\n
    //    \r\n
    start_pos_ = strstr(tcp_header, HEADER_HOST_TITLE_);

    if (!start_pos_ || strlen(start_pos_) <= HEADER_HOST_TITLE_SIZE_)
        return false;

    //    \n
    //    Host: abc.com[:80]
    if (NULL == (end_pos_ = strchr(start_pos_, '\r')))
        return false;

    //    abc.com[:80]
    start_pos_ += strlen(HEADER_HOST_TITLE_);
    *len = strlen(start_pos_) - strlen(end_pos_);

    //    abc.com:80 -> abc.com
    // 处理 Host 值中的端口号 {
    // 如果不复制并设置'\0'，查找端口号的位置会不准确
    host_ = (char*) kmalloc(*len + NULL_BYTE_SIZE, GFP_ATOMIC);
    memcpy(host_, start_pos_, *len);
    host_[*len] = '\0';

    if (NULL != (end_pos_ = strchr(host_, ':')))
        // 减去 :80 的长度
        *len -= strlen(end_pos_);

    kfree(host_);
    // }

    *start_pos = start_pos_;
    return true;
}

//    GET / HTTP/1.1\r\n
//    User-Agent: curl/7.41.0\r\n
//    Host: abc.com\r\n
//    Accept: */*\r\n
//    \r\n
int check_http_header(unsigned char* haystack) {
    size_t data_len_ = strlen(haystack);

    if(data_len_ < 8) {
        if (DEBUG) pr_info("[%s] not HTTP header, skip...\n", MODOUBLE_NAME);
        return -1;
    }

    if (memcmp(haystack, "GET ", 4) == 0) {
        return 0;
    } else if (memcmp(haystack, "POST ", 5) == 0) {
        return 0;
    } else if (memcmp(haystack, "OPTIONS ", 8) == 0) {
        return 0;
    } else if (memcmp(haystack, "HEAD ", 5) == 0) {
        return 0;
    } else if (memcmp(haystack, "PUT ", 4) == 0) {
        return 0;
    } else if (memcmp(haystack, "DELETE ", 7) == 0) {
        return 0;
    } else if (memcmp(haystack, "CONNECT ", 8) == 0) {
        return 0;
    }

    if (DEBUG) pr_info("[%s] not HTTP header, skip...\n", MODOUBLE_NAME);
    return -1;
}

int cmp_domain(char* request_domain, char* wlist_domain) {
    char* cut_request_domain = NULL;
    size_t request_domain_len_ = strlen(request_domain);
    size_t wlist_domain_len_ = strlen(wlist_domain);

    // 普通域名
    if (request_domain_len_ == wlist_domain_len_
            && strcmp(wlist_domain, request_domain) == 0)
        return 0;

    // 泛域名
    if (wlist_domain[0] == '*' && request_domain_len_ >= wlist_domain_len_ - 1) {
        // *.abc.com -> .abc.com
        ++wlist_domain;
        // 请求域名长度A - 白名单域名长度B = 域名长度差C
        // 指向请求域名的char*，向前移动 C，比如 www.abc.com -> .abc.com
        cut_request_domain = request_domain + (request_domain_len_ - (wlist_domain_len_ - 1));

        if (strcmp(wlist_domain, cut_request_domain) == 0)
            return 0;
    }

    return -1;
}

//TODO 需要将域名列表单独存储
int check_domain_wlist(
        char* request_domain, char* wlist, size_t wlist_len) {
    int ret_ = 0;
    int i_ = 0;
    char* wlist_domain_ = NULL;

    for (i_ = 0; i_ < wlist_len; ++i_) {
        wlist_domain_ = wlist + i_;

        ret_ = cmp_domain(request_domain, wlist_domain_);

        if (ret_ == 0) break;

        i_ += strlen(wlist_domain_);
    }

    if (DEBUG) {
        if (ret_ == 0)
            pr_info("[%s] accept domain \"%s\"\n", MODOUBLE_NAME, request_domain);
        else
            pr_info("[%s] drop domain \"%s\"\n", MODOUBLE_NAME, request_domain);
    }

    return ret_;
}
