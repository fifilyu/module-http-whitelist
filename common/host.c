/*
 * host.c
 *
 *  Created on: 2015年3月16日
 *      Author: Fifi Lyu
 */

#include "host.h"

#include "../issue.h"
#include "file.h"
#include "misc.h"

// 此代码不会修改 tcp_data 指针指向的值
bool get_http_host(unsigned char *tcp_data, char **host) {
    static const char    *HEADER_HOST_TITLE_ = "\nHost: ";
    static size_t        HEADER_HOST_TITLE_SIZE_ = 7;
    char                 *start_pos_ = NULL;
    char                 *end_pos_ = NULL;
    size_t               size_ = 0;

    // [:端口号] 表示可能会出现

    //    \n
    //    Host: abc.com[:80]\r\n
    //    Accept: */*\r\n
    //    \r\n
    start_pos_ = strstr(tcp_data, HEADER_HOST_TITLE_);

    if (!start_pos_ || strlen(start_pos_) <= HEADER_HOST_TITLE_SIZE_)
        return false;

    //    \n
    //    Host: abc.com[:80]
    if (NULL == (end_pos_ = strchr(start_pos_, '\r')))
        return false;

    //    abc.com[:80]
    start_pos_ += strlen(HEADER_HOST_TITLE_);
    size_ = strlen(start_pos_) - strlen(end_pos_);

    //    abc.com:80 -> abc.com
    // 处理 Host 值中的端口号 {

    // 如果不复制并设置'\0'，查找端口号的位置会不准确
    *host = (char*) kmalloc(size_ + NULL_BYTE_SIZE, GFP_ATOMIC);
    memcpy(*host, start_pos_, size_);
    (*host)[size_] = '\0';

    if (NULL != (end_pos_ = strchr(*host, ':'))) {
        // 减去 :80 的长度
        size_ -= strlen(end_pos_);
        (*host)[size_] = '\0';
    }

    // }

    return true;
}

//    GET / HTTP/1.1\r\n
//    User-Agent: curl/7.41.0\r\n
//    Host: abc.com\r\n
//    Accept: */*\r\n
//    \r\n
bool check_http_header(unsigned char *tcp_data) {
    const size_t data_size_ = strlen(tcp_data);

    if(data_size_ < 8) {
        if (DEBUG)
            pr_info("[%s] Not HTTP header, skip...\n", MODOUBLE_NAME);

        return false;
    }

    if (memcmp(tcp_data, "GET ", 4) == 0) {
        return true;
    } else if (memcmp(tcp_data, "POST ", 5) == 0) {
        return true;
    } else if (memcmp(tcp_data, "OPTIONS ", 8) == 0) {
        return true;
    } else if (memcmp(tcp_data, "HEAD ", 5) == 0) {
        return true;
    } else if (memcmp(tcp_data, "PUT ", 4) == 0) {
        return true;
    } else if (memcmp(tcp_data, "DELETE ", 7) == 0) {
        return true;
    } else if (memcmp(tcp_data, "CONNECT ", 8) == 0) {
        return true;
    }

    if (DEBUG)
        pr_info("[%s] Not HTTP header, skip...\n", MODOUBLE_NAME);

    return false;
}

bool cmp_host(char *request_host, char *host) {
    char            *cut_request_host_ = NULL;
    const size_t    request_host_size_ = strlen(request_host);
    const size_t    host_size_ = strlen(host);

    // 普通域名
    if (request_host_size_ == host_size_
            && strcmp(host, request_host) == 0)
        return true;

    // 泛域名
    if (host[0] == '*' && request_host_size_ >= host_size_ - 1) {
        // *.abc.com -> .abc.com
        ++host;
        // 请求域名长度A - 白名单域名长度B = 域名长度差C
        // 指向请求域名的char*，向前移动 C，比如 www.abc.com -> .abc.com
        cut_request_host_ = request_host + (request_host_size_ - (host_size_ - 1));

        if (strcmp(host, cut_request_host_) == 0)
            return true;
    }

    return false;
}

bool check_host(unsigned char *tcp_data, char *hosts, size_t hosts_size) {
    bool    ret_ = false;
    int     i_ = 0;
    char    *host_ = NULL;
    char    *request_host_ = NULL;

    if (!get_http_host(tcp_data, &request_host_))
        return false;

    for (i_ = 0; i_ < hosts_size; ++i_) {
        host_ = hosts + i_;

        ret_ = cmp_host(request_host_, host_);

        if (ret_) break;

        i_ += strlen(host_);
    }

    if (DEBUG) {
        if (ret_)
            pr_info("[%s] Accept host \"%s\"\n", MODOUBLE_NAME, request_host_);
        else
            pr_info("[%s] Drop host \"%s\"\n", MODOUBLE_NAME, request_host_);
    }

    kfree(request_host_);
    return ret_;
}

bool init_host_str(char **data, loff_t* size) {
    if (!read_cfg(WL_HOST, data, size))
        return false;

    tok_str(data, '\n');

    return true;
}
