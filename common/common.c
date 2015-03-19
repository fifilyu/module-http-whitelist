/*
 * common.c
 *
 *  Created on: 2015年3月16日
 *      Author: Fifi Lyu
 */

#include "common.h"
#include "file.h"
#include "../issue.h"
#include <asm/segment.h>
#include <linux/buffer_head.h>

int read_list(const char* path, char** data, loff_t* len) {
    struct file* fp_ = NULL;
    int ret_ = 0;

    fp_ = file_open(path, O_RDONLY, 0);

    if (!fp_) {
        pr_info("[%s] cannot open \"%s\"\n", MODOUBLE_NAME, path);
        return -1;
    }

    ret_ = file_read(fp_, data, len);
    file_close(fp_);

    if (ret_ < 0) {
        pr_info("[%s] cannot read \"%s\"\n", MODOUBLE_NAME, path);
        return -1;
    }

    return 0;
}

int write_list(const char* path, char* data, loff_t len) {
    struct file* fp = NULL;
    int i_;
    int ret = 0;
    char* new_content_;

    fp = file_open(path, O_RDWR|O_CREAT,0644);

    if (!fp) {
        pr_info("[%s] cannot open \"%s\"\n", MODOUBLE_NAME, path);
        return -1;
    }

    new_content_ = (char*) kmalloc(len + 1, GFP_ATOMIC);
    memcpy(new_content_, data, len + 1);

    for (i_ = 0; i_< len;++i_) {
        if (new_content_[i_] == '\0')
            new_content_[i_] = '\n';
    }

    ret = file_write(fp, new_content_, len);
    file_close(fp);

    kfree(new_content_);

    if (ret < 0) {
        pr_info("[%s] cannot write \"%s\"\n", MODOUBLE_NAME, path);
        return -1;
    }

    return 0;
}

unsigned char* get_tcp_data(
        struct sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph) {

    // How SKBs work
    // http://vger.kernel.org/~davem/skb_data.html
    //    |xxxxxxxxxxx|
    //    |    head   |
    //    |    room   |
    //    |xxxxxxxxxxx|++++
    //    |    IP     |   +
    //    |    header |   +
    //    |xxxxxxxxxxx|   +
    //    |    TCP    |   +++>skb_data
    //    |    header |   +
    //    |xxxxxxxxxxx|   +
    //    |    user   |   +
    //    |    data   |   +
    //    |xxxxxxxxxxx|++++
    //    |    tail   |
    //    |    room   |
    //    |xxxxxxxxxxx|
    unsigned char* tcp_data_ =
            (unsigned char*)(skb->data + iph->ihl * 4 + tcph->doff * 4);

    return tcp_data_;
}

int get_request_domain_pos(unsigned char* tcp_header, char** start_pos, size_t* len) {
    char* header_host_title_ = NULL;
    char* end_pos_ = NULL;

    header_host_title_ = "\nHost: ";

    //    \n
    //    Host: abc.com\r\n
    //    Accept: */*\r\n
    //    \r\n
    *start_pos = strstr(tcp_header, header_host_title_);

    //    \r\n
    //    Accept: */*\r\n
    //    \r\n
    end_pos_ = strchr(*start_pos, '\r');

    // 这是非标准的 HTTP 协议，没找到 Host 值
    if (!*start_pos || !end_pos_)
        return -1;

    //    abc.com\r\n
    //    Accept: */*\r\n
    //    \r\n
    *start_pos += strlen(header_host_title_);

    //    abc.com
    *len = strlen(*start_pos) - strlen(end_pos_);

    return 0;
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

int check_ip_wlist(
        char* request_ip, char* wlist, size_t wlist_len) {
    int ret_ = -1;
    int i_ = 0;
    char* wlist_ip_ = NULL;

    for (i_ = 0; i_ < wlist_len; ++i_) {
        wlist_ip_ = wlist + i_;

        if (strcmp(wlist_ip_, request_ip) == 0) {
            ret_ = 0;
            break;
        }

        i_ = i_ + strlen(wlist_ip_);
    }

    if (DEBUG && ret_ == 0)
        pr_info("[%s] accept IP address \"%s\"\n", MODOUBLE_NAME, request_ip);

    return ret_;
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

int check_domain_wlist(
        char* request_domain, char* wlist, size_t wlist_len) {
    int ret_ = -1;
    int i_ = 0;
    char* wlist_domain_ = NULL;

    for (i_ = 0; i_ < wlist_len; ++i_) {
        wlist_domain_ = wlist + i_;

        ret_ = cmp_domain(request_domain, wlist_domain_);

        if (ret_ == 0) break;

        i_ = i_ + strlen(wlist_domain_);
    }

    if (DEBUG) {
        if (ret_ == 0)
            pr_info("[%s] accept domain \"%s\"\n", MODOUBLE_NAME, request_domain);
        else
            pr_info("[%s] drop domain \"%s\"\n", MODOUBLE_NAME, request_domain);
    }

    return ret_;
}
