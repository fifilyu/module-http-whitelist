/*
 * misc.c
 *
 *  Created on: 2015年3月16日
 *      Author: Fifi Lyu
 */

#include "misc.h"

#include "../issue.h"
#include "file.h"
#include <asm-generic/fcntl.h>
#include <linux/inet.h>
#include <linux/version.h>  // for LINUX_VERSION_CODE KERNEL_VERSION

bool read_cfg(const char *path, char **data, loff_t* size) {
    struct file    *fp_ = NULL;
    bool           ret_ = false;

    fp_ = file_open(path, O_RDONLY, 0);

    if (!fp_) {
        pr_info("[%s] Cannot open \"%s\"\n", MODOUBLE_NAME, path);
        return false;
    }

    ret_ = file_read(fp_, data, size);
    file_close(fp_);

    if (!ret_)
        pr_info("[%s] Cannot read \"%s\"\n", MODOUBLE_NAME, path);

    return ret_;
}

bool validate_ipv4_address(const char *ip) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
    __be32 result_;

    return (in4_pton(ip, strlen(ip), (__u8 *) &result_, '\0', NULL) == 1);
#else
    char           src_ip_[50];
    __be32 result_ = in_aton(ip);
    sprintf(src_ip_, "%d.%d.%d.%d", NIPQUAD(result_));
    src_ip_[strlen(ip)] = '\0';

    return strcmp(ip, src_ip_) == 0;
#endif
}

void byte_to_binary(int src, char *dest) {
    int i_;

    dest[0] = '\0';

    for (i_ = 128; i_ > 0; i_ >>= 1)
        strcat(dest, ((src & i_) == i_) ? "1" : "0");
}

void tok_str(char ** s, char delim) {
    size_t       i_ = 0;
    const size_t size_ = strlen(*s);

    for (i_ = 0; i_ < size_; ++i_)
        if ((*s)[i_] == delim)
            (*s)[i_] = '\0';
}

int get_line_count(const char *s, loff_t size) {
    loff_t    i_ = 0;
    int       count_ = 0;

    for (i_ = 0; i_ < size; ++i_)
        if (s[i_] == '\0')
            ++count_;

    return count_;
}


unsigned char *get_tcp_data(
        struct sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph) {
    unsigned char *tcp_data_ = NULL;

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
    tcp_data_ = (unsigned char*)(skb->data + iph->ihl * 4 + tcph->doff * 4);

    return tcp_data_;
}
