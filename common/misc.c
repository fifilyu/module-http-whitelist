/*
 * misc.c
 *
 *  Created on: 2015年3月16日
 *      Author: Fifi Lyu
 */

#include "misc.h"

#include "file.h"
#include "../issue.h"
#include <asm/segment.h>
#include <linux/buffer_head.h>
#include <asm-generic/fcntl.h>
#include <linux/inet.h>

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

bool validate_ipv4_address(const char* ip) {
    __be32 result_;
    return (in4_pton(ip, strlen(ip), (__u8 *) &result_, '\0', NULL) == 0);
}

void byte_to_binary(int x, char* b) {
    int z;

    b[0] = '\0';

    for (z = 128; z > 0; z >>= 1)
        strcat(b, ((x & z) == z) ? "1" : "0");
}

void tok_str(char** s, char delim) {
    size_t i_ = 0;
    const size_t len_ = strlen(*s);

    for (i_ = 0; i_ < len_; ++i_)
        if ((*s)[i_] == delim)
            (*s)[i_] = '\0';
}

int get_line_count(const char* s, loff_t len) {
    size_t i_ = 0;
    int count_ = 0;

    for (i_ = 0; i_ < len; ++i_)
        if (s[i_] == '\0')
            ++count_;

    return count_;
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
