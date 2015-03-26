/*
 * host.c
 *
 *  Created on: 2015年3月16日
 *      Author: Fifi Lyu
 */

#include "host.h"

#include "file.h"
#include "../issue.h"
#include "misc.h"
#include <asm/segment.h>
#include <linux/buffer_head.h>
#include <asm-generic/fcntl.h>
#include <linux/inet.h>

bool validate_cidr(int cidr) {
    return (cidr < MIN_CIDR || cidr > MAX_CIDR);
}

bool tok_ip_cidr(const char* s, char* ip, int* cidr) {
    static const char* delim_ = "/";
    char* ip_cidr_ = (char*) kmalloc(strlen(s) + NULL_BYTE_SIZE, GFP_ATOMIC);
    char* tmp_ = ip_cidr_;
    char* block_ = NULL;
    size_t block_len_ = 0;
    int i_ = 0;
    bool ret_ = false;

    strcpy(ip_cidr_, s);

    // strsep 会将第一个参数指向 NULL，导致内存无法释放。所以，使用临时指针
    while (NULL != (block_ = strsep(&tmp_, delim_))) {
        ++i_;
        block_len_ = strlen(block_);

        if (i_ == 1) {
            if (validate_ipv4_address(block_) < 0)
                break;

            strcpy(ip, block_);
            continue;
        }

        if (i_ == 2) {
            sscanf(block_, "%d", &(*cidr));
            if (validate_cidr(*cidr) == 0)
                ret_ = true;
            break;
        }
    }  // end of while

    kfree(ip_cidr_);
    return ret_;
}

void ip_to_binary(const char* ip, const int cidr, char* bin) {
    int ip_block_ = 0;
    size_t i_ = 0;
    size_t j_ = 0;

    const size_t ip_len_ = strlen(ip);
    char* ip_ = (char*) kmalloc(ip_len_ + NULL_BYTE_SIZE, GFP_ATOMIC);
    char* ip_block_str_ = NULL;
    char bin_ip_block_[4][9];

    strcpy(ip_, ip);
    tok_str(&ip_, '.');

    for (i_ = 0, j_ = 0; j_ < 4; ++i_, ++j_) {
        ip_block_str_ = ip_ + i_;
        sscanf(ip_block_str_, "%d", &ip_block_);
        byte_to_binary(ip_block_, bin_ip_block_[j_]);
        i_ += strlen(ip_block_str_);
    }

    snprintf(
            bin,
            cidr + NULL_BYTE_SIZE,
            "%s%s%s%s",
            bin_ip_block_[0],
            bin_ip_block_[1],
            bin_ip_block_[2],
            bin_ip_block_[3]);

    kfree(ip_);
}

bool read_host_cfg(char** data, loff_t* len, size_t* line_count) {
    if (read_list(WL_HOSTS, data, len) < 0)
        return false;

    tok_str(data, '\n');
    // 根据 '\0' 确定行数更加准确
    *line_count = get_line_count(*data, *len);

    return true;
}

bool to_wlist_ip_array(char* cfg, wlist_ip_t* array, size_t array_count) {
    int i_ = 0;
    int j_ = 0;
    char* ip_cidr_ = NULL;
    wlist_ip_t* wlist_ip_ = NULL;

    for (i_ = 0, j_ = 0; j_ < array_count; ++i_, ++j_) {
        ip_cidr_ = cfg + i_;

        wlist_ip_ = &(array[j_]);
        wlist_ip_->ip[0] = '\0';
        wlist_ip_->cidr = DEFAULT_CIDR;

        if (!tok_ip_cidr(ip_cidr_, wlist_ip_->ip, &wlist_ip_->cidr)) {
            pr_err("invaild configuration: \"%s\"\n", ip_cidr_);
            return false;
        }

        strcpy(wlist_ip_->ip_cidr, ip_cidr_);
        ip_to_binary(wlist_ip_->ip, wlist_ip_->cidr, wlist_ip_->cidr_prefix);
        i_ += strlen(ip_cidr_);
    }

    return true;
}

bool check_trust_net(
        const char* request_ip, wlist_ip_t* array, const size_t array_size) {
    int i_ = 0;
    wlist_ip_t* wlist_ip_ = NULL;
    char bin_ip[MAX_CIDR_PREFIX_SIZE + NULL_BYTE_SIZE];

    for (i_ = 0; i_ < array_size; ++i_) {
        wlist_ip_ = &(array[i_]);
        memset(bin_ip, 0, MAX_CIDR_PREFIX_SIZE + NULL_BYTE_SIZE);
        ip_to_binary(request_ip, wlist_ip_->cidr, bin_ip);

        if (strcmp(bin_ip, wlist_ip_->cidr_prefix) == 0) {
            pr_info("%s is part of %s\n", request_ip, wlist_ip_->ip_cidr);
            return true;
        }
    }

    return false;
}
