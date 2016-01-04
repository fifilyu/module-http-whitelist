/*
 * network.c
 *
 *  Created on: 2015年3月16日
 *      Author: Fifi Lyu
 */

#include "network.h"

#include "../issue.h"
#include "file.h"
#include "misc.h"
#include <linux/version.h>  // for LINUX_VERSION_CODE KERNEL_VERSION

bool validate_cidr(int cidr) {
    return (cidr >= MIN_CIDR && cidr <= MAX_CIDR);
}

bool tok_ip_cidr(const char *s, char *ip, int *cidr) {
    static const char    *delim_ = "/";
    char                 *ip_cidr_ = NULL;
    char                 *tmp_ = NULL;
    char                 *block_ = NULL;
    size_t               block_size_ = 0;
    int                  i_ = 0;
    bool                 ret_ = false;

    // 没有 CIDR 标识的网络地址，比如 8.8.8.8，使用默认 CIDR
    // 8.8.8.8 == 8.8.8.8/32
    if (validate_ipv4_address(s)) {
        strcpy(ip, s);
        *cidr = DEFAULT_CIDR;
        return true;
    }

    ip_cidr_ = (char*) kmalloc(strlen(s) + NULL_BYTE_SIZE, GFP_ATOMIC);
    strcpy(ip_cidr_, s);
    tmp_ = ip_cidr_;

    // strsep 会将第一个参数指向 NULL，导致内存无法释放。所以，使用临时指针
    while (NULL != (block_ = strsep(&tmp_, delim_))) {
        ++i_;
        block_size_ = strlen(block_);

        if (i_ == 1) {
            if (!validate_ipv4_address(block_))
                break;

            strcpy(ip, block_);
            continue;
        }

        if (i_ == 2) {
            sscanf(block_, "%d", &(*cidr));
            ret_ = validate_cidr(*cidr);
            break;
        }
    }  // end of while

    kfree(ip_cidr_);
    return ret_;
}

void ip_to_binary(const char *ip, const int cidr, char *dest) {
    size_t          i_ = 0;
    size_t          j_ = 0;
    char            *ip_ = NULL;
    int             ip_block_ = 0;
    char            *ip_block_str_ = NULL;
    char            bin_ip_block_[4][9];
    const size_t    ip_size_ = strlen(ip);

    ip_ = (char*) kmalloc(ip_size_ + NULL_BYTE_SIZE, GFP_ATOMIC);
    strcpy(ip_, ip);
    tok_str(&ip_, '.');

    for (i_ = 0, j_ = 0; j_ < 4; ++i_, ++j_) {
        ip_block_str_ = ip_ + i_;
        sscanf(ip_block_str_, "%d", &ip_block_);
        byte_to_binary(ip_block_, bin_ip_block_[j_]);
        i_ += strlen(ip_block_str_);
    }

    kfree(ip_);

    snprintf(
            dest,
            cidr + NULL_BYTE_SIZE,
            "%s%s%s%s",
            bin_ip_block_[0],
            bin_ip_block_[1],
            bin_ip_block_[2],
            bin_ip_block_[3]);
}

bool read_host_cfg(char **data, size_t *line_count) {
    loff_t size_ = 0;

    if (!read_cfg(WL_NETWORK, data, &size_))
        return false;

    tok_str(data, '\n');
    // 根据 '\0' 确定行数更加准确
    *line_count = get_line_count(*data, size_);

    return true;
}

bool init_net_array(network_t **array, size_t *array_size) {
    int          i_ = 0;
    int          j_ = 0;
    char         *ip_cidr_ = NULL;
    network_t    *network_ = NULL;
    char         *host_cfg_ = NULL;

    if (!read_host_cfg(&host_cfg_, array_size))
        return false;

    *array = (network_t*) kmalloc((*array_size) * sizeof(network_t), GFP_ATOMIC);

    for (i_ = 0, j_ = 0; j_ < (*array_size); ++i_, ++j_) {
        ip_cidr_ = host_cfg_ + i_;
        network_ = &((*array)[j_]);
        network_->ip[0] = '\0';

        // 跳过空行
        if (strlen(ip_cidr_) == 0)
            continue;

        if (!tok_ip_cidr(ip_cidr_, network_->ip, &network_->cidr)) {
            pr_info("[%s] Invaild configuration: \"%s\"\n", MODOUBLE_NAME, ip_cidr_);
            kfree(host_cfg_);
            return false;
        }

        strcpy(network_->ip_cidr, ip_cidr_);
        ip_to_binary(network_->ip, network_->cidr, network_->cidr_prefix);
        i_ += strlen(ip_cidr_);
    }

    kfree(host_cfg_);
    return true;
}

bool check_net(__be32 src_addr, network_t *array, const size_t array_size) {
    int            i_ = 0;
    network_t*     network_ = NULL;
    char           bin_ip_[MAX_CIDR_PREFIX_SIZE + NULL_BYTE_SIZE];
    char           src_ip_[MAX_IP_SIZE];

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
    sprintf(src_ip_, "%pI4", &src_addr);
#else
    sprintf(src_ip_, "%d.%d.%d.%d", NIPQUAD(src_addr));
#endif

    for (i_ = 0; i_ < array_size; ++i_) {
        network_ = &(array[i_]);
        memset(bin_ip_, 0, MAX_CIDR_PREFIX_SIZE + NULL_BYTE_SIZE);
        ip_to_binary(src_ip_, network_->cidr, bin_ip_);

        if (strcmp(bin_ip_, network_->cidr_prefix) == 0) {
            if (DEBUG)
                pr_info(
                        "[%s] Accept all http packages from \"%s\"\n",
                        MODOUBLE_NAME,
                        src_ip_);

            return true;
        }
    }

    return false;
}
