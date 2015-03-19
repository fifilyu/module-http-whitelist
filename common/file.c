/*
 * file.c
 *
 *  Created on: 2015年3月16日
 *      Author: Fifi Lyu
 */

#include "file.h"
#include <asm/uaccess.h>
#include <linux/slab.h>

struct file* file_open(const char* path, int flags, int rights) {
    struct file* f_ = NULL;
    mm_segment_t oldfs_;

    oldfs_ = get_fs();
    set_fs(get_ds());
    f_ = filp_open(path, flags, rights);
    set_fs(oldfs_);

    if (IS_ERR(f_))
        return NULL;

    return f_;
}

void file_close(struct file* f) {
    if (f)
        filp_close(f, NULL);
}

int file_read(struct file* f, char** data, loff_t* len) {
    mm_segment_t oldfs_;
    int ret_;
    struct inode *inode_;
    char* data_;
    loff_t len_;
    int i_;

    inode_ = f->f_dentry->d_inode;
    *len = inode_->i_size;
    len_ = *len;

    *data = (char*) kmalloc(len_ + 1, GFP_ATOMIC);
    data_ = *data;

    oldfs_ = get_fs();
    set_fs(get_ds());
    ret_ = f->f_op->read(f, data_, len_, &f->f_pos);
    set_fs(oldfs_);

    if (ret_ < 0)
        return -1;

    data_[len_ - 1]='\0';

    // 转换为 char 数组
    // test.com\n*.abc.com\nabc.com\n
    // ->
    // test.com\0*.abc.com\0abc.com\0
    for (i_ = 0; i_< len_;++i_) {
        if (data_[i_] == '\n')
            data_[i_] = '\0';
    }

    return 0;
}

int file_write(struct file* f, char* data, size_t len) {
    mm_segment_t oldfs_;
    int ret_;

    oldfs_ = get_fs();
    set_fs(get_ds());
    ret_ = f->f_op->write(f, data, len, &f->f_pos);
    set_fs(oldfs_);

    return ret_;
}

// Write back data and metadata for @file to disk
int file_sync(struct file* f) {
    return vfs_fsync(f, 0);
}
