/*
 * file.c
 *
 *  Created on: 2015年3月16日
 *      Author: Fifi Lyu
 */

#include "file.h"

#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/version.h>  // for LINUX_VERSION_CODE KERNEL_VERSION

struct file *file_open(const char *path, int flags, int rights) {
    struct file      *f_ = NULL;
    mm_segment_t     oldfs_;

    oldfs_ = get_fs();
    set_fs(get_ds());
    f_ = filp_open(path, flags, rights);
    set_fs(oldfs_);

    if (IS_ERR(f_))
        return NULL;

    return f_;
}

void file_close(struct file *f) {
    if (f)
        filp_close(f, NULL);
}

bool file_read(struct file *f, char **data, loff_t *size) {
    mm_segment_t     oldfs_;
    int              ret_ = 0;
    struct inode     *inode_ = NULL;
    char             *data_ = NULL;
    loff_t           size_ = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
    inode_ = file_inode(f);
#else
    inode_ = f->f_dentry->d_inode;
#endif
    *size = inode_->i_size;
    size_ = *size;

    *data = (char*) kmalloc(size_ + 1, GFP_ATOMIC);
    data_ = *data;

    oldfs_ = get_fs();
    set_fs(get_ds());
    ret_ = vfs_read(f, data_, size_, &f->f_pos);
    set_fs(oldfs_);

    if (ret_ < 0)
        return false;

    data_[size_ - 1]='\0';

    return true;
}

bool file_write(struct file *f, char *data, size_t size) {
    mm_segment_t    oldfs_;
    int             ret_ = 0;

    oldfs_ = get_fs();
    set_fs(get_ds());
    ret_ = vfs_write(f, data, size, &f->f_pos);
    set_fs(oldfs_);

    return ret_ >= 0;
}
