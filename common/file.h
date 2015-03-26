/*
 * file.h
 *
 *  Created on: 2015年3月16日
 *      Author: Fifi Lyu
 */

#ifndef COMMON_FILE_H_
#define COMMON_FILE_H_

#include <linux/fs.h>

struct file *file_open(const char *path, int flags, int rights);

void file_close(struct file *f);

bool file_read(struct file *f, char **data, loff_t *size);

bool file_write(struct file *f, char *data, size_t size);

// Write back data and metadata for @file to disk
bool file_sync(struct file *f);

#endif /* COMMON_FILE_H_ */
