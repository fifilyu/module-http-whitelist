/*
 * file.h
 *
 *  Created on: 2015年3月16日
 *      Author: Fifi Lyu
 */

#ifndef COMMON_FILE_H_
#define COMMON_FILE_H_

#include <linux/fs.h>

struct file* file_open(const char* path, int flags, int rights);
void file_close(struct file* f);

int file_read(struct file* f, char** data, loff_t* len);
int file_write(struct file* f, char* data, size_t len);
// Write back data and metadata for @file to disk
int file_sync(struct file* f);

#endif /* COMMON_FILE_H_ */
