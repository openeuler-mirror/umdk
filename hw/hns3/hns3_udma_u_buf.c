// SPDX-License-Identifier: GPL-2.0
/* Huawei UDMA Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 */

#include <errno.h>
#include <sys/mman.h>
#include "hns3_udma_u_buf.h"

int udma_alloc_buf(struct udma_buf *buf, uint32_t size, int page_size)
{
	int ret;

	buf->length = align(size, page_size);
	buf->buf = mmap(NULL, buf->length, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (buf->buf == MAP_FAILED)
		return errno;

	ret = madvise(buf->buf, buf->length, MADV_DONTFORK);
	if (ret) {
		munmap(buf->buf, buf->length);
		URMA_LOG_ERR("madvise failed! ret=%d\n", ret);
	}

	return ret;
}

void udma_free_buf(struct udma_buf *buf)
{
	if (!buf->buf)
		return;

	munmap(buf->buf, buf->length);
}
