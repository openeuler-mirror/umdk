// SPDX-License-Identifier: GPL-2.0
/* Huawei HNS3_UDMA Linux driver
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

#include "urma_provider.h"
#include "hns3_udma_u_provider_ops.h"

static __attribute__((constructor)) void urma_provider_hns3_udma_init(void)
{
	int ret;

	ret = urma_register_provider_ops(&g_hns3_udma_u_provider_ops);
	if (ret)
		HNS3_UDMA_LOG_ERR("Provider HNS3_UDMA register ops failed(%d).\n", ret);
}

static __attribute__((destructor)) void urma_provider_hns3_udma_uninit(void)
{
	int ret;

	ret = urma_unregister_provider_ops(&g_hns3_udma_u_provider_ops);
	if (ret)
		HNS3_UDMA_LOG_ERR("Provider HNS3_UDMA register ops not registered(%d).\n",
			     ret);
}
