// SPDX-License-Identifier: MIT
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 *
 */

#include "udma_u_ops.h"

static __attribute__((constructor)) void urma_provider_ub_init(void)
{
	int ret;

	ret = urma_register_provider_ops(&g_udma_provider_ops);
	if (ret)
		UDMA_LOG_ERR("Provider UB register operations failed(%d).\n", ret);
	return;
}

static __attribute__((destructor)) void urma_provider_ub_uninit(void)
{
	int ret;

	ret = urma_unregister_provider_ops(&g_udma_provider_ops);
	if (ret)
		UDMA_LOG_ERR("Provider UB register operations unregister failed(%d).\n", ret);

	return;
}