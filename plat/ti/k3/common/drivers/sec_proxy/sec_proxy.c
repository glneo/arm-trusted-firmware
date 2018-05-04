/*
 * Texas Instruments K3 Secure Proxy Driver
 *   Based on Linux and U-Boot implementation
 *
 * Copyright (C) 2018 Texas Instruments Incorporated - http://www.ti.com/
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <debug.h>
#include <errno.h>
#include <mmio.h>
#include <platform_def.h>
#include <stdlib.h>
#include <utils.h>
#include <utils_def.h>

#include "sec_proxy.h"

/* SEC PROXY RT THREAD STATUS */
#define RT_THREAD_STATUS			0x0
#define RT_THREAD_STATUS_ERROR_SHIFT		31
#define RT_THREAD_STATUS_ERROR_MASK		(1 << 31)
#define RT_THREAD_STATUS_CUR_CNT_SHIFT		0
#define RT_THREAD_STATUS_CUR_CNT_MASK		(0xff << 0)

/* SEC PROXY SCFG THREAD CTRL */
#define SCFG_THREAD_CTRL			0x1000
#define SCFG_THREAD_CTRL_DIR_SHIFT		31
#define SCFG_THREAD_CTRL_DIR_MASK		(1 << 31)

#define SEC_PROXY_THREAD(base, x)		((base) + (0x1000 * (x)))
#define THREAD_IS_RX				1
#define THREAD_IS_TX				0

/**
 * struct k3_sec_proxy_desc - Description of secure proxy integration.
 * @thread_count:	Number of Threads.
 * @max_msg_size:	Message size in bytes.
 * @data_start_offset:	Offset of the First data register of the thread
 * @data_end_offset:	Offset of the Last data register of the thread
 */
struct k3_sec_proxy_desc {
	uint16_t thread_count;
	uint16_t max_msg_size;
	uint16_t data_start_offset;
	uint16_t data_end_offset;
};

/**
 * struct k3_sec_proxy_thread - Description of a secure proxy Thread
 * @id:		Thread ID
 * @data:	Thread Data path region for target
 * @scfg:	Secure Config Region for Thread
 * @rt:		RealTime Region for Thread
 * @rx_buf:	Receive buffer data, max message size.
 */
struct k3_sec_proxy_thread {
	uint32_t id;
	uintptr_t data;
	uintptr_t scfg;
	uintptr_t rt;
	uint32_t rx_buf[SEC_PROXY_MAX_MESSAGE_SIZE];
};

/**
 * struct k3_sec_proxy_mbox - Description of a Secure Proxy Instance
 * @desc:		Description of the SoC integration
 * @chans:		Array for valid thread instances
 */
struct k3_sec_proxy_mbox {
	const struct k3_sec_proxy_desc desc;
	struct k3_sec_proxy_thread threads[];
};

/*
 * Thread ID #0: DMSC notify
 * Thread ID #1: DMSC request response
 * Thread ID #2: DMSC request high priority
 * Thread ID #3: DMSC request low priority
 * Thread ID #4: DMSC notify response
 */
#define SP_THREAD(_x) \
	[_x] = { \
		.id = _x, \
		.data = SEC_PROXY_THREAD(SEC_PROXY_DATA_BASE, _x), \
		.scfg = SEC_PROXY_THREAD(SEC_PROXY_SCFG_BASE, _x), \
		.rt = SEC_PROXY_THREAD(SEC_PROXY_RT_BASE, _x), \
	}

struct k3_sec_proxy_mbox spm = {
	.desc = {
		.thread_count = SEC_PROXY_THREADS,
		.max_msg_size = SEC_PROXY_MAX_MESSAGE_SIZE,
		.data_start_offset = 0x4,
		.data_end_offset = 0x3C,
	},
	.threads = {
		SP_THREAD(SP_NOTIFY),
		SP_THREAD(SP_RESPONSE),
		SP_THREAD(SP_HIGH_PRIORITY),
		SP_THREAD(SP_LOW_PRIORITY),
		SP_THREAD(SP_NOTIFY_RESP),
	},
};

static inline uint32_t sp_readl(uintptr_t addr, unsigned int offset)
{
	return mmio_read_32(addr + offset);
}

static inline void sp_writel(uintptr_t addr, unsigned int offset, uint32_t data)
{
	mmio_write_32(addr + offset, data);
}

/**
 * k3_sec_proxy_verify_thread() - Verify thread status before
 *				  sending/receiving data.
 * @spt: Pointer to Secure Proxy thread description
 * @dir: Direction of the thread
 *
 * Return: 0 if all goes well, else appropriate error message.
 */
static inline int k3_sec_proxy_verify_thread(struct k3_sec_proxy_thread *spt,
					     uint8_t dir)
{
	/* Check for any errors already available */
	if (sp_readl(spt->rt, RT_THREAD_STATUS) &
	    RT_THREAD_STATUS_ERROR_MASK) {
		ERROR("Thread %d is corrupted, cannot send data\n", spt->id);
		return -EINVAL;
	}

	/* Make sure thread is configured for right direction */
	if ((sp_readl(spt->scfg, SCFG_THREAD_CTRL) & SCFG_THREAD_CTRL_DIR_MASK)
	    != (dir << SCFG_THREAD_CTRL_DIR_SHIFT)) {
		if (dir)
			ERROR("Trying to receive data on tx Thread %d\n",
			      spt->id);
		else
			ERROR("Trying to send data on rx Thread %d\n",
			      spt->id);
		return -EINVAL;
	}

	/* Check the message queue before sending/receiving data */
	while (!(sp_readl(spt->rt, RT_THREAD_STATUS) & RT_THREAD_STATUS_CUR_CNT_MASK))
		VERBOSE("Waiting for thread %d to clear\n", spt->id);

	return 0;
}

/**
 * k3_sec_proxy_send() - Send data over a Secure Proxy thread
 * @id: Channel Identifier
 * @msg: Pointer to k3_sec_proxy_msg
 *
 * Return: 0 if all goes well, else appropriate error message.
 */
int k3_sec_proxy_send(uint32_t id, const struct k3_sec_proxy_msg *msg)
{
	struct k3_sec_proxy_thread *spt = &spm.threads[id];
	int num_words, trail_bytes, i, ret;
	uintptr_t data_reg;

	ret = k3_sec_proxy_verify_thread(spt, THREAD_IS_TX);
	if (ret) {
		ERROR("Thread %d verification failed (%d)\n", spt->id, ret);
		return ret;
	}

	/* Check the message size. */
	if (msg->len > spm.desc.max_msg_size) {
		ERROR("Thread %d message length %lu > max msg size %d\n",
		      spt->id, msg->len, spm.desc.max_msg_size);
		return -EINVAL;
	}

	/* Send the message */
	data_reg = spm.desc.data_start_offset;
	num_words = msg->len / sizeof(uint32_t);
	for (i = 0; i < num_words; i++) {
		sp_writel(spt->data, data_reg, msg->buf[i]);
		data_reg += sizeof(uint32_t);
	}

	trail_bytes = msg->len % sizeof(uint32_t);
	if (trail_bytes) {
		uint32_t data_trail = msg->buf[i];

		/* Ensure all unused data is 0 */
		uint32_t trail_mask = 0xFFFFFFFF >>
				      (8 * (sizeof(uint32_t) - trail_bytes));
		data_trail &= trail_mask;
		sp_writel(spt->data, data_reg, data_trail);
		data_reg++;
	}
	/*
	 * 'data_reg' indicates next register to write. If we did not already
	 * write on tx complete reg(last reg), we must do so for transmit
	 */
	if (data_reg <= spm.desc.data_end_offset)
		sp_writel(spt->data, spm.desc.data_end_offset, 0);

	VERBOSE("Message successfully sent on thread %ud\n", id);

	return 0;
}

/**
 * k3_sec_proxy_recv() - Receive data from a Secure Proxy thread
 * @id: Channel Identifier
 * @msg: Pointer to k3_sec_proxy_msg
 *
 * Return: 0 if all goes well, else appropriate error message.
 */
int k3_sec_proxy_recv(uint32_t id, struct k3_sec_proxy_msg *msg)
{
	struct k3_sec_proxy_thread *spt = &spm.threads[id];
	uintptr_t data_reg;
	int num_words, i, ret;

	ret = k3_sec_proxy_verify_thread(spt, THREAD_IS_RX);
	if (ret) {
		ERROR("Thread %d verification failed (%d)\n", spt->id, ret);
		return ret;
	}

	data_reg = spm.desc.data_start_offset;
	num_words = spm.desc.max_msg_size / sizeof(uint32_t);
	for (i = 0; i < num_words; i++) {
		spt->rx_buf[i] = sp_readl(spt->data, data_reg);
		data_reg += sizeof(uint32_t);
	}

	msg->len = spm.desc.max_msg_size;
	msg->buf = spt->rx_buf;

	VERBOSE("Message successfully received from thread %ud\n", id);

	return 0;
}
