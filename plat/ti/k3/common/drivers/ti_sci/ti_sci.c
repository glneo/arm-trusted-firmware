/*
 * Texas Instruments System Control Interface Driver
 *   Based on Linux and U-Boot implementation
 *
 * Copyright (C) 2018 Texas Instruments Incorporated - http://www.ti.com/
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <debug.h>
#include <errno.h>
#include <platform_def.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <sec_proxy.h>

#include "ti_sci_protocol.h"
#include "ti_sci.h"

/**
 * struct ti_sci_xfer - Structure representing a message flow
 * @tx_message:	Transmit message
 * @rx_len:	Receive message length
 */
struct ti_sci_xfer {
	struct k3_sec_proxy_msg tx_message;
	uint8_t rx_len;
};

/**
 * struct ti_sci_desc - Description of SoC integration
 * @host_id:		Host identifier representing the compute entity
 * @max_rx_timeout_us:	Timeout for communication with SoC (in Microseconds)
 * @max_msg_size:	Maximum size of data per message that can be handled.
 */
struct ti_sci_desc {
	uint8_t host_id;
	int max_rx_timeout_us;
	int max_msg_size;
};

/**
 * struct ti_sci_info - Structure representing a TI SCI instance
 * @desc:	SoC description for this instance
 * @seq:	Seq id used for verification for tx and rx message.
 */
struct ti_sci_info {
	const struct ti_sci_desc desc;
	uint8_t seq;
};

struct ti_sci_info info = {
	.desc = {
		.host_id = TI_SCI_HOST_ID,
		.max_rx_timeout_us = TI_SCI_TIMEOUT_US,
		.max_msg_size = TI_SCI_MAX_MESSAGE_SIZE,
	},
	.seq = 0x0a,
};

/**
 * ti_sci_setup_one_xfer() - Setup one message type
 *
 * @msg_type:	Message type
 * @msg_flags:	Flag to set for the message
 * @buf:	Buffer to be send to mailbox channel
 * @tx_message_size: transmit message size
 * @rx_message_size: receive message size
 *
 * Helper function which is used by various command functions that are
 * exposed to clients of this driver for allocating a message traffic event.
 *
 * Return: 0 if all went fine, else corresponding error.
 */
static int ti_sci_setup_one_xfer(uint16_t msg_type, uint32_t msg_flags,
				 uint32_t *buf,
				 size_t tx_message_size,
				 size_t rx_message_size,
				 struct ti_sci_xfer *xfer)
{
	struct ti_sci_msg_hdr *hdr;

	/* Ensure we have sane transfer sizes */
	if (rx_message_size > info.desc.max_msg_size ||
	    tx_message_size > info.desc.max_msg_size ||
	    rx_message_size < sizeof(*hdr) || tx_message_size < sizeof(*hdr))
		return -ERANGE;

	info.seq = ~info.seq;
	xfer->tx_message.buf = buf;
	xfer->tx_message.len = tx_message_size;
	xfer->rx_len = (uint8_t)rx_message_size;

	hdr = (struct ti_sci_msg_hdr *)buf;
	hdr->seq = info.seq;
	hdr->type = msg_type;
	hdr->host = info.desc.host_id;
	hdr->flags = msg_flags;

	return 0;
}

/**
 * ti_sci_get_response() - Receive response from mailbox channel
 *
 * @xfer:	Transfer to initiate and wait for response
 * @chan:	Channel to receive the response
 *
 * Return: -ETIMEDOUT in case of no response, if transmit error,
 *	   return corresponding error, else if all goes well,
 *	   return 0.
 */
static inline int ti_sci_get_response(struct ti_sci_xfer *xfer,
				      enum k3_sec_proxy_chan_id chan)
{
	struct k3_sec_proxy_msg *msg = &xfer->tx_message;
	struct ti_sci_msg_hdr *hdr;
	int ret;

	/* Receive the response */
	ret = k3_sec_proxy_recv(chan, msg);
	if (ret) {
		ERROR("Message receive failed (%d)\n", ret);
		return ret;
	}

	/* msg is updated by Secure Proxy driver */
	hdr = (struct ti_sci_msg_hdr *)msg->buf;

	/* Sanity check for message response */
	if (hdr->seq != info.seq) {
		ERROR("Message for %d is not expected\n", hdr->seq);
		return -EINVAL;
	}

	if (msg->len > info.desc.max_msg_size) {
		ERROR("Unable to handle %lu xfer (max %d)\n",
		      msg->len, info.desc.max_msg_size);
		return -EINVAL;
	}

	if (msg->len < xfer->rx_len) {
		ERROR("Recv xfer %lu < expected %d length\n",
		      msg->len, xfer->rx_len);
		return -EINVAL;
	}

	return 0;
}

/**
 * ti_sci_do_xfer() - Do one transfer
 *
 * @xfer:	Transfer to initiate and wait for response
 *
 * Return: 0 if all went fine, else return appropriate error.
 */
static inline int ti_sci_do_xfer(struct ti_sci_xfer *xfer)
{
	struct k3_sec_proxy_msg *msg = &xfer->tx_message;
	int ret;

	/* Send the message */
	ret = k3_sec_proxy_send(SP_HIGH_PRIORITY, msg);
	if (ret) {
		ERROR("Message sending failed (%d)\n", ret);
		return ret;
	}

	ret = ti_sci_get_response(xfer, SP_RESPONSE);
	if (ret) {
		ERROR("Failed to get response (%d)\n", ret);
		return ret;
	}

	return 0;
}

/**
 * ti_sci_get_revision() - command to get the revision of the SCI entity
 *
 * Updates the SCI information in the internal data structure.
 *
 * Return: 0 if all went fine, else return appropriate error.
 */
int ti_sci_get_revision(struct ti_sci_msg_resp_version *rev_info)
{
	struct ti_sci_msg_hdr hdr;
	struct ti_sci_xfer xfer;
	int ret;

	ret = ti_sci_setup_one_xfer(TI_SCI_MSG_VERSION, 0x0,
				    (uint32_t *)&hdr, sizeof(hdr),
				    sizeof(*rev_info), &xfer);
	if (ret) {
		ERROR("Message alloc failed (%d)\n", ret);
		return ret;
	}

	ret = ti_sci_do_xfer(&xfer);
	if (ret) {
		ERROR("Transfer send failed (%d)\n", ret);
		return ret;
	}

	memcpy(rev_info, xfer.tx_message.buf, sizeof(*rev_info));

	return 0;
}

/**
 * ti_sci_init() - Basic initialization
 *
 * Return: 0 if all goes good, else appropriate error message.
 */
int ti_sci_init(void)
{
	struct ti_sci_msg_resp_version rev_info;
	int ret;

	ret = ti_sci_get_revision(&rev_info);
	if (ret) {
		ERROR("Unable to communicate with control firmware (%d)\n", ret);
		return ret;
	}

	INFO("SYSFW ABI: %d.%d (firmware rev 0x%04x '%s')\n",
	     rev_info.abi_major, rev_info.abi_minor,
	     rev_info.firmware_revision,
	     rev_info.firmware_description);

	return 0;
}
