/**
 * (C) Copyright 2016 Intel Corporation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * GOVERNMENT LICENSE RIGHTS-OPEN SOURCE SOFTWARE
 * The Government's rights to use, modify, reproduce, release, perform, display,
 * or disclose this software are subject to the terms of the Apache License as
 * provided in Contract No. B609815.
 * Any reproduction of computer software, computer software documentation, or
 * portions thereof marked with this legend must also reproduce the markings.
 */
/**
 * dsr: RPC Protocol Definitions
 *
 * This is naturally shared by both dsrc and dsrs. The in and out data
 * structures may safely contain compiler-generated paddings, which will be
 * removed dtp's serialization process.
 *
 */

#ifndef __DAOS_OBJ_RPC_H__
#define __DAOS_OBJ_RPC_H__

#include <stdint.h>
#include <uuid/uuid.h>
#include <daos/event.h>
#include <daos/rpc.h>
#include <daos/transport.h>
#include <daos_event.h>

/*
 * RPC operation codes
 *
 * These are for daos_rpc::dr_opc and DAOS_RPC_OPCODE(opc, ...) rather than
 * dtp_req_create(..., opc, ...). See daos_rpc.h.
 */
enum obj_rpc_opc {
	DAOS_OBJ_RPC_UPDATE	= 1,
	DAOS_OBJ_RPC_FETCH	= 2,
	DAOS_OBJ_RPC_ENUMERATE	= 3,
};

struct obj_update_in {
	daos_unit_oid_t		oui_oid;
	uuid_t			oui_co_hdl;
	uint64_t		oui_epoch;
	uint32_t		oui_nr;
	uint32_t		oui_pad;
	daos_dkey_t		oui_dkey;
	struct dtp_array	oui_iods;
	struct dtp_array	oui_bulks;
};

struct obj_fetch_out {
	int32_t			ofo_ret;
	uint32_t		ofo_pad;
	struct dtp_array	ofo_sizes;
};

/* object Enumerate in/out */
struct obj_key_enum_in {
	daos_unit_oid_t		oei_oid;
	uuid_t			oei_co_hdl;
	uint64_t		oei_epoch;
	uint32_t		oei_nr;
	uint32_t		oei_pad;
	daos_hash_out_t		oei_anchor;
	dtp_bulk_t		oei_bulk;
};

struct obj_key_enum_out {
	int32_t			oeo_ret;
	uint32_t		oeo_pad;
	daos_hash_out_t		oeo_anchor;
	struct dtp_array	oeo_kds;
};

extern struct daos_rpc daos_obj_rpcs[];

int obj_req_create(dtp_context_t dtp_ctx, dtp_endpoint_t tgt_ep,
		   dtp_opcode_t opc, dtp_rpc_t **req);
void obj_reply_set_status(dtp_rpc_t *rpc, int status);
int obj_reply_get_status(dtp_rpc_t *rpc);

#endif /* __DAOS_OBJ_RPC_H__ */