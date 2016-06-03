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
 * dsmc: object operation.
 *
 * dsmc is the DSM client to do object operation.
 */

#include <daos/pool_map.h>
#include <daos/transport.h>
#include "dsm_rpc.h"
#include "dsmc_internal.h"

struct daos_hhash *dsmc_hhash;

static inline struct dsmc_object*
dsmc_handle2obj(daos_handle_t hdl)
{
	struct daos_hlink *dlink;

	dlink = daos_hhash_link_lookup(dsmc_hhash, hdl.cookie);
	if (dlink == NULL)
		return NULL;

	return container_of(dlink, struct dsmc_object, do_hlink);
}

static int
dsmc_obj_pool_container_uuid_get(struct dsmc_object *dobj, uuid_t puuid,
				 uuid_t cuuid, daos_unit_oid_t *do_id)
{
	struct dsmc_pool	*pool;
	struct dsmc_container	*dc;

	D_ASSERT(!daos_handle_is_inval(dobj->do_co_hdl));
	dc = dsmc_handle2container(dobj->do_co_hdl);
	if (dc == NULL)
		return -DER_NO_HDL;

	D_ASSERT(!daos_handle_is_inval(dc->dc_pool_hdl));
	pool = dsmc_handle2pool(dc->dc_pool_hdl);
	if (pool == NULL) {
		dsmc_container_put(dc);
		return -DER_NO_HDL;
	}

	uuid_copy(puuid, pool->dp_pool);
	uuid_copy(cuuid, dc->dc_uuid);

	*do_id = dobj->do_id;
	dsmc_container_put(dc);
	dsmc_pool_put(pool);

	return 0;
}

static int
update_cp(struct daos_op_sp *sp, daos_event_t *ev, int rc)
{
	struct object_update_in *oui;
	struct dtp_single_out *dso;
	dtp_bulk_t *bulks;
	int i;

	oui = dtp_req_get(sp->sp_rpc);
	D_ASSERT(oui != NULL);
	bulks = oui->oui_bulks.arrays;
	D_ASSERT(bulks != NULL);
	if (rc) {
		D_ERROR("RPC error: %d\n", rc);
		D_GOTO(out, rc);
	}

	dso = dtp_reply_get(sp->sp_rpc);
	if (dso->dso_ret != 0) {
		D_ERROR("DSM_OBJ_UPDATE replied failed, rc: %d\n",
			dso->dso_ret);
		D_GOTO(out, rc = dso->dso_ret);
	}
out:
	for (i = 0; i < oui->oui_nr; i++)
		dtp_bulk_free(bulks[i]);

	D_FREE(oui->oui_bulks.arrays,
	       oui->oui_nr * sizeof(dtp_bulk_t));
	dtp_req_decref(sp->sp_rpc);
	D_DEBUG(DF_MISC, "update finish %d\n", rc);
	return rc;
}

static inline bool
dsm_io_check(unsigned int nr, daos_vec_iod_t *iods, daos_sg_list_t *sgls)
{
	int i;

	for (i = 0; i < nr; i++) {
		int j;

		if (iods[i].vd_name.iov_buf == NULL ||
		    iods[i].vd_recxs == NULL || iods[i].vd_csums == NULL ||
		    iods[i].vd_eprs == NULL)
			/* XXX checksum & eprs should not be mandatory */
			return false;

		for (j = 0; j < iods[i].vd_nr; j++) {
			if (iods[i].vd_csums[j].cs_csum == NULL)
				return false;
		}
	}

	return true;
}

static int
dsm_obj_rw(daos_handle_t oh, daos_epoch_t epoch, daos_dkey_t *dkey,
	   unsigned int nr, daos_vec_iod_t *iods, daos_sg_list_t *sgls,
	   daos_event_t *ev, enum dsm_operation op)
{
	struct dsmc_object	*dobj;
	dtp_endpoint_t		 tgt_ep;
	dtp_rpc_t		*req;
	struct object_update_in *oui;
	dtp_bulk_t		*bulks;
	struct daos_op_sp	*sp;
	int			 i;
	int			 rc;

	/** sanity check input parameters */
	if (dkey == NULL || dkey->iov_buf == NULL || nr == 0 ||
	    !dsm_io_check(nr, iods, sgls))
		return -DER_INVAL;

	dobj = dsmc_handle2obj(oh);
	if (dobj == NULL)
		return -DER_NO_HDL;

	if (ev == NULL) {
		rc = daos_event_priv_get(&ev);
		if (rc != 0) {
			dsmc_object_put(dobj);
			return rc;
		}
	}

	tgt_ep.ep_rank = dobj->do_rank;
	tgt_ep.ep_tag = 0;
	rc = dsm_req_create(daos_ev2ctx(ev), tgt_ep, op, &req);
	if (rc != 0) {
		dsmc_object_put(dobj);
		return rc;
	}

	oui = dtp_req_get(req);
	D_ASSERT(oui != NULL);

	rc = dsmc_obj_pool_container_uuid_get(dobj,
			oui->oui_pool_uuid, oui->oui_co_uuid,
			&oui->oui_oid);
	dsmc_object_put(dobj);
	if (rc != 0)
		D_GOTO(out, rc);

	oui->oui_epoch = epoch;
	oui->oui_nr = nr;
	/** FIXME: large dkey should be transferred via bulk */
	oui->oui_dkey = *dkey;
	/* FIXME: if iods is too long, then we needs to do bulk transfer
	 * as well, but then we also needs to serialize the iods
	 **/
	D_ALLOC(bulks, nr * sizeof(*bulks));
	if (bulks == NULL)
		D_GOTO(out, rc = -DER_NOMEM);

	oui->oui_iods.count = nr;
	oui->oui_iods.arrays = iods;
	oui->oui_bulks.count = nr;
	oui->oui_bulks.arrays = bulks;
	/* create bulk transfer for daos_sg_list */
	for (i = 0; i < nr; i++) {
		rc = dtp_bulk_create(daos_ev2ctx(ev), &sgls[i], DTP_BULK_RW,
				     &bulks[i]);
		if (rc < 0) {
			int j;

			for (j = 0; j < i; j++)
				rc = dtp_bulk_free(bulks[j]);

			D_GOTO(out_free, rc);
		}
	}

	sp = daos_ev2sp(ev);
	dtp_req_addref(req);
	sp->sp_rpc = req;
	rc = daos_event_launch(ev, NULL, update_cp);
	if (rc != 0) {
		dtp_req_decref(req);
		D_GOTO(out_bulk, rc);
	}

	/** send the request */
	return daos_rpc_send(req, ev);
out_bulk:
	for (i = 0; i < nr; i++)
		rc = dtp_bulk_free(bulks[i]);

out_free:
	if (bulks != NULL)
		D_FREE(bulks, nr * sizeof(*bulks));
out:
	dtp_req_decref(req);
	return rc;
}

int
dsm_obj_update(daos_handle_t oh, daos_epoch_t epoch, daos_dkey_t *dkey,
	       unsigned int nr, daos_vec_iod_t *iods, daos_sg_list_t *sgls,
	       daos_event_t *ev)
{
	return dsm_obj_rw(oh, epoch, dkey, nr, iods, sgls, ev,
			  DSM_TGT_OBJ_UPDATE);
}

int
dsm_obj_fetch(daos_handle_t oh, daos_epoch_t epoch, daos_dkey_t *dkey,
	      unsigned int nr, daos_vec_iod_t *iods, daos_sg_list_t *sgls,
	      daos_vec_map_t *maps, daos_event_t *ev)
{
	return dsm_obj_rw(oh, epoch, dkey, nr, iods, sgls, ev,
			  DSM_TGT_OBJ_FETCH);
}

static void
dsmc_object_free(struct daos_hlink *hlink)
{
	struct dsmc_object *dobj;

	dobj = container_of(hlink, struct dsmc_object, do_hlink);
	D_FREE_PTR(dobj);
}

struct daos_hlink_ops dobj_h_ops = {
	.hop_free = dsmc_object_free,
};

static struct dsmc_object *
dsm_obj_alloc(daos_rank_t rank, daos_unit_oid_t id)
{
	struct dsmc_object *dobj;

	D_ALLOC_PTR(dobj);
	if (dobj == NULL)
		return NULL;

	dobj->do_rank = rank;
	dobj->do_id = id;
	DAOS_INIT_LIST_HEAD(&dobj->do_co_list);
	daos_hhash_hlink_init(&dobj->do_hlink, &dobj_h_ops);
	return dobj;
}

int
dsm_obj_open(daos_handle_t coh, uint32_t tgt, daos_unit_oid_t id,
	     unsigned int mode, daos_handle_t *oh, daos_event_t *ev)
{
	struct dsmc_object	*dobj;
	struct dsmc_container	*dc;
	struct dsmc_pool	*pool;
	struct pool_target	*map_tgt;
	int			n;

	dc = dsmc_handle2container(coh);
	if (dc == NULL)
		return -DER_NO_HDL;

	/* Get map_tgt so that we can have the rank of the target. */
	pool = dsmc_handle2pool(dc->dc_pool_hdl);
	D_ASSERT(pool != NULL);
	n = pool_map_find_target(pool->dp_map, tgt, &map_tgt);
	dsmc_pool_put(pool);
	if (n != 1) {
		D_ERROR("failed to find target %u\n", tgt);
		dsmc_container_put(dc);
		return -DER_INVAL;
	}

	dobj = dsm_obj_alloc(map_tgt->ta_comp.co_rank, id);
	if (dobj == NULL) {
		dsmc_container_put(dc);
		return -DER_NOMEM;
	}

	/* XXX Might have performance issue here */
	pthread_rwlock_wrlock(&dc->dc_obj_list_lock);
	if (dc->dc_closing) {
		pthread_rwlock_unlock(&dc->dc_obj_list_lock);
		dsmc_object_put(dobj);
		dsmc_container_put(dc);
		return -DER_INVAL;
	}
	daos_list_add(&dobj->do_co_list, &dc->dc_obj_list);
	dobj->do_co_hdl = coh;
	pthread_rwlock_unlock(&dc->dc_obj_list_lock);

	dsmc_object_add_cache(dobj, oh);
	dsmc_container_put(dc);
	return 0;
}

int
dsm_obj_close(daos_handle_t oh, daos_event_t *ev)
{
	struct dsmc_object *dobj;
	struct dsmc_container *dc;

	dobj = dsmc_handle2obj(oh);
	if (dobj == NULL)
		return -DER_NO_HDL;

	dc = dsmc_handle2container(dobj->do_co_hdl);
	if (dc == NULL) {
		dsmc_object_put(dobj);
		return -DER_NO_HDL;
	}

	/* remove from container list */
	pthread_rwlock_wrlock(&dc->dc_obj_list_lock);
	daos_list_del_init(&dobj->do_co_list);
	pthread_rwlock_unlock(&dc->dc_obj_list_lock);

	/* remove from hash */
	dsmc_object_put(dobj);
	dsmc_object_del_cache(dobj);
	dsmc_container_put(dc);
	return 0;
}