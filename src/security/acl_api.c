/*
 * (C) Copyright 2019 Intel Corporation.
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
 * provided in Contract No. 8F-30005.
 * Any reproduction of computer software, computer software documentation, or
 * portions thereof marked with this legend must also reproduce the markings.
 */

#include <daos_types.h>
#include <daos_api.h>
#include <gurt/common.h>

#define DAOS_ACL_VERSION	1

struct daos_acl *
daos_acl_alloc(struct daos_ace **aces, uint16_t num_aces)
{
	struct daos_acl	*acl;
	size_t		ace_len = 0;
	int		i;
	uint8_t		*current_ace;

	for (i = 0; i < num_aces; i++) {
		ace_len += daos_ace_get_size(aces[i]);
	}

	D_ALLOC(acl, sizeof(struct daos_acl) + ace_len);
	acl->dal_ver = DAOS_ACL_VERSION;
	acl->dal_len = ace_len;

	current_ace = acl->dal_ace;
	for (i = 0; i < num_aces; i++) {
		int ace_size = daos_ace_get_size(aces[i]);

		memcpy(current_ace, aces[i], ace_size);
		current_ace += ace_size;
	}

	return acl;
}

void
daos_acl_free(struct daos_acl *acl)
{
	/* The ACL is one contiguous data blob - nothing special to do */
	D_FREE(acl);
}

struct daos_acl *
daos_acl_add_ace_realloc(struct daos_acl *acl, struct daos_ace *new_ace)
{
	struct daos_acl	*new_acl;
	int		new_ace_len;
	int		new_total_len;

	if (acl == NULL) {
		return NULL;
	}

	new_ace_len = daos_ace_get_size(new_ace);
	if (new_ace_len < 0) {
		/* ACE was invalid */
		return NULL;
	}

	new_total_len = acl->dal_len + daos_ace_get_size(new_ace);

	D_ALLOC(new_acl, sizeof(struct daos_acl) + new_total_len);
	if (new_acl == NULL) {
		return NULL;
	}

	new_acl->dal_ver = acl->dal_ver;
	new_acl->dal_len = acl->dal_len + daos_ace_get_size(new_ace);
	memcpy(new_acl->dal_ace, new_ace, new_ace_len);
	memcpy(new_acl->dal_ace + new_ace_len, acl->dal_ace, acl->dal_len);

	return new_acl;
}

struct daos_ace *
daos_acl_get_first_ace(struct daos_acl *acl)
{
	return NULL;
}

struct daos_ace *
daos_acl_get_next_ace(struct daos_acl *acl, struct daos_ace *current_ace)
{
	return NULL;
}

struct daos_ace *
daos_acl_get_ace_for_principal(struct daos_acl *acl,
		enum daos_acl_principal_type type, const char *principal)
{
	return NULL;
}

static bool
type_needs_name(enum daos_acl_principal_type type)
{
	/*
	 * The only ACE types that require a name are User and Group. All others
	 * are "special" ACEs that apply to an abstract category.
	 */
	if (type == DAOS_ACL_USER || type == DAOS_ACL_GROUP) {
		return true;
	}

	return false;
}

static bool
type_is_group(enum daos_acl_principal_type type)
{
	if (type == DAOS_ACL_GROUP || type == DAOS_ACL_OWNER_GROUP) {
		return true;
	}

	return false;
}

static bool
type_is_valid(enum daos_acl_principal_type type)
{
	bool result = false;

	switch (type) {
	case DAOS_ACL_USER:
	case DAOS_ACL_GROUP:
	case DAOS_ACL_OWNER:
	case DAOS_ACL_OWNER_GROUP:
	case DAOS_ACL_EVERYONE:
		result = true;
		break;
	}

	return result;
}

struct daos_ace *
daos_ace_alloc(enum daos_acl_principal_type type, const char *principal_name,
		size_t principal_name_len)
{
	struct daos_ace	*ace;
	size_t		principal_array_len = 0;

	if (!type_is_valid(type)) {
		return NULL;
	}

	if (type_needs_name(type)) {
		if (principal_name == NULL || principal_name_len == 0) {
			return NULL;
		}

		/* align to 64 bits */
		principal_array_len = D_ALIGNUP(principal_name_len, 8);
	}

	D_ALLOC(ace, sizeof(struct daos_ace) + principal_array_len);
	if (ace != NULL) {
		ace->dae_principal_type = type;
		ace->dae_principal_len = principal_array_len;
		strncpy(ace->dae_principal, principal_name,
				principal_array_len);

		if (type_is_group(type)) {
			ace->dae_access_flags |= DAOS_ACL_FLAG_GROUP;
		}
	}

	return ace;
}


void
daos_ace_free(struct daos_ace *ace)
{
	D_FREE(ace);
}

int
daos_ace_get_size(struct daos_ace *ace)
{
	if (ace == NULL) {
		return -DER_INVAL;
	}

	return sizeof(struct daos_ace) + ace->dae_principal_len;
}
