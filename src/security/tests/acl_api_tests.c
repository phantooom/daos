/**
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
 * provided in Contract No. B609815.
 * Any reproduction of computer software, computer software documentation, or
 * portions thereof marked with this legend must also reproduce the markings.
 */

/**
 * Unit tests for the ACL property API
 */

#include <stdarg.h>
#include <stdlib.h>
#include <setjmp.h>
#include <cmocka.h>

#include <daos_types.h>
#include <daos_api.h>
#include <gurt/common.h>

static size_t
aligned_strlen(const char *str)
{
	size_t len = strlen(str) + 1;

	return D_ALIGNUP(len, 8);
}

static void
test_ace_alloc_principal_user(void **state)
{
	const char			*expected_name = "user1@";
	enum daos_acl_principal_type	expected_type = DAOS_ACL_USER;
	struct daos_ace			*ace;

	ace = daos_ace_alloc(expected_type, expected_name,
			strlen(expected_name) + 1);

	assert_non_null(ace);
	assert_int_equal(ace->dae_principal_type, expected_type);
	assert_int_equal(ace->dae_principal_len, aligned_strlen(expected_name));
	assert_string_equal(ace->dae_principal, expected_name);
	assert_false(ace->dae_access_flags & DAOS_ACL_FLAG_GROUP);

	daos_ace_free(ace);
}

static void
test_ace_alloc_principal_user_no_name(void **state)
{
	struct daos_ace *ace;

	ace = daos_ace_alloc(DAOS_ACL_USER, "", 0);

	assert_null(ace);
}

static void
test_ace_alloc_principal_user_bad_len(void **state)
{
	struct daos_ace *ace;

	/* nonzero len for NULL name is invalid */
	ace = daos_ace_alloc(DAOS_ACL_USER, NULL, 5);

	assert_null(ace);
}

static void
test_ace_alloc_principal_group(void **state)
{
	const char			*expected_name = "group1234@";
	enum daos_acl_principal_type	expected_type = DAOS_ACL_GROUP;
	struct daos_ace			*ace;

	ace = daos_ace_alloc(expected_type, expected_name,
			strlen(expected_name) + 1);

	assert_non_null(ace);
	assert_int_equal(ace->dae_principal_type, expected_type);
	assert_int_equal(ace->dae_principal_len, aligned_strlen(expected_name));
	assert_string_equal(ace->dae_principal, expected_name);
	assert_true(ace->dae_access_flags & DAOS_ACL_FLAG_GROUP);

	daos_ace_free(ace);
}

static void
test_ace_alloc_principal_group_no_name(void **state)
{
	struct daos_ace *ace;

	ace = daos_ace_alloc(DAOS_ACL_GROUP, "", 0);

	assert_null(ace);
}

static void
expect_valid_owner_ace(struct daos_ace *ace)
{
	assert_non_null(ace);
	assert_int_equal(ace->dae_principal_type, DAOS_ACL_OWNER);
	assert_int_equal(ace->dae_principal_len, 0);
	assert_false(ace->dae_access_flags & DAOS_ACL_FLAG_GROUP);
}

static void
test_ace_alloc_principal_owner(void **state)
{
	struct daos_ace *ace;

	ace = daos_ace_alloc(DAOS_ACL_OWNER, "", 0);

	expect_valid_owner_ace(ace);

	daos_ace_free(ace);
}

static void
test_ace_alloc_principal_owner_ignores_name(void **state)
{
	const char	*name = "owner@";
	struct daos_ace	*ace;

	ace = daos_ace_alloc(DAOS_ACL_OWNER, name, strlen(name) + 1);

	expect_valid_owner_ace(ace);

	daos_ace_free(ace);
}

static void
test_ace_alloc_principal_owner_ignores_len(void **state)
{
	struct daos_ace *ace;

	ace = daos_ace_alloc(DAOS_ACL_OWNER, NULL, 6);

	expect_valid_owner_ace(ace);

	daos_ace_free(ace);
}

static void
test_ace_alloc_principal_owner_group(void **state)
{
	enum daos_acl_principal_type	expected_type = DAOS_ACL_OWNER_GROUP;
	struct daos_ace			*ace;

	ace = daos_ace_alloc(expected_type, NULL, 0);

	assert_non_null(ace);
	assert_int_equal(ace->dae_principal_type, expected_type);
	assert_int_equal(ace->dae_principal_len, 0);
	assert_true(ace->dae_access_flags & DAOS_ACL_FLAG_GROUP);

	daos_ace_free(ace);
}

static void
test_ace_alloc_principal_everyone(void **state)
{
	enum daos_acl_principal_type	expected_type = DAOS_ACL_EVERYONE;
	struct daos_ace			*ace;

	ace = daos_ace_alloc(expected_type, NULL, 0);

	assert_non_null(ace);
	assert_int_equal(ace->dae_principal_type, expected_type);
	assert_int_equal(ace->dae_principal_len, 0);
	assert_false(ace->dae_access_flags & DAOS_ACL_FLAG_GROUP);

	daos_ace_free(ace);
}

static void
test_ace_alloc_principal_invalid(void **state)
{
	struct daos_ace *ace;

	ace = daos_ace_alloc(DAOS_ACL_EVERYONE + 0xFF, "", 0);

	assert_null(ace);
}

static void
test_ace_get_size_null(void **state)
{
	assert_int_equal(daos_ace_get_size(NULL), -DER_INVAL);
}

static void
test_ace_get_size_without_name(void **state)
{
	struct daos_ace	*ace;

	ace = daos_ace_alloc(DAOS_ACL_EVERYONE, NULL, 0);

	assert_int_equal(daos_ace_get_size(ace), sizeof(struct daos_ace));

	daos_ace_free(ace);
}

static void
test_ace_get_size_with_name(void **state)
{
	const char	*name = "group1@";
	struct daos_ace	*ace;

	ace = daos_ace_alloc(DAOS_ACL_GROUP, name, strlen(name) + 1);

	/* name string rounded up to 64 bits */
	assert_int_equal(daos_ace_get_size(ace), sizeof(struct daos_ace) +
			aligned_strlen(name));

	daos_ace_free(ace);
}

static void
test_acl_alloc_empty(void **state)
{
	struct daos_acl *acl = daos_acl_alloc(NULL, 0);

	assert_non_null(acl);
	assert_int_equal(acl->dal_ver, 1);
	assert_int_equal(acl->dal_len, 0);

	daos_acl_free(acl);
}

static void
test_acl_alloc_one_user(void **state)
{
	struct daos_acl *acl;
	struct daos_ace *ace[1];
	const char	*name = "user1@";

	ace[0] = daos_ace_alloc(DAOS_ACL_USER, name, strlen(name) + 1);

	acl = daos_acl_alloc(ace, 1);

	assert_non_null(acl);
	assert_int_equal(acl->dal_ver, 1);
	assert_int_equal(acl->dal_len, daos_ace_get_size(ace[0]));
	assert_memory_equal(acl->dal_ace, ace[0], daos_ace_get_size(ace[0]));

	daos_ace_free(ace[0]);
	daos_acl_free(acl);
}

static void
test_acl_alloc_two_users(void **state)
{
	struct daos_acl *acl;
	int		i;
	int		ace_len = 0;
	size_t		num_aces = 2;
	struct daos_ace *ace[num_aces];
	const char	*names[] ={
			"user1@",
			"superuser@",
	};

	for (i = 0; i < num_aces; i++) {
		ace[i] = daos_ace_alloc(DAOS_ACL_USER, names[i],
				strlen(names[i]) + 1);
		ace_len += daos_ace_get_size(ace[i]);
	}

	acl = daos_acl_alloc(ace, num_aces);

	assert_non_null(acl);
	assert_int_equal(acl->dal_ver, 1);
	assert_int_equal(acl->dal_len, ace_len);
	/* expect the ACEs to be laid out in flat contiguous memory */
	assert_memory_equal(acl->dal_ace, ace[0], daos_ace_get_size(ace[0]));
	assert_memory_equal(acl->dal_ace + daos_ace_get_size(ace[0]),
			ace[1], daos_ace_get_size(ace[1]));

	/* cleanup */
	for (i = 0; i < num_aces; i++) {
		daos_ace_free(ace[i]);
	}
	daos_acl_free(acl);
}

static void
test_acl_add_ace_with_null_acl(void **state)
{
	struct daos_ace *ace;

	ace = daos_ace_alloc(DAOS_ACL_EVERYONE, NULL, 0);

	assert_null(daos_acl_add_ace_realloc(NULL, ace));

	daos_ace_free(ace);
}

static void
test_acl_add_ace_with_null_ace(void **state)
{
	struct daos_acl *acl;

	acl = daos_acl_alloc(NULL, 0);
	assert_null(daos_acl_add_ace_realloc(acl, NULL));

	daos_acl_free(acl);
}

static void
expect_empty_acl_adds_ace_as_only_item(struct daos_ace *ace)
{
	struct daos_acl *acl;
	struct daos_acl *new_acl;
	size_t		ace_len;

	ace_len = daos_ace_get_size(ace);

	acl = daos_acl_alloc(NULL, 0);
	new_acl = daos_acl_add_ace_realloc(acl, ace);

	assert_non_null(new_acl);
	assert_ptr_not_equal(new_acl, acl);

	assert_int_equal(new_acl->dal_ver, acl->dal_ver);
	assert_int_equal(new_acl->dal_len, ace_len);
	assert_memory_equal(new_acl->dal_ace, ace, ace_len);

	daos_acl_free(acl);
	daos_acl_free(new_acl);
}

static void
test_acl_add_ace_without_name(void **state)
{
	struct daos_ace *ace;

	ace = daos_ace_alloc(DAOS_ACL_EVERYONE, NULL, 0);
	ace->dae_access_types = DAOS_ACL_ACCESS_ALLOW;
	ace->dae_allow_perms = DAOS_ACL_PERM_READ;

	expect_empty_acl_adds_ace_as_only_item(ace);

	daos_ace_free(ace);
}

static void
test_acl_add_ace_with_name(void **state)
{
	struct daos_ace	*ace;
	const char	*name = "myuser@";

	ace = daos_ace_alloc(DAOS_ACL_USER, name, strlen(name) + 1);
	ace->dae_access_types = DAOS_ACL_ACCESS_ALLOW;
	ace->dae_allow_perms = DAOS_ACL_PERM_READ;

	expect_empty_acl_adds_ace_as_only_item(ace);

	daos_ace_free(ace);
}

static void
test_acl_add_ace_multiple_users(void **state)
{
	int		num_names = 2;
	struct daos_ace	*aces[num_names];
	struct daos_acl	*orig_acl, *tmp_acl, *result_acl;
	size_t		total_ace_len = 0;
	int		i;
	const char	*names[] = {
			"user1@",
			"anotheruser@"
	};

	orig_acl = daos_acl_alloc(NULL, 0);
	tmp_acl = orig_acl;

	/* Add all the ACEs to the ACL */
	for (i = 0; i < num_names; i++) {
		aces[i] = daos_ace_alloc(DAOS_ACL_USER, names[i],
				strlen(names[i]) + 1);
		aces[i]->dae_access_types = DAOS_ACL_ACCESS_ALLOW;
		aces[i]->dae_allow_perms = DAOS_ACL_PERM_READ;

		total_ace_len += daos_ace_get_size(aces[i]);

		result_acl = daos_acl_add_ace_realloc(tmp_acl, aces[i]);

		/* preserve initial ACL for comparison */
		if (tmp_acl != orig_acl) {
			daos_acl_free(tmp_acl);
		}
		tmp_acl = result_acl;
	}

	assert_int_equal(result_acl->dal_ver, orig_acl->dal_ver);
	assert_int_equal(result_acl->dal_len, total_ace_len);
	/* Added to the top of the list */
	assert_memory_equal(result_acl->dal_ace, aces[1],
			daos_ace_get_size(aces[1]));
	assert_memory_equal(result_acl->dal_ace + daos_ace_get_size(aces[1]),
			aces[0], daos_ace_get_size(aces[0]));

	/* cleanup */
	daos_acl_free(orig_acl);
	daos_acl_free(result_acl);
	for (i = 0; i < num_names; i++) {
		daos_ace_free(aces[i]);
	}
}

/*
 * TODO:
 * - Correct ordering
 * - Duplicate entry
 * - Updated entry for existing user
 * - Updated entry for existing group
 * - Updated entry for special principals
 */

int
main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_ace_alloc_principal_user),
		cmocka_unit_test(test_ace_alloc_principal_user_no_name),
		cmocka_unit_test(test_ace_alloc_principal_user_bad_len),
		cmocka_unit_test(test_ace_alloc_principal_group),
		cmocka_unit_test(test_ace_alloc_principal_group_no_name),
		cmocka_unit_test(test_ace_alloc_principal_owner),
		cmocka_unit_test(test_ace_alloc_principal_owner_ignores_name),
		cmocka_unit_test(test_ace_alloc_principal_owner_ignores_len),
		cmocka_unit_test(test_ace_alloc_principal_owner_group),
		cmocka_unit_test(test_ace_alloc_principal_everyone),
		cmocka_unit_test(test_ace_alloc_principal_invalid),
		cmocka_unit_test(test_ace_get_size_null),
		cmocka_unit_test(test_ace_get_size_without_name),
		cmocka_unit_test(test_ace_get_size_with_name),
		cmocka_unit_test(test_acl_alloc_empty),
		cmocka_unit_test(test_acl_alloc_one_user),
		cmocka_unit_test(test_acl_alloc_two_users),
		cmocka_unit_test(test_acl_add_ace_with_null_acl),
		cmocka_unit_test(test_acl_add_ace_with_null_ace),
		cmocka_unit_test(test_acl_add_ace_without_name),
		cmocka_unit_test(test_acl_add_ace_with_name),
		cmocka_unit_test(test_acl_add_ace_multiple_users),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
