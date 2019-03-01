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
 * Unit tests for the ACL manipulation API
 */

#include <stdarg.h>
#include <stdlib.h>
#include <setjmp.h>
#include <cmocka.h>

#include <daos_types.h>
#include <daos_api.h>
#include <gurt/common.h>

static void
test_acl_alloc_free(void **state)
{
	struct daos_acl *acl = daos_acl_alloc();

	assert_non_null(acl);
	assert_int_equal(acl->dal_ver, 1);
	assert_int_equal(acl->dal_len, 0);

	daos_acl_free(acl);
}

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
test_acl_add_ace_without_name(void **state)
{
	struct daos_acl *acl;
	struct daos_acl *new_acl;
	struct daos_ace *ace;

	ace = daos_ace_alloc(DAOS_ACL_EVERYONE, NULL, 0);
	ace->dae_access_types = DAOS_ACL_ACCESS_ALLOW;
	ace->dae_allow_perms = DAOS_ACL_PERM_READ;

	acl = daos_acl_alloc();
	new_acl = daos_acl_realloc_with_new_ace(acl, ace);

	assert_non_null(new_acl);
	assert_ptr_not_equal(new_acl, acl);

	assert_int_equal(new_acl->dal_len, daos_ace_get_size(ace));

	daos_acl_free(acl);
	daos_acl_free(new_acl);
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_acl_alloc_free),
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
		cmocka_unit_test(test_acl_add_ace_without_name),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
