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

static void
test_ace_alloc_principal_user(void **state)
{
	const char				*expected_name = "user1@";
	const enum daos_acl_principal_type	expected_type = DAOS_ACL_USER;
	struct daos_ace				*ace;

	ace = daos_ace_alloc(expected_type, expected_name,
			strlen(expected_name) + 1);

	assert_non_null(ace);
	assert_int_equal(ace->dae_principal_type, expected_type);
	assert_int_equal(ace->dae_principal_len,
			D_ALIGNUP(strlen(expected_name) + 1, 8));
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
	const char				*expected_name = "group1@";
	const enum daos_acl_principal_type	expected_type = DAOS_ACL_GROUP;
	struct daos_ace				*ace;

	ace = daos_ace_alloc(expected_type, expected_name,
			strlen(expected_name) + 1);

	assert_non_null(ace);
	assert_int_equal(ace->dae_principal_type, expected_type);
	assert_int_equal(ace->dae_principal_len,
			D_ALIGNUP(strlen(expected_name) + 1, 8));
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
	const enum daos_acl_principal_type	expected_type =
							DAOS_ACL_OWNER_GROUP;
	struct daos_ace				*ace;

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
	const enum daos_acl_principal_type	expected_type =
							DAOS_ACL_EVERYONE;
	struct daos_ace				*ace;

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

//static void
//test_acl_add_ace(void **state)
//{
//	struct daos_acl *acl;
//	struct daos_acl *new_acl;
//	struct daos_ace ace;
//
//	memset(&ace, 0, sizeof(ace));
//
//	acl = daos_acl_alloc();
//	new_acl = daos_acl_realloc_with_new_ace(acl, );
//
//	daos_acl_free(acl);
//}

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
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
