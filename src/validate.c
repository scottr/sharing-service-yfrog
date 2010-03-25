/*
 * validate.c
 * Account validation functions for sharing-service-yfrog
 *
 * (C) 2010 Scott Raynel <scottraynel@gmail.com>
 * This code is licensed under the GPLv2.
 *
 * This file was part of sharing-plugin-template
 *
 * Copyright (C) 2008-2009 Nokia Corporation. All rights reserved.
 *
 * This maemo code example is licensed under a MIT-style license,
 * that can be found in the file called "COPYING" in the root
 * directory.
 *
 */

#include <stdio.h>
#include <glib.h>
#include <glib/gprintf.h>
#include <string.h>
#include <sharing-account.h>
#include <sharing-http.h>
#include <osso-log.h>
#include <conicconnection.h>
#include "validate.h"
#include "common.h"

/**
 * test:
 * @account: #SharingAccount to be tested
 * @con: Connection used
 * @dead_mans_switch: Turn to %FALSE at least every 30 seconds.
 *
 * Test if #SharingAccount is valid.
 *
 * Returns: #SharingPluginInterfaceTestAccountResult
 */
SharingPluginInterfaceAccountValidateResult validate (SharingAccount* account,
    ConIcConnection* con, gboolean *cont, gboolean* dead_mans_switch)
{
	SharingPluginInterfaceAccountValidateResult ret =
		SHARING_ACCOUNT_VALIDATE_SUCCESS;

	gchar *user = sharing_account_get_username(account);
	gchar *password = sharing_account_get_password(account);
	gchar buffer[1204];

	/* Sanity check user/pass lengths */
	if ((strlen(user) + strlen(password)) > 1024)
		return SHARING_ACCOUNT_VALIDATE_NOT_STARTED;

	/* Create b64 encoded user/pass into buffer */
	snprintf(buffer, sizeof(buffer), "%s:%s", user, password);
	gchar *encoded = g_base64_encode((guchar *)buffer, (gsize)strlen(buffer));
	if (!encoded)
		return SHARING_ACCOUNT_VALIDATE_ERROR_UNKNOWN;
	snprintf(buffer, sizeof(buffer), "Basic %s", encoded);

	g_free(encoded);

	SharingHTTP * http = sharing_http_new ();

	sharing_http_add_req_header(http, "Authorization", buffer);

	/* Reduce the amount of data we need to get back */
	sharing_http_add_req_header(http, "Accept-Encoding", "gzip,deflate");

	SharingHTTPRunResponse res;
	res = sharing_http_run (http, "http://api.twitter.com/1/account/verify_credentials.xml");

	if (res == SHARING_HTTP_RUNRES_SUCCESS) {
		if (sharing_http_get_res_code(http) != 200)
			ret = SHARING_ACCOUNT_VALIDATE_FAILED;
	} else {
		ret = SHARING_ACCOUNT_VALIDATE_FAILED;
	}

	sharing_http_unref (http);

	return ret;
}

