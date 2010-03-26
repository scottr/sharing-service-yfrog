/*
 * This file is part of sharing-plugin-template
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
#include <string.h>
#include <osso-log.h>
#include <sharing-http.h>
#include "send.h"
#include "common.h"

#define YFROG_UPLOAD_AND_POST_URL "http://yfrog.com/api/uploadAndPost"
#define YFROG_UPLOAD_ONLY_URL "http://yfrog.com/api/upload"

struct data_t {
	guint64 total_size;
	guint64 total_sent;
	SharingTransfer *transfer;
	gboolean *dead_mans_switch;
};

static gboolean
send_progress_cb(SharingHTTP *http, guint64 bytes_send, gpointer user_data)
{
	struct data_t *data = (struct data_t *)user_data;
	SharingTransfer *transfer = data->transfer;

	*(data->dead_mans_switch) = FALSE;

	if (transfer != NULL) {
		if (sharing_transfer_continue(transfer) == FALSE) {
			return FALSE;
		}
	}

	/* The sum of all other media sent already + the current entry */
	guint64 total_sent = data->total_sent + bytes_send;
	sharing_transfer_set_progress(transfer, (gdouble)total_sent/(gdouble)data->total_size);

	return TRUE;
}

static gboolean
transfer_upload_is_public(SharingTransfer *transfer)
{
	gboolean is_public = TRUE;
	SharingEntry *entry = sharing_transfer_get_entry(transfer);
	const gchar *value = sharing_entry_get_option(entry, "privacy");

	if (value && (strncmp(value, "private", strlen(value)) == 0))
		is_public = FALSE;

	return is_public;
}

static gboolean
transfer_upload_and_post(SharingTransfer *transfer)
{
	gboolean post = FALSE;
	SharingEntry *entry = sharing_transfer_get_entry(transfer);
	const gchar *value = sharing_entry_get_option(entry, "post");

	if (value && (strncmp(value, "uploadAndPost", strlen("uploadAndPost")) == 0))
		post = TRUE;

	return post;
}

/** Send a single media file.
 *
 */
SharingPluginInterfaceSendResult send_media (SharingEntryMedia *media,
		gchar *username, gchar *password, struct data_t *data)
{
	int ret = SHARING_SEND_SUCCESS;
	SharingHTTP *http = sharing_http_new ();

	gboolean public = transfer_upload_is_public(data->transfer);
	gboolean post = transfer_upload_and_post(data->transfer);

	gchar *filename = sharing_entry_media_get_filename(media);
	gchar *mime = sharing_entry_media_get_mime(media);
	const gchar *message = sharing_entry_media_get_desc(media);

	sharing_http_add_req_multipart_data(http, "username", username, -1, "text/plain");
	sharing_http_add_req_multipart_data(http, "password", password, -1, "text/plain");
	sharing_http_add_req_multipart_data(http, "public", public ? "yes" : "no", -1, "text/plain");
	sharing_http_add_req_multipart_data(http, "message", message ? message : "", -1, "text/plain");

	sharing_http_add_req_multipart_file_with_filename(http, "media",
			sharing_entry_media_get_localpath(media),
			mime ? mime : "image/jpeg", filename ? filename : "image.jpg");

	sharing_http_set_progress_callback(http, send_progress_cb, data);

	gchar *url;
	if (post == TRUE)
		url = g_strdup(YFROG_UPLOAD_AND_POST_URL);
	else
		url = g_strdup(YFROG_UPLOAD_ONLY_URL);

	SharingHTTPRunResponse res = sharing_http_run (http, url);

	g_free(url);

	switch(res) {
		case SHARING_HTTP_RUNRES_SUCCESS:
			ret = SHARING_SEND_SUCCESS;
			break;
		case SHARING_HTTP_RUNRES_CANCELLED:
			ret = SHARING_SEND_CANCELLED;
			break;
		default:
			ret = SHARING_SEND_ERROR_UNKNOWN;
	}

	sharing_http_unref (http);

	if (filename)
		g_free(filename);
	if (mime)
		g_free(mime);

	return ret;
}

/**
 * send:
 * @account: #SharingTransfer to be send
 * @con: Connection used
 * @dead_mans_switch: Turn to %FALSE at least every 30 seconds.
 *
 * Sends #SharingTransfer to service.
 *
 * Returns: #SharingPluginInterfaceSendResult
 */
SharingPluginInterfaceSendResult yfrog_send (SharingTransfer* transfer,
    ConIcConnection* con, gboolean* dead_mans_switch)
{
	struct data_t *data = g_new0(struct data_t, 1);
	SharingPluginInterfaceSendResult ret = SHARING_SEND_SUCCESS;
	SharingAccount *account;

	if (!data)
		return SHARING_SEND_ERROR_UNKNOWN;

	data->dead_mans_switch = dead_mans_switch;
	data->transfer = transfer;
	data->total_sent = 0;

	SharingEntry *entry = sharing_transfer_get_entry( transfer );
	data->total_size = sharing_entry_get_size(entry);

	account = sharing_entry_get_account(entry);
	gchar *username = sharing_account_get_username(account);
	gchar *password = sharing_account_get_password(account);

	for (GSList* p = sharing_entry_get_media (entry); p != NULL; p = g_slist_next(p)) {
		SharingEntryMedia* media = p->data;

		/* Skip media that's already been sent before */
		if (sharing_entry_media_get_sent(media))
			continue;

		/* Post media */
		ret = send_media (media, username, password, data);

		sharing_entry_media_set_sent(media, TRUE);

		/* Keep track of total progress */
		data->total_sent += sharing_entry_media_get_size(media);

		/* Break out of the sending loop if anything bad happened */
		if (ret != SHARING_SEND_SUCCESS)
			break;
	}

	sharing_account_free(account);
	g_free(data);

	return ret;
}

