#
# This file is part of sharing-plugin-template
#
# Copyright (C) 2008-2009 Nokia Corporation. All rights reserved.
#
# This maemo code example is licensed under a MIT-style license,
# that can be found in the file called "COPYING" in the root
# directory.
#

plugins_LTLIBRARIES = libsharingserviceyfrog.la

libsharingserviceyfrog_la_SOURCES = plugin.c common.c send.c validate.c

libsharingserviceyfrog_la_CFLAGS = $(PACKAGE_CFLAGS) $(DEBUG_CFLAGS)
libsharingserviceyfrog_la_LDFLAGS = -module -avoid-version -export-dynamic
libsharingserviceyfrog_la_LIBADD = $(PACKAGE_LIBS)


MAINTAINERCLEANFILES = Makefile.in


