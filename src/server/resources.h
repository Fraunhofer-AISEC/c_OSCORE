/*
 * Copyright (c) 2016 Intel Corporation
 * Modified by Fraunhofer AISEC, see the COPYRIGHT file
 * at the top-level directory of this distribution for
 * a list of all changes.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef NONE_RESOURCES_H
#define NONE_RESOURCES_H

#include <tinycrypt/constants.h>
#include <net/coap.h>
#include <net/coap_link_format.h>

#include "coap-server.h"
#include "oscore_post.h"
#include "../main.h"

static const char * const test_path[] = {"test", NULL };

static const char * const segments_path[] = { "seg1", "seg2", "seg3", NULL };

static const char * const query_path[] = { "query", NULL };

static const char * const separate_path[] = { "separate", NULL };

static const char * const large_path[] = { "large", NULL };

static const char * const location_query_path[] = { "location-query", NULL };

static const char * const large_update_path[] = { "large-update", NULL };

static const char * const large_create_path[] = { "large-create", NULL };

static const char * const obs_path[] = { "obs", NULL };

static const char* const oscore_path[] = { "oscore", "hello", "1", NULL };

static const char * const core_1_path[] = { "core1", NULL };
static const char * const core_1_attributes[] = {
        "title=\"Core 1\"",
        "rt=core1",
        NULL };

static const char * const core_2_path[] = { "core2", NULL };
static const char * const core_2_attributes[] = {
        "title=\"Core 1\"",
        "rt=core1",
        NULL };

static struct coap_resource resources[] = {
    { .get = piggyback_get,
        .post = test_post,
        .del = test_del,
        .put = test_put,
        .path = test_path
    },
    { .get = piggyback_get,
        .path = segments_path,
    },
    { .get = query_get,
        .path = query_path,
    },
    { .get = separate_get,
        .path = separate_path,
    },
    { .path = large_path,
        .get = large_get,
    },
    { .path = location_query_path,
        .post = location_query_post,
    },
    { .path = large_update_path,
        .put = large_update_put,
    },
    { .path = large_create_path,
        .post = large_create_post,
    },
    { .path = obs_path,
        .get = obs_get,
        .notify = obs_notify,
    },
    { .get = well_known_core_get,
        .path = COAP_WELL_KNOWN_CORE_PATH,
    },
    { .get = well_known_core_get,
        .path = COAP_WELL_KNOWN_CORE_PATH,
    },
    { .get = core_get,
        .path = core_1_path,
        .user_data = &((struct coap_core_metadata) {
            .attributes = core_1_attributes,
        }),
    },
    { .get = core_get,
        .path = core_2_path,
        .user_data = &((struct coap_core_metadata) {
            .attributes = core_2_attributes,
        }),
    },
    {
        .get = oscore_post,
        .path = oscore_path,
    },
    { },
};

#endif //NONE_RESOURCES_H
