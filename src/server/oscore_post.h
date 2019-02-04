/*
 * Copyright (c) 2016 Intel Corporation
 * Modified by Fraunhofer AISEC, see the COPYRIGHT file
 * at the top-level directory of this distribution for
 * a list of all changes.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef NONE_OSCORE_POST_H
#define NONE_OSCORE_POST_H

#include <net/coap.h>

int oscore_post(struct coap_resource *resource, struct coap_packet *request);

#endif //NONE_OSCORE_POST_H
