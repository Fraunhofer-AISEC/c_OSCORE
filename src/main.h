/*
 * Copyright (c) 2019 Fraunhofer AISEC. See the COPYRIGHT
 * file at the top-level directory of this distribution.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

#ifndef NONE_MAIN_H
#define NONE_MAIN_H

#include <net/coap.h>

int oscore_post(struct coap_resource *resource, struct coap_packet *request);

#endif //NONE_MAIN_H
