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

#ifndef NONE_COAP_URI_H
#define NONE_COAP_URI_H

#include <net/coap.h>
#include "../util/array.h"
#include "../util/error.h"

struct proxy_url_info {
    array scheme;
    array host;
    array port;
    array path;
    array query;
};

/**
 * Parses the CoAP Proxy-Uri option according to the OSCORE Draft.
 *
 * 4.1.3.3. Proxy-Uri (OSCORE Draft)
 * 6.4 Decomposing URIs into Options (CoAP RFC7252)
 *
 * @param option "Proxy-Uri" coap option
 * @param to address to send the packet to
 * @param out out-pointer which will be filled with the parsed information
 * @return OscoreError
 */
OscoreError coap_parse_uri(struct coap_option option, struct sockaddr_in6 to, struct proxy_url_info* out);

#endif //NONE_COAP_URI_H
