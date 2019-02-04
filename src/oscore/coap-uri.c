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

#include "coap-uri.h"
#include <net/http_parser_url.h>
#include <ctype.h>

/**
 * Compare two ASCII strings ignoring their case
 * @param s1 first string represented as array
 * @param s2 second string represented as array
 * @return true if the strings are equal ignoring their case, false otherwise
 */
static bool strcasecmp(array s1, array s2) {
    if (s1.len != s2.len) {
        return false;
    }
    for (int i = 0; i < s1.len; i++) {
        if (tolower(s1.ptr[i]) != tolower(s2.ptr[i])) {
            return false;
        }
    }
    return true;
}

OscoreError coap_parse_uri(struct coap_option option, struct sockaddr_in6 to, struct proxy_url_info* out) {
    // "1. If the |url| string is not an absolute URI ([RFC3986]), then fail
    //    this algorithm."
    // TODO: check if absolute url

    // "2. Resolve the |url| string using the process of reference
    //     resolution defined by [RFC3986].  At this stage, the URL is in
    //     ASCII encoding [RFC0020], even though the decoded components will
    //     be interpreted in UTF-8 [RFC3629] after steps 5, 8, and 9.
    //
    //     NOTE: It doesn't matter what it is resolved relative to, since we
    //     already know it is an absolute URL at this point."
    struct http_parser_url url;
    http_parser_url_init(&url);
    try_http_parser(http_parser_parse_url((const char*)&option.value[0], option.len, false, &url));

    // "3. If |url| does not have a <scheme> component whose value, when
    //     converted to ASCII lowercase, is "coap" or "coaps", then fail
    //     this algorithm."
    array opt_value = {
            .len = url.field_data[UF_SCHEMA].len,
            .ptr = &option.value[url.field_data[UF_SCHEMA].off],
    };
    array coap = { .len = 4, .ptr = (u8_t*)"coap" };
    array coaps = { .len = 5, .ptr = (u8_t*)"coaps" };
    ensure(strcasecmp(opt_value, coap) || strcasecmp(opt_value, coaps), OscoreUriInvalidProtocol);

    // "4.  If |url| has a <fragment> component, then fail this algorithm."
    ensure(url.field_data[UF_FRAGMENT].len == 0, OscoreUriInvalidFragment);

    // "5. If the <host> component of |url| does not represent the request's
    //     destination IP address as an IP-literal or IPv4address, include a
    //     Uri-Host Option and let that option's value be the value of the
    //     <host> component of |url|, converted to ASCII lowercase, and then
    //     convert all percent-encodings ("%" followed by two hexadecimal
    //     digits) to the corresponding characters.
    //
    //     NOTE: In the usual case where the request's destination IP
    //     address is derived from the host part, this ensures that a Uri-
    //     Host Option is only used for a <host> component of the form reg-
    //     name."

    // not required here because we only need to parse certain fields

    // "6. If |url| has a <port> component, then let |port| be that
    //     component's value interpreted as a decimal integer; otherwise,
    //     let |port| be the default port for the scheme."
    array port = {
        .len = 0,
        .ptr = 0,
    };
    u16_t port_len = url.field_data[UF_PORT].len;
    if (port_len != 0) {
        if (url.port != to.sin6_port) {
            port.len = port_len;
            port.ptr = &option.value[url.field_data[UF_PORT].off];
        }
    } else {
        if (to.sin6_port != 5683) {
            port.len = 4;
            port.ptr = (u8_t*)"5683";
        }
    }

    // "7.  If |port| does not equal the request's destination UDP port,
    //      include a Uri-Port Option and let that option's value be |port|."

    // not relevant for parsing

    // "8. If the value of the <path> component of |url| is empty or
    //     consists of a single slash character (U+002F SOLIDUS "/"), then
    //     move to the next step.
    //
    //     Otherwise, for each segment in the <path> component, include a
    //     Uri-Path Option and let that option's value be the segment (not
    //     including the delimiting slash characters) after converting each
    //     percent-encoding ("%" followed by two hexadecimal digits) to the
    //     corresponding byte."

    // not relevant for parsing

    // "9. If |url| has a <query> component, then, for each argument in the
    //     <query> component, include a Uri-Query Option and let that
    //     option's value be the argument (not including the question mark
    //     and the delimiting ampersand characters) after converting each
    //     percent-encoding to the corresponding byte."

    // not relevant for parsing

    struct proxy_url_info info = {
        .scheme = {
            .len = url.field_data[UF_SCHEMA].len,
            .ptr = &option.value[url.field_data[UF_SCHEMA].off],
        },
        .host = {
            .len = url.field_data[UF_HOST].len,
            .ptr = &option.value[url.field_data[UF_HOST].off],
        },
        .port = port,
        .path = {
            .len = url.field_data[UF_PATH].len,
            .ptr = &option.value[url.field_data[UF_PATH].off],
        },
        .query = {
            .len = url.field_data[UF_QUERY].len,
            .ptr = &option.value[url.field_data[UF_QUERY].off],
        },
    };
    *out = info;
    return OscoreNoError;
}
