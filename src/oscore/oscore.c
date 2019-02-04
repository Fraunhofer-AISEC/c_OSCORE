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

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <tinycrypt/hmac.h>
#include <tinycrypt/constants.h>
#include <sys_io.h>
#include <misc/rb.h>
#include <kernel.h>
#include <logging/sys_log.h>
#include <net/tcp.h>
#include <net/http_parser_url.h>
#include <net/coap.h>
#include "cbor.h"
#include "../server/coap-server.h"
#include "../crypto/aes.h"
#include "../util/macros.h"
#include "oscore.h"
#include "../crypto/oscore_cose.h"
#include "coap-uri.h"
#include "options.h"
#include "../crypto/hkdf.h"
#include "../codec/aad.h"
#include "../codec/oscore_option.h"
#include "../codec/nonce.h"
#include "coap_helper.h"

u8_t MASTER_SECRET[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
u8_t SENDER_ID[1] = { 1 };
u8_t RECIPIENT_ID[0] = { };
u8_t MASTER_SALT[8] = { 0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40 };
struct pre_established_opt OPT = {
    .aead_alg = AES_CCM_16_64_128,
    .master_salt = {
        .len = 8,
        .ptr = MASTER_SALT,
    },
    /// default HKDF-SHA-256
    // TODO: actually be generic over the algorithm
    .kdf = SHA_256,
    /// default DTLS-type replay protection & window-size 32
    .replay_window = NULL,
};

struct pre_established PRE_ESTABLISHED = {
    .master_secret = {
        .len = 16,
        .ptr = MASTER_SECRET,
    },
    .sender_id = {
        .len = sizeof(SENDER_ID),
        .ptr = SENDER_ID,
    },
    .recipient_id = {
        .len = sizeof(RECIPIENT_ID),
        .ptr = RECIPIENT_ID,
    },
    .common_id_context = {
        .len = 0,
        .ptr = NULL,
    },
    .opt = &OPT,
};

static u8_t common_iv[13];
static u8_t sender_key[16];
static u8_t recipient_key[16];
static struct common_context cctx;
static struct sender_context sctx;
static struct recipient_context rctx;

OscoreError oscore_init(struct pre_established pre_established) {
    try(derive_common_context(pre_established, &common_iv[0], &cctx));
    try(derive_sender_context(pre_established, &sender_key[0], &sctx));
    try(derive_recipient_context(pre_established, &recipient_key[0], &rctx));
    return OscoreNoError;
}

/**
 * Initialize the packet at @a out, copy the request's UDP/IP and CoAP header with given @a coap_code.
 * @param request Request to copy UDP/IP and CoAP header (except CoAP Code) from
 * @param coap_code CoAP Code to write to out-packet
 * @param out packet to copy headers into
 * @return OscoreError
 */
static OscoreError init_decrypted_packet(struct coap_packet* request, u8_t coap_code, struct coap_packet* out) {
    struct sockaddr_in6 from;
    get_from_ip_addr(request, &from);

    u8_t version = coap_header_get_version(request);
    u8_t type = coap_header_get_type(request);
    u8_t token[8];
    u8_t tkl = coap_header_get_token(request, token);
    u16_t id = coap_header_get_id(request);

    struct net_pkt* pkt = net_pkt_get_rx(context, K_FOREVER);
    ensure(pkt != NULL, OscorePktError);
    struct net_buf* frag = net_pkt_get_data(context, K_FOREVER);
    ensure(frag != NULL, OscorePktError);
    net_pkt_frag_add(pkt, frag);

    // We can't use coap_packet_init here, because we need to also add the original IPv6 and UDP header to the packet,
    // which coap_packet_init doesn't allow. Thus we need to do the relevant work here.
//    ensure_eq(coap_packet_init(out, pkt, version, type, tkl, (u8_t *)token, coap_code, id), 0, OscoreCoapPacketInitError);
    u16_t ip_udp_header_len = request->offset;
    out->pkt = pkt;
    out->frag = pkt->frags;
    out->offset = ip_udp_header_len;
    out->hdr_len = 0;
    // set opt_len and last_delta to zero, as they'll be set when we write the options with `coap_append_option`
    out->opt_len = 0;
    out->last_delta = 0;

    // Restore IP and UDP header from request to newly built request
    // The checksum and length field of the UDP header will be wrong, but those checks should already have happened anyways.
    // TODO: calculate and set correct checksum and length
    u8_t ip_udp_header[ip_udp_header_len];
    u16_t pos;
    frag = net_frag_read(request->frag, 0, &pos, ip_udp_header_len, ip_udp_header);
    ensure(!(frag == NULL && pos == 0xffff), OscorePktError);
    ensure(net_pkt_append_all(pkt, ip_udp_header_len, ip_udp_header, K_SECONDS(1)), OscoreNetPacketAppendError);
    get_from_ip_addr(request, &from);
    net_pkt_set_ip_hdr_len(out->pkt, net_pkt_ip_hdr_len(request->pkt));
    net_pkt_set_ipv6_ext_len(out->pkt, net_pkt_ipv6_ext_len(request->pkt));
    net_pkt_set_family(out->pkt, net_pkt_family(request->pkt));
    net_pkt_set_iface(out->pkt, net_pkt_iface(request->pkt));

    ensure(version < 4, OscoreInvalidVersion);
    ensure(type < 4, OscoreInvalidType);
    ensure(tkl < 16, OscoreInvalidTokenLength);
    u8_t info_byte = version << 6;
    info_byte += type << 4;
    info_byte += tkl;

    ensure_eq(net_pkt_append_u8(pkt, info_byte), true, OscoreNetPacketAppendError);
    ensure_eq(net_pkt_append_u8(pkt, coap_code), true, OscoreNetPacketAppendError);
    ensure_eq(net_pkt_append_be16(pkt, id), true, OscoreNetPacketAppendError);
    out->hdr_len += 4;
    ensure_eq(net_pkt_append_all(pkt, tkl, token, K_SECONDS(1)), true, OscoreNetPacketAppendError);
    out->hdr_len += tkl;
    return OscoreNoError;
}

/**
 * Merge decrypted options into the rebuilt decrypted packet
 * @param opt_u Class U option array
 * @param opt_u_num Number of Class U options in @a opt_u
 * @param opt_e Class E option array
 * @param opt_e_num Number of Class E options in @a opt_e
 * @param out packet to merge options into
 * @return OscoreError
 */
static OscoreError merge_decrypted_options(struct coap_option* opt_u, u16_t opt_u_num, struct coap_option* opt_e, u16_t opt_e_num, struct coap_packet* out) {
    u16_t total_delta_u = 0;
    size_t index_u = 0;
    u16_t total_delta_e = 0;
    size_t index_e = 0;
    while (index_u < opt_u_num || index_e < opt_e_num) {
        // TODO: refactor to remove code duplication
        if (index_u >= opt_u_num) {
            // add rest of Class E opt_u
            total_delta_e += opt_e[index_e].delta;
            ensure_eq(coap_packet_append_option(out, total_delta_e, opt_e[index_e].value, opt_e[index_e].len), 0, OscoreCoapPacketAppendError);
            index_e++;
            continue;
        }
        if (index_e >= opt_e_num) {
            // add rest of Class U/I opt_u
            total_delta_u += opt_u[index_u].delta;
            ensure_eq(coap_packet_append_option(out, total_delta_u, opt_u[index_u].value, opt_u[index_u].len), 0, OscoreCoapPacketAppendError);
            index_u++;
            continue;
        }

        u16_t new_delta_u = total_delta_u + opt_u[index_u].delta;
        u16_t new_delta_e = total_delta_e + opt_e[index_e].delta;
        // TODO: handle special options
        // * Should we handle Proxy-Uri? In theory it shouldn't be needed by the server anymore, but implementations
        //   may rely on it existing / its values.
        if (new_delta_e < new_delta_u) {
            total_delta_e = new_delta_e;
            ensure_eq(coap_packet_append_option(out, total_delta_e, opt_e[index_e].value, opt_e[index_e].len), 0, OscoreCoapPacketAppendError);
            index_e++;
        } else {
            total_delta_u = new_delta_u;
            ensure_eq(coap_packet_append_option(out, total_delta_u, opt_u[index_u].value, opt_u[index_u].len), 0, OscoreCoapPacketAppendError);
            index_u++;
        }
    }
    return OscoreNoError;
}

OscoreError from_oscore(struct coap_packet request, struct coap_packet* out) {
    // Class I / U options
    // TODO: find out actual number of options, assume max 10 for now
    u8_t opt_num = 10;
    struct coap_option options[opt_num];
    try(get_options(&request, options, &opt_num));

    // get the OSCORE option value
    array oscore_value = get_option_value(options, opt_num, COAP_OPTION_OSCORE);
    log_hex("oscore option value", oscore_value.ptr, oscore_value.len);
    ensure(!array_equals(oscore_value, NULL_ARRAY), OscoreNoOscoreOption);
    // extract info
    u8_t partial_iv_bytes[8] = { 0 };
    // TODO: actually be generic over the algorithm
    u8_t kid_bytes[7] = { 0 };
    // MUST be shorter than 256 bytes
    // TODO: don't only assume <16 bytes
    u8_t kid_context_bytes[16] = { 0 };
    struct unprotected unprotected = {
        .partial_iv = {
            .len = sizeof(partial_iv_bytes),
            .ptr = partial_iv_bytes,
        },
        .kid = {
            .len = sizeof(kid_bytes),
            .ptr = kid_bytes,
        },
        .kid_context = {
            .len = sizeof(kid_context_bytes),
            .ptr = kid_context_bytes,
        }
    };
    try(from_oscore_option(oscore_value, &unprotected));
    // TODO: replay protection
    // TODO: use unprotected.kid_context

    // ciphertext (original payload)
    struct payload_info request_info;
    try(get_payload_info(&request, &request_info));
    u8_t ciphertext_bytes[request_info.len];
    array ciphertext = {
        .len = request_info.len,
        .ptr = ciphertext_bytes,
    };
    try(read_payload(request_info, ciphertext));
    log_hex("received ciphertext", ciphertext.ptr, ciphertext.len);


    // create nonce
    // TODO: can the kid be NULL and the recipient id is just used?
    ensure(array_equals(rctx.recipient_id, unprotected.kid), OscoreInvalidKid);
    u8_t nonce[13];
    try(create_nonce(unprotected.kid, unprotected.partial_iv, cctx.common_iv, &nonce[0]));

    // construct aad
    size_t aad_len;
    try(aad_length(options, opt_num, cctx.aead_alg, rctx.recipient_id, unprotected.partial_iv, &aad_len));
    u8_t aad_bytes[aad_len];
    array aad = {
        .len = aad_len,
        .ptr = aad_bytes,
    };
    try(create_aad(options, opt_num, cctx.aead_alg, rctx.recipient_id, unprotected.partial_iv, aad));


    // actually decrypt
    u8_t plaintext_bytes[ciphertext.len - 8];
    memset(&plaintext_bytes, 0, sizeof(plaintext_bytes));
    array plaintext = {
        .len = sizeof(plaintext_bytes),
        .ptr = plaintext_bytes,
    };
    ensure_eq(rctx.recipient_key.len, 16, OscoreInvalidKeyLength);
    try(from_oscore_cose_encrypt0(rctx.recipient_key.ptr, nonce, ciphertext, aad, plaintext));
    log_hex("decrypted plaintext", plaintext.ptr, plaintext.len);

    // Plaintext: CoAP Code || Class E options || 0xFF (if payload) || payload (if any)
    u8_t coap_code = plaintext.ptr[0];

    // parse Class E options
    // skip coap code
    array options_array = {
        .len = plaintext.len - 1,
        .ptr = &plaintext.ptr[1],
    };
    u16_t opt_e_num;
    try(num_options(options_array, &opt_e_num));
    struct coap_option opt_e[opt_e_num];
    u16_t opt_e_byte_len;
    try(decode_options(options_array, opt_e, &opt_e_byte_len));

    // ... = coap code + Class E options
    u16_t payload_offset = (u16_t)(1 + opt_e_byte_len);
    if (plaintext.len > payload_offset) {
        ensure_eq(plaintext.ptr[payload_offset], 0xff, OscorePayloadNoPayloadMarker);
        // skip payload marker
        payload_offset++;
    }
    plaintext.len = plaintext.len - payload_offset;
    plaintext.ptr = &plaintext.ptr[payload_offset];

    // construct unencrypted coap_packet
    try(init_decrypted_packet(&request, coap_code, out));

    // merge options
    try(merge_decrypted_options(options, opt_num, opt_e, opt_e_num, out));

    // append payload
    if (plaintext.len > 0) {
        ensure_eq(coap_packet_append_payload_marker(out), 0, OscoreCoapPacketAppendError);
        ensure_eq(coap_packet_append_payload(out, plaintext.ptr, (u16_t)plaintext.len), 0, OscoreCoapPacketAppendError);
    }

    // "consume" original request
    net_pkt_unref(request.pkt);
    return OscoreNoError;
}

/**
 * Inits the encrypted packet @a out with data parsed from the unencrypted packet @a response
 * @param response Original unencrypted packet
 * @param out Packet to write encrypted data to
 * @return OscoreError
 */
static OscoreError init_encrypted_packet(struct coap_packet* response, struct coap_packet* out) {
    u8_t version = coap_header_get_version(response);
    u8_t type = coap_header_get_type(response);
    u8_t token[8];
    u8_t tkl = coap_header_get_token(response, token);
    u16_t id = coap_header_get_id(response);

    struct net_pkt* pkt = net_pkt_get_tx(context, K_FOREVER);
    ensure(pkt != NULL, OscorePktError);
    struct net_buf* frag = net_pkt_get_data(context, K_FOREVER);
    ensure(frag != NULL, OscorePktError);
    net_pkt_frag_add(pkt, frag);

//    u8_t request_code = coap_header_get_code(request);
    // TODO: Observe
    u8_t code_faked = COAP_RESPONSE_CODE_CHANGED;
    ensure_eq(coap_packet_init(out, pkt, version, type, tkl, (u8_t *)token, code_faked, id), 0, OscoreCoapPacketInitError);
    return OscoreNoError;
}

/**
 * Writes all Class U options from @a options to the out-packet and adds the OSCORE CoAP Option @a oscore_option.
 * @param request Request to get from-IP from (for the Proxy-URI option).
 * @param options Array containing all options.
 * @param opt_num Number of options in @a options.
 * @param oscore_option Value of the OSCORE Option to be included in the correct position into the packet.
 * @param out Packet to write options into.
 * @return OscoreError
 */
static OscoreError write_class_u_options(struct coap_packet* request, struct coap_option* options, u16_t opt_num, array oscore_option, struct coap_packet* out) {
    bool has_oscore_option = false;
    u16_t total_delta = 0;
    for (int i = 0; i < opt_num; i++) {
        total_delta += options[i].delta;
        if (!is_class_u(total_delta)) {
            continue;
        }
        struct coap_option option = options[i];

        // special cases
        //   * Max-Age: outer: "MAY"
        if (total_delta == COAP_OPTION_PROXY_URI) {
            // only forward scheme, host, port; strip path and query
            struct sockaddr_in6 to;
            get_from_ip_addr(request, &to);
            struct proxy_url_info info;
            try(coap_parse_uri(options[i], to, &info));
            u8_t len = 0;
            // no length check of value size needed, because we only put parts of it back into the field
            memcpy(&option.value[len], info.scheme.ptr, info.scheme.len);
            len += info.scheme.len;
            option.value[len] = ':';
            option.value[len + 1] = '/';
            option.value[len + 2] = '/';
            len += 3;
            memcpy(&option.value[len], info.host.ptr, info.host.len);
            len += info.host.len;
            if (info.port.len != 0) {
                memcpy(&option.value[len], info.port.ptr, info.port.len);
                len += info.port.len;
            }
            option.len = len;
        }
        if (total_delta > COAP_OPTION_OSCORE && !has_oscore_option) {
            ensure_eq(coap_packet_append_option(out, COAP_OPTION_OSCORE, oscore_option.ptr, (u16_t)oscore_option.len), 0, OscoreCoapPacketAppendError);
            has_oscore_option = true;
        }
        ensure_eq(coap_packet_append_option(out, total_delta, option.value, option.len), 0, OscoreCoapPacketAppendError);
    }
    if (!has_oscore_option) {
        ensure_eq(coap_packet_append_option(out, COAP_OPTION_OSCORE, oscore_option.ptr, (u16_t)oscore_option.len), 0, OscoreCoapPacketAppendError);
    }
    return OscoreNoError;
}

OscoreError into_oscore(struct coap_packet response, struct coap_packet* request, struct coap_packet* out) {
    // get request OSCORE option value, which is needed for nonce construction
    // TODO: find out actual number of options, assume max 10 for now
    u8_t request_opt_num = 10;
    struct coap_option request_options[request_opt_num];
    try(get_options(request, request_options, &request_opt_num));

    // get the request's OSCORE option value
    array request_oscore_option_value = get_option_value(request_options, (u8_t)request_opt_num, COAP_OPTION_OSCORE);
    ensure(!array_equals(request_oscore_option_value, NULL_ARRAY), OscoreNoOscoreOption);
    // extract info
    u8_t partial_iv_bytes[8] = { 0 };
    // TODO: actually be generic over the algorithm
    u8_t kid_bytes[7] = { 0 };
    // MUST be shorter than 256 bytes
    // TODO: don't only assume <16 bytes
    u8_t kid_context_bytes[16] = { 0 };
    struct unprotected request_unprotected = {
            .partial_iv = {
                    .len = sizeof(partial_iv_bytes),
                    .ptr = partial_iv_bytes,
            },
            .kid = {
                    .len = sizeof(kid_bytes),
                    .ptr = kid_bytes,
            },
            .kid_context = {
                    .len = sizeof(kid_context_bytes),
                    .ptr = kid_context_bytes,
            }
    };
    try(from_oscore_option(request_oscore_option_value, &request_unprotected));



    // AEAD Nonce (could be reused, but implemented for completeness)
    // reuse nonce (we create a new one, thus commented out)
//    u8_t nonce[13];
//    try(create_nonce(request_unprotected.kid, request_unprotected.partial_iv, cctx->common_iv, &nonce[0]));

    // increment seq_num
    size_t index = sizeof(sctx.sender_seq_num) - 1;
    do {
        sctx.sender_seq_num[index] += 1;
        index--;
    } while (index > 0 && sctx.sender_seq_num[index+1] == 0);
    // TODO: save new seq num to disk

    // build nonce
    u8_t nonce[13];
//    array piv = {
//        .len = sizeof(sctx.sender_seq_num),
//        .ptr = sctx.sender_seq_num,
//    };
    u8_t piv_leading_zeroes = 0;
    while(sctx.sender_seq_num[piv_leading_zeroes] == 0) {
        piv_leading_zeroes++;
    }
    array piv_stripped = {
        .ptr = &sctx.sender_seq_num[piv_leading_zeroes],
        .len = (size_t)(sizeof(sctx.sender_seq_num) - piv_leading_zeroes),
    };
    try(create_nonce(sctx.sender_id, piv_stripped, cctx.common_iv, &nonce[0]));

    // Collect all information to create plaintext to encrypt

    // We can't use coap_packet_parse here because it assumes a fully built packet, which this isn't (yet before sending it).
    // coap_packet_parse will skip over the network headers to get to the COAP header,
    // but our COAP header already starts where the offset is pointing to.
//    ensure_eq(coap_packet_parse(&response, response.pkt, &options[0], opt_len), 0, OscoreCoapPacketParseError);
    // All that coap_packet_parse does is
    // 1. Skip headers (not needed here)
    // 2. Check that the fragment is valid (we assume this here as it should have been written to before being
    //    passed to us.
    // 3. Set the hdr_len (also not needed here) and check if tkl is valid (also not needed here)
    // 4. Parse the options (done below)
    u8_t option_bytes[response.opt_len];
    array option_bytes_array = {
            .ptr = &option_bytes[0],
            .len = response.opt_len,
    };
    u16_t option_offset;
    struct net_buf* option_frag = net_frag_skip(response.frag, response.offset, &option_offset, response.hdr_len);
    u16_t new_pos;
    struct net_buf* ret = net_frag_read(option_frag, option_offset, &new_pos, (u16_t)option_bytes_array.len, option_bytes_array.ptr);
    assert_actually(!(ret == NULL && new_pos == 0xFFFF), "option copy failed");

    u16_t opt_num;
    try(num_options(option_bytes_array, &opt_num));
    struct coap_option options[opt_num];
    decode_options(option_bytes_array, options, NULL);

    u16_t payload_offset;
    u16_t payload_len;
    // payload already contains payload marker `0xff`
    struct net_buf* frag = net_frag_skip(response.frag, response.offset, &payload_offset, response.hdr_len + response.opt_len);
    ensure(!(frag == NULL && payload_offset == 0xffff), OscoreCoapPacketParseError);
    payload_len = (u16_t)(net_pkt_get_len(response.pkt) - response.offset - response.hdr_len - response.opt_len);

    u32_t encoded_opt_len = encoded_option_len(options, opt_num, CLASS_E);
    size_t maxlen = 1 + encoded_opt_len + payload_len;
    u8_t plaintext_bytes[maxlen];
    array plaintext = {
            .len = maxlen,
            .ptr = plaintext_bytes,
    };

    // Plaintext (Payload): CoAP Code || Class E options || 0xFF (if payload) || payload (if any)

    // CoAP Code
    plaintext.ptr[0] = coap_header_get_code(&response);

    // encode Class E options
    u32_t len = encode_options(options, opt_num, CLASS_E, &plaintext.ptr[1]);
    assert_eq(len, encoded_opt_len);
    u32_t idx = 1 + len;

    // payload (with contained payload marker `0xff`)
    if (!(frag == NULL && payload_offset == 0)) {
        ret = net_frag_read(frag, payload_offset, &new_pos, payload_len, &plaintext.ptr[idx]);
        assert_actually(!(ret == NULL && new_pos == 0xFFFF), "payload copy failed");
    }
    assert_eq(idx + payload_len, plaintext.len);


    // additional authenticated data
    // "NOTE: The format of the external_aad is for simplicity the same for
    //   requests and responses, although some parameters, e.g. request_kid,
    //   need not be integrity protected in all requests."
    size_t aad_len;
    try(aad_length(options, opt_num, cctx.aead_alg, request_unprotected.kid, request_unprotected.partial_iv, &aad_len));
    u8_t aad_bytes[aad_len];
    array aad = {
        .len = aad_len,
        .ptr = aad_bytes,
    };
    try(create_aad(options, opt_num, cctx.aead_alg, request_unprotected.kid, request_unprotected.partial_iv, aad));

    // encrypt
    u8_t payload_bytes[plaintext.len + 8];
    array payload = {
        .len = sizeof(payload_bytes),
        .ptr = payload_bytes,
    };
    try(to_oscore_cose_encrypt0(sctx.sender_key.ptr, nonce, plaintext, aad, payload));
    log_hex("plaintext to send", plaintext.ptr, plaintext.len);
    log_hex("encrypted ciphertext", payload.ptr, payload.len);

    // OSCORE Option
    struct unprotected unprotected = {
        .partial_iv = piv_stripped,
        .kid = sctx.sender_id,
        .kid_context = NULL_ARRAY,
    };
    size_t oscore_option_len = option_value_length(unprotected);
    u8_t oscore_option_bytes[oscore_option_len];
    array oscore_option = {
        .len = oscore_option_len,
        .ptr = oscore_option_bytes,
    };
    try(to_oscore_option(unprotected, oscore_option));

    // actually write data

    try(init_encrypted_packet(&response, out));
    try(write_class_u_options(request, options, opt_num, oscore_option, out));
    // there is always a payload, at least the original CoAP Code
    ensure_eq(coap_packet_append_payload_marker(out), 0, OscoreCoapPacketAppendError);
    ensure_eq(coap_packet_append_payload(out, payload.ptr, (u16_t)payload.len), 0, OscoreCoapPacketAppendError);

    // TODO: find out if we need to unref `request` because we constructed it manually
    net_pkt_unref(response.pkt);
    return OscoreNoError;
}

