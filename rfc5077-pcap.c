/*
 * Copyright (c) 2011 Vincent Bernat <bernat@luffy.cx>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* Parse SSL/TLS Client Hello to extract statistics. Should be feeded
   with PCAP files on stdin. */

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pcap.h>
#include <time.h>
#include <arpa/inet.h>
#include "common.h"

struct ip4hdr {
  u_int8_t  ihlv;
  u_int8_t  tos;
  u_int16_t tot_len;
  u_int16_t id;
  u_int16_t frag_off;
  u_int8_t  ttl;
  u_int8_t  protocol;
  u_int16_t check;
  u_int32_t saddr;
  u_int32_t daddr;
  /* Options */
} __attribute__ ((__packed__));

struct tcphdr {
  u_int16_t  source;
  u_int16_t  dest;
  u_int32_t  seq;
  u_int32_t  ack_seq;
  u_int16_t  flags;
  u_int16_t  window;
  u_int16_t  checksum;
  u_int16_t  urg;
  /* Options */
} __attribute__ ((__packed__));

struct value_string {
  u_int32_t   value;
  const char *string;
};

/* Stolen from Wireshark */
const struct value_string ssl_compression_method[] = {
    { 0, "NULL" },
    { 1, "DEFLATE" },
    { 64, "LZS" },
    { 0x00, NULL }
};
/* Also stolen from Wireshark */
static const struct value_string ssl_cipher_suites[] = {
    { 0x000000, "TLS_NULL_WITH_NULL_NULL" },
    { 0x000001, "TLS_RSA_WITH_NULL_MD5" },
    { 0x000002, "TLS_RSA_WITH_NULL_SHA" },
    { 0x000003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5" },
    { 0x000004, "TLS_RSA_WITH_RC4_128_MD5" },
    { 0x000005, "TLS_RSA_WITH_RC4_128_SHA" },
    { 0x000006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5" },
    { 0x000007, "TLS_RSA_WITH_IDEA_CBC_SHA" },
    { 0x000008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x000009, "TLS_RSA_WITH_DES_CBC_SHA" },
    { 0x00000a, "TLS_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x00000b, "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x00000c, "TLS_DH_DSS_WITH_DES_CBC_SHA" },
    { 0x00000d, "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA" },
    { 0x00000e, "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x00000f, "TLS_DH_RSA_WITH_DES_CBC_SHA" },
    { 0x000010, "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x000011, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x000012, "TLS_DHE_DSS_WITH_DES_CBC_SHA" },
    { 0x000013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA" },
    { 0x000014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x000015, "TLS_DHE_RSA_WITH_DES_CBC_SHA" },
    { 0x000016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x000017, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5" },
    { 0x000018, "TLS_DH_anon_WITH_RC4_128_MD5" },
    { 0x000019, "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA" },
    { 0x00001a, "TLS_DH_anon_WITH_DES_CBC_SHA" },
    { 0x00001b, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA" },
    { 0x00001c, "SSL_FORTEZZA_KEA_WITH_NULL_SHA" },
    { 0x00001d, "SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA" },
#if 0
    { 0x00001e, "SSL_FORTEZZA_KEA_WITH_RC4_128_SHA" },
#endif
    /* RFC 2712 */
    { 0x00001E, "TLS_KRB5_WITH_DES_CBC_SHA" },
    { 0x00001F, "TLS_KRB5_WITH_3DES_EDE_CBC_SHA" },
    { 0x000020, "TLS_KRB5_WITH_RC4_128_SHA" },
    { 0x000021, "TLS_KRB5_WITH_IDEA_CBC_SHA" },
    { 0x000022, "TLS_KRB5_WITH_DES_CBC_MD5" },
    { 0x000023, "TLS_KRB5_WITH_3DES_EDE_CBC_MD5" },
    { 0x000024, "TLS_KRB5_WITH_RC4_128_MD5" },
    { 0x000025, "TLS_KRB5_WITH_IDEA_CBC_MD5" },
    { 0x000026, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA" },
    { 0x000027, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA" },
    { 0x000028, "TLS_KRB5_EXPORT_WITH_RC4_40_SHA" },
    { 0x000029, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5" },
    { 0x00002A, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5" },
    { 0x00002B, "TLS_KRB5_EXPORT_WITH_RC4_40_MD5" },
    /* RFC 4785 */
    { 0x00002C, "TLS_PSK_WITH_NULL_SHA" },
    { 0x00002D, "TLS_DHE_PSK_WITH_NULL_SHA" },
    { 0x00002E, "TLS_RSA_PSK_WITH_NULL_SHA" },
    /* RFC 5246 */
    { 0x00002f, "TLS_RSA_WITH_AES_128_CBC_SHA" },
    { 0x000030, "TLS_DH_DSS_WITH_AES_128_CBC_SHA" },
    { 0x000031, "TLS_DH_RSA_WITH_AES_128_CBC_SHA" },
    { 0x000032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA" },
    { 0x000033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" },
    { 0x000034, "TLS_DH_anon_WITH_AES_128_CBC_SHA" },
    { 0x000035, "TLS_RSA_WITH_AES_256_CBC_SHA" },
    { 0x000036, "TLS_DH_DSS_WITH_AES_256_CBC_SHA" },
    { 0x000037, "TLS_DH_RSA_WITH_AES_256_CBC_SHA" },
    { 0x000038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA" },
    { 0x000039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA" },
    { 0x00003A, "TLS_DH_anon_WITH_AES_256_CBC_SHA" },
    { 0x00003B, "TLS_RSA_WITH_NULL_SHA256" },
    { 0x00003C, "TLS_RSA_WITH_AES_128_CBC_SHA256" },
    { 0x00003D, "TLS_RSA_WITH_AES_256_CBC_SHA256" },
    { 0x00003E, "TLS_DH_DSS_WITH_AES_128_CBC_SHA256" },
    { 0x00003F, "TLS_DH_RSA_WITH_AES_128_CBC_SHA256" },
    { 0x000040, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256" },
    { 0x000041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x000042, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x000043, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x000044, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x000045, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x000046, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA" },
    { 0x000047, "TLS_ECDH_ECDSA_WITH_NULL_SHA" },
    { 0x000048, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA" },
    { 0x000049, "TLS_ECDH_ECDSA_WITH_DES_CBC_SHA" },
    { 0x00004A, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x00004B, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA" },
    { 0x00004C, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA" },
    { 0x000060, "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5" },
    { 0x000061, "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5" },
    { 0x000062, "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA" },
    { 0x000063, "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA" },
    { 0x000064, "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA" },
    { 0x000065, "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA" },
    { 0x000066, "TLS_DHE_DSS_WITH_RC4_128_SHA" },
    { 0x000067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256" },
    { 0x000068, "TLS_DH_DSS_WITH_AES_256_CBC_SHA256" },
    { 0x000069, "TLS_DH_RSA_WITH_AES_256_CBC_SHA256" },
    { 0x00006A, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256" },
    { 0x00006B, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256" },
    { 0x00006C, "TLS_DH_anon_WITH_AES_128_CBC_SHA256" },
    { 0x00006D, "TLS_DH_anon_WITH_AES_256_CBC_SHA256" },
    /* 0x00,0x6E-83 Unassigned  */
    { 0x000084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x000085, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x000086, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x000087, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x000088, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA" },
    { 0x000089, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA" },
    /* RFC 4279 */
    { 0x00008A, "TLS_PSK_WITH_RC4_128_SHA" },
    { 0x00008B, "TLS_PSK_WITH_3DES_EDE_CBC_SHA" },
    { 0x00008C, "TLS_PSK_WITH_AES_128_CBC_SHA" },
    { 0x00008D, "TLS_PSK_WITH_AES_256_CBC_SHA" },
    { 0x00008E, "TLS_DHE_PSK_WITH_RC4_128_SHA" },
    { 0x00008F, "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA" },
    { 0x000090, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA" },
    { 0x000091, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA" },
    { 0x000092, "TLS_RSA_PSK_WITH_RC4_128_SHA" },
    { 0x000093, "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA" },
    { 0x000094, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA" },
    { 0x000095, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA" },
    /* RFC 4162 */
    { 0x000096, "TLS_RSA_WITH_SEED_CBC_SHA" },
    { 0x000097, "TLS_DH_DSS_WITH_SEED_CBC_SHA" },
    { 0x000098, "TLS_DH_RSA_WITH_SEED_CBC_SHA" },
    { 0x000099, "TLS_DHE_DSS_WITH_SEED_CBC_SHA" },
    { 0x00009A, "TLS_DHE_RSA_WITH_SEED_CBC_SHA" },
    { 0x00009B, "TLS_DH_anon_WITH_SEED_CBC_SHA" },
    /* RFC 5288 */
    { 0x00009C, "TLS_RSA_WITH_AES_128_GCM_SHA256" },
    { 0x00009D, "TLS_RSA_WITH_AES_256_GCM_SHA384" },
    { 0x00009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256" },
    { 0x00009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384" },
    { 0x0000A0, "TLS_DH_RSA_WITH_AES_128_GCM_SHA256" },
    { 0x0000A1, "TLS_DH_RSA_WITH_AES_256_GCM_SHA384" },
    { 0x0000A2, "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256" },
    { 0x0000A3, "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384" },
    { 0x0000A4, "TLS_DH_DSS_WITH_AES_128_GCM_SHA256" },
    { 0x0000A5, "TLS_DH_DSS_WITH_AES_256_GCM_SHA384" },
    { 0x0000A6, "TLS_DH_anon_WITH_AES_128_GCM_SHA256" },
    { 0x0000A7, "TLS_DH_anon_WITH_AES_256_GCM_SHA384" },
    /* RFC 5487 */
    { 0x0000A8, "TLS_PSK_WITH_AES_128_GCM_SHA256" },
    { 0x0000A9, "TLS_PSK_WITH_AES_256_GCM_SHA384" },
    { 0x0000AA, "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256" },
    { 0x0000AB, "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384" },
    { 0x0000AC, "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256" },
    { 0x0000AD, "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384" },
    { 0x0000AE, "TLS_PSK_WITH_AES_128_CBC_SHA256" },
    { 0x0000AF, "TLS_PSK_WITH_AES_256_CBC_SHA384" },
    { 0x0000B0, "TLS_PSK_WITH_NULL_SHA256" },
    { 0x0000B1, "TLS_PSK_WITH_NULL_SHA384" },
    { 0x0000B2, "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256" },
    { 0x0000B3, "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384" },
    { 0x0000B4, "TLS_DHE_PSK_WITH_NULL_SHA256" },
    { 0x0000B5, "TLS_DHE_PSK_WITH_NULL_SHA384" },
    { 0x0000B6, "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256" },
    { 0x0000B7, "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384" },
    { 0x0000B8, "TLS_RSA_PSK_WITH_NULL_SHA256" },
    { 0x0000B9, "TLS_RSA_PSK_WITH_NULL_SHA384" },
    /* From RFC 5932 */
    { 0x0000BA, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x0000BB, "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x0000BC, "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x0000BD, "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x0000BE, "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x0000BF, "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256" },
    { 0x0000C0, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x0000C1, "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x0000C2, "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x0000C3, "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x0000C4, "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256" },
    { 0x0000C5, "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256" },
    /* 0x00,0xC6-FE Unassigned  */
    { 0x0000FF, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV" },
    /* 0x01-BF,* Unassigned  */
    /* From RFC 4492 */
    { 0x00c001, "TLS_ECDH_ECDSA_WITH_NULL_SHA" },
    { 0x00c002, "TLS_ECDH_ECDSA_WITH_RC4_128_SHA" },
    { 0x00c003, "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x00c004, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA" },
    { 0x00c005, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA" },
    { 0x00c006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA" },
    { 0x00c007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA" },
    { 0x00c008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x00c009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" },
    { 0x00c00a, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA" },
    { 0x00c00b, "TLS_ECDH_RSA_WITH_NULL_SHA" },
    { 0x00c00c, "TLS_ECDH_RSA_WITH_RC4_128_SHA" },
    { 0x00c00d, "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x00c00e, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA" },
    { 0x00c00f, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA" },
    { 0x00c010, "TLS_ECDHE_RSA_WITH_NULL_SHA" },
    { 0x00c011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA" },
    { 0x00c012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x00c013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" },
    { 0x00c014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" },
    { 0x00c015, "TLS_ECDH_anon_WITH_NULL_SHA" },
    { 0x00c016, "TLS_ECDH_anon_WITH_RC4_128_SHA" },
    { 0x00c017, "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA" },
    { 0x00c018, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA" },
    { 0x00c019, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA" },
    /* RFC 5054 */
    { 0x00C01A, "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA" },
    { 0x00C01B, "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA" },
    { 0x00C01C, "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA" },
    { 0x00C01D, "TLS_SRP_SHA_WITH_AES_128_CBC_SHA" },
    { 0x00C01E, "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA" },
    { 0x00C01F, "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA" },
    { 0x00C020, "TLS_SRP_SHA_WITH_AES_256_CBC_SHA" },
    { 0x00C021, "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA" },
    { 0x00C022, "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA" },
    /* RFC 5589 */
    { 0x00C023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256" },
    { 0x00C024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384" },
    { 0x00C025, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256" },
    { 0x00C026, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384" },
    { 0x00C027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256" },
    { 0x00C028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384" },
    { 0x00C029, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256" },
    { 0x00C02A, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384" },
    { 0x00C02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" },
    { 0x00C02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" },
    { 0x00C02D, "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256" },
    { 0x00C02E, "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384" },
    { 0x00C02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" },
    { 0x00C030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" },
    { 0x00C031, "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256" },
    { 0x00C032, "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384" },
    /* RFC 5489 */
    { 0x00C033, "TLS_ECDHE_PSK_WITH_RC4_128_SHA" },
    { 0x00C034, "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA" },
    { 0x00C035, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA" },
    { 0x00C036, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA" },
    { 0x00C037, "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256" },
    { 0x00C038, "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384" },
    { 0x00C039, "TLS_ECDHE_PSK_WITH_NULL_SHA" },
    { 0x00C03A, "TLS_ECDHE_PSK_WITH_NULL_SHA256" },
    { 0x00C03B, "TLS_ECDHE_PSK_WITH_NULL_SHA384" },
    /* 0xC0,0x3C-FF Unassigned
            0xC1-FD,* Unassigned
            0xFE,0x00-FD Unassigned
            0xFE,0xFE-FF Reserved to avoid conflicts with widely deployed implementations [Pasi_Eronen]
            0xFF,0x00-FF Reserved for Private Use [RFC5246]
            */

    /* these from http://www.mozilla.org/projects/
         security/pki/nss/ssl/fips-ssl-ciphersuites.html */
    { 0x00fefe, "SSL_RSA_FIPS_WITH_DES_CBC_SHA"},
    { 0x00feff, "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA" },
    { 0x00ffe0, "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA" },
    { 0x00ffe1, "SSL_RSA_FIPS_WITH_DES_CBC_SHA"},
    /* note that ciphersuites of {0x00????} are TLS cipher suites in
     * a sslv2 client hello message; the ???? above is the two-byte
     * tls cipher suite id
     */

    { 0x010080, "SSL2_RC4_128_WITH_MD5" },
    { 0x020080, "SSL2_RC4_128_EXPORT40_WITH_MD5" },
    { 0x030080, "SSL2_RC2_CBC_128_CBC_WITH_MD5" },
    { 0x040080, "SSL2_RC2_CBC_128_CBC_WITH_MD5" },
    { 0x050080, "SSL2_IDEA_128_CBC_WITH_MD5" },
    { 0x060040, "SSL2_DES_64_CBC_WITH_MD5" },
    { 0x0700c0, "SSL2_DES_192_EDE3_CBC_WITH_MD5" },
    { 0x080080, "SSL2_RC4_64_WITH_MD5" },

    /* Microsoft's old PCT protocol. These are from Eric Rescorla's
       book "SSL and TLS" */
    { 0x800001, "PCT_SSL_CERT_TYPE | PCT1_CERT_X509" },
    { 0x800003, "PCT_SSL_CERT_TYPE | PCT1_CERT_X509_CHAIN" },
    { 0x810001, "PCT_SSL_HASH_TYPE | PCT1_HASH_MD5" },
    { 0x810003, "PCT_SSL_HASH_TYPE | PCT1_HASH_SHA" },
    { 0x820001, "PCT_SSL_EXCH_TYPE | PCT1_EXCH_RSA_PKCS1" },
    { 0x830004, "PCT_SSL_CIPHER_TYPE_1ST_HALF | PCT1_CIPHER_RC4" },
    { 0x842840, "PCT_SSL_CIPHER_TYPE_2ND_HALF | PCT1_ENC_BITS_40 | PCT1_MAC_BITS_128" },
    { 0x848040, "PCT_SSL_CIPHER_TYPE_2ND_HALF | PCT1_ENC_BITS_128 | PCT1_MAC_BITS_128" },
    { 0x8f8001, "PCT_SSL_COMPAT | PCT_VERSION_1" },
    { 0x00, NULL }
};

struct hello {
  char          client[INET6_ADDRSTRLEN];
  char          server[INET6_ADDRSTRLEN];
  char          ssl2;		/* Inside a SSL2 packet */
  unsigned char vmajor;		/* Major SSL version */
  unsigned char vminor;		/* Minor SSL version */
  int           sessionidlen;
  unsigned char sessionid[32];	/* Session ID */
  char         *ciphers;	/* List of cipher suites */
  char         *compression;	/* List of compression methods */
  char         *servername;	/* TLS extension: server name */
  char          ticket;		/* Ticket extension present */
  int           ticketlen;	/* Ticket length */
};

static void
append(char **to, const char *what) {
  if (!*to)
    *to = strdup(what);
  else {
    int l = strlen(*to);
    *to = realloc(*to,
		  l + strlen(what) + 2);
    strcat(*to, ":"); strcat(*to, what);
    (*to)[l] = ':';
  }
}

static struct hello*
parse(const u_char *data, int len) {
  static struct hello hello;
  memset(&hello, 0, sizeof(hello));

  /* Ethernet header */
  if (len < 14) return NULL;
  int proto;
  memcpy(&proto, data + 12, 2);
  if (ntohs(proto) != 0x800) return NULL;
  data += 14;
  len -= 14;

  /* IP header. */
  u_int8_t version;
  if (len < 1) return NULL;
  version = (data[0] & 0xf0) >> 4;
  switch (version) {
  case 4:
    /* IPv4 */
    if (len < 20) return NULL;
    struct ip4hdr ip4;
    memcpy(&ip4, data, sizeof(ip4));
    if ((ntohs(ip4.frag_off) & 0xbf) != 0) return NULL; /* Don't handle fragments */
    if (ip4.protocol != 6) return NULL;		 /* TCP only */
    if (ntohs(ip4.tot_len) < len) return NULL;	 /* Packet too small */
    len = ntohs(ip4.tot_len);			 /* Keep only real data */
    if (!inet_ntop(AF_INET, &ip4.saddr,
		   hello.client, sizeof(hello.client))) return NULL;
    if (!inet_ntop(AF_INET, &ip4.daddr,
		   hello.server, sizeof(hello.server))) return NULL;
    data += (ip4.ihlv & 0xf) * 4;
    len -= (ip4.ihlv & 0xf) * 4;
    /* TCPv4 */
    if (len < 20) return NULL;
    struct tcphdr tcp4;
    memcpy(&tcp4, data, sizeof(tcp4));
    if (ntohs(tcp4.flags) & 0x7) return NULL;	/* SYN, FIN, RST */
    data += ((ntohs(tcp4.flags) & 0xf000) >> 12) * 4;
    len -= ((ntohs(tcp4.flags) & 0xf000) >> 12) * 4;
    break;
  case 6:
    /* IPv6 */
    return NULL;			/* TODO */
    break;
  default: return NULL;
  }

  /* SSLv2 + SSLv3/TLS. See ssl/s23_srvr.c for detection logic */
  if (len < 11) return NULL;
  u_int16_t tlen;
  if ((data[0] & 0x80) && (data[2] == 1)) {
    /* Let's assume SSLv2. This is now prohibited, see RFC 6176, but
       we want to keep track of clients still using it. */
    hello.ssl2 = 1;
    memcpy(&tlen, data, 2);
    tlen = ntohs(tlen) & 0x2fff;
    hello.vmajor = data[3]; hello.vminor = data[4];
    if (hello.vmajor != 2 && hello.vmajor != 3) return NULL;
    if (hello.vmajor == 2 && hello.vminor != 0) return NULL;
    if (hello.vmajor == 3 && hello.vminor > 3)  return NULL;
    if (tlen != len - 2) return NULL;

    u_int16_t sidlen;
    u_int16_t ciphlen;
    memcpy(&sidlen, data + 7, 2);
    sidlen = ntohs(sidlen);
    memcpy(&ciphlen, data + 5, 2);
    ciphlen = ntohs(ciphlen);
    if (len < 11 + sidlen + ciphlen) return NULL;

    /* Session ID */
    if (sidlen != 16 && sidlen != 0) return NULL;
    memcpy(hello.sessionid, data + 11 + ciphlen, sidlen);
    hello.sessionidlen = sidlen;

    /* Ciphers */
    u_int32_t cipher;
    while (ciphlen) {
      memcpy(&cipher, data + 11 + ciphlen - 3, 3);
      cipher = ntohl(cipher);
      cipher = cipher >> 8;
      ciphlen -= 3;
      const struct value_string *cs = ssl_cipher_suites;
      while (cs->string) {
	if (cs->value == cipher) {
	  append(&hello.ciphers, cs->string);
	  break;	  
	}
	cs++;
      }
    }
  } else {
    /* SSLv3 or TLS */
    if (data[0] != 22) return NULL;	/* Not TLS Handshake */
    if (data[1] != 3) return NULL;	/* Not TLS 1.x */
    if (data[2] > 3) return NULL;	/* TLS 1.3 or more */
    memcpy(&tlen, data + 3, 2);
    tlen = ntohs(tlen);
    data += 5;
    len -= 5;
    if (tlen != len) return NULL;
    if (len < 5) return NULL;
    if (data[0] != 1) return NULL;	/* Client Hello */
    if (data[1] != 0) return NULL;	/* We don't handle fragmentation */
    memcpy(&tlen, data + 2, 2);
    if (ntohs(tlen) != len - 4) return NULL;
    hello.vmajor = data[4]; hello.vminor = data[5];
    if (hello.vmajor != 3) return NULL;
    if (hello.vminor > 3) return NULL;
    data += 38;
    len -= 38;

    /* Session ID */
    if (len < 1) return NULL;
    hello.sessionidlen = data[0];
    if (hello.sessionidlen != 0 &&
	hello.sessionidlen != 32) return NULL; /* Session ID should be 32 */
    memcpy(hello.sessionid, data + 1, hello.sessionidlen);
    data += 1 + hello.sessionidlen;
    len -= 1 + hello.sessionidlen;

    /* Ciphers */
    if (len < 2) return NULL;
    u_int16_t ciphlen;
    u_int16_t cipher;
    memcpy(&ciphlen, data, 2);
    ciphlen = ntohs(ciphlen);
    if (len < 2 + ciphlen) return NULL;
    while (ciphlen) {
      memcpy(&cipher, data + 2 + ciphlen - 2, 2);
      cipher = ntohs(cipher);
      ciphlen -= 2;
      const struct value_string *cs = ssl_cipher_suites;
      while (cs->string) {
	if (cs->value == cipher) {
	  append(&hello.ciphers, cs->string);
	  break;
	}
	cs++;
      }
    }
    memcpy(&ciphlen, data, 2);
    ciphlen = ntohs(ciphlen);
    data += ciphlen + 2;
    len -= ciphlen + 2;

    /* Compression methods */
    if (len < 1) goto err;
    unsigned char complen = data[0];
    if (complen == 0) goto err;
    if (len < 1 + complen) goto err;
    while (complen--) {
      const struct value_string *cm = ssl_compression_method;
      while (cm->string) {
	if (cm->value == data[complen + 1]) {
	  append(&hello.compression, cm->string);
	  break;	  
	}
	cm++;
      }
    }
    len -= data[0] + 1;
    data += data[0] + 1;

    /* Extensions */
    if (len > 2) {
      u_int16_t extlen;
      memcpy(&extlen, data, 2);
      extlen = ntohs(extlen);
      if (len != extlen + 2) goto err;
      data += 2;
      len -= 2;
      while (len > 0) {
	u_int16_t exttype;
	char *sni;		/* Current name */
	u_int16_t snilen;	/* Length of current name */
	u_int16_t clen;		/* Remaining length in extension */
	const unsigned char *p;	/* Current position in data */
	if (len < 4) goto err;
	memcpy(&exttype, data, 2);
	exttype = ntohs(exttype);
	memcpy(&extlen, data + 2, 2);
	extlen = ntohs(extlen);
	if (len + 4 < extlen) goto err;
	switch (exttype) {
	case 0:			/* Server name */
	  if (extlen < 2) break;
	  memcpy(&clen, data + 4, 2);
	  clen = ntohs(clen);
	  if (clen + 2 != extlen) break;
	  p = data + 6;
	  while (clen >= 3) {
	    memcpy(&snilen, p + 1, 2);
	    snilen = ntohs(snilen);
	    if (clen < snilen + 3) break;
	    if (*p == 0) {
	      sni = malloc(snilen + 1);
	      memcpy(sni, p + 3, snilen);
	      sni[snilen] = '\0';
	      append(&hello.servername, sni);
	      free(sni);
	    }
	    p += 3 + snilen;
	    clen -= 3 + snilen;
	  }
	  break;
	case 0x23:
	  hello.ticket = 1;
	  hello.ticketlen = extlen;
	  break;
	}
	data += extlen + 4;
	len -= extlen + 4;
      }
      if (len != 0) goto err;
    }
  }

  return &hello;
 err:
  if (hello.compression) free(hello.compression);
  if (hello.ciphers) free(hello.ciphers);
  if (hello.servername) free(hello.servername);
  return NULL;
}

static int
count(const char *list) {
  if (!list) return 0;
  int c = 1;
  while ((list = strchr(list, ':'))) {
    c++;
    list++;
  }
  return c;
}

void
display(struct timeval *ts, struct hello *hello) {
  /* Date */
  struct tm *tm = gmtime(&ts->tv_sec);
  char       date[100];
  strftime(date, sizeof(date), "%FT%TZ", tm);

  end("Packet received at %s\n"
      " %s → %s\n"
      "   Version:             %d.%d%s\n"
      "   Session ID len:      %d\n"
      "   Cipher suites:       %d\n"
      "   Compression methods: %d\n"
      "   Server Name:         %s\n"
      "   Ticket extension:    %s\n"
      "   Ticket length        %d",
      date, hello->client, hello->server,
      hello->vmajor, hello->vminor,
      hello->ssl2?" (inside SSLv2)":"",
      hello->sessionidlen,
      count(hello->ciphers),
      count(hello->compression),
      hello->servername?hello->servername:"Not present",
      hello->ticket?"Present":"Absent",
      hello->ticketlen);
}

void
dump(FILE *output, struct timeval *ts, struct hello *hello) {
  if (ftell(output) == 0)
    fprintf(output,
	    "date;client;server;ssl2;version;sessionid;ciphers;compression;"
	    "servername;ticket;ticketlen\n");
  fprintf(output,
	  "%ld.%ld;%s;%s;%d;%d.%d;",
	  (long)ts->tv_sec, (long)ts->tv_usec,
	  hello->client, hello->server,
	  hello->ssl2,
	  hello->vmajor, hello->vminor);
  for (int i=0; i < hello->sessionidlen; i++)
    fprintf(output, "%02X", hello->sessionid[i]);
  fprintf(output, ";%s;%s;%s;%d;%d\n",
	  hello->ciphers,
	  hello->compression?hello->compression:"",
	  hello->servername?hello->servername:"",
	  hello->ticket, hello->ticketlen);
}

int
main(int argc, char * const argv[]) {

  FILE *output;

  start("Check arguments");
  if (argc != 2)
    fail("Usage: %s output\n"
	 "\n"
	 " Decode TLS Client Hello packets in PCAP files from stdin.\n"
	 "\n"
	 " For example, ‘%s output.csv < my.pcap‘ or\n"
	 " ‘tcpdump -r my.pcap dst port 443 | %s output.csv‘",
	 argv[0], argv[0], argv[0]);
  if (!(output = fopen(argv[1], "a")))
    fail("Unable to open output file:\n%m");

  start("Preparing libpcap to read input");
  pcap_t *pcap;
  char    errbuf[PCAP_ERRBUF_SIZE];
  if ((pcap = pcap_open_offline("-", errbuf)) == NULL)
    fail("Unable to open standard input for packets:\n%s",
	 errbuf);

  struct hello       *hello;
  struct pcap_pkthdr *h;
  const u_char       *data;
  int                 n;
  start("Read packets");
  while (1) {
    n = pcap_next_ex(pcap, &h, &data);
    if (n == -2) {
      end("No more packets available.");
      break;
    }
    if (n == -1)
      fail("Unable to read one packet:\n%s", pcap_geterr(pcap));
    hello = parse(data, h->caplen);
    if (hello) {
      dump(output, &h->ts, hello);
      display(&h->ts, hello);
      if (hello->ciphers) free(hello->ciphers);
      if (hello->compression) free(hello->compression);
      if (hello->servername) free(hello->servername);
      start("Read other packets");
    }
  }

  pcap_close(pcap);
  end(NULL);
  return 0;
}
