# Fingerprint lab: what the edge sees

Collected 2026-11-22T11:55:50.783Z on Darwin 25.6.0 (arm64). Google Chrome 157.0.8103.80. Node v24.22.2.

| Client | User-Agent claims | JA4 | JA3 | HTTP/2 (Akamai) | Verdict |
|---|---|---|---|---|---|
| curl (macOS) h1 | curl | `t13d4907h1_0d8feac7bc37_7395dae3b2f3` | `375c6162a492…` | (http/1.1) | consistent |
| curl (macOS) h2 | curl | `t13d4907h2_0d8feac7bc37_7395dae3b2f3` | `375c6162a492…` | `3:100;4:10485760;2:0|1048510465|0|m,s,a,p` | consistent |
| curl + Chrome UA/headers | chromium | `t13d4907h2_0d8feac7bc37_7395dae3b2f3` | `375c6162a492…` | `3:100;4:10485760;2:0|1048510465|0|m,s,a,p` | **MISMATCH** |
| Node v24.22.2 fetch (undici) | node | `t13d5212h1_b262b3658495_8e6e362c5eac` | `d67b094811e5…` | (http/1.1) | consistent |
| Node https + Chrome UA | chromium | `t13d521100_b262b3658495_8e6e362c5eac` | `944d1e1858cd…` | (http/1.1) | **MISMATCH** |
| Node http2 client | unknown | `t13d5212h2_b262b3658495_8e6e362c5eac` | `d67b094811e5…` | `|00|0|p,m,a,s` | undetermined |
| Python urllib | python | `t13d171100_ab0a1bf427ad_e44827223d20` | `0e56dbc63eb7…` | (http/1.1) | consistent |
| Python urllib + Chrome UA | chromium | `t13d171100_ab0a1bf427ad_e44827223d20` | `0e56dbc63eb7…` | (http/1.1) | **MISMATCH** |
| openssl s_client | unknown | `t13d3012h1_1d37bd780c83_e44827223d20` | `fe84d8d81009…` | (http/1.1) | undetermined |
| Chrome headless #1 | chromium | `t13d1517h2_8daaf6152771_cb7bf5808d99` | `ceb429611c8a…` | `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p` | consistent |
| Chrome headless #2 | chromium | `t13d1517h2_8daaf6152771_cb7bf5808d99` | `a1856b62deda…` | `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p` | consistent |
| Chrome headless #3 | chromium | `t13d1517h2_8daaf6152771_cb7bf5808d99` | `c4dd69a71e05…` | `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p` | consistent |
| Chrome headless #4 | chromium | `t13d1517h2_8daaf6152771_cb7bf5808d99` | `bd456ee3b262…` | `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p` | consistent |
| Chrome headless #5 | chromium | `t13d1517h2_8daaf6152771_cb7bf5808d99` | `b7752a53b6aa…` | `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p` | consistent |

## Why each script was caught

- **curl + Chrome UA/headers**: User-Agent claims chromium, but the ClientHello is a plain TLS library's; HTTP/2 frames look like other, not chromium
- **Node https + Chrome UA**: User-Agent claims chromium, but the ClientHello is a plain TLS library's
- **Python urllib + Chrome UA**: User-Agent claims chromium, but the ClientHello is a plain TLS library's

## Chrome shuffles its extensions every connection

5 fresh Chrome launches produced **5 distinct JA3** hashes, **1 distinct JA3N** (sorted) and **1 distinct JA4**.

Wire order of extensions per launch:

- Chrome headless #1: GREASE, psk_key_exchange_modes, signature_algorithms, encrypted_client_hello, application_settings, 0xca34, extended_master_secret, renegotiation_info, signed_cert_timestamp, server_name, alpn, session_ticket, status_request, key_share, supported_versions, compress_certificate, supported_groups, ec_point_formats, GREASE
- Chrome headless #2: GREASE, session_ticket, 0xca34, status_request, application_settings, alpn, signature_algorithms, server_name, renegotiation_info, supported_versions, supported_groups, encrypted_client_hello, signed_cert_timestamp, psk_key_exchange_modes, compress_certificate, ec_point_formats, extended_master_secret, key_share, GREASE
- Chrome headless #3: GREASE, compress_certificate, supported_versions, encrypted_client_hello, extended_master_secret, session_ticket, ec_point_formats, server_name, status_request, 0xca34, application_settings, renegotiation_info, psk_key_exchange_modes, alpn, signed_cert_timestamp, supported_groups, signature_algorithms, key_share, GREASE
- Chrome headless #4: GREASE, server_name, extended_master_secret, application_settings, signed_cert_timestamp, encrypted_client_hello, supported_versions, compress_certificate, ec_point_formats, renegotiation_info, alpn, status_request, 0xca34, session_ticket, psk_key_exchange_modes, signature_algorithms, supported_groups, key_share, GREASE
- Chrome headless #5: GREASE, signature_algorithms, server_name, encrypted_client_hello, renegotiation_info, extended_master_secret, status_request, signed_cert_timestamp, alpn, compress_certificate, supported_versions, key_share, 0xca34, psk_key_exchange_modes, application_settings, session_ticket, ec_point_formats, supported_groups, GREASE

Chrome key shares: GREASE, X25519MLKEM768, x25519; HTTP/2 header order: sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform, upgrade-insecure-requests, user-agent, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-user, sec-fetch-dest, accept-encoding, accept-language, priority

## HTTP/3: Chrome over QUIC, decrypted passively

| Run | JA4 (q) | Initial packets | CRYPTO frames | Frame layout of the first packet |
|---|---|---|---|---|
| Chrome HTTP/3 #1 | `q13d0312h3_55b375c5d22e_178839b6cec1` | 2 | 16 | CRYPTO[10+12] PING CRYPTO[22+42] PADDING(28) PING PING PING PADDING(10) PING CRYPTO[1022+413] CRYPTO[1435+476] CRYPTO[0+9] PING PADDING(11) PING CRYPTO[9+1] PING PING PING PADDING(161) |
| Chrome HTTP/3 #2 | `q13d0312h3_55b375c5d22e_178839b6cec1` | 2 | 10 | CRYPTO[4+1] PADDING(1) PING CRYPTO[5+65] PING PADDING(4) PING PADDING(137) CRYPTO[1910+2] PING CRYPTO[1902+8] PING PADDING(4) PING CRYPTO[0+4] PADDING(63) CRYPTO[1028+874] PING PING PING |
| Chrome HTTP/3 #3 | `q13d0312h3_55b375c5d22e_178839b6cec1` | 2 | 18 | PADDING(69) CRYPTO[1034+128] CRYPTO[1032+2] PING PADDING(6) CRYPTO[1248+255] PING CRYPTO[1512+7] CRYPTO[1522+297] CRYPTO[1520+2] PADDING(98) CRYPTO[1519+1] PADDING(2) CRYPTO[1031+1] PADDING(1) CRYPTO[1503+9] PADDING(12) CRYPTO[0+75] CRYPTO[1819+88] PING CRYPTO[1162+86] |

Extensions (wire order): key_share, alpn, supported_versions, supported_groups, signature_algorithms, server_name, compress_certificate, 0xca34, quic_transport_parameters, application_settings, psk_key_exchange_modes, encrypted_client_hello

Transport parameters (wire order):

- `0x6` initial_max_stream_data_bidi_remote = 6291456
- `0x7` initial_max_stream_data_uni = 6291456
- `0x9` initial_max_streams_uni = 103
- `0x3` max_udp_payload_size = 1472
- `0x4` initial_max_data = 15728640
- `0x5` initial_max_stream_data_bidi_local = 6291456
- `0x20` max_datagram_frame_size = 65536
- `0x1` max_idle_timeout = 30000
- `0x3128` google_connection_options = ORIG
- `0xf` initial_source_connection_id
- `0x11` version_information = 00000001000000010afacaba
- `0x8` initial_max_streams_bidi = 100
- `0x136e259bb32322af` GREASE

3 runs: 1 distinct JA4, 3 distinct JA3, 3 distinct transport-parameter orders.
