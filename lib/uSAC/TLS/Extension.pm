package uSAC::TLS::Extension;
package TLS::TYPE::EXT
# names 0 to 60
my @name=
qw<
server_name
max_fragment_length
client_certificate_url
trusted_ca_keys
truncated_hmac
status_request
user_mapping
client_authz
server_authz
cert_type
supported_groups
ec_point_formats
srp
signature_algorithms
use_srtp
heartbeat
application_layer_protocol_negotiation
status_request_v2
signed_certificate_timestamp
client_certificate_type
server_certificate_type
padding
encrypt_then_mac
extended_master_secret
token_binding
cached_info
tls_lts
compress_certificate
record_size_limit
pwd_protect
pwd_clear
password_salt
ticket_pinning
tls_cert_with_extern_psk
delegated_credential
session_ticket
TLMSP
TLMSP_proxying
TLMSP_delegate
supported_ekt_ciphers
Reserved
pre_shared_key
early_data
supported_versions
cookie
psk_key_exchange_modes
Reserved
certificate_authorities
oid_filters
post_handshake_auth
signature_algorithms_cert
key_share
transparency_info
connection_id (deprecated)
connection_id
external_id_hash
external_session_id
quic_transport_parameters
ticket_request
dnssec_chain
sequence_number_encryption_algorithms
>;

use constant::more map {uc($names[$_])=>$_} 0...$#names;

# Cert types
package TLS::TYPE::CERT;
use constant::more qw{X509=0 OPEN_PGP RAW 1609D2};



"HTTP/0.9"=>pack("C*", 0x68 0x74 0x74 0x70 0x2f 0x30 0x2e 0x39),
"HTTP/1.0"=>pack("C*", 0x68 0x74 0x74 0x70 0x2f 0x31 0x2e 0x30),
"HTTP/1.1"=>pack("C*", 0x68 0x74 0x74 0x70 0x2f 0x31 0x2e 0x31),
"SPDY/1"=>pack "C*", 0x73 0x70 0x64 0x79 0x2f 0x31),
"SPDY/2"=>pack "C*", 0x73 0x70 0x64 0x79 0x2f 0x32),
"SPDY/3"=>pack "C*", 0x73 0x70 0x64 0x79 0x2f 0x33),
"Traversal Using Relays around NAT (TURN)"=>pack "C*", 0x73 0x74 0x75 0x6E 0x2E 0x74 0x75 0x72 0x6E ), #(""stun.turn"")"",
"NAT discovery using Session Traversal Utilities for NAT (STUN)"=>pack "C*", 0x73 0x74 0x75 0x6E 0x2E 0x6e 0x61 0x74 0x2d 0x64 0x69 0x73 0x63 0x6f 0x76 0x65 0x72 0x79), # (""stun.nat-discovery""))"",
"HTTP/2 over TLS"=>pack "C*", 0x68 0x32),#(""h2"")"",
HTTP/2 over TCP=>""0x68 0x32 0x63 (""h2c"")"",
WebRTC Media and Data=>""0x77 0x65 0x62 0x72 0x74 0x63 (""webrtc"")"",
Confidential WebRTC Media and Data=>""0x63 0x2d 0x77 0x65 0x62 0x72 0x74 0x63 (""c-webrtc"")"",
FTP=>""0x66 0x74 0x70 (""ftp"")"",
IMAP=>""0x69 0x6d 0x61 0x70 (""imap"")"",
POP3=>""0x70 0x6f 0x70 0x33 (""pop3"")"",
ManageSieve=>""0x6d 0x61 0x6e 0x61 0x67 0x65 0x73 0x69 0x65 0x76 0x65 (""managesieve"")"",
CoAP=>""0x63 0x6f 0x61 0x70 (""coap"")"",
XMPP jabber:client namespace=>""0x78 0x6d 0x70 0x70 0x2d 0x63 0x6c 0x69 0x65 0x6e 0x74 (""xmpp-client"")"",
XMPP jabber:server namespace=>""0x78 0x6d 0x70 0x70 0x2d 0x73 0x65 0x72 0x76 0x65 0x72 (""xmpp-server"")"",
acme-tls/1=>""0x61 0x63 0x6d 0x65 0x2d 0x74 0x6c 0x73 0x2f 0x31 (""acme-tls/1"")"",
OASIS Message Queuing Telemetry Transport (MQTT)=>"0x6d 0x71 0x74 0x74 (“mqtt”)",
DNS-over-TLS=>""0x64 0x6F 0x74 (""dot"")"",
"Network Time Security Key Establishment=>" version 1"",
SunRPC=>""0x73 0x75 0x6e 0x72 0x70 0x63 (""sunrpc"")"",
HTTP/3=>""0x68 0x33 (""h3"")"",
SMB2=>"0x73 0x6D 0x62 (“smb”)",
IRC=>""0x69 0x72 0x63 (""irc"")"",
NNTP (reading)=>""0x6E 0x6E 0x74 0x70 (""nntp"")"",
NNTP (transit)=>""0x6E 0x6E 0x73 0x70 (""nnsp"")"",
DoQ=>""0x64 0x6F 0x71 (""doq"")"",
SIP=>""0x73 0x69 0x70 0x2f 0x32 (""sip/2"")"",
TDS/8.0=>""0x74 0x64 0x73 0x2f 0x38 0x2e 0x30 (""tds/8.0"")"",
DICOM=>""0x64 0x69 0x63 0x6f 0x6d (""dicom"")"",


1;