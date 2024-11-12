package uSAC::TLS;
use v5.36;

use Export::These ;

use constant::more 
  MAX_FRAG=>2^14
;

# Version
use constant::more
  <PROTOCOLVERSION_{MAJOR=0,MINOR}>;

my $PACK_PROTOCOL_VERSION="CC";


# Content Type Enumerations
use constant::more 
  <CONTENTTYPE_{CHANGE_CIPHER_SPEC=20,ALERT,HANDSHAKE,APPLICATION_DATA}>;


# TLS Plain Text/Compressed/CipherText
use constant::more
  <TLSPLAINTEXT_{TYPE=0,VERSION,LENGTH,FRAGMENT}>;

use constant::more
  <TLSPCOMPRESSED_{TYPE=0,VERSION,LENGTH,FRAGMENT}>;

use constant::more
  <TLSCIPHERTEXT_{TYPE=0,VERSION,LENGTH,FRAGMENT}>;


# Stream cipher
use constant::more
  <GENERICSTREAMCIPHER_{CONTENT=0,MAC}>;

# Block cipher
use constant::more
  <GENERICBLOCKCIPHER_{IV=0,CONTENT,MAC,PADDING,PADDING_LENGTH}>;

# AEAD Cipher
use constant::more
  <GENERICAEADCIPHER_{NONCE_EXPLICIT=0,CONTENT}>;


#Change Cipher Specs Message
use constant::more 
  <CHANGECIPHERSPEC_{CHANGE_CIPHER_SPEC=1}>;




# Handshake Protocol
use constant::more 
  <HANDSHAKETYPE_{HELLO_REQUEST=0,CLIENT_HELLO,SERVER_HELLO, CERTIFICATE=11,SERVER_KEY_EXCHANGE,CERTIFICATE_REQUEST, SERVER_HELLO_DONE,CERTIFICATE_VERIFY,CLIENT_KEY_EXCHANGE, FINISHED=20}>;

use constant::more
  <HANDSHAKE_{MSG_TYPE=0,LENGTH,BODY}>;


#Hello Messages

  #struct { } HelloRequest;

use constant::more
  <RANDOM_{GMT_UNIX_TIME=0,RANDOM_BYTES}>;
my $PACK_RANDOM ="Lx28";

  #opaque SessionID<0..32>;

  #uint8 CipherSuite[2];
my $PACK_CIPHER_SUITE="CC";

use constant::more 
  <COMPRESSIONMETHOD_{NULL=0}>;
my $PACK_COMPRESSION_METHOD="C";

use constant::more
  <CLIENTHELLO_{CLIENT_VERSION=0,RANDOM,SESSION_ID,CIPHER_SUITES,COMPRESSION_METHODS,EXTENSIONS}>;

my $PACK_CLIENTHELLO ="
$PACK_PROTOCOL_VERSION
$PACK_RANDOM
$PACK_SESSION
$PACK_CIPHER_SUITE
$PACK_COMPRESSION_METHOD

";
# Note extensions are detected by 'presents of bytes' after compression method field...
my $PACK_SERVERHELLO=$PACK_CLIENTHELLO;



use constant::more
  <SERVERHELLO_{SERVER_VERSION=0,RANDOM,SESSION_ID,CIPHER_SUITES,COMPRESSION_METHOD,EXTENSIONS}>;

use constant::more
  <EXTENSION_{EXTENSION_TYPE=0,EXTENSION_DATA}>;

use constant::more
  <EXTENSIONTYPE_{SIGNATURE_ALGORITHMS=13}>;

use constant::more 
  <HASHALGORITHM_{NONE=0,MD5,SHA1,SHA224,SHA256,SHA384,SHA512}>;

use constant::more
  <SIGNATUREALGORITHM_{ANONYMOUS=0,RSA,DSA,ECDSA}>;

use constant::more
  <SIGNATUREANDHASHALGORITHM_{HASH=0,SIGNATURE}>;


   #SignatureAndHashAlgorithm
   #supported_signature_algorithms<2..2^16-1>;

# Server Authentication and Key Exchange Messages

   ##############################################
   # opaque ASN.1Cert<2^24-1>;                  #
   #                                            #
   # struct {                                   #
   #     ASN.1Cert certificate_list<0..2^24-1>; #
   # } Certificate;                             #
   ##############################################

use constant::more 
  <KEYEXCHANGEALGORITHM_{DHE_DSS=0,DHE_RSA,DH_ANON,RSA,DH_DSS,DH_RSA}>;

use constant::more
  <SERVERDHPARAMS_{DH_P=0,DH_G,DH_YS}>;

use constant::more
  <SERVERKEYEXCHANGE_{SIGNED_PARAMS=0,RSA,DH_RSS,DH_RSA}>;

use constant::more
  <CLIENTCERTIFICATETYPE_{RSA_SIGN=1,DSS_SIGN,RSA_FIXED_DH,DSS_FIXED_DH,RSA_EPHEMERAL_DH,DSS_EPHEMERAL_DH,FORTEZZA_DMS}>;

  #opaque DistinguishedName<1..2^16-1>;
use constant::more 
  <CERTIFICATEREQUEST_{CERTIFICATE_TYPES=0,CERTIFICATE_AUTHORITIES}>;

  #struct { } ServerHelloDone;
















# Client Authentication and Key Exchange Messages

use constant::more 
  <CLIENTKEYEXCHANGE_{EXCHANGE_KEYS=0}>;
use constant::more
  <PREMASTERSECRET_{CLIENT_VERSION=0,RANDOM}>;


  #struct {
     #public-key-encrypted PreMasterSecret pre_master_secret;
       #} EncryptedPreMasterSecret;

use constant::more
  <PUBLICVALUEENCODING_{IMPLICIT=0,EXPLICIT}>;


   ###################################################
   # struct {                                        #
   #     select (PublicValueEncoding) {              #
   #         case implicit: struct {};               #
   #         case explicit: opaque DH_Yc<1..2^16-1>; #
   #     } dh_public;                                #
   # } ClientDiffieHellmanPublic;                    #
   ###################################################

#####################################################################
#    struct {                                                       #
#         digitally-signed struct {                                 #
#             opaque handshake_messages[handshake_messages_length]; #
#         }                                                         #
#    } CertificateVerify;                                           #
#                                                                   #
# A.4.4.  Handshake Finalization Message                            #
#                                                                   #
#    struct {                                                       #
#        opaque verify_data[verify_data_length];                    #
#    } Finished;                                                    #
#####################################################################

# record

use constant::more ENCODE_PLAIN=>"nnnn/A";
use constant::more DECODE_PLAIN=>ENCODE_PLAIN;

my @version=(3,3);
my $data="";
sub encode {
  #CTX, data
  # Copy data into plain text structure ->
  # send data to compression stage ->
  # protection stage
  # 
}
#pack ENCODE_PLAIN, CONTENTTYPE_APPLICATION_DATA, @version, $data;
#my @out=unpack DECODE_PLAIN, "text";

1;

