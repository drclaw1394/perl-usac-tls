use v5.36;
package uSAC::TLS::Cipher;

# Cipher suite id codes
use constant::more
  TLS_NULL_WITH_NULL_NULL              => 0x00,
  TLS_RSA_WITH_NULL_MD5                => 0x01,
  TLS_RSA_WITH_NULL_SHA                => 0x02,
  TLS_RSA_WITH_NULL_SHA256             => 0x3B,
  TLS_RSA_WITH_RC4_128_MD5             => 0x04,
  TLS_RSA_WITH_RC4_128_SHA             => 0x05,
  TLS_RSA_WITH_3DES_EDE_CBC_SHA        => 0x0A,
  TLS_RSA_WITH_AES_128_CBC_SHA         => 0x2F,
  TLS_RSA_WITH_AES_256_CBC_SHA         => 0x35,
  TLS_RSA_WITH_AES_128_CBC_SHA256      => 0x3C,
  TLS_RSA_WITH_AES_256_CBC_SHA256      => 0x3D,

  TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA     => 0x0D,
  TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA     => 0x10,
  TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA    => 0x13,
  TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA    => 0x16,
  TLS_DH_DSS_WITH_AES_128_CBC_SHA      => 0x30,
  TLS_DH_RSA_WITH_AES_128_CBC_SHA      => 0x31,
  TLS_DHE_DSS_WITH_AES_128_CBC_SHA     => 0x32,
  TLS_DHE_RSA_WITH_AES_128_CBC_SHA     => 0x33,
  TLS_DH_DSS_WITH_AES_256_CBC_SHA      => 0x36,
  TLS_DH_RSA_WITH_AES_256_CBC_SHA      => 0x37,
  TLS_DHE_DSS_WITH_AES_256_CBC_SHA     => 0x38,
  TLS_DHE_RSA_WITH_AES_256_CBC_SHA     => 0x39,
  TLS_DH_DSS_WITH_AES_128_CBC_SHA256   => 0x3E,
  TLS_DH_RSA_WITH_AES_128_CBC_SHA256   => 0x3F,
  TLS_DHE_DSS_WITH_AES_128_CBC_SHA256  => 0x40,
  TLS_DHE_RSA_WITH_AES_128_CBC_SHA256  => 0x67,
  TLS_DH_DSS_WITH_AES_256_CBC_SHA256   => 0x68,
  TLS_DH_RSA_WITH_AES_256_CBC_SHA256   => 0x69,
  TLS_DHE_DSS_WITH_AES_256_CBC_SHA256  => 0x6A,
  TLS_DHE_RSA_WITH_AES_256_CBC_SHA256  => 0x6B,

  TLS_DH_anon_WITH_RC4_128_MD5         => 0x18,
  TLS_DH_anon_WITH_3DES_EDE_CBC_SHA    => 0x1B,
  TLS_DH_anon_WITH_AES_128_CBC_SHA     => 0x34,
  TLS_DH_anon_WITH_AES_256_CBC_SHA     => 0x3A,
  TLS_DH_anon_WITH_AES_128_CBC_SHA256  => 0x6C,
  TLS_DH_anon_WITH_AES_256_CBC_SHA256  => 0x6D,
;


use constant::more NULL=>0;
use constant::more qw<RC4_128=1 _3DES_EDE_CBC AES_128_CBC AES_256_CBC>;


#                        Key      IV   Block
#Cipher        Type    Material  Size  Size
#------------  ------  --------  ----  -----
our %Cipher=(
  NULL()          =>["Stream",      0,    0,  "N/A"],
  RC4_128()       =>["Stream",     16,    0,  "N/A"],
  _3DES_EDE_CBC() =>["Block",      24,    8,      8],
  AES_128_CBC()   =>["Block",     16,     16,     16],
  AES_256_CBC()   =>["Block",      32,    16,     16]
);


use constant::more qw<MD5=0 SHA SHA256>;

#MAC       Algorithm    mac_length  mac_key_length
#--------  -----------  ----------  --------------
our %MAC=(
  NULL()      =>["N/A",             0,             0],
  MD5()       =>["HMAC-MD5",        16,            16],
  SHA()       =>["HMAC-SHA1",       20,            20],
  SHA256()    =>["HMAC-SHA256",     32,            32]
);

#Cipher Suite Definitions

#Cipher Suite                              Key        Cipher         Mac
#                                          Exchange
our %Definitions =(
  TLS_NULL_WITH_NULL_NULL()                 =>[qw<NULL         NULL         NULL>],
  TLS_RSA_WITH_NULL_MD5()                   =>[qw<RSA          NULL         MD5>],
  TLS_RSA_WITH_NULL_SHA()                   =>[qw<RSA          NULL         SHA>],
  TLS_RSA_WITH_NULL_SHA256()                =>[qw<RSA          NULL         SHA256>],
  TLS_RSA_WITH_RC4_128_MD5()                =>[qw<RSA          RC4_128      MD5>],
  TLS_RSA_WITH_RC4_128_SHA()                =>[qw<RSA          RC4_128      SHA>],
  TLS_RSA_WITH_3DES_EDE_CBC_SHA()           =>[qw<RSA          3DES_EDE_CBC SHA>],
  TLS_RSA_WITH_AES_128_CBC_SHA()            =>[qw<RSA          AES_128_CBC  SHA>],
  TLS_RSA_WITH_AES_256_CBC_SHA()            =>[qw<RSA          AES_256_CBC  SHA>],
  TLS_RSA_WITH_AES_128_CBC_SHA256()         =>[qw<RSA          AES_128_CBC  SHA256>],
  TLS_RSA_WITH_AES_256_CBC_SHA256()         =>[qw<RSA          AES_256_CBC  SHA256>],
  TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA()        =>[qw<DH_DSS       3DES_EDE_CBC SHA>],
  TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA()        =>[qw<DH_RSA       3DES_EDE_CBC SHA>],
  TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA()       =>[qw<DHE_DSS      3DES_EDE_CBC SHA>],
  TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA()       =>[qw<DHE_RSA      3DES_EDE_CBC SHA>],
  TLS_DH_anon_WITH_RC4_128_MD5()            =>[qw<DH_anon      RC4_128      MD5>],
  TLS_DH_anon_WITH_3DES_EDE_CBC_SHA()       =>[qw<DH_anon      3DES_EDE_CBC SHA>],
  TLS_DH_DSS_WITH_AES_128_CBC_SHA()         =>[qw<DH_DSS       AES_128_CBC  SHA>],
  TLS_DH_RSA_WITH_AES_128_CBC_SHA()         =>[qw<DH_RSA       AES_128_CBC  SHA>],
  TLS_DHE_DSS_WITH_AES_128_CBC_SHA()        =>[qw<DHE_DSS      AES_128_CBC  SHA>],
  TLS_DHE_RSA_WITH_AES_128_CBC_SHA()        =>[qw<DHE_RSA      AES_128_CBC  SHA>],
  TLS_DH_anon_WITH_AES_128_CBC_SHA()        =>[qw<DH_anon      AES_128_CBC  SHA>],
  TLS_DH_DSS_WITH_AES_256_CBC_SHA()         =>[qw<DH_DSS       AES_256_CBC  SHA>],
  TLS_DH_RSA_WITH_AES_256_CBC_SHA()         =>[qw<DH_RSA       AES_256_CBC  SHA>],
  TLS_DHE_DSS_WITH_AES_256_CBC_SHA()        =>[qw<DHE_DSS      AES_256_CBC  SHA>],
  TLS_DHE_RSA_WITH_AES_256_CBC_SHA()        =>[qw<DHE_RSA      AES_256_CBC  SHA>],
  TLS_DH_anon_WITH_AES_256_CBC_SHA()        =>[qw<DH_anon      AES_256_CBC  SHA>],
  TLS_DH_DSS_WITH_AES_128_CBC_SHA256()      =>[qw<DH_DSS       AES_128_CBC  SHA256>],
  TLS_DH_RSA_WITH_AES_128_CBC_SHA256()      =>[qw<DH_RSA       AES_128_CBC  SHA256>],
  TLS_DHE_DSS_WITH_AES_128_CBC_SHA256()     =>[qw<DHE_DSS      AES_128_CBC  SHA256>],
  TLS_DHE_RSA_WITH_AES_128_CBC_SHA256()     =>[qw<DHE_RSA      AES_128_CBC  SHA256>],
  TLS_DH_anon_WITH_AES_128_CBC_SHA256()     =>[qw<DH_anon      AES_128_CBC  SHA256>],
  TLS_DH_DSS_WITH_AES_256_CBC_SHA256()      =>[qw<DH_DSS       AES_256_CBC  SHA256>],
  TLS_DH_RSA_WITH_AES_256_CBC_SHA256()      =>[qw<DH_RSA       AES_256_CBC  SHA256>],
  TLS_DHE_DSS_WITH_AES_256_CBC_SHA256()     =>[qw<DHE_DSS      AES_256_CBC  SHA256>],
  TLS_DHE_RSA_WITH_AES_256_CBC_SHA256()     =>[qw<DHE_RSA      AES_256_CBC  SHA256>],
  TLS_DH_anon_WITH_AES_256_CBC_SHA256()     =>[qw<DH_anon      AES_256_CBC  SHA256>],
);
1;
