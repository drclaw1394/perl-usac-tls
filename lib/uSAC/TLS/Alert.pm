# Define these enumerations in seperate namespace

package TLS::Alert::Level;
use constant::more qw<WARNING=1 FATAL>;

package TLS::Alert::Description;
use constant::more
  CLOSE_NOTIFY            =>  0,
  UNEXPECTED_MESSAGE      =>  10,
  BAD_RECORD_MAC          =>  20,
  DECRYPTION_FAILED       =>  21,
  RECORD_OVERFLOW         =>  22,
  DECOMPRESSION_FAILURE   =>  30,
  HANDSHAKE_FAILURE       =>  40,

  NO_CERTIFICATE          =>  41,
  BAD_CERTIFICATE         =>  42,
  UNSUPPORTED_CERTIFICATE =>  43,
  CERTIFICATE_REVOKED     =>  44,
  CERTIFICATE_EXPIRED     =>  45,
  CERTIFICATE_UNKOWN      =>  46,

  ILLEGAL_PARAMETER       =>  47,
  UKNOWN_CA               =>  48,
  ACCESS_DENIED           =>  49,
  DECODE_ERROR            =>  50,
  DECRYPT_ERROR           =>  51,
  EXPORT_RESTRICTION      =>  60,
  PROTOCOAL_VERSION       =>  70,

  INSUFFICIENT_SECURITY   =>  71,
  INTERNAL_ERROR          =>  80,
  USER_CANCELED           =>  90,
  NO_RENEGOTIATION        =>  100,
  UNSUPPORTED_EXTENSION   =>  110
;  


package TLS::Alert;
# Alert struct. First element (index 0) is a dummy for negative lookup
use constant::more qw<UNDEF=0 LEVEL DESCRIPTION>;

no warnings "experimental";

sub struct{
  # take key value pairs and create a structure /array
  my @struct=(1, undef, undef);
  if($struct[$_[0]]){
    # String name
    die "String names are not supported in ". __PACKAGE__."::struct";
    ########################
    # for my ($k, $v)(@_){ #
    #   $struct[$k]=$v;    #
    # }                    #
    ########################


  }
  else{
    # Integer constants
    for my ($k, $v)(@_){
      $struct[$k]=$v;
    }
  }
}

1;
