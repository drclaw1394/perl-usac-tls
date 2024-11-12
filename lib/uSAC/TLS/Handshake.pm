package TLS::Handshake::Type;
use constant::more 
  HELLO_REQUEST         =>  0,
  CLIENT_HELLO          =>  1,
  SERVER_HELLO          =>  2,
  CERTIFICATE           =>  11,
  SERVER_KEY_EXCHANGE   =>  12,
  CERTIFICATE_REQUEST   =>  13,
  SERVER_HELLO_DONE     =>  14,
  CERTIFICATE_VERIFY    =>  15,
  CLIENT_KEY_EXCHANGE   =>  16,
  FINISHED              =>  20
;


package TLS::Handshake;
use constant::more qw<UNDEF=0 MSG_TYPE LENGTH BODY>;

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


package TLS::Handshake::Type::HelloRequest;

package TLS::Handshake::Random;
use constant::more qw<UNDEF=0 GMT_UNIX_TIME RANDOM_BYTES>;

package TLS::Handshake::Type::ClientHello;
use constant::more qw<
                  UNDEF=0
                  CLIENT_VERSION
                  RANDOM
                  SESSION_ID
                  CIPHER_SUITES
                  COMPRESSION_METHODS
                  EXTENSIONS
                  >;
sub struct {
  my @struct;
}

package TLS::Handshake::Type::ServerHello;
use constant::more qw<
                  UNDEF=0
                  SERVER_VERSION
                  RANDOM
                  SESSION_ID
                  CIPHER_SUITES
                  COMPRESSION_METHODS
                  EXTENSIONS
                  >;
sub struct {
  my @struct;
}

package TLS::Handshake::Type::HelloExtension;
use constant::more qw< 
                  UNDEF=0
                  EXTENTION_TYPE
                  EXTENSION_DATA
                  >;
1;
