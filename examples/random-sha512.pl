
use strict;
use warnings;
use Bytes::Random::Secure qw( random_bytes );
use Digest::SHA qw( sha512_base64 );

my $quantity = 128;

my $bytes    = random_bytes($quantity);

my $digest   = sha512_base64( $bytes );

print "$digest\n";

