## no critic (RCS,VERSION,encapsulation,Module)

use strict;
use warnings;

use Test::More;


use Bytes::Random::Secure;

my $random = Bytes::Random::Secure->new(
  Weak => 1,
  NonBlocking => 1,
  Source => sub { 1 },
);

#  Accessors are auto-generated.
#  get_Weak    get_NonBlocking     get_Only    get_Never   get_Source
#  get_PRNG    get_Bits

is( $random->get_Weak, 1, 'get_Weak() accessor ok.' );
is( $random->get_NonBlocking, 1, 'get_NonBlocking() accessor ok.' );
is( ref( $random->get_Source ), 'CODE', 'get_Source() accessor ok.' );
is( $random->get_Bits, 512, 'get_Bits() accessor ok.' );
is( $random->get_PRNG, 'ISAAC', 'get_PRNG() accessor ok.' );
is( $random->get_Only, undef, 'get_Only() accessor ok.' );
is( $random->get_Never, undef, 'get_Never() accessor ok.' );

# Auto-generated accessors tested here.
ok(1);
done_testing();
