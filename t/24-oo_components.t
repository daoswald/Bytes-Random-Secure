## no critic (RCS,VERSION,encapsulation,Module)

use strict;
use warnings;
use Test::More;

use 5.006000;

use Bytes::Random::Secure;

can_ok( 'Bytes::Random::Secure', 'new' );

done_testing();
