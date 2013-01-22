## no critic (RCS,VERSION,encapsulation,Module)

use strict;
use warnings;
use Test::More;

# Public methods tested here (bytes(), etc.).
# Much of this has already been put through the paces via the "functions" layer
# tests in 20-functions.t, so we're only going for coverage here.

my $random = Bytes::Random::Secure->new( Bits => 64, NonBlocking=>1, Weak=>1 );

is( length $random->bytes(10), 10, 'bytes(10) returns ten bytes.' );


done_testing();
