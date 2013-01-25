use strict;
use warnings;

use Bytes::Random::Secure qw( random_string_from );

my $quantity = 64;

my $bag = 'abcde';

# Generate a random string of 64 characters, each selected from
# the "bag" of 'a' through 'e', inclusive.

my $string = random_string_from( $bag, $quantity );

print $string, "\n";
