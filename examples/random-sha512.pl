
use strict;
use warnings;
use Bytes::Random::Secure qw( random_bytes );
use Digest::SHA qw( sha512_base64 );

my $quantity = 128;

# Normally it's unnecessary to configure the seeding.  But we're doing it in
# this example code just to demonstrate how it's done.

# Seed configuration must be done before the first call to "random_bytes", or
# any of its cousins.

Bytes::Random::Secure->config_seed( NonBlocking => 1 );

# In addition to the POD, also read the POD for Crypt::Random::Seed for info on
# what seed configuration options are available.



# Now we'll get a string of 128 random bytes.
my $bytes    = random_bytes($quantity);

# And just for fun, generate a base64 encoding of a sha2-512 digest of the
# random byte string.
my $digest   = sha512_base64( $bytes );

print "$digest\n";

