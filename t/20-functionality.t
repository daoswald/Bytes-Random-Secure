## no critic (RCS,VERSION,encapsulation,Module)

use strict;
use warnings;
use Test::More;
use Scalar::Util qw( looks_like_number );

use 5.006000;

BEGIN {
  use_ok( 'Bytes::Random::Secure',
          qw/ random_bytes random_bytes_hex random_bytes_base64 random_bytes_qp/
  );
}

can_ok( 'Bytes::Random::Secure',
  qw/ random_bytes random_bytes_hex random_bytes_base64 random_bytes_qp   _seed
/ );


my @seeds = Bytes::Random::Secure::_seed;
is( scalar @seeds, 16, 'Received 16 longs from _seed' );
foreach my $seed ( @seeds ) {
  ok( looks_like_number( $seed ), 'All seeds should "look like numbers"' );
  is( $seed, int( $seed ), 'All seeds are integers.' );
  ok( $seed =~ m/^[0-9]+$/, 'All seeds contain only numeric digits.' );
  is( $seed >= 0 && $seed < 2**32, 1, "Seed $seed is in range." );
}


foreach my $want ( qw/ -1 0 1 2 3 4 5 6 7 8 16 17 1024 10000 / ) {
  my $correct = $want >= 0 ? $want : 0;
  is( length random_bytes( $want ), $correct,
      "random_bytes($want) returns $correct bytes." );
}

my @counts;
my $iterations = 500;  
for( 1 .. $iterations ) {
    my( $count, $low, $high, $range_err ) = ( 0, 0, 0, 0 );
    while( $low < 10 || $high < 10 ) {
      my $byte = ord random_bytes( 1 );
      $byte == 0 && $low++;
      $byte == 255 && $high++;
      $byte < 0 || $byte > 255 && $range_err++;
      $count++;
    }
    ok( $low,  "random_bytes produces $low bytes of '0'."   );
    ok( $high, "random_bytes produces $high bytes of '255'." );
    ok( !$range_err, "random_bytes produced $range_err values out of 0 .. 255.");
    push @counts, $count;
}

my $total_count;
$total_count += $_ for @counts;
my $avg_count = $total_count / scalar @counts;

# Allow for a 10% deviation from average after 500 passes.
# Testing of 500 test-suite runs shows that the deviation should never be more
# than about 4%, but we don't need tests failing unless things are really wonky.
ok( ( $avg_count > 2711 && $avg_count < 3313 ),
    "$avg_count average iterations to reach five '0' bytes and five '255' " .
    'bytes. Within reasonable range (expected approx 3012)'
);
diag "Average iterations: $avg_count (expect approx 3012).";

foreach my $want ( qw/ -1 0 1 2 3 4 5 6 7 8 16 17 1024 10000 / ) {
  my $result  = random_bytes_hex( $want );
  my $correct = $want >= 0 ? $want * 2 : 0;
  is( length random_bytes_hex( $want ), $correct,
      "random_bytes_hex($want) returned $correct hex digits." );
};

ok( random_bytes_hex(128) =~ /^[[:xdigit:]]+$/,
    'random_bytes_hex only produces hex digits.' );

is( length random_bytes_base64(-1), 0,
    'random_bytes_base64(-1) returns an empty string.' );

is( length random_bytes_base64(0),  0,
    'random_bytes_base64(0) returns an empty string.'  );

ok( length random_bytes_base64(1) > 0,
    'random_bytes_base64(1) returns a string of some non-zero length.' );

ok( length random_bytes_base64(5) < length random_bytes_base64( 16 ),
    'random_bytes_base64(5) returns a shorter string than ' .
    'random_bytes_base64(16)'                                );

ok( random_bytes_base64(128) =~ /^[^\n]{76}\n/,
    'random_bytes_base64 uses "\n" appropriately' );
ok( random_bytes_base64(128, q{}) =~ /^[^\n]+$/,
    'random_bytes_base64 passes EOL delimiter correctly.' );

is( length random_bytes_qp(-1), 0,
    'random_bytes_qp(-1) returns an empty string.' );

is( length random_bytes_qp(0),  0,
    'random_bytes_qp(0) returns an empty string.'  );

ok( length random_bytes_qp(1) > 0,
    'random_bytes_qp(1) returns a string of some non-zero length.' );

ok( length random_bytes_qp(5) < length random_bytes_qp( 16 ),
    'random_bytes_qp(5) returns a shorter string than ' .
    'random_bytes_qp(16)'                                );
ok( random_bytes_qp(100) =~ m/^[^\n]{1,76}\n/,
    'random_bytes_qp uses "\n" appropriately' );
ok( random_bytes_qp(128, q{}) =~ /^[^\n]+$/,
    'random_bytes_qp passes EOL delimiter correctly.' );

is( length random_bytes(), 0,
    'random_bytes(): No param defaults to zero bytes.' );

done_testing();
