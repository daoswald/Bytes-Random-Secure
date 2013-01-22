## no critic (RCS,VERSION,encapsulation,Module)

use strict;
use warnings;
use MIME::Base64;
use MIME::QuotedPrint;
use Data::Dumper;

use Test::More;

use Bytes::Random::Secure;

# Public methods tested here (bytes(), etc.).
# Much of this has already been put through the paces via the "functions" layer
# tests in 20-functions.t, so we're only going for coverage here.

my $random = Bytes::Random::Secure->new( Bits => 64, NonBlocking=>1, Weak=>1 );

is( length $random->bytes(10), 10, 'bytes(10) returns ten bytes.' );

is( length decode_base64($random->bytes_base64(111)), 111,
    'decode_base64() can be decoded, and returns correct number of bytes.');
like( $random->bytes_base64(111,"\n\n"), qr/\n\n/,
      'bytes_base64(111,"\n\n"): EOL handled properly.' );

is( length decode_qp( $random->bytes_qp(200) ), 200,
    'bytes_qp(): Decodable Quoted Printable returned.'
    . ' Decodes to proper length.' );

like( $random->bytes_qp(200, "\n\n"), qr/\n\n/,
      'bytes_qp(): EOL handled properly.' );

like( $random->bytes_hex(16), qr/^[1234567890abcdef]{32}$/,
      'bytes_hex() returns only hex digits, of correct length.' );

like( $random->string_from('abc', 100 ), qr/^[abc]{100}$/,
      'string_from() returns proper length and proper string.' );

done_testing();
