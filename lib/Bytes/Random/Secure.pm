package Bytes::Random::Secure;

use strict;
use warnings;
use bytes;

use MIME::Base64 'encode_base64';
use MIME::QuotedPrint 'encode_qp';
use Math::Random::Secure 'irand';

use Exporter;
our @ISA = qw( Exporter );

our @EXPORT_OK = qw( random_bytes     random_bytes_base64
                     random_bytes_hex random_bytes_qp     );

our @EXPORT    = qw( random_bytes ); ## no critic(export)

our $VERSION = '0.01';

sub random_bytes {
  my $bytes = shift;
  return join '', map{ chr irand(256) } 1 .. $bytes;
}


sub random_bytes_base64 {
  my ( $bytes, $eof ) = @_;
  return encode_base64 random_bytes( $bytes ), $eof // qq{\n};
}


sub random_bytes_hex {
  my $bytes = shift;
  return unpack 'H*', random_bytes( $bytes );
}


sub random_bytes_qp {
  my ( $bytes, $eof ) = @_;
  return encode_qp random_bytes( $bytes ), $eof // qq{\n}, 1;
}


1;


=pod

=head1 NAME

Bytes::Random::Secure - Perl extension to generate cryptographically-secure
random bytes.

=head1 SYNOPSIS

    use Bytes::Random::Secure qw(
        random_bytes random_bytes_base64 random_bytes_hex
    );

    my $bytes = random_bytes(32); # A string of 32 random bytes.
    
    my $bytes_as_base64 = random_bytes_base64(57);

    my $bytes_as_hex = random_bytes_hex(8);

=head1 DESCRIPTION

L<Bytes::Random::Secure> provides three functions that can be used anytime you
need a string (or MIME Base64 representation, or hex-digits representation) of
a specific number of random bytes.

This module can be a drop-in replacement for L<Bytes::Random>, with the primary
enhancement of using a much higher quality random number generator to create
the random data.  The random number generator comes from
L<Math::Random::Secure>, and is suitable for cryptographic purposes, including
the generation of random salt or random secrets.

In addition to providing C<random_bytes()>, this module also provides two
functions not found in L<Bytes::Random>: C<random_bytes_base64()>, and
C<random_bytes_hex>.

=head1 RATIONALE

It's impossible to predict what uses others might find for any given module, but
this author has the following use cases:

=over 4

=item * Generating random salt to be hashed along with passphrases (and stored
alongside them) to prevent rainbow table attacks.

=item * Generating a secret that can be hashed along with a cookie's session
content to prevent cookie forgeries.

=item * Generating raw cryptographic-quality pseudo-random data sets for testing
or sampling.

=back

=head1 EXPORTS

By default C<random_bytes> is the only function exported.  Optionally
C<random_bytes_base64> and C<random_bytes_hex> may be exported.

=head1 FUNCTIONS

=head2 random_bytes( $number_of_bytes )

Returns a string containing as many random bytes as requested.

=head2 random_bytes_base64

    my $random_bytes_b64 = random_bytes_base64( $num_bytes );
    my $random_bytes_b64_formatted = random_bytes_base64( $num_bytes, $eol );

Returns a MIME Base64 encoding of the string of $number_of_bytes random bytes.
Note, it should be obvious, but is worth mentioning that a base64 encoding of
base256 data requires more digits to represent the bytes requested.  The actual
number of digits required, including padding is C<4(n/3)>.
Furthermore, the Base64 standard is to add padding to the end of any string for
which C<length % 57> is a non-zero value.

If an C<$eol> is specified, the character(s) specified will be used as line
delimiters after every 76th character.  The default is C<qq{\n}>.  If you wish
to eliminate line-break insertions, specify an empty string: C<q{}>.

=head2 random_bytes_hex( $number_of_bytes )

Returns a string of hex digits representing the string of $number_of_bytes
random bytes.

Again, it should be obvious, but is worth mentioning that a hex (base16)
representation of base256 data requires two digits for every byte requested.
So C<length( random_bytes_hex( 16 ) )> will return 32, as it takes 32 hex digits
to represent 16 bytes.  Simple stuff, but better to mention it now than forget
and set a database field that's too narrow.

=head2 random_bytes_qp

    my $random_bytes_qp = random_bytes_qp( $num_bytes );
    my $random_bytes_qp_formatted = random_bytes_qp( $num_bytes, $eol );

Produces a string of C<$num_bytes> random bytes, using MIME Quoted Printable
encoding (as produced by L<MIME::QuotedPrint>'s C<encode_qp> function.  The
default configuration uses C<\n> as a line break after every 76 characters, and
the "binmode" setting is used to guarantee a lossless round trip.  If no line
break is wanted, pass an empty string as C<$eol>.

=head1 AUTHOR

David Oswald C<< <davido [at] cpan (dot) org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-bytes-random-secure at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Bytes-Random-Secure>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Bytes::Random::Secure


You can also look for information at:

=over 4

=item * Github Repo: L<https://github.com/daoswald/Bytes-Random-Secure>

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Bytes-Random-Secure>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Bytes-Random-Secure>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Bytes-Random-Secure>

=item * Search CPAN

L<http://search.cpan.org/dist/Bytes-Random-Secure/>

=back


=head1 ACKNOWLEDGEMENTS

L<Mojolicious> for providing the motivation from its "App secret".
L<Bytes::Random> for providing a starting-point for this module.
L<Math::Random::Secure> for providing an excellent random number tool.

=head1 LICENSE AND COPYRIGHT

Copyright 2012 David Oswald.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut
