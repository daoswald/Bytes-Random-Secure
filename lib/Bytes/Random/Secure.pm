package Bytes::Random::Secure;

use strict;
use warnings;
use Carp;

use MIME::Base64 'encode_base64';
use MIME::QuotedPrint 'encode_qp';
use Math::Random::ISAAC;
use Crypt::Random::Source::Factory;

use constant ON_WINDOWS => $^O =~ /Win32/i ? 1 : 0;    ## no critic (constant)
use constant SEED_SIZE => 64;                          ## no critic (constant)

# If we're in a Windows environment we need extra help in getting a
# strong source.  This doesn't come cheap, so load only if we really need it.
use if ON_WINDOWS, 'Crypt::Random::Source::Strong::Win32';

use Exporter;
our @ISA       = qw( Exporter );

our @EXPORT_OK = qw(
  random_bytes
  random_bytes_base64
  random_bytes_hex
  random_bytes_qp
  random_string_from
);

our @EXPORT = qw( random_bytes );    ## no critic(export)

our $VERSION = '0.12';

# Instantiate our random number generator inside of a lexical closure, limiting
# the scope of the object, as well as its visibility to the outside.
{
    my $RNG = Math::Random::ISAAC->new( _seed() );

    # Original random_bytes() (superceded by Dana's version, below).
    #    sub random_bytes {
    #        my $bytes = shift;
    #        $bytes = defined $bytes ? $bytes : 0; # Default to zero bytes.
    #        # 2^32 *is* evenly divisible by 256, so no modulo-bias concern here.
    #        return join '', map { chr $RNG->irand % 256 } 1 .. $bytes;
    #    }

    # New and improved version from Dana Jacobsen.
    # Faster, and makes better use of the full width of M::R::ISAAC's
    # 32 bit irand().
    sub random_bytes {
        my $bytes = shift;
        $bytes = defined $bytes ? $bytes : 0; # Default to zero bytes.
        my $str = '';

        while ($bytes >= 4) {                 # Utilize irand()'s 32 bits.
            $str .= pack("L", $RNG->irand);
            $bytes -= 4;
        }

        if ($bytes > 0) {
            my $rval = $RNG->irand;

            $str .= pack("S", ($rval >> 8) & 0xFFFF) if $bytes >= 2; # 16 bits.
            $str .= pack("C", $rval & 0xFF) if $bytes % 2;           # 8 bits.

        }
        return $str;
    }

    # Generate a list of $count random numbers between 0 and $range.
    sub _ranged_randoms {
        my( $range, $count ) = @_;
        $count = defined $count ? $count : 0;
        
        my $divisor = _closest_divisor( $range );
        my @randoms;

        for my $n ( 1 .. $count ) {
            my $random;

            do{
                $random = $RNG->irand % $divisor;
            } while ( $random >= $range );

            push @randoms, $random;
        }

        return @randoms;
    }

}


sub random_bytes_base64 {
    my ( $bytes, $eof ) = @_;
    return encode_base64 random_bytes($bytes), defined($eof) ? $eof : qq{\n};
}

sub random_bytes_hex {
    my $bytes = shift;
    return unpack 'H*', random_bytes($bytes);
}

sub random_bytes_qp {
    my ( $bytes, $eof ) = @_;
    return encode_qp random_bytes($bytes), defined($eof) ? $eof : qq{\n}, 1;
}
  

# Generate some high-quality long int seeds for Math::Random::ISAAC to use.

sub _seed {
    my $factory = Crypt::Random::Source::Factory->new();
    my $source;
    if (ON_WINDOWS) {
        $source = $factory->get_strong;
    }
    else {
        # Usually we get a strong source to begin with.
        $source = $factory->get;

        # Just in case, ensure that we haven't fallen back to Perl's 'rand'.
        if ( $source->isa('Crypt::Random::Source::Weak::rand') ) {

            # If we have, force a strong source.
            $source = $factory->get_strong;
        }
    }
    my $seed = $source->get(SEED_SIZE);

    # Change our byte stream into long ints to use as seeds.
    my @seed_ints = unpack( 'L*', $seed );
    return @seed_ints;
}


# random_string_from(), and its support functions (note, _ranged_randoms is
# handled inside of a lexical closure block, above.

sub random_string_from {
    my( $bag, $bytes ) = @_;
    $bag      = defined $bag ? $bag : '';
    $bytes    = defined $bytes ? $bytes : 0;
    my $range = length $bag;

    croak "Bag's size must be at least 1 character."
        if $range < 1;
    croak "Bag's size was $range, but cannot be longer than 2**32 characters."
        if $range > 2 ** 32;

    my $rand_bytes = '';
    for my $random ( _ranged_randoms($range, $bytes) ) {
        $rand_bytes .= substr( $bag, $random, 1 );
    }

    return $rand_bytes;
}


sub _closest_divisor {
  my $range = shift;
  $range = defined $range ? $range : 0;
  
  croak "$range must be positive." if $range < 0;
  croak "$range exceeds irand max limit of 2**32." if $range > 2 ** 32;

  my $n = 0;
  while( ( my $d = 2 ** $n ) && $n++ <= 32 ) {
    return $d if $d >= $range;
  }
  
  return;
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

    my $bytes = random_string_from( 'abcde', 10 ); # 10 random a,b,c,d, and e's.

    my $bytes_as_base64 = random_bytes_base64(57); # Base64 encoded rand bytes.

    my $bytes_as_hex = random_bytes_hex(8); # Eight random bytes as hex digits.

    my $bytes_as_quoted_printable = random_bytes_qp(100); # QP encoded bytes.

=head1 DESCRIPTION

L<Bytes::Random::Secure> provides five functions that can be used anytime you
need a string (or MIME Base64 representation, or hex-digits representation, or
Quoted Printable representation) of a specific number of random bytes.

This module can be a drop-in replacement for L<Bytes::Random>, with the primary
enhancement of using a much higher quality random number generator to create
the random data.  The random number generator comes from L<Math::Random::ISAAC>,
and is suitable for cryptographic purposes.  Actually, the harder problem to
solve is how to seed the generator.  This module uses L<Crypt::Random::Source>
to generate the initial seeds for Math::Random::ISAAC.  On Windows platforms
Crypt::Random::Source needs L<Crypt::Random::Source::Strong::Win32> to obtain
high quality seeds.

In addition to providing C<random_bytes()>, this module also provides four
functions not found in L<Bytes::Random>: C<random_string_from>,
C<random_bytes_base64()>, C<random_bytes_hex>, and C<random_bytes_qp>.

=head1 RATIONALE

There are many uses for cryptographic quality randomness.  This module aims to
provide a generalized tool that can fit into many applications.  You're free
to come up with your own use-cases, but there are several obvious ones:

=over 4

=item * Generating temporary passphrases (C<random_string_from()>).

=item * Generating per-account random salt to be hashed along with passphrases 
(and stored alongside them) to prevent rainbow table attacks.

=item * Generating a secret that can be hashed along with a cookie's session
content to prevent cookie forgeries.

=item * Generating raw cryptographic-quality pseudo-random data sets for testing
or sampling.

=back

Why this module?  This module uses several well-designed CPAN tools to first
generate strong random seeds, and then to instantiate a high quality random
number factory based on the strong seed.  The code in this module really just
glues together the building blocks.  However, it has taken a good deal of
research to come up with what I feel is a strong tool-chain that isn't going to
fall back to a weaker state on some systems.  Hopefully others can benefit from
this work.

=head1 EXPORTS

By default C<random_bytes> is the only function exported.  Optionally
C<random_string_from>, C<random_bytes_base64>, C<random_bytes_hex>,
and C<random_bytes_qp> may be exported.

=head1 FUNCTIONS

=head2 random_bytes

    my $random_bytes = random_bytes( 512 );
    
Returns a string containing as many random bytes as requested.  Obviously the
string isn't useful for display, as it can contain any byte value from 0 through
255.

=head2 random_string_from

    my $random_bytes = random_string_from( $bag, $length );
    my $random_bytes = random_string_from( 'abc', 50 );

C<$bag> is a string of characters from which C<random_string_from> may choose in
building a random string.  We call it a 'bag', because it's permissible to have
repeated chars in the bag (if not, we could call it a set).  Repeated digits
get more weight.  For example, C<random_string_from( 'aab', 1 )> would have a
66.67% chance of returning an 'a', and a 33.33% chance of returning a 'b'.  For
unweighted distribution, ensure there are no duplicates in C<$bag>.

This isn't a "draw and discard", or a permutation algorithm; each character
selected is independent of previous or subsequent selections; duplicate
selections are possible by design.

Return value is a string of size C<$length>, of characters chosen at random
from the 'bag' string.

It is perfectly legal to pass a Unicode string as the "bag", and in that case,
the yield will include Unicode characters selected from those passed in via the
bag string.

This function is useful for random string generation such as temporary
random passwords.

=head2 random_bytes_base64

    my $random_bytes_b64           = random_bytes_base64( $num_bytes );
    my $random_bytes_b64_formatted = random_bytes_base64( $num_bytes, $eol );

Returns a MIME Base64 encoding of a string of $number_of_bytes random bytes.
Note, it should be obvious, but is worth mentioning that a base64 encoding of
base256 data requires more digits to represent the bytes requested.  The actual
number of digits required, including padding is C<4(n/3)>.
Furthermore, the Base64 standard is to add padding to the end of any string for
which C<length % 57> is a non-zero value.

If an C<$eol> is specified, the character(s) specified will be used as line
delimiters after every 76th character.  The default is C<qq{\n}>.  If you wish
to eliminate line-break insertions, specify an empty string: C<q{}>.

=head2 random_bytes_hex

    my $random_bytes_as_hex = random_bytes_hex( $num_bytes );

Returns a string of hex digits representing the string of $number_of_bytes
random bytes.

Again, it should be obvious, but is worth mentioning that a hex (base16)
representation of base256 data requires two digits for every byte requested.
So C<length( random_bytes_hex( 16 ) )> will return 32, as it takes 32 hex digits
to represent 16 bytes.  Simple stuff, but better to mention it now than forget
and set a database field that's too narrow.

=head2 random_bytes_qp

    my $random_bytes_qp           = random_bytes_qp( $num_bytes );
    my $random_bytes_qp_formatted = random_bytes_qp( $num_bytes, $eol );

Produces a string of C<$num_bytes> random bytes, using MIME Quoted Printable
encoding (as produced by L<MIME::QuotedPrint>'s C<encode_qp> function.  The
default configuration uses C<\n> as a line break after every 76 characters, and
the "binmode" setting is used to guarantee a lossless round trip.  If no line
break is wanted, pass an empty string as C<$eol>.

=head1 CONFIGURATION

L<Bytes::Random::Secure>'s interface I<keeps it simple>.  There is generally 
nothing to configure.  This is by design, as it eliminates much of the 
potential for diminishing the quality of the random byte stream by through
misconfiguration.  Finding a reliable seed source is the hardest component.  If
you would prefer to supply your own, skip this module and go directly to
L<Math::Random::ISAAC> (or get in touch with me and we can discuss whether your
method might be a better choice for this module too). ;)

L<Crypt::Random::Source> provides our strong seed.  For better or worse, this
module uses L<Any::Moose>, which will default to the lighter-weight L<Mouse>
if it is available.  If Mouse is I<not> available, but L<Moose> I<is>, Moose
will be used.  This is a significantly heavier dependency.  Unless you are using
Moose in your application already, it's probably better to allow Mouse to be
used instead.  It is my recommendation that if you don't have Mouse installed,
you install it right now before you use this module to keep the bloat to a
minimum.

If you really have the need to feel useful, you may also install 
L<Math::Random::ISAAC::XS>. Bytes::Random::Secure's random number generator 
uses L<Math::Random::ISAAC>.  That module implements the ISAAC algorithm in pure
Perl.  However, if you install L<Math::Random::ISAAC::XS>, you get the same 
algorithm implemented in C/XS, which will provide better performance.  If you 
need to produce your random bytes more quickly, simply installing 
Math::Random::ISAAC::XS will result in it automatically being used, and a
pretty good performance improvement will coincide.

=head2 Win32 Special Dependency

In Win32 environments, Crypt::Random::Source uses a different technique to
generate high quality randomness.  In a Windows environment, this module has
the additional requirement of needing L<Crypt::Random::Source::Strong::Win32>.
Unfortunately, the current version of that module has a broken test, and in
some cases may fail its test suite.  It may be necessary to force the
installation of Crypt::Random::Source::Strong::Win32 before
Bytes::Random::Secure can be installed.

=head1 CAVEATS

It's easy to generate weak pseudo-random bytes.  It's also easy to think you're
generating strong pseudo-random bytes when really you're not.  And it's hard to
test for pseudo-random cryptographic acceptable quality.

It's also hard to generate strong (ie, secure) random bytes in a way that works
across a wide variety of platforms.  A primary goal for this module is to
provide cryptographically secure pseudo-random bytes.  A secondary goal is to
provide a simple user experience (thus reducing the propensity for getting it
wrong).  A terciary goal is to minimize the dependencies required to achieve the
primary and secondary goals, to the extent that is practical.

This module steals some code from L<Math::Random::Secure>.  That module is an
excellent resource, but implements a broader range of functionality than is
needed here.  So we just borrowed some code from it, and some of its
dependencies.

The primary source of random data in this module comes from the excellent
L<Math::Random::ISAAC>.  Unfortunately, to be useful and secure, even
Math::Random::ISAAC needs a cryptographically sound seed, which we derive from
L<Crypt::Random::Source>. Neither of those modules are light on dependencies.
The situation becomes even more difficult in a Win32 environment, where
Crypt::Random::Source needs the L<Crypt::Random::Source::Strong::Win32> plug-in,
which is even heavier in external dependencies.

The result is that the cost of getting cryptographically strong random bytes
on most platforms is a heavy dependency chain, and the cost of getting them
in a windows platform is about twice as heavy of a dependency chain as on most
other platforms.  If you're a Win32 user, and you cannot justify the dependency
chain, look elsewhere (and let me know what you find!).  On the other hand, if
you're looking for a secure random bytes solution that "just works" portably
(and are willing to live with the fact that the dependencies are heavier for
Windows users), you've come to the right place.

Patches that improve the Win32 situation without compromising the module's
primary and secondary goals, and without growing the dependencies for *nix users
are certainly welcome.

All users can minimize the number of modules loaded upon startup by making sure
that L<Mouse> is available on their system so that L<Any::Moose> can choose that
lighter-weight alternative to L<Moose>.  Of course if your application already
uses Moose, this becomes a non-issue.

A note regarding modulo bias:  Care is taken such that there is no modulo bias
in the randomness returned either by C<random_bytes> and its siblings, nor by
C<random_string_from>.  As a matter if fact, this is exactly I<why> the
C<random_string_from> function is useful.  However, the algorithm to eliminate
modulo bias can impact the performance of the C<random_string_from> function.
Any time the length of the bag string is significantly less than the nearest
greater or equal factor of 2**32, performance suffers.  Unfortunately there is
no known algorithm that improves upon this situation.  Fortunately, for sanely
sized strings, it's a minor issue.

=head1 AUTHOR

David Oswald C<< <davido [at] cpan (dot) org> >>

=head1 BUGS

Please report any bugs or feature requests to 
C<bug-bytes-random-secure at rt.cpan.org>, or through the web interface at 
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Bytes-Random-Secure>.  I will 
be notified, and then you'll automatically be notified of progress on your bug 
as I make changes.

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
