package Bytes::Random::Secure;

use strict;
use warnings;
use bytes;

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
our @EXPORT_OK = qw( random_bytes     random_bytes_base64
  random_bytes_hex random_bytes_qp     );
our @EXPORT = qw( random_bytes );    ## no critic(export)

our $VERSION = '0.06';



{
    my $RNG = Math::Random::ISAAC->new( _seed() );

    sub random_bytes {
        my $bytes = shift;

        # 2^32 *is* evenly divisible by 256, so no modulo-bias concern here.
        return join '', map { chr $RNG->irand % 256 } 1 .. $bytes;
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

L<Bytes::Random::Secure> provides four functions that can be used anytime you
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

In addition to providing C<random_bytes()>, this module also provides three
functions not found in L<Bytes::Random>: C<random_bytes_base64()>, 
C<random_bytes_hex>, and C<random_bytes_qp>.

=head1 RATIONALE

There are many uses for cryptographic quality randomness.  This module aims to
provide a generalized tool that can fit into many applications.  You're free
to come up with your own use-cases, but there are several obvious ones:

=over 4

=item * Generating per-account random salt to be hashed along with passphrases 
(and stored alongside them) to prevent rainbow table attacks.

=item * Generating a secret that can be hashed along with a cookie's session
content to prevent cookie forgeries.

=item * Generating raw cryptographic-quality pseudo-random data sets for testing
or sampling.

Why this module?  This module uses several high quality CPAN tools to first
generate a strong random seed, and then to instantiate a high quality random
number factory based on the strong seed.  The code in this module really just
glues together the building blocks.  I'm sure that with a little research
just about anyone could do the same.  But chances are you'll end up using the
same dependencies I did, or others of similar quality (and weight).  It's taken
a good deal of research to come up with what I feel is the strongest possible
tool-chain.  Hopefully others can benefit from this work.

=back

=head1 EXPORTS

By default C<random_bytes> is the only function exported.  Optionally
C<random_bytes_base64>, C<random_bytes_hex>, and C<random_bytes_qp>
may be exported.

=head1 FUNCTIONS

=head2 random_bytes( $number_of_bytes )

Returns a string containing as many random bytes as requested.

=head2 random_bytes_base64

    my $random_bytes_b64           = random_bytes_base64( $num_bytes );
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
potential for diminishing the quality of the random byte stream by picking your 
own (possibly less secure) seed or seed-generator.  Finding a reliable seed
source is not an easy task.  If you would prefer to supply your own, skip 
this module and go directly to  Math::Random::ISAAC (or get in touch with me 
and we can discuss whether your method might be a better choice globally). ;)

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
wrong).  A terciary goal (and one that will never be permitted to compromise the
primary goal) is to minimize the dependencies required to achieve the primary
and secondary goals.

To re-iterate: We want secure random bytes, we want ease of use, and if we can
get both while minimizing the dependencies, that would be nice, but is not a
requirement.

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
