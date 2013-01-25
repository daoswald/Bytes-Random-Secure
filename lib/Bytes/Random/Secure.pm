## no critic (constant,unpack)
package Bytes::Random::Secure;

use strict;
use warnings;
use 5.006000;
use Carp;
use Scalar::Util qw( looks_like_number );

use Math::Random::ISAAC;
use Crypt::Random::Seed;

use MIME::Base64 'encode_base64';
use MIME::QuotedPrint 'encode_qp';

use Exporter;
our @ISA = qw( Exporter );

our @EXPORT_OK = qw(
  random_bytes          random_bytes_hex
  random_bytes_base64   random_bytes_qp
  random_string_from
);

our @EXPORT = qw( random_bytes );    ## no critic(export)

our $VERSION = '0.21';

# Seed size: 512 bits is sixteen 32-bit integers.
use constant SEED_SIZE => 256;       # In bits
use constant SEED_MIN  => 64;
use constant SEED_MAX  => 512;
use constant PRNG      => 'ISAAC';


use constant OO_ATTRIBS => {
    Weak        => 0,            # Boolean. (0)            Crypt::Random::Seed
    NonBlocking => 0,            # Boolean. (0)            Crypt::Random::Seed
    Only        => undef,        # Aref of strings.        Crypt::Random::Seed
    Never       => undef,        # Aref of strings.        Crypt::Random::Seed
    Source      => undef,        # Subref or ARef.         Crypt::Random::Seed
    PRNG        => PRNG,         # String. Alt RNG.        Internal (ISAAC)
    Bits        => SEED_SIZE,    # Seed 64 <= Bits <= 512. Internal (512)
};

# Function interface seed attributes (standard, and lite).
use constant FUNC_STD => {
    Weak        => 0,
    NonBlocking => 0,
    Bits        => SEED_SIZE,
};


use constant CRYPT_RANDOM_SEED_OPTS =>
  [ qw( Weak NonBlocking Only Never Source ) ];



################################################################################
# OO interface class/object methods:                                          ##
################################################################################

# Constructor
sub new {
    my ( $class, @config ) = @_;

    my $self = bless {}, $class;
    my $args_href = $self->_build_args(@config);
    $self->_build_attributes($args_href);

    return $self;
}


sub _build_args {
    my ( $self, @args ) = @_;

    @args = %{ $args[0] } if ref $args[0] eq 'HASH';

    croak "Illegal argument list; key => value pairs expected."
      if @args % 2;

    my %args = $self->_validate_args( OO_ATTRIBS, @args );

    if ( exists $args{Bits} ) {
        $args{Bits} = $self->_round_bits_to_ge_32( $args{Bits} );
        $args{Bits} = $self->_constrain_bits( $args{Bits}, SEED_MIN, SEED_MAX );
    }

    return \%args;
}


# _build_args() helpers:

# Verify drop illegal or 'undef' args.
sub _validate_args {
  my( $self, $legal_args_href, %args ) = @_;

  # Iterate through input args.
  while( my ( $arg_key, $arg_value ) = each %args ) {

    # Disqualify if not in white list.
    if( ! exists $legal_args_href->{$arg_key} ) {
      carp "Illegal argument ($arg_key) will be ignored.";
      delete $args{$arg_key};
      next;
    }

    # Disqualify if undef passed.
    if( ! defined $arg_value ) {
      carp "Undefined value specified for attribute ($arg_key). "
           . "Attribute will be ignored.";
      delete $args{$arg_key};
    }
  }
  return %args;
}


# Round bits parameter to nearest greater or equal 32-bit "long".
sub _round_bits_to_ge_32 {
  my( $self, $bits ) = @_;
  my $remainder = $bits % 32;
  return $bits if $remainder == 0;
  carp "Bits field must be a multiple of 32.  Rounding up.";
  return $bits + 32 - $remainder;
}


# Constrain bits argument to a reasonable range.
sub _constrain_bits {
  my( $self, $bits, $min, $max ) = @_;

  if( $bits < $min ) {
    carp "Bits field must be >= 64 (two longs). Rounding up.";
    $bits = $min;
  }
  elsif( $bits > $max ) {
    carp "Bits field must be <= 512 (sixteen longs). Rounding down.";
    $bits = $max;
  }
  # No need for an 'else' here.
  
  return $bits;
}


# Build attributes set by new().  Any not explicitly set will use defaults
# as described in the constant OO_ATTRIBS.
sub _build_attributes {
    my ( $self, $args ) = @_;

    while ( my ( $arg, $default ) = each %{ OO_ATTRIBS() } ) {
      $self->{$arg} = exists $args->{$arg} ? $args->{$arg} : $default;
    }

    $self->{_RNG} = undef;    # Lazy initialization.
    return $self;
}


# Get a seed and use it to instantiate a RNG.
# Note: Currently we specify only Math::Random::ISAAC.  However, the PRNG
# object attribute may be used in the future to specify alternate RNG's.
sub _instantiate_rng {
    my $self = shift;

    my ( %seed_opts ) = $self->_build_seed_options;
    my @seeds = $self->_generate_seed( %seed_opts );
    $self->{_RNG} = Math::Random::ISAAC->new(@seeds);

    return $self->{_RNG};
}


# Set up seed options for Crypt::Random::Seed
sub _build_seed_options {
  my( $self ) = @_;

  my %crs_opts;

  # CRYPT_RANDOM_SEED_OPTS enumerates the options that Crypt::Random::Seed
  # supports.  We have already built object attributes for those options.
  foreach my $opt ( @{ CRYPT_RANDOM_SEED_OPTS() } ) {
      $crs_opts{$opt} = $self->{$opt} if defined $self->{$opt};
  }

  return %crs_opts;
}


# Use Crypt::Random::Seed to generate some high-quality long int
# seeds for Math::Random::ISAAC.
sub _generate_seed {
    my ( $self, %options_hash ) = @_;

    my $seed_size = $self->{Bits} / 32;
    my $source = Crypt::Random::Seed->new(%options_hash);

    croak 'Unable to obtain a strong seed source from Crypt::Random::Seed.'
      unless defined $source;

    return $source->random_values($seed_size); # List of unsigned longs.
}


# Validate that we are getting an integer >= 0.
# If not, throw an exception.
sub _validate_int {
  my( $self, $input ) = @_;
  croak "Byte count must be a positive integer."
    unless    looks_like_number( $input )
           && $input == int( $input )
           && $input >= 0;
  return 1;
}


# Random bytes string.
sub bytes {
  my( $self, $bytes ) = @_;
  $bytes = defined $bytes ? $bytes : 0; # Default to zero bytes.
  $self->_validate_int( $bytes ); # Throws on violation.

  $self->_instantiate_rng unless defined $self->{_RNG};

  my $str = '';

  while ( $bytes >= 4 ) {                  # Utilize irand()'s 32 bits.
    $str .= pack( "L", $self->{_RNG}->irand );
    $bytes -= 4;
  }

  if ( $bytes > 0 ) {
    my $rval = $self->{_RNG}->irand;

    $str .= pack( "S", ( $rval >> 8 ) & 0xFFFF )
      if $bytes >= 2;                    # 16 bits.
    $str .= pack( "C", $rval & 0xFF ) if $bytes % 2;    # 8 bits.

  }
  return $str;
}

# Base64 encoding of random byte string.
sub bytes_base64 {
  my ( $self, $bytes, $eol ) = @_;
  return encode_base64( $self->bytes($bytes), defined($eol) ? $eol : qq{\n} );
}

# Hex digits representing random byte string (No whitespace, no '0x').
sub bytes_hex {
  my ( $self, $bytes ) = @_;
  return unpack 'H*', $self->bytes($bytes);
}

# Quoted Printable representation of random byte string.
sub bytes_qp {
  my ( $self, $bytes, $eol ) = @_;
  return encode_qp $self->bytes($bytes), defined($eol) ? $eol : qq{\n}, 1;
}


sub string_from {
  my( $self, $bag, $bytes ) = @_;
  $bag   = defined $bag   ? $bag   : '';
  $bytes = defined $bytes ? $bytes : 0;
  my $range = length $bag;
  
  $self->_validate_int( $bytes );
  
  croak "Bag's size must be at least 1 character."
    if $range < 1;

  my $rand_bytes = '';
  for my $random ( $self->_ranged_randoms( $range, $bytes ) ) {
      $rand_bytes .= substr( $bag, $random, 1 );
  }

  return $rand_bytes;
}

# Helpers for string_from()

sub _ranged_randoms {
    my ( $self, $range, $count ) = @_;
    $count = defined $count ? $count : 0;

    # Lazily seed the RNG so we don't waste available strong entropy.
    $self->_instantiate_rng unless defined $self->{_RNG};

    my $divisor = $self->_closest_divisor($range);
    my @randoms;

    for my $n ( 1 .. $count ) {
        my $random;

        do {
            $random = $self->{_RNG}->irand % $divisor;
        } while ( $random >= $range );

        push @randoms, $random;
    }

    return @randoms;
}

sub _closest_divisor {
    my ( $self, $range ) = @_;
    $range = defined $range ? $range : 0;

    croak "$range must be positive." if $range < 0;
    croak "$range exceeds irand max limit of 2**32." if $range > 2**32;

    my $n = 0;
    my $d;
    while ( $n <= 32 ) {
        $d = 2 ** $n++;
        last if $d >= $range;
    }
    
     return $d;
}


################################################################################
##  Functions interface                                                       ##
################################################################################

# Instantiate our random number generator(s) inside of a lexical closure,
# limiting the scope of the RNG object so it can't be tampered with.

{
  my $RNG_object = undef;


  # Lazily, instantiate the RNG object, but only once.
  my $fetch_RNG = sub {
    $RNG_object = Bytes::Random::Secure->new( FUNC_STD )
      unless defined $RNG_object;
    return $RNG_object;
  };


  sub random_bytes {
    return $fetch_RNG->()->bytes( @_ );
  }


  sub random_string_from {
    return $fetch_RNG->()->string_from( @_ );
  }

}


# Base64 encoded random bytes functions

sub random_bytes_base64 {
  my ( $bytes, $eof ) = @_;
  return encode_base64 random_bytes($bytes), defined($eof) ? $eof : qq{\n};
}


# Hex digit encoded random bytes

sub random_bytes_hex {
  return unpack 'H*', random_bytes( shift );
}


# Quoted Printable encoded random bytes

sub random_bytes_qp {
  my ( $bytes, $eof ) = @_;
  return encode_qp random_bytes($bytes), defined($eof) ? $eof : qq{\n}, 1;
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


    my $random = Bytes::Random::Secure->new(
        Bits        => 64,
        NonBlocking => 1,
    ); # Seed with 64 bits, and use /dev/urandom (or other non-blocking).

    my $bytes = $random->bytes(32); # A string of 32 random bytes.


=head1 DESCRIPTION

L<Bytes::Random::Secure> provides two interfaces for obtaining crypt-quality
random bytes.  The simple interface is built around plain functions.  For
greater control over the Random Number Generator's seeding, there is an Object
Oriented interface that provides much more flexibility.

The "functions" interface provides five functions that can be used any time you
need a string (or MIME Base64 representation, or hex-digits representation, or
Quoted Printable representation) of a specific number of random bytes.  There
are equivalent methods available via the OO interface.

This module can be a drop-in replacement for L<Bytes::Random>, with the primary
enhancement of using a much higher quality random number generator to create
the random data.  The C<random_bytes> function emulates the user interface of
L<Bytes::Random>'s function by the same name.  But with Bytes::Random::Secure
the random number generator comes from L<Math::Random::ISAAC>, and is suitable
for cryptographic purposes.  The harder problem to solve is how to seed the
generator.  This module uses L<Crypt::Random::Seed> to generate the initial
seeds for Math::Random::ISAAC.

In addition to providing C<random_bytes()>, this module also provides four
functions not found in L<Bytes::Random>: C<random_string_from>,
C<random_bytes_base64()>, C<random_bytes_hex>, and C<random_bytes_qp>.

And finally, for those who need finer control over how L<Crypt::Random::Seed>
generates its seed, there is an object oriented interface with a constructor
that facilitates configuring the seeding process, while providing methods that
do everything the "functions" interface can do (truth be told, the functions
interface is just a thin wrapper around the OO version, with some sane defaults
selected).

=head1 RATIONALE

There are many uses for cryptographic quality randomness.  This module aims to
provide a generalized tool that can fit into many applications while providing
a minimal dependency chain, and a user interface that is simple.  You're free
to come up with your own use-cases, but there are several obvious ones:

=over 4

=item * Creating temporary passphrases (C<random_string_from()>).

=item * Generating per-account random salt to be hashed along with passphrases 
(and stored alongside them) to prevent rainbow table attacks.

=item * Generating a secret that can be hashed along with a cookie's session
content to prevent cookie forgeries.

=item * Building raw cryptographic-quality pseudo-random data sets for testing
or sampling.

=item * Feeding secure key-gen utilities.

=back

Why use this module?  This module employs several well-designed CPAN tools to
first generate strong random seeds, and then to instantiate a high quality
random number factory based on the strong seed.  The code in this module really
just glues together the building blocks.  However, it has taken a good deal of
research to come up with what I feel is a strong tool-chain that isn't going to
fall back to a weak state on some systems.  The interface is designed with
simplicity in mind, to minimize the potential for misconfiguration.  Hopefully
others may benefit from this work.


=head1 EXPORTS

By default C<random_bytes> is the only function exported.  Optionally
C<random_string_from>, C<random_bytes_base64>, C<random_bytes_hex>,
and C<random_bytes_qp> may be exported.

=head1 FUNCTIONS

The B<functions interface> seeds the ISAAC generator on first use with a 256 bit
seed that uses Crypt::Random::Seed's default configuration as a strong random
seed source.

=head2 random_bytes

    my $random_bytes = random_bytes( 512 );
    
Returns a string containing as many random bytes as requested.  Obviously the
string isn't useful for display, as it can contain any byte value from 0 through
255.

The parameter is a byte-count, and must be an integer greater or equal to zero.

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

=head1 METHODS

The B<Object Oriented interface> provides methods that mirror the "functions"
interface.  However, the OO interface offers the advantage that the user can
control how many bits of entropy are used in seeding, and even how
L<Crypt::Random::Seed> is configured.

=head2 new

    my $random = Bytes::Random::Secure->new( Bits => 512 );

The constructor is used to specify how the ISAAC generator is seeded.  Future
versions may also allow for an alternate PSRNG to be selected.  If no parameters
are passed the default configuration specifies 256 bits for the seed.  The rest
of the default configuration accepts the L<Crypt::Random::Seed> defaults, which
favor the strongest operating system provided entropy source, which in many
cases may be "blocking".

=head3 CONSTRUCTOR PARAMETERS

=head4 Bits

    my $random = Bytes::Random::Secure->new( Bits => 128 );
    
The C<Bits> parameter specifies how many bits (rounded up to nearest multiple of
32) will be used in seeding the ISAAC random number generator.  The default is
256 bits of entropy.  But in some cases it may not be necessary, or even wise to
pull so many bits of entropy out of C</dev/random> (a blocking source).

Any value between 64 and 512 will be accepted. If an out-of-range value is
specified, or a value that is not a multiple of 32, a warning will be generated
and the parameter will be rounded up to the nearest multiple of 32 within the
range of 64 through 512 bits.  So if 1024 is specified, you will get 512.  If
33 is specified, you will get 64.  

=head4 PRNG

Reserved for future use.  Eventually the user will be able to select other RNGs
aside from Math::Random::ISAAC.

=head4 Unique

Reserved for future use.

=head4 Crypt::Random::Seed Configuration Parameters

For additional seeding control, refer to the POD for L<Crypt::Random::Seed>.
By supplying a Crypt::Random::Seed parameter to Bytes::Random::Secure's
constructor, it will be passed through to Crypt::Random::Seed.  For example:

    my $random = Bytes::Random::Secure->new( NonBlocking => 1, Bits => 64 );

In this example, C<Bits> is used internally, while C<NonBlocking> is passed
through to Crypt::Random::Seed.


=head2 bytes

    my $random_bytes = $random->bytes(1024);

This works just like the C<random_bytes> function.


=head2 string_from

    my $random_string = $random->string_from( 'abcdefg', 10 );

Just like C<random_string_from>: Returns a string of random octets selected
from the "Bag" string (in this case ten octets from 'abcdefg').


=head2 bytes_hex

    my $random_hex = $random->bytes_hex(12);

Identical in function to C<random_bytes_hex>.


=head2 bytes_base64

    my $random_base64 = $random->bytes_base64( 32, EOL => "\n" );

Identical in function to C<random_bytes_base64>.


=head2 bytes_qp

    my $random_qp = $random->bytes_qp( 80 );

You guessed it: Identical in function to C<random_bytes_qp>.


=head1 CONFIGURATION

L<Bytes::Random::Secure>'s interface I<keeps it simple>.  There is generally 
nothing to configure.  This is by design, as it eliminates much of the 
potential for diminishing the quality of the random byte stream by through
misconfiguration.  The ISAAC algorithm is used as our factory, seeded with a
strong source.

There may be times when the default seed characteristics carry too heavy a
burden on system resources.  The default seed for the functions interface is
256 bits of entropy taken from /dev/random (a blocking source on many systems),
or via API calls on Windows.  The default seed size for the OO interface is also
256 bits. If /dev/random should become depleted at the time that this module
attempts to seed the ISAAC generator, there could be delay while additional
system entropy is generated.  If this is a problem, it is possible to override
the default seeding characteristics using the OO interface instead of the
functions interface.  However, under most circumstances, this capability may be
safely ignored.

Beginning with Bytes::Random::Secure version 0.20, L<Crypt::Random::Seed>
provides our strong seed (previously it was Crypt::Random::Source).  This module
gives us excellent "strong source" failsafe behavior, while keeping the
non-core dependencies to a bare minimum.  Best of all, it performs well across
a wide variety of platforms, and is compatible with Perl versions back through
5.6.0.

And as mentioned earlier in this document, there may be circumstances where
the performance of the operating system's strong random source is prohibitive
from using the module's default seeding configuration.  Use the OO interface
instead, and read the documentation for L<Crypt::Random::Seed> to learn what
options are available.

Prior to version 0.20, a heavy dependency chain was required for reliably
and securely seeding the ISAAC generator.  Earlier versions required
L<Crypt::Random::Source>, which in turn required L<Any::Moose>.  Thanks to Dana
Jacobsen's new Crypt::Random::Seed module, this situation has been resolved.
So if you're looking for a secure random bytes solution that "just works"
portably, and on Perl versions as far back as 5.6.0, you've come to the right
place.  Users of older versions of this module are encouraged to update to
version 0.20 or higher to benefit from the improved user interface and lighter
dependency chain.


=head2 OPTIONAL (RECOMMENDED) DEPENDENCY

If performance is a consideration, you may also install 
L<Math::Random::ISAAC::XS>. Bytes::Random::Secure's random number generator 
uses L<Math::Random::ISAAC>.  That module implements the ISAAC algorithm in pure
Perl.  However, if you install L<Math::Random::ISAAC::XS>, you
get the same algorithm implemented in C/XS, which will provide better
performance.  If you need to produce your random bytes more quickly, simply
installing Math::Random::ISAAC::XS will result in it automatically being used,
and a pretty good performance improvement will coincide.


=head1 CAVEATS

It's easy to generate weak pseudo-random bytes.  It's also easy to think you're
generating strong pseudo-random bytes when really you're not.  And it's hard to
test for pseudo-random cryptographic acceptable quality.

Assuring strong (ie, secure) random bytes in a way that works across a wide
variety of platforms is also challenging.  A primary goal for this module is to
provide cryptographically secure pseudo-random bytes.  A secondary goal is to
provide a simple user experience (thus reducing the propensity for getting it
wrong).  A terciary goal is to minimize the dependencies required to achieve the
primary and secondary goals, to the extent that is practical.

To keep the dependencies as light as possible this module steals some code from
L<Math::Random::Secure>.  That module is an excellent resource, but implements a
broader range of functionality than is needed here.  So we just borrowed some
code from it.

The primary source of random data in this module comes from the excellent
L<Math::Random::ISAAC>.  To be useful and secure, even Math::Random::ISAAC
needs a cryptographically sound seed, which we derive from
L<Crypt::Random::Seed>.  To date, there are no known weaknesses in the ISAAC
algorithm.  And Crypt::Random::Seed does a very good job of preventing fall-back
to weak seed sources.

However, it is possible (and has been seen in testing) that the system's random
entropy source might not have enough entropy in reserve to generate the seed
requested by this module without blocking.  If you suspect that you're a victim
of blocking from reads on C</dev/random>, your best option is to manipulate
the random seed configuration by using the C<config_seed> class method.  This
module does seed as lazily as possible so that using the module, and even
instantiating a Bytes::Random::Seed object will not trigger reads from
C</dev/random>.  Only the first time the object is used to deliver random bytes
will the RNG be seeded.

A note regarding modulo bias:  Care is taken such that there is no modulo bias
in the randomness returned either by C<random_bytes> or its siblings, nor by
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

Dana Jacobsen ( I<< <dana@acm.org> >> ) for his work that led to
L<Crypt::Random::Seed>, thereby significantly reducing the dependencies while
improving the portability and backward compatibility of this module.  Also for
providing a patch to this module that greatly improved the performance
of C<random_bytes>.

Dana Jacosen also provided extensive input that helped guide the direction this
module has taken.  Thanks!

L<Bytes::Random> for implementing a nice interface that this module patterns
itself after.

=head1 LICENSE AND COPYRIGHT

Copyright 2012 David Oswald.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.

=cut
