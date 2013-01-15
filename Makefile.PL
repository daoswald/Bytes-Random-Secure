use 5.006000;
use strict;
use warnings;
use ExtUtils::MakeMaker;

my %PREREQ_PM = (
    'Test::More'            => '0',    # Core.
    'Crypt::Random::Seed'   => '0',    # Provides a high quality seed.
    'Math::Random::ISAAC'   => '0',    # Provides our random number generator.
    'MIME::Base64'          => '0',    # Core.
    'MIME::QuotedPrint'     => '0',    # Core.
    'Carp'                  => '0',    # Core.
);

WriteMakefile(
    NAME          => 'Bytes::Random::Secure',
    AUTHOR        => q{David Oswald <davido@cpan.org>},
    VERSION_FROM  => 'lib/Bytes/Random/Secure.pm',
    ABSTRACT_FROM => 'lib/Bytes/Random/Secure.pm',
    ( $ExtUtils::MakeMaker::VERSION >= 6.3002
        ? ( 'LICENSE' => 'perl' )
        : () ),
    PL_FILES  => {},
    MIN_PERL_VERSION => '5.006000',
    PREREQ_PM => \%PREREQ_PM,
    dist      => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES => 'Bytes-Random-Secure-*' },
);
