use 5.006;
use strict;
use warnings;
use ExtUtils::MakeMaker;

my %PREREQ_PM = (
    'Test::More'            => '0',
    'Crypt::Random::Source' => '0',    # Provides a high quality seed.
    'Math::Random::ISAAC'   => '0',    # Provides our random number generator.
    'MIME::Base64'          => '0',
    'MIME::QuotedPrint'     => '0',
);

# Crypt::Random::Source needs the Crypt::Random::Source::Strong::Win32
# Plug-in under Windows, but it's not explicitly listed in that module's
# Makefile.PL, so we list it here if needed.
$PREREQ_PM{'Crypt::Random::Source::Strong::Win32'} = '0'
  if ( $^O =~ /Win32/i );

WriteMakefile(
    NAME          => 'Bytes::Random::Secure',
    AUTHOR        => q{David Oswald <davido@cpan.org>},
    VERSION_FROM  => 'lib/Bytes/Random/Secure.pm',
    ABSTRACT_FROM => 'lib/Bytes/Random/Secure.pm',
    ( $ExtUtils::MakeMaker::VERSION >= 6.3002
        ? ( 'LICENSE' => 'perl' )
        : () ),
    PL_FILES  => {},
    BUILD_REQUIRES => {
        'Statistics::Basic'    => 1,
    },
    PREREQ_PM => \%PREREQ_PM,
    dist      => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES => 'Bytes-Random-Secure-*' },
);
