use 5.006;
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Bytes::Random::Secure',
    AUTHOR              => q{David Oswald <davido@cpan.org>},
    VERSION_FROM        => 'lib/Bytes/Random/Secure.pm',
    ABSTRACT_FROM       => 'lib/Bytes/Random/Secure.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'perl')
      : ()),
    PL_FILES            => {},
    BUILD_REQUIRES => {
        'Statistics::Test::RandomWalk' => '0',
    },
    PREREQ_PM => {
        'Test::More'           => '0',
        'Math::Random::Secure' => '0',
        'MIME::Base64'         => '0',
        'Mime::QuotedPrint'    => '0',
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Bytes-Random-Secure-*' },
);
