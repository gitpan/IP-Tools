use strict;
use warnings;
use ExtUtils::MakeMaker;

my $pm = 'lib/IP/Tools.pm';
my $repo = 'https://github.com/benkasminbullock/IP-Tools';

WriteMakefile (
    NAME => 'IP::Tools',
    VERSION_FROM => $pm,
    ABSTRACT_FROM => $pm,
    AUTHOR => 'Ben Bullock <bkb@cpan.org>',
    LICENSE => 'perl',
    PREREQ_PM => {
    },
    META_MERGE => {
        resources => {
            repository => $repo,
            bugtracker => "$repo/issues",
        },
    },
    EXE_FILES => ['script/iprtocidr'],
    OBJECT => 'Tools.o ip-tools.o',

    # Export these C functions to other Perl libraries.

    DL_FUNCS => {
        'IP::Tools' => [
            'ip_tools_ip_to_int',
            'ip_tools_ip_range',
        ],
    }
);
