use strict;
use warnings;
use ExtUtils::MakeMaker;
use ExtUtils::Mksymlists;

my $pm = 'lib/IP/Tools.pm';
my $repo = 'https://github.com/benkasminbullock/IP-Tools';
my $name = 'IP::Tools';

if ($^O eq 'MSWin32') {

    # The following command exports the C functions in "ip-tools.c" to
    # outside this module, for Microsoft Windows.

    Mksymlists (
        NAME => $name,
        FUNCLIST => [
            'ip_tools_ip_to_int',
            'ip_tools_ip_range',
        ],
        DL_FUNCS => {
            'IP::Tools' => [
                'boot_IP__Tools',
            ],
        },
        IMPORTS => {},
    );
}

WriteMakefile (
    NAME => $name,
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
    EXE_FILES => [
        'script/iprtocidr',
    ],
    OBJECT => 'Tools.o ip-tools.o',
);
