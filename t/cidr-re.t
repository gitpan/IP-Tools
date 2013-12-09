use warnings;
use strict;
use Test::More;
use IP::Tools '$cidr_re';
like ('133.15.0.0/16', $cidr_re);
like ("[Network Number]   133.15.0.0/16\n", $cidr_re);
done_testing ();
exit;

