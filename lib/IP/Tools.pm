=encoding UTF-8

=head1 NAME

IP::Tools - internet protocol address tools

=head1 SYNOPSIS

    use IP::Tools;

=head1 DESCRIPTION

Do not use this module.

=head1 FUNCTIONS

=cut

package IP::Tools;

# See the following for the meaning of "dl_load_flags" and why it uses
# DynaLoader and not XSLoader.

# http://www.perlmonks.org/?node_id=691130

require DynaLoader;
require Exporter;

@ISA = qw(Exporter DynaLoader);

our $VERSION = 0.03;

__PACKAGE__->bootstrap ($VERSION);

sub dl_load_flags
{
    return 0x01;
}


@EXPORT_OK = qw/
                   ip_to_int
                   int_to_ip
                   get_ip_range
                   get_cidr
                   cidr_to_ip_range
                   read_whitelist
                   search_whitelist
                   ip_range_to_cidr
                   $cidr_re
                   $ip_re
               /;

%EXPORT_TAGS = (
    all => \@EXPORT_OK,
);
use warnings;
use strict;
use Carp;

=head2 $ip_re

    if ($ip =~ /$ip_re/) {
    }

This regular expression matches an ip address.

=cut

our $ip_re = qr/
                   (?:\d+\.){3}
                   \d+
               /x;

=head2 $cidr_re

    if ($ip =~ /$ip_re/) {
    }

This regular expression matches a CIDR.

=cut

our $cidr_re = qr!
                     ^
                     \s*
                     (
                         $ip_re
                     )
                     /
                     (\d+)
                     \s*
                     $
                 !x;

sub split_ip
{
    my ($ip) = @_;
    return split /\./, $ip;
}

=head2 ip_to_int

    my $int = ip_to_int ($ip);

Convert an IP address to an integer.

=cut

=head2 int_to_ip

    my $ip = int_to_ip ($int);

Given an integer C<$int>, turn it into an IP address.

=cut

sub int_to_ip
{
    my ($int) = @_;
    my @bytes;
    while ($int) {
        push @bytes, $int % 0x100;
        $int /= 0x100;
        $int = int $int;
    }
    my $ip = join ".", reverse @bytes;
    return $ip;
}

=head2 cidr_to_ip_range

    my ($ip1, $ip2) = cidr_to_ip_range ($ip, $bits);

=cut

sub cidr_to_ip_range
{
    my ($ip, $log_mask) = @_;
    my $log_mask_max = 32;
    my $ip_int = ip_to_int ($ip);
    if ($log_mask > $log_mask_max) {
        croak "The mask value of $log_mask is too big; the maximum is $log_mask_max";
    }
    my $add = (1 << ($log_mask_max - $log_mask)) - 1;
    my $lower = $ip_int;
    my $zeroed = $lower - ($lower % ($add + 1));
    if ($lower != $zeroed) {
        croak "cannot handle CIDR address $ip: $lower != $zeroed";
    }
    my $upper = $lower + $add;
    return ($lower, $upper);
}

=head2 get_ip_range

    my ($ip_range, $error) = get_ip_range ('12.23.34.56/13');

Given a CIDR range, turn it into two ip addresses.

=cut

sub get_ip_range
{
    my ($cidr) = @_;
    # Return value container.
    my $ip_range;
    # Error container.
    my $error;
    my $log_mask_max = 32;
    # Error tolerance for floating point calculation.
    my $eps = 0.0001;
    my $ip_re = qr/(?:\d+\.)+\d+/;
    if ($cidr =~ m!^\s*($ip_re)\s*/\s*(\d+)\s*$!) {
        my $ip = $1;
        my $log_mask = $2;
        my $ip_int;
        if ($log_mask > $log_mask_max) {
            $error = <<EOF;
The mask value of $log_mask is too big; the maximum is $log_mask_max.
EOF
            return undef, $error;
        }
        ($ip_int, $error) = ip_to_int ($ip);
        if ($error) {
            return undef, $error;
        }
        my $add = (1 << ($log_mask_max - $log_mask)) - 1;
        my $lower = $ip_int;
        my $zeroed = $lower - ($lower % ($add + 1));
        if ($lower != $zeroed) {
            my $zeroed_ip = int_to_ip ($zeroed);
            $error = <<EOF;
This CIDR address doesn't look right: maybe it should be $zeroed_ip/$log_mask?
EOF
            $lower = $zeroed;
        }
        my $upper = $lower + $add;
        $ip_range = int_to_ip ($lower) . " - " . int_to_ip ($upper);
        # Zero out lower bits.
    }
    return ($ip_range, $error);
}

sub get_cidr
{
    my ($ip_range) = @_;
    # Return value container.
    my $cidr;
    # Error container.
    my $error;
    # Error tolerance for floating point calculation.
    my $eps = 0.0001;
    my $ip_re = qr/(?:\d+\.)+\d+/;
    if ($ip_range =~ m!^\s*($ip_re)\D+($ip_re)\s*$!) {
        my $ip1 = $1;
        my $ip2 = $2;
        my $ip1_int;
        my $ip2_int;
        ($ip1_int, $error) = ip_to_int ($ip1);
        if ($error) {
            return undef, $error;
        }
        ($ip2_int, $error) = ip_to_int ($ip2);
        if ($error) {
            return undef, $error;
        }
        my $base = $ip1_int;
        
        my $mask = $ip2_int - $ip1_int;
        if ($mask < 0) {
            $error = <<EOF;
The first IP, $ip1, is greater than the second IP address, $ip2,
by $mask, so the range cannot be calculated.
EOF
            return "$ip1/32", $error;
        }
        if ($mask == 0) {
            return "$ip1/32", undef;
        }
        my $log2mask = log ($mask + 1) / log (2);
        if (abs ($log2mask) > abs (int $log2mask) + $eps) {
            $error = <<EOF;
The difference between $ip1 and $ip2, $mask, is not a power of two minus one,
so there is probably an error in your inputs.

EOF
        }

        $cidr = "$ip1/" . int (32 - $log2mask);
    }
    else {
        $error = <<EOF;
Sorry, I could not parse that. The range should be in a format
<pre>
123.45.6.7 - 123.45.6.8
</pre>
EOF
    }
    return ($cidr, $error);
}

=head2 ip_range_to_cidr

    ip_range_to_cidr ($ip1, $ip2);

Given two IP addresses, return the difference as a CIDR.

This is not able to split into multiple CIDRs.

=cut

sub ip_range_to_cidr
{
    my ($ip1, $ip2) = @_;
    # Return value container.
    my $cidr;
    # Error container.
    my $error;
    # Error tolerance for floating point calculation.
    my $eps = 0.0001;
    my $ip1_int = ip_to_int ($ip1);
    my $ip2_int = ip_to_int ($ip2);
    my $base = $ip1_int;
    my $mask = $ip2_int - $ip1_int;
    if ($mask < 0) {
        croak "$ip1 is greater than $ip2";
    }
    if ($mask == 0) {
        return "$ip1/32";
    }
    my $log2mask = log ($mask + 1) / log (2);
    if (abs ($log2mask) > abs (int $log2mask) + $eps) {
        croak "Cannot handle non-power-of-two mask $mask";
    }
    $cidr = "$ip1/" . int (32 - $log2mask);
    return $cidr;
}

=head2 read_whitelist

    my @list = read_whitelist ('file.txt');

    my @list = read_whitelist ('file.txt', 1);

Read a whitelist from disc.

=cut

sub read_whitelist
{
    my ($infile, $verbose) = @_;
    open my $in, "<", $infile or die $!;
    my @ips;
    my $comment = '';
    while (<$in>) {
        chomp;
        if (/^\s*#\s*(.*)/) {
            $comment = $1;
            if ($verbose) {
                print "$infile:$.: Comment '$comment'.\n";
            }
            next;
        }
        # Skip blank lines
        if (/^\s*$/) {
            if ($verbose) {
                print "$infile:$.: Skipping whitespace.\n";
            }
            next;
        }
        if (/$cidr_re/) {
            # I do not know the correct terms here.
            my $base = $1;
            my $bits = $2;
            if ($verbose) {
                print "$infile:$.: base = $base, bits = $bits.\n";
            }
            my ($lower, $upper) = cidr_to_ip_range ($base, $bits);
            if ($verbose) {
                printf "$infile:$.: %X - %X\n", $lower, $upper;
            }
            push @ips, {
                lower => $lower,
                upper => $upper,
                line => $.,
                comment => $comment,
            };
            next;
        }
        die "$infile:$.: Unparseable line '$_'.\n"
    }
    close $in or die $!;

    # Sort the addresses from lowest to highest.

    @ips = sort {$a->{lower} <=> $b->{lower}} @ips;

    # Check they are not overlapping.

    for my $i (0..$#ips - 1) {
        if ($ips[$i]->{upper} > $ips[$i + 1]->{lower}) {
            die "$infile:$ips[$i]->{line}: upper range overlaps";
        }
    }
    return @ips;
}

=head2 search_whitelist

Search a whitelist for an IP. This is a Perl version of the C code in
IP::Whitelist.

=cut

sub search_whitelist
{
    my ($ips, $ip, $verbose) = @_;
    my $int = ip_to_int ($ip);
    if ($verbose) {
        printf "%s corresponds to %X.\n", $ip, $int;
    }
    my $n_ips = scalar (@$ips);
    if ($verbose) {
        printf "There are %d IPs.\n", $n_ips;
    }
    my $count = 0;
    my $division = int ($n_ips / 2);
    my $i = $division;
    while (1) {
        $count++;
        if ($count > 100) {
            die "There is bad logic in the search.\n";
        }
        $division = int ($division/2);
        if ($division == 0) {
            $division = 1;
        }
        if ($i > $n_ips - 1) {
            # $i is greater than the biggest entry, so we cannot
            # find it in the list.
            return undef;
        }
        elsif ($i < 0) {
            # $i is smaller than the smallest entry, so we cannot find
            # it in the list.
            return undef;
        }
        if ($int >= $ips->[$i]->{lower}) {
            if ($verbose) {
                printf ("%X: checking within %X-%X.\n", $int, $ips->[$i]->{lower}, $ips->[$i]->{upper});
            }
            if ($i == $n_ips - 1 || $int <= $ips->[$i + 1]->{lower}) {
                if ($int <= $ips->[$i]->{upper}) {
                    # The IP lies between the lower and upper bounds of
                    # this range.
                    return $ips->[$i];
                }
                else {
                    # The IP lies between the upper bound of $i and the
                    # lower bound of $i+1, so it is unknown.
                    return undef;
                }
            }
            else {
                # $i is less than or equal to $n_ips - 1, so we
                # increase $i by $division and check again.
                if ($verbose) {
                    printf ("%X: going up from %X, i = %d, division = %d.\n", $int, $ips->[$i]->{lower}, $i + $division, $division);
                }
                $i += $division;
            }
        }
        else {
            # $i is greater than zero, so go down by $division steps
            # and check again.
            if ($verbose) {
                printf "%X: Going down from %X, i = %d.\n", $int,
                $ips->[$i]->{lower},
                $i - $division;
            }
            $i -= $division;
        }
    }
}

1;
