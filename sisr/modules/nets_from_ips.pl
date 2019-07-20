#!/usr/bin/perl

# nets_from_ips.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# nets_from_ips.pl is a Pipeline module used to extract the network portion
#   (of a given size) of IP addresses in a field.  The distinct results are
#   sorted and stored in a field, separated by commas.  The module can
#   accept a broad array of formats for input strings.  The netmask size
#   can be in the range [1,32] but only 8, 16, 24, and 32 produce correct
#   results at present.
# pipeline args: IP address input field, output field
# side effect: output loc get set

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

sub process {
    require "sisr_utils.pl";
    my ($input)= shift;
    @_ == 2 || @_ == 3 || (&reporterr("nets_from_ips.pl takes 2 or 3 arguments (ips field,net output fields,[net size]), but got:".join(' ',@_),0) && return 0);
    my ($ips,$outloc,$netsize)= @_;
    $netsize= 24 unless defined($netsize);
    
    if ($netsize > 32 || $netsize <= 0) {
        &reporterr("nets_from_ips.pl: netsize param out of bounds ($netsize): should be [1,32]",0);
        return;
    }
    if ($netsize % 8 > 0) {
        &reporterr("warning: nets_from_ips.pl can only calculate nets of size 8,16,24,or 32 at present, rounding up",0);
        $netsize += (8-($netsize % 8));
    }
    
    ($ips,$netsize)= &arg_to_val($input,$ips,$netsize);

    my @ips= ();
    while ($ips =~ s/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})//) {
        push(@ips,$1);
    }
    
    my %nets=();
    my $netbytes= 4-($netsize/8);
    my $suffix= '.0' x $netbytes;
    my $regexp= '\.(\d+)' x $netbytes;
    foreach (@ips) {
        s/$regexp$/$suffix/;
        $nets{$_}=1;
    }
    my $nets= join(',',sort keys %nets);
    
    &write_out_to_arg($input,$outloc,$nets);
};

\&process;

# $Id: nets_from_ips.pl,v 1.12 2001/10/18 18:23:25 jim Exp $
