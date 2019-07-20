#!/usr/bin/perl

# whois_lookup.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# whois_lookup.pl is a Pipeline module used to obtain a list of contact
#   e-mail addresses for an IP address using IPAddrContact.pm
# pipeline args: Ip address, output loc
# side effect: output loc gets a comma-separated list of e-mail addresses

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

sub process {
    require "sisr_utils.pl";
    use IPAddrContact;
    my ($input)= shift;
    @_ == 2 || (&reporterr("whois_lookup.pl takes 2 arguments (address,output file/envvar), but got:".join(' ',@_),0) && return 0);
    my $outloc= pop(@_);
    
    my ($addrs,$fld)= &arg_to_val($input,@_);

    my @emails= ();
    while ($addrs =~ s/([\w\.\-]+)//) {
        push(@emails,&lookup($1,0));
    }

    my $res= join(',',@emails);
    
    &write_out_to_arg($input,$outloc,$res);
};

\&process;

# $Id: whois_lookup.pl,v 1.12 2001/10/18 18:23:25 jim Exp $
