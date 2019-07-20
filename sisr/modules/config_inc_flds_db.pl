#!/usr/bin/perl

# config_inc_flds_db.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# config_inc_flds_db.pl is a Pipeline module to extract inc field info and
#   the incident db path from the given configuration file. The incident
#   field info is encoded in a string in the form "field-name:value" with
#   "\n" between entries
# pipeline args: configuration file location, field info output field loc,
#   inc database output field loc
# side effect: sets the output fields appropriately

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

sub process {
    require "sisr_utils.pl";
    my ($input)= shift;
    @_ == 3 || (&reporterr("config_inc_flds_db.pl takes 3 arguments (config file location,fld info output loc,db output loc), but got:".join(' ',@_),0) && return 0);
    my($dboutloc)= pop;
    my($fldinfooutloc)= pop;
    
    my ($configfile)= &arg_to_val($input,@_);

    open(C,"<$configfile") || die "could not open config file \"$configfile\"";
    my $incfile= undef;
    my $fldinfo= '';
    while (<C>) {
        next if m/^\#/;
        s/\s+$//;
        if (s/^inc-db-loc\s*:\s*//) {
            $incfile= $_;
        } elsif (s/^ifield\s+(\S+)\s*:\s*//) {
            $fldinfo.= "$1:$_\n";
        }
    }
    chop $fldinfo; # remove trailing newline
    close C;
    defined($incfile) || (&reporterr("could not find labeled set database file \"inc-db-loc\" in $configfile".join(' ',@_),0) && return 0);;
    $fldinfo ne '' || (&reporterr("could not find any incident field info \"ifield [name]: [info]\" in $configfile".join(' ',@_),0) && return 0);;
    
    &write_out_to_arg($input,$dboutloc,$incfile);
    &write_out_to_arg($input,$fldinfooutloc,$fldinfo);
};

\&process;

# $Id: config_inc_flds_db.pl,v 1.11 2001/10/18 18:23:25 jim Exp $
