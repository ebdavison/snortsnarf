#!/usr/bin/perl

# set_field_summation.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# set_field_summation.pl is a Pipeline module used summarize a certain
#   field in the events into a string.  The distinct values found in that
#   field are sorted lexically and joined by commas into a string.  These
#   events are in the format of the hash created by the event_details
#   routine in alertset_xml.pl.
# pipeline args: event details, field to sum, output loc
# side effect: output loc get set

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

sub process {
    require "sisr_utils.pl";
    my ($input)= shift;
    @_ == 3 || (&reporterr("set_field_summation.pl takes 3 arguments (event details,field to sum,output file/envvar), but got:".join(' ',@_),0) && return 0);
    my $outloc= pop(@_);
    
    my ($events,$fld)= &arg_to_val($input,@_);

    my $event;
    my %vals=();
    my $val;
#&reporterr("debug***: ".join(',',@{$events}),0);
    foreach $event (@{$events}) {
#&reporterr("debug: $event\->{$fld}=".$event->{$fld},0);
        $val= $event->{$fld};
        $val= '*undef*' unless defined($val);
        $vals{$val}++;
    }
    my $summ= join(',',sort keys %vals);
    
    &write_out_to_arg($input,$outloc,$summ);
};

\&process;

# $Id: set_field_summation.pl,v 1.11 2001/10/18 18:23:25 jim Exp $
