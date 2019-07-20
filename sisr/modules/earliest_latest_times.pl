#!/usr/bin/perl

# earliest_latest_times.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# earliest_latest_times.pl is a Pipeline module used to obtain the earlist
#   and latest times of a set of events.  These events are in the format of
#   the hash created by the event_details routine in alertset_xml.pl
# pipeline args: event details, earliest time output loc, latest time
#   output loc
# side effect: output locs get set

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

sub process {
    require "sisr_utils.pl";
    my ($input)= shift;
    @_ == 3 || (&reporterr("earliest_latest_times.pl takes 3 arguments (event details,earliest time file/envvar,latest time file/envvar), but got:".join(' ',@_),0) && return 0);
    my $lateoutloc= pop(@_);
    my $earlyoutloc= pop(@_);
    
    my ($events)= &arg_to_val($input,@_);
    my (@events)= @{$events};
    my $event1= shift(@events);
    my @pcs1= ($event1->{'MONTH'},$event1->{'DATE'},split(':',$event1->{'TIME'}));

    my @minpcs= @pcs1;
    my @maxpcs= @pcs1;
    my $event;
    my @pcs;
    foreach $event (@events) {
        @pcs = ($event->{'MONTH'},$event->{'DATE'},split(':',$event->{'TIME'}));
        foreach (0..$#pcs) {
            next if $minpcs[$_] == $pcs[$_];
            if ($pcs[$_] < $minpcs[$_]) {
                @minpcs= @pcs;
            } 
            last;
        }
        foreach (0..$#pcs) {
            next if $maxpcs[$_] == $pcs[$_];
            if ($pcs[$_] > $maxpcs[$_]) {
                @maxpcs= @pcs;
            }  
            last;
        }
    }
    
    my $text=&pcs_to_text(@minpcs);
    &write_out_to_arg($input,$earlyoutloc,$text);
    
    my $text=&pcs_to_text(@maxpcs);
    &write_out_to_arg($input,$lateoutloc,$text);
};

sub pcs_to_text {
    my @monthnum2text=('','Jan','Feb','March','April','May','June','July','Aug','Sept','Oct','Nov','Dec');
    my $mo= $monthnum2text[shift];
    my $date= shift;
    return "$mo $date ".join(':',@_);
}

\&process;

# $Id: earliest_latest_times.pl,v 1.12 2001/10/18 18:23:25 jim Exp $
