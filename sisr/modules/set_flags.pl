#!/usr/bin/perl

# set_flags.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# set_flags.pl is a Pipeline module used summarize the FLAGS field in the events into a string.  The distinct values found in that
#   field are made easily human readable and sorted lexically and joined by commas into a string.  Events with that field empty are ignored.  These
#   events are in the format of the hash created by the event_details
#   routine in alertset_xml.pl.
# pipeline args: event details,output loc
# side effect: output loc gets set

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

sub process {
    require "sisr_utils.pl";
    my ($input)= shift;
    @_ == 2 || (&reporterr("set_flags.pl takes 2 arguments (event details,output file/envvar), but got:".join(' ',@_),0) && return 0);
    my $outloc= pop(@_);
    
    my ($events)= &arg_to_val($input,@_);

    my $event;
    my %vals=();
    my $flags;
    foreach $event (@{$events}) {
        $flags= $event->{'FLAGS'};
        if (defined($flags)) {
            if ($flags eq '********') {
                $alert{'flags'}= 'NULL';
            } else {
                @flags= ();
                push(@flags,'SYN') if $flags =~ /S/;
                push(@flags,'FIN') if $flags =~ /F/;
                push(@flags,'RST') if $flags =~ /R/;
                push(@flags,'PSH') if $flags =~ /P/;
                push(@flags,'ACK') if $flags =~ /A/;
                push(@flags,'URG') if $flags =~ /U/;
                push(@flags,'RES1') if $flags =~ /1/;
                push(@flags,'RES2') if $flags =~ /2/;
                $flags= join('-',@flags);
            }
            $vals{$flags}++ 
        }
    }   
    
    my $summ= join(',',sort keys %vals);
    
    &write_out_to_arg($input,$outloc,$summ);
};

\&process;

# $Id: set_flags.pl,v 1.8 2001/10/18 18:23:25 jim Exp $
