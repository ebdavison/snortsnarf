#!/usr/bin/perl


# MemTimeBase.pm, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2001 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# MemTimeBase is a base class to implements part of the Packet and Alert API
# it provides the methods utime, year, month, day, tod_text, tod, and time_cmp
# this assumes an object instance that it gets is a hash reference with
#   the fields 'utime', 'year', 'month', 'day', and 'tod_text' possibly
#   defined.
# if utime is requested by not stored in 'utime', 'utime' is dervied from
#   the other 5 fields (using localtime())
# if information stored in one of the 5 non-'utime' fields is requested,
#   it is derived from 'utime' and stored

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.


package MemTimeBase;

# Packet and Alert API routines

sub utime {
    unless (defined($_[0]->{'utime'})) { # calculate utime from other time fields and store it
        return undef unless defined($_[0]->{'tod_text'}) && defined($_[0]->{'day'}) && defined($_[0]->{'month'}) && defined($_[0]->{'year'});

        # we have all necessary fields to calculate utime
        use Time::JulianDay;
        my ($hour,$min,$secs)= split(':',$_[0]->{'tod_text'});
        my $isecs= int($secs);
        $_[0]->{'utime'}= jd_timelocal($secs,$min,$hour,$_[0]->{'day'},$_[0]->{'month'}-1,$_[0]->{'year'}-1900)+($secs-$isecs);
    }
    return $_[0]->{'utime'};
}

sub year {
    $_[0]->_expand_utime_locally() if (!defined($_[0]->{'year'}) && defined($_[0]->{'utime'}));
    return $_[0]->{'year'}
}

sub month {
    $_[0]->_expand_utime_locally() if (!defined($_[0]->{'month'}) && defined($_[0]->{'utime'}));
    return $_[0]->{'month'}
}

sub day {
    $_[0]->_expand_utime_locally() if (!defined($_[0]->{'day'}) && defined($_[0]->{'utime'}));
    return $_[0]->{'day'}
}

sub tod_text {
    $_[0]->_expand_utime_locally() if (!defined($_[0]->{'tod_text'}) && defined($_[0]->{'utime'}));
    return $_[0]->{'tod_text'}
}

sub tod {
    $_[0]->_expand_utime_locally() if (!defined($_[0]->{'tod_text'}) && defined($_[0]->{'utime'}));
    return split(':',$_[0]->{'tod_text'});
}

sub time_cmp {
    return $_[0]->utime() <=> $_[1]->utime();
}


# private function to fill in 'year', 'month', 'date', and 'tod_text' from utime using localtime()
sub _expand_utime_locally {
	#print STDOUT "_expand_utime_locally: utime= ",$_[0]->{'utime'},"\n";
    # calculate time fields from utime using localtime()
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst)= localtime($_[0]->{'utime'});
    $_[0]->{'year'}= $year+1900;
    $_[0]->{'month'}= $mon+1;
    $_[0]->{'day'}= $mday;
    $_[0]->{'tod_text'}= sprintf("%02d:%02d:",$hour,$min);
    $_[0]->{'tod_text'}.= '0' if $sec < 10.0 && $sec !~ /^0/; # pad 0 if needed
    $_[0]->{'tod_text'}.= $sec;
}

1;
