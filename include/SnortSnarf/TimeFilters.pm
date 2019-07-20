#!/usr/bin/perl 

# TimeFilters.pm, distributed as part of Snortsnarf v020516.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# this file contains a set of time-related implementations of the SnortSnarf
# Filter API

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

use KnownEquiv;
use Time::ParseDate;


package TimeSpec;

# a set of routines in the TimeSpec namespace to work with time specifitions

sub BEGIN {
    $now= time(); # store this for relative time specifications
	($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($now);
}

# converts the given time specification into a Unix time
# returns undef if the specification is not valid
sub spec_to_utime {
    my ($spec)= shift;
	
    if ($spec =~ /^\d+$/) { # just a number, must be in Unix time already
        return $spec;
    } else {
    	my $ret= Time::ParseDate::parsedate($spec, 'FUZZY' => 1);
print "$spec => $ret\n";
    	return $ret;
    }
}

#======================================

package MinTimeFilter;

# a filter class that matches iff an alert's time is not before a given time/day

@ISA= (qw(ScalarKE));

sub new {
	my($class)= shift;
	my($timespec)= shift;
	my $utime= TimeSpec::spec_to_utime($timespec);
	return undef unless defined($utime);
	return bless \$utime,$class; 
}

sub as_str {
	return ${$_[0]};
}

sub test {
	my($self,$alert)= @_;
	return $alert->utime() >= ${$self};
}

#======================================

package MaxTimeFilter;

# a filter class that matches iff an alert's time is not after a given time/day

@ISA= (qw(ScalarKE));

sub new {
	my($class)= shift;
	my($timespec)= shift;
	my $utime= TimeSpec::spec_to_utime($timespec);
	return undef unless defined($utime);
	return bless \$utime,$class; 
}

sub as_str {
	return ${$_[0]};
}

sub test {
	my($self,$alert)= @_;
	return $alert->utime() <= ${$self};
}

1;
