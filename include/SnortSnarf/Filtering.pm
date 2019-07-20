#!/usr/bin/perl

# Filter.pm, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2001 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# This file contains a set of helper functions for filter modules.

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.


package Filtering;

$strcmpops_regex= '(!=|<=|>=|<|>|=)';

sub strcmpops {
    my($op,$l,$r)= @_;
    #print "strcmpops(".join(',',@_).")\n";
    if ($op eq '=') {
        return $l eq $r;
    } elsif ($op eq '!=') {
        return $l ne $r;
    } elsif ($op eq '<') {
        return $l lt $r;
    } elsif ($op eq '>') {
        return $l gt $r;
    } elsif ($op eq '<=') {
        return ($l lt $r || $l eq $r);
    } elsif ($op eq '>=') {
        return ($l gt $r || $l eq $r);
    }
    warn "unknown string compare operation: $op";
    return 0;
}

$numcmpops_regex= '(!=|<=|>=|<|>|=)';

sub numcmpops {
    my($op,$l,$r)= @_;
    if ($op eq '=') {
        return $l == $r;
    } elsif ($op eq '!=') {
        return $l != $r;
    } elsif ($op eq '<') {
        return $l < $r;
    } elsif ($op eq '>') {
        return $l > $r;
    } elsif ($op eq '<=') {
        return $l <= $r;
    } elsif ($op eq '>=') {
        return $l >= $r;
    }
    warn "unknown numeric compare operation: $op";
    return 0;
}
