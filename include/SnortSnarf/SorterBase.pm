#!/usr/bin/perl

# SorterBase.pm, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2001 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# SorterBase is optional base class for Sorter API modules taking gueeses at
# some functions.

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

package SorterBase;

###### API functions #######

sub known_equiv {
    return 0;
}

sub cmp {
    my($self,$alert1,$alert2)= @_;
    return $alert1 cmp $alert2;
}

sub sort {
    my($self,@alerts)= @_;
    return sort {$self->cmp($a,$b)} @alerts;
}

sub first_last {
    my($self,@alerts)= @_;
    return () unless @alerts;
    my($first)= shift(@alerts);
    my($last)= $first;
    foreach (@alerts) {
        if ($self->cmp($first,$_) == 1) {
            $first= $_;
        } elsif ($self->cmp($last,$_) == -1) {
            $last= $_;
        }
    }
    return ($first,$last);
}

sub merge {
    my($self) = shift;
    my($list) = shift;
    my($alert);
    $pos= $#{$list};
    while ($alert= pop(@_)) {
        while ($pos >= 0 && $self->cmp($alert,$list->[$pos]) == -1) {
            $pos--;
        }
        if ($pos < 0) { # hit the front
            unshift(@{$list},@_,$alert);
            last;
        }
        splice(@{$list},$pos+1,0,$alert);
    }
}

1;
