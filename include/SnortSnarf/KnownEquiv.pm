#!/usr/bin/perl

# Filter.pm, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2001 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# This file contains classes to be used as an inherited class, providing
# solely the function known_equiv.  This function returns whether self and the
# given class are known to be semanitically equivalent.  These
# implementations assume that if each contained piece in the corresponding
# spots are the same (and all spots correspond), then they are semantically
# equivalent.  If corresponding elements are not references, they are
# compared stringwise.  If they are both references if they are the same
# reference or of the same class and a call to known_equiv returns true.

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

package ScalarKE;

sub known_equiv {
    my($self,$other)= @_;
    return 0 unless ref($self) eq ref($other);
    my $s= ${$self};
    my $o= ${$other};
    if (ref($s)) {
        return $s == $o || (ref($s) eq ref($o) && $s->known_equiv($o));
    } else {
        return $s eq $o;
    }
}

#################################
package ArrayKE;

sub known_equiv {
    my($self,$other)= @_;
    return 1 if $self == $other;
    if (ref($self) eq ref($other)) {
        my(@self)= @{$self};
        my(@other)= @{$other};
        return 0 if @self != @other;
        foreach (0 .. $#self) {
            my $s= $self[$_];
            my $o= $other[$_];
            if (ref($s)) {
                next if $s == $o;
                return 0 unless ref($s) eq ref($o);
                return 0 unless $s->known_equiv($o);
            } else {
                return 0 unless $s eq $o;
            }
        }
        return 1;
    }   
    return 0;
}


1;
