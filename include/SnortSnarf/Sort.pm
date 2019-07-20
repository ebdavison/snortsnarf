#!/usr/bin/perl

# Sort.pm, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2001 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# This file is a package holding an instance of some common sorters.

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

package Sort;
use BasicSorters;

sub BEGIN {
    $bytime= NumFieldSorter->new('utime');
    $byhighestanom= NumHighestPktFieldSorter->new('anom');
    $bypkt1time= FirstPktFieldNumSorter->new('utime',NumFieldPktSorter->new('utime'));
}

1;
