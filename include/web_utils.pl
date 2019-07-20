#!/usr/bin/perl

# web_utils.pl, distributed as part of Snortsnarf v020516.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# web_utils.pl is a library file for web-related utility functions

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.


# encode the given text for use in a URL;
# this version probably encodes more than it needs to
sub url_encode {
    my $text= shift;
    $text =~ s/%/%25/g;
    $text =~ s/([^\w%\.\,])/'%'.sprintf("%02X",ord($1))/eg;
    return $text;
}



1;
