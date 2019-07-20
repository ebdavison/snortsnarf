#!/usr/bin/perl

# add_alerts_to_db_set.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# add_alerts_to_db_set.pl is a Pipeline module to add alerts to a set in an
#   labled set database file, creating the set if needed.
# pipeline args: alerts, set name, set file
# side effect: creates the set in the file or appends to the set

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

sub process {
    require "sisr_utils.pl";
    require "alertset_xml.pl";
    my ($input)= shift;
    @_ == 3 || (&reporterr("add_alerts_to_db_set.pl takes 3 arguments (alerts,set name,labeled alert set file), but got:".join(' ',@_),0) && return 0);
    
    my ($alerts,$setname,$file)= &arg_to_val($input,@_);

    my $tree= &load_XML_tree($file);
    
    $tree= &create_tree_unless_exists($tree);
    my $set= &get_set_named($tree,$setname);
    my(@alerts)= @{$alerts};
    if (ref($alerts[0]) eq 'HASH') { # old style alerts
        &add_events_to_set($set,@{alerts});
    } else { # alert API alert objects
        &add_alerts_to_set($set,@{alerts});
    }
    
    &save_XML_tree($tree,$file);
};

\&process;

# $Id: add_alerts_to_db_set.pl,v 1.11 2001/10/18 18:23:25 jim Exp $
