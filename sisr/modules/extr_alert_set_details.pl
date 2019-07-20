#!/usr/bin/perl

# extr_alert_set_details.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# extr_alert_set_details.pl is a Pipeline module to load all the alerts in
#   a labeled alert set into a list ref; these alerts are in a hash created
#   by the event_details routine in alertset_xml.pl. 
# pipeline args: set name, alert set database file path, output loc (may
#   need to be an env var)
# side effect: in the output loc, a reference to a list of parsed events
#   (alerts) is stored

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

sub process {
    require "sisr_utils.pl";
    require "alertset_xml.pl";
    my ($input)= shift;
    @_ == 3 || (&reporterr("extr_alert_set_details.pl takes 3 arguments (set file path,set name,output field/envvar), but got:".join(' ',@_),0) && return 0);
    my($outloc)= pop;
    
    my ($setfile,$setname)= &arg_to_val($input,@_);

    my $tree= &load_XML_tree($setfile);
    my @events= &get_set_event_details($tree,$setname);
    
    &write_out_to_arg($input,$outloc,\@events);
};

\&process;

# $Id: extr_alert_set_details.pl,v 1.11 2001/10/18 18:23:25 jim Exp $
