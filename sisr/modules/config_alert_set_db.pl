#!/usr/bin/perl

# config_alert_set_db.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# config_alert_set_db.pl is a Pipeline module to extract the alert set
#   database path from the given configuration file.
# pipeline args: configuration file location, alert set output field loc
# side effect: sets the output field appropriately

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

sub process {
    require "sisr_utils.pl";
    my ($input)= shift;
    @_ == 2 || (&reporterr("config_alert_set_db.pl takes 2 arguments (config file location,output loc), but got:".join(' ',@_),0) && return 0);
    my($outloc)= pop;
    
    my ($configfile)= &arg_to_val($input,@_);

    my $setfile= &get_config_field($configfile,'set-db-loc');
    return 0 if $setfile eq '';
    
    &write_out_to_arg($input,$outloc,$setfile);
};

\&process;

# $Id: config_alert_set_db.pl,v 1.11 2001/10/18 18:23:25 jim Exp $
