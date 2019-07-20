#!/usr/bin/perl

# extr_alert_ids.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# extr_alert_ids.pl is a Pipeline module extract a set of alert ids from
#   a given input modules specification string.
# pipeline args: input modules specification string, alert ids, output loc
# side effect: in the output loc, the parsed alerts indicated 

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

sub process {
    # avoid needing to refer to SnortSnarf packages as SnortSnarf::*, even if
    # that is where they really are
    push(@INC,map("$_/SnortSnarf",grep(-d "$_/SnortSnarf",@INC)));

    require "sisr_utils.pl";
    require Input;
    require AllMods;
    
    my ($input)= shift;
    @_ == 3 || (&reporterr("extr_alert_ids.pl takes 3 arguments (input modules specification,alert ids,output field/envvar), but got:".join(' ',@_),0) && return 0);
    my($outloc)= pop;
    
    my ($modspec,$alertids)= &arg_to_val($input,@_);

    &AllMods::load_all_input_modules();
    my @alerts= &Input::grab_alert_ids_from_mods([split(';',$alertids)],&Input::recreate_input_mods($modspec));
    
    &write_out_to_arg($input,$outloc,\@alerts);
};

\&process;
