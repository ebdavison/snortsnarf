#!/usr/bin/perl

# extr_alerts.pl, distributed as part of Snortsnarf v011601.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/snortsnarf/ for
# details.

# extr_alerts.pl is a Pipeline module extract the alerts chosen on the form
#   created by sel_to_add.pl.  This involved loading the selected alerts
#   from files and parsing it.
# pipeline args: alerts (fileid:number;fileid:number), file info fields
#   prefix (for mapping prefix_<fileid> to [file format,path], output loc
# side effect: in the output loc, the parsed alerts indicated 

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

sub process {
	require "sisr_utils.pl";
	require "snort_alert_parse.pl";
	my ($input)= shift;
	@_ == 3 || (&reporterr("extr_alerts.pl takes 3 arguments (alert locations,file info fields prefix,output field/envvar), but got:".join(' ',@_),0) && return 0);
	my($outloc)= pop;
	
	my ($alertlocs,$info_field_prefix)= &arg_to_val($input,@_);

	my %file_info= ();
	foreach $fld ($input->param) {
#print "param $fld\n";
		if ($fld =~ /^$info_field_prefix/) {
			$file= $fld;
			$file =~ s/^$info_field_prefix//;
#print "  contains $file\n";
			$file_info{$file}= [split(',',$input->param($fld),2)]; # [file format, path]
		}	
	}
	
	my @alerts= &get_alerts_parsed(split(';',$alertlocs),\%file_info);
	
	&write_out_to_arg($input,$outloc,\@alerts);
};

\&process;

# $Id: extr_alerts.pl,v 1.10 2001/01/17 01:07:23 jim Exp $
