#!/usr/bin/perl

# add_alert_set_notes_to_anns.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# add_alert_set_notes_to_anns.pl is a Pipeline module to add annotations that
# the given alerts have been added to the given labeled set and file
# pipeline args: alerts, set name, set file
# side effect: adds the annotation to the annotation database listed in the
# config file

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

sub process {
	require "sisr_utils.pl";
	require "ann_xml.pl";
	my ($input)= shift;
	@_ == 3 || (&reporterr("add_alert_set_notes_to_anns.pl takes 3 arguments (alerts,set name,labeled alert set file), but got:".join(' ',@_),0) && return 0);
	
	my($alerts,$setname,$lsfile)= &arg_to_val($input,@_);
	my $configfile= $input->param('configfile');
	my($annfile)= &get_config_field($configfile,'ann-db-loc');
	if ($annfile eq '') {
		warn "ann-db-locnot provided in $configfile, so no annotations made on labeled set creation";
		return;
	}
	
	my $setviewurl='view_lset.pl?'.join('&','setname='.&url_encode($setname),'setfile='.&url_encode($lsfile),'configfile='.&url_encode($configfile));
	my $settext= "<A HREF=\"$setviewurl\">set \"$setname\" in file $lsfile</A>";
	
	my $tree= &load_XML_tree($annfile);
	
	$tree->[0] eq "ANNOTATION-BASE" || die "invalid annotation XML file ($annfile); expected root element to be ANNOTATION-BASE";

	$tree= &create_ann_tree_unless_exists($tree);
	my($a,%sip,%snet,$src,@srcs);
	foreach $a (@{$alerts}) {
		if (ref($a) eq 'HASH') { # old style hash
			@srcs= ($a->{'src'});
		} else { # alert API instance
			@srcs= map($_->sip(),$a->packets());
		}
		foreach $src (@srcs) {
			$sip{$src}++;
			$src =~ /^(\d+\.\d+\.\d+)/;
			$snet{$1.'.0/24'}++;
			$src =~ /^(\d+\.\d+)/;
			$snet{$1.'.0.0/16'}++;
        }
	}
	foreach (keys %sip) {
		&add_ann($tree,'IP',$_,'SISR','in labeled set',$sip{$_}." packets with $_ as source are in $settext");
	}
	foreach (keys %snet) {
		&add_ann($tree,'network',$_,'SISR','in labeled set',$snet{$_}." packets with $_ as source network are in $settext");
	}
	
	&save_XML_tree($tree,$annfile);
};

\&process;

# $Id: add_alert_set_notes_to_anns.pl,v 1.11 2001/10/18 18:23:25 jim Exp $
