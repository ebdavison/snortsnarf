#!/usr/bin/perl

# lab_set_view.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# lab_set_view.pl is a Pipeline module to take an set name and a path to an
#   set file and show the set on the browser
# pipeline args: set name, set file
# side effect: displayes HTML on browser

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

sub process {
    require "sisr_utils.pl";
    require "alertset_xml.pl";
    my ($input)= shift;
    @_ == 2 || (&reporterr("lab_set_view.pl takes 2 arguments (set name,set file), but got:".join(' ',@_),0) && return 0);
    
    my ($setname,$setfile)= &arg_to_val($input,@_);
    
    # print out headers
    print $input->header(-header => 'text/html',-expires => '+0d');

    my $configfile= $input->param('configfile');

    # probably really want to get these from the config file
    my($path)= $input->param('_path');

    my $tree= &load_XML_tree($setfile);
    my @events= &set_events($tree,$setname);
    # should check if @events== undef; indicates there is no such set
    my @eventtexts= map(&event_field($_,'TEXT'),@events);

    print <<">>";
<HTML>
<HEAD>
    <TITLE>Listing of labeled event set $setname</TITLE>
</HEAD>
<BODY bgcolor="#E7DEBD">
<H1>Labeled event set $setname</H1>
>>
    # eventually want to add links to save selection, delete set, deleted selected, rename, arrange (listing) by field, etc.
    print "Options: <UL>\n";
    my $inc_text_prod_mods= &get_config_field($configfile,'inc-field-calc-pipe');
    print '<LI><A HREF="',&pipeline_submit_url("config_alert_set_db.pl $configfile \$setfile | config_inc_flds_db.pl $configfile \$ifieldinfo \$incfile | extr_alert_set_details.pl \$setfile $setname \%events | $inc_text_prod_mods | create_inc_form.pl \$ifieldinfo $setname \$setfile",$path,'configfile' => $configfile,'setname' => $setname),
        "\">Create incident from $setname</A>";
    my $encconfig= &url_encode($configfile);
    print "<LI><A HREF=\"lsetlist.pl?configfile=$encconfig\">List all sets</A>";
    print "<LI><A HREF=\"inclist.pl?configfile=$encconfig\">List all incidents</A>";
    print "</UL>\n<HR>\n";
    if (@eventtexts==0) {
        print "No events were found in the event set $setname from file $setfile<BR>\n";
    } else {
        print "There are ",0+@eventtexts," events in labeled event set $setname in file $setfile:\n<BR>";
        print "<table border cellpadding = 3>\n";
        foreach (@eventtexts) {
            s/[\n\r]/<BR>/g;
            print "<tr><td>".$_."</td></tr>\n";
        }
        print "</table>\n";
    }

    print "</BODY></HTML>";
};

\&process;

# $Id: lab_set_view.pl,v 1.11 2001/10/18 18:23:25 jim Exp $
