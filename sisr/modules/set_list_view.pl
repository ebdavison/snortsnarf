#!/usr/bin/perl

# set_list_view.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# set_list_view.pl is a Pipeline module to take a path to an set file and
#   show the list of sets in the file on the browser
# pipeline args: set file
# side effect: displayes HTML on browser

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

sub process {
    require "sisr_utils.pl";
    require "alertset_xml.pl";
    my ($input)= shift;
    @_ == 1 || (&reporterr("set_list_view.pl takes 1 arguments (set file), but got:".join(' ',@_),0) && return 0);
    
    my ($setfile)= &arg_to_val($input,@_);
    
    # print out headers
    print $input->header(-header => 'text/html',-expires => '+0d');

    # probably really want to get these from the config file
    my($path)= $input->param('_path');
    
    my $configfile= $input->param('configfile');

    my $tree= &load_XML_tree($setfile);
    my @sets= &get_all_sets($tree);

    print <<">>";
<HTML>
<HEAD>
    <TITLE>All labeled sets in $setfile</TITLE>
</HEAD>
<BODY bgcolor="#E7DEBD">
<H1>Labeled sets in $setfile</H1>
>>
    if (@sets==0) {
        print "No sets were found in file $setfile<BR>\n";
    } else {
        print "There are ",0+@sets," labeled sets in file $setfile:\n<BR>";
        print "<table border cellpadding = 3>\n";
        print "<tr><td><B>Set name</B></td><td><B>Date created</B></td></tr>\n";

        foreach (@sets) {
            my %attrs= &set_attrs($_);
            my $url= &pipeline_submit_url("lab_set_view.pl \$setname $setfile",$path,'configfile' => $configfile,'setname' => $attrs{'name'});
            print "<tr><td><A HREF=\"$url\">",$attrs{'name'},"</A></td><td>".localtime($attrs{'created'})."</td></tr>\n";
        }
        print "</table>\n";
    }

    
    #print "<A HREF=\"pipeline.pl?",join('&','_path='.&url_encode($path),'_pipeline='.&url_encode('showflds.pl'),'configfile='.&url_encode($input->param('configfile'))),"\">List all sets</A>";
    print "</BODY></HTML>";
};

\&process;

# $Id: set_list_view.pl,v 1.12 2001/10/18 18:23:25 jim Exp $
