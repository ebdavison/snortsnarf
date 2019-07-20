#!/usr/bin/perl

# inc_list_view.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# inc_list_view.pl is a Pipeline module to take a path to an incident file
#   and show the list of incidents in the file on the browser
# pipeline args: incident file
# side effect: displayes HTML on browser

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

sub process {
    require "sisr_utils.pl";
    require "inc_xml.pl";
    my ($input)= shift;
    @_ == 1 || (&reporterr("inc_list_view.pl takes 1 argument (incident db file), but got:".join(' ',@_),0) && return 0);
    
    my ($incfile)= &arg_to_val($input,@_);
    
    # print out headers
    print $input->header(-header => 'text/html',-expires => '+0d');

    # probably really want to get these from the config file
    my($path)= $input->param('_path');
    
    my $configfile= $input->param('configfile');

    my $tree= &load_XML_tree($incfile);
    my @incs= &get_all_incidents($tree);

    print <<">>";
<HTML>
<HEAD>
    <TITLE>All incidents in $incfile</TITLE>
</HEAD>
<BODY bgcolor="#E7DEBD">
<H1>Incidents in $incfile</H1>
>>
    if (@incs==0) {
        print "No incidents were found in file $incfile<BR>\n";
    } else {
        print "There are ",0+@incs," incidents in file $incfile:\n<BR>";
        print "<table border cellpadding = 3>\n";
        print <<">>";
    <tr>
        <th>Incident name</th>
        <th>Creator</th>
        <th>Date created</th>
        <th>Labeled set name</th>
        <th>Labeled set location</th>
    </tr>
>>
        foreach (@incs) {
            my %attrs= &incident_attrs($_);
            my $incurl= &pipeline_submit_url("config_inc_flds_db.pl $configfile \$ifieldinfo \$unused | incident_view.pl \$incname $incfile",$path,'configfile' => $configfile,'incname' => $attrs{'name'});
            my $setfile= $attrs{'event-set-loc'};
            $setfile =~ s/^file:\/\///;
            my $setnameurl= &pipeline_submit_url("lab_set_view.pl $attrs{'event-set-name'} $setfile",$path,'configfile' => $configfile);
            my $setfileurl= &pipeline_submit_url("set_list_view.pl $setfile",$path,'configfile' => $configfile);
            $date= localtime($attrs{'created'});
            print <<">>";
    <tr>
        <td><A HREF="$incurl">$attrs{'name'}</A></td>
        <td>$attrs{'creator'}</td>
        <td>$date</td>
        <td><A HREF="$setnameurl">$attrs{'event-set-name'}</A></td>
        <td><A HREF="$setfileurl">$attrs{'event-set-loc'}</A></td>
    </tr>
>>
        }
        print "</table>\n";
    }

    
    print "</BODY></HTML>";
};

\&process;

# $Id: inc_list_view.pl,v 1.12 2001/10/18 18:23:25 jim Exp $
