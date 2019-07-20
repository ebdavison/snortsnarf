#!/usr/bin/perl

# create_inc_form.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# create_inc_form.pl is a Pipeline module to display an HTML page that
#   displays incident fields and allows the user to edit them before they
#   are stored in an incident database
# pipeline args: incident field info, set name to be part of incident, set
#   file to be part of incident
# side effect: displayes HTML on browser

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

sub process {
    require "sisr_utils.pl";
    require "alertset_xml.pl";
    my ($input)= shift;
    @_ == 3 || (&reporterr("create_inc_form.pl takes 3 arguments (inc field info,set name,set file), but got:".join(' ',@_),0) && return 0);
    
    my ($incfldinfo,$setname,$setfile)= &arg_to_val($input,@_);
    my ($flddescr,$fldorder)= &decode_fldinfo($incfldinfo);
    $setfile= "file://$setfile";
    
    # print out headers
    print $input->header(-header => 'text/html',-expires => '+0d');

    # probably really want to get these from the config file
    my($path)= $input->param('_path');
    
    my $configfile= $input->param('configfile');

    print "<HTML><HEAD><TITLE>Establish fields for new incident</TITLE></HEAD>\n";

    print <<">>";
<BODY bgcolor="#E7DEBD">
<H1>Establish fields for new incident</H1>
Fill out this form to create a new incident for the labeled alert set "$setname".  Some fields have been filled in based on the alerts.  Please review all fields before creating the incident.<P>
>>

&pipeline_form_start("notempty.pl \$creator \$name|config_inc_flds_db.pl $configfile \$ifieldinfo \$incfile | add_incident_to_db.pl \$ifieldinfo \$incfile | incident_view.pl \$name \$incfile",$path);

print <<">>";
<TABLE BORDER=3>
    <TR>
        <TH>Field</TH>
        <TH>Value</TH>
    </TR>
    <TR>
        <TD ALIGN=right>Incident name</TD>
        <TD ALIGN=left><INPUT NAME="name" VALUE="$setname" SIZE=25></TD>
    </TR>
    <TR>
        <TD ALIGN=right>Your name</TD>
        <TD ALIGN=left><INPUT NAME="creator" SIZE=25></TD>
    </TR>
    <TR>
        <TD ALIGN=right>Alert set name</TD>
        <TD ALIGN=left>$setname<INPUT TYPE=hidden NAME="setname" VALUE="$setname"></TD>
    </TR>
    <TR>
        <TD ALIGN=right>Alert set file location</TD>
        <TD ALIGN=left>$setfile<INPUT TYPE=hidden NAME="setfile" VALUE="$setfile"></TD>
    </TR>
>>

    my($curval,$size);
    foreach $fld (@{$fldorder}) {
        $curval= $input->param($fld);
        $size= (length $curval) + 5;
        $size= 45 unless $size > 45; 
        print <<">>"
    <TR>
        <TD ALIGN=right>$flddescr->{$fld}</TD>
        <TD ALIGN=left><INPUT NAME="$fld" VALUE="$curval" SIZE=$size></TD>
    </TR>
>>
    }
    
    print <<">>";

</TABLE>
<INPUT TYPE="submit" VALUE="Create incident">

<INPUT TYPE=hidden NAME="configfile" VALUE="$configfile">
</FORM>
</BODY>
</HTML>
>>
}

\&process;

# $Id: create_inc_form.pl,v 1.11 2001/10/18 18:23:25 jim Exp $
