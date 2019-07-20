#!/usr/bin/perl

# add_inc_mail_annotation.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# add_inc_mail_annotation.pl is a Pipeline module to record an annotation
#   with an incident that someone just sent mail regarding that incident
# pipeline args: incident file, incident name, template file
# side effect: modifies the incident in the file by adding an annotation

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

sub process {
    require "sisr_utils.pl";
    require "inc_xml.pl";
    my ($input)= shift;

    @_ == 3 || (&reporterr("add_inc_mail_annotation.pl takes 3 arguments (inc file,inc name,templ file), but got:".join(' ',@_),0) && return 0);
    
    my ($file,$incname,$reporttempl,$fldprefix)= &arg_to_val($input,@_);

    my $fld;
    foreach $fld (qw(To Cc Bcc Subject From)) {
        $hdrs{$fld}= $input->param($fld);
    }

    my $tree= &load_XML_tree($file);
    
    my $inc= &find_incident_named($tree,$incname);
    my $note= "Based on template: $reporttempl\nTo: $hdrs{'To'}\n";
    $note.= ("Cc: ".$hdrs{'Cc'}."\n") if $hdrs{'Cc'} !~ /^\s*$/;
    $note.= ("Bcc: ".$hdrs{'Bcc'}."\n") if $hdrs{'Bcc'} !~ /^\s*$/;
    $note.= "Subject: ".$hdrs{'Subject'};
    &add_note_to_incident($inc,$hdrs{'From'},'Mail sent',$note);
    
    &save_XML_tree($tree,$file);
};


\&process;

# $Id: add_inc_mail_annotation.pl,v 1.11 2001/10/18 18:23:25 jim Exp $
