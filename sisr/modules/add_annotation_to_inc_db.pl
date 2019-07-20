#!/usr/bin/perl

# add_annotation_to_inc_db.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# add_annotation_to_inc_db.pl is a Pipeline module to record an annotation
#   with the given author, subject, and note with an incident
# pipeline args: incident file, incident name, author, subject, note
# side effect: modifies the incident in the file by adding an annotation

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

sub process {
    require "sisr_utils.pl";
    require "inc_xml.pl";
    my ($input)= shift;
    @_ == 5 || (&reporterr("add_annotation_to_inc_db.pl takes 5 arguments (inc file,inc name,author,subject,text), but got:".join(' ',@_),0) && return 0);
    
    my ($file,$incname,$author,$subj,$note)= &arg_to_val($input,@_);

    my $tree= &load_XML_tree($file);
    
    my $inc= &find_incident_named($tree,$incname);
    &add_note_to_incident($inc,$author,$subj,$note);
    
    &save_XML_tree($tree,$file);
};


\&process;

# $Id: add_annotation_to_inc_db.pl,v 1.11 2001/10/18 18:23:25 jim Exp $
