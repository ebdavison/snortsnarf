#!/usr/bin/perl

# add_incident_to_db.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# add_incident_to_db.pl is a Pipeline module to add an incident to an
#   incident file.  The fields mentioned in the incident field info are
#   recorded along with their description from same and with name 'name',
#   creator 'creator', labeled set name 'setname', and set file 'setfile'.
# pipeline args: incident field info, incident file
# side effect: creates the incident in the file

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

sub process {
    require "sisr_utils.pl";
    require "inc_xml.pl";
    my ($input)= shift;
    @_ == 2 || (&reporterr("add_incident_to_db.pl takes 2 arguments (inc field info,inc file), but got:".join(' ',@_),0) && return 0);
    
    my ($incfldinfo,$file)= &arg_to_val($input,@_);

    my ($flddescr,$fldorder)= &decode_fldinfo($incfldinfo);
    my %flddescr= %{$flddescr};

    my $tree= &load_XML_tree($file);
    
    $tree= &create_tree_unless_exists($tree);
    my $inc= &add_incident($tree,$input->param('name'),$input->param('creator'),$input->param('setname'),$input->param('setfile'));
    foreach (@{$fldorder}) {
        &add_text_field_to_incident($inc,$_,$flddescr{$_},$input->param($_));
    }
    
    &save_XML_tree($tree,$file);
};


\&process;

# $Id: add_incident_to_db.pl,v 1.11 2001/10/18 18:23:25 jim Exp $
