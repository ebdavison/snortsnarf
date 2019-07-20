#!/usr/bin/perl

# load_inc_fields.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# load_inc_fields.pl is a Pipeline module to load the contents of an
#   incident with a give name into form fields
# pipeline args: incident name, incident database file path
# side effect: for each incident field found, sets a like-named form field to the value.  Also loaded are incident name (stored in 'name' field), incident creator ('creator'), labeled set name ('event-set-name'), labeled set db path ('event-set-loc'), and creation time string ('created')

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

sub process {
    require "sisr_utils.pl";
    require "inc_xml.pl";
    my ($input)= shift;
    @_ == 2 || (&reporterr("load_inc_fields.pl takes 2 arguments (inc name,inc file), but got:".join(' ',@_),0) && return 0);
    
    my ($incname,$file)= &arg_to_val($input,@_);

    my $tree= &load_XML_tree($file);
    my $inc= &find_incident_named($tree,$incname);
    my %attrs=&incident_attrs($inc);
    foreach (keys %attrs) {
        my $fld= $_;
        $fld =~ tr/-/_/;
        $input->param($fld,$attrs{$_});
    }
    my($fldsref,$notesref)= &incident_fields_and_notes($inc);
    
    my $fld;
    my($name,$descr,$text);
    foreach $fld (@{$fldsref}) {
        ($name,$descr,$text)= &get_incident_text_field_info($fld);
        $input->param($name,$text);
    }
}

\&process;

# $Id: load_inc_fields.pl,v 1.11 2001/10/18 18:23:25 jim Exp $
