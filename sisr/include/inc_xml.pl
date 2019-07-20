#!/usr/bin/perl

# inc_xml.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# inc_xml.pl contains useful functions in working with the incident
#   database XML.

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program. 

require "xml_help.pl";

# if given an exisiting tree, returns it.  If given undef creates a new
# incidents tree.
sub create_tree_unless_exists {
    my($tree)= shift;
    if (defined($tree) && @$tree) {
        return $tree;
    } else {
        return ['INCIDENTS',[{}]];
    }
}

# return all INCIDENT entries in the tree
sub get_all_incidents {
    my($tree)= @_;
    my(@incs)= ();
    my @content= @{$tree->[1]};
    shift @content; # ignore INCIDENTS attrs
    while (@content) {
       my $tagname=shift(@content);
       my $content=shift(@content);
       next unless $tagname eq 'INCIDENT'; # should always be this actually
       push(@incs,$content);
    }
    return @incs;
}

# add an incident to the tree with the given name, creator, set name and set location
sub add_incident {
    my($tree,$incname,$creator,$setname,$setloc)= @_;
    my $inctree=[{'name' => $incname, 'creator' => $creator, 'event-set-name' => $setname, 'event-set-loc' => $setloc, 'created' => time()}];
    push(@{$tree->[1]},'INCIDENT',$inctree);
    return $inctree;
}

# find the incident with the given name in the tree
sub find_incident_named {
    my($tree,$incname)= @_;
    my @content= @{$tree->[1]};
    shift @content; # ignore INCIDENTS attrs
    while (@content) {
       my $tagname=shift(@content);
       my $content=shift(@content);
       next unless $tagname eq 'INCIDENT'; # should always be this actually
       my @inc_trees= @{$content};
       my %inc_attrs= %{shift(@inc_trees)};
       return $content if $inc_attrs{'name'} eq $incname;
    }
    return undef;
}

# return the attributes of the given incident
sub incident_attrs {
    my($inctree)= shift;
    return %{$inctree->[0]};
}

# return two references, one to a list of TEXT-FIELDs in a incident tree and
# the other to a list of NOTEs in the tree
sub incident_fields_and_notes {
    my($tree)= @_;
    return undef unless defined($tree);
    my(@fields)= ();
    my(@notes)= ();
    my @content= @{$tree};
    shift @content; # ignore INCIDENTS attrs
    while (@content) {
        my $tagname=shift(@content);
        my $content=shift(@content);
        if ($tagname eq 'TEXT-FIELD') {
            push(@fields,$content);
        } elsif ($tagname eq 'NOTE') {
            push(@notes,$content);
        }
    }
    return (\@fields,\@notes);
}

# adds a text field wiht the given name, description and value to a given
# incident
sub add_text_field_to_incident {
    my($incroot,$name,$descr,$val)= @_;
    push(@{$incroot},'TEXT-FIELD',[
        {'name' => $name, 'descr' => $descr},
        0,$val
    ]);
}

# adds a new note with the given author, subject and text and the current time
# to the given incident 
sub add_note_to_incident {
    my($incroot,$author,$subject,$note)= @_;
    my(@t)=localtime(time());
    my $date=($t[5]+1900)."/".($t[4]+1)."/$t[3]";
    push(@{$incroot},'NOTE',[
        {'author' => $author, 'date' => $date, 'subject' => $subject},
        0,$note
    ]);
}

# given an reference to an entry for a field (such as that returned by
# incident_fields_and_notes()), return its name, description, and text content
sub get_incident_text_field_info {
    my($fieldtree)= shift;
    my @content= @{$fieldtree};
    my %attrs= %{shift @content};
    return ($attrs{'name'},$attrs{'descr'},$content[1]);
}

# given an reference to an entry for a NOTE (such as that returned by
# incident_fields_and_notes()), return its author, date, subject, and text
sub get_note_info {
    my($notetree)= shift;
    my @content= @{$notetree};
    my %attrs= %{shift @content};
    return ($attrs{'author'},$attrs{'date'},$attrs{'subject'},$content[1]);
}

1;

# $Id: inc_xml.pl,v 1.2 2000/06/14 18:39:47 jim Exp $
