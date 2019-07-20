#!/usr/bin/perl

# ann_xml.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# ann_xml.pl contains useful functions in working with the annotation base XML.

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program. 

require "xml_help.pl";

# if given an exisiting tree, returns it.  If given undef creates a new tree.
sub create_ann_tree_unless_exists {
    my($tree)= shift;
    if (defined($tree) && @$tree) {
        return $tree;
    } else {
        return ['ANNOTATION-BASE',[{}]];
    }
}

# given a tree and a search type and search key, returns the part of the tree
# for that annotation entry (or undef if there is none currently)
sub annsroot_for_key {
    my($tree,$search_type,$search_key)= @_;
    my @content= @{$tree->[1]};
    shift @content;
    while (@content) {
       $tagname=shift(@content);
       $content=shift(@content);
       next unless $tagname eq 'ANNOTATIONS';
       # content is like [{...}, 'type',[...], 'key',[...], 'annotation',[...], 'annotation',[...],...]
       ($type,$key)= &get_type_and_key($content);
       return $content if $type eq $search_type && $key eq $search_key;
    }
    return undef;
}

# given the content of an ANNOTATIONS entry, return the type and key entries
sub get_type_and_key {
    my($anns)= shift;
    my @content= @{$anns};
    shift @content;
    my($tagname,$content,$type,$key,$info);
    $type= $key= undef;
    @annlist=();
    while (@content) {
        $tagname=shift(@content);
        $info= shift(@content);
        #print "tagname=$tagname; $info=(",join(',',@{$info}),")\n";
        if ($tagname eq 'TYPE') {
            $type= $info->[2];
        } elsif ($tagname eq 'KEY') {
            $key= $info->[2];
        } else {
            next;
        }
    }      
    return ($type,$key);
}

# create a new annotation with the given type, key, author, subject, and note
# and add it to the tree
sub add_new_anns_entry {
    my($root,$type,$key,$author,$subject,$note)= @_;
    my $root_content= $root->[1];
    my $annsroot= [{}, 'TYPE',[{},0,$type], 'KEY',[{},0,$key]];
    push(@{$root_content},'ANNOTATIONS',$annsroot); 
    &append_to_annsroot($annsroot,$author,$subject,$note);
}

# create a new annotation with the given author, subject and note and the
# current time to add to a given ANNOTATIONS root
sub append_to_annsroot {
    my($annsroot,$author,$subject,$note)= @_;
    my(@t)=localtime(time());
    my $date=($t[5]+1900)."/".($t[4]+1)."/$t[3]";
    push(@{$annsroot},'ANNOTATION',[{}, 'AUTHOR',[{},0,$author], 'DATE',[{},0,$date], 'SUBJECT',[{},0,$subject], 'NOTE',[{},0,$note]]);
}

# creates a new annotation with the given type, key, author, subject, and
# note, appending to an existing entry if one exists
sub add_ann {
    my($tree,$type,$key,$author,$subject,$note)= @_;
    my $annsroot= &annsroot_for_key($tree,$type,$key);
    #print "annsroot=$annsroot (",join(',',@{$annsroot}),")\n";
    unless (defined($annsroot)) {
        &add_new_anns_entry($tree,$type,$key,$author,$subject,$note);
    } else {
        &append_to_annsroot($annsroot,$author,$subject,$note);
    }
}

1;

# $Id: ann_xml.pl,v 1.5 2000/06/14 18:39:47 jim Exp $
