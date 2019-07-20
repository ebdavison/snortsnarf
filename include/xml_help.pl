#!/usr/bin/perl

# xml_help.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# xml_help.pl contains useful functions in working with XML.

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program. 

use XML::Parser;

# uses XML::Parser to load the XML tree from the file (or die if the file does
# not exist).  Note that this must load the whole file so might lead to
# scalability problems.
sub load_XML_tree {
    my $source_file= shift;
    # create a tree representing the XML in the given file
    -e $source_file || die "XML file $source_file does not exist";
    my $xml= new XML::Parser(Style => 'Tree');
    return $xml->parsefile($source_file);
}

# save the whole XML tree in a given file.
sub save_XML_tree {
    my($tree,$filename)= @_;
    if (-e $filename) {
        rename($filename,"$filename.bak") || warn "could not make backup of $filename";
    }
    open(F,">$filename") || die "could not create $filename";
    $oldsel= select F;
    &print_XML_tree($tree);
    select $oldsel;
    close F;
}

# print the XML tree to the selected file handle
sub print_XML_tree {
    my(@info)= @{$_[0]};
    while (@info) {
        my $tag= shift(@info);
        if ($tag eq '0') {
            print &encode_text(shift(@info));
        } else {
            my $content= shift(@info);
            my %attrs= %{shift(@{$content})};
            print "<$tag";
            foreach (keys %attrs) {
                print " $_=\"",&encode_attr($attrs{$_}),"\"";
            }
            print ">";
            &print_XML_tree($content);
            print "</$tag>"
        }
    }
}

# encode attribute text to be safe to include in an tag's attribute
sub encode_attr {
    my $text= shift;
    # borrowed from XML::Writer:
    $text =~ s/&/&amp;/g;
    $text =~ s/</&lt;/g;
    $text =~ s/>/&gt;/g;
    $text =~ s/"/&quot;/g;          
    return $text;   
}

# encode text to be safe to include as general text in an XML file
sub encode_text {
    my $text= shift;
    # borrowed from XML::Writer:
    $text =~ s/&/&amp;/g;
    $text =~ s/</&lt;/g;
    $text =~ s/>/&gt;/g;
    return $text;   
}

1;

# $Id: xml_help.pl,v 1.2 2000/06/14 18:39:47 jim Exp $
