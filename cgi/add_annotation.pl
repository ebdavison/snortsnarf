#!/usr/bin/perl -w

# add_annotation.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# add_annotation.pl is a CGI script to add an entry to the annotation base
# with type and key given.  This user is returned to the view/add page.

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

use CGI;
use XML::Parser;
require "ann_xml.pl";
require "web_utils.pl";


# get parameters of the invocation
$input= new CGI;
foreach (@ARGV) {  # simulate field input if running on command line
    $input->param(split('=',$_,2));
}
$source_file= $input->param('file');
$Type= $input->param('type');
$Key= $input->param('key');
$Author= $input->param('author');
$Subject= $input->param('subject');
$Note= $input->param('note');

#print $input->header(-header => 'text/plain',-expires => '+0d'); # for debugging

# create a tree representing the XML in the given file
-e $source_file || die "annotation file $source_file does not exist";
$xml= new XML::Parser(Style => 'Tree');
$tree= $xml->parsefile($source_file);

$tree->[0] eq "ANNOTATION-BASE" || die "invalid XML file ($source_file); expected root element to be ANNOTATION-BASE";

&add_ann($tree,$Type,$Key,$Author,$Subject,$Note);
&save_XML_tree($tree,$source_file);

# print out headers to return
print $input->redirect("view_annotations.pl\?".join('&','file='.&url_encode($source_file),'type='.&url_encode($Type),'key='.&url_encode($Key)));



1;

# $Id: add_annotation.pl,v 1.5 2000/06/14 18:39:47 jim Exp $
