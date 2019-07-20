#!/usr/bin/perl

# view_lset.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# view_lset.pl is a CGI script to generate a HTML view of a labeled set in
#   a given file and with a given name.  The config file is given to get
#   pipeline configuration info and for possible use in subsequent scripts.
#   This simply redirects to a pipeline submit with appropriate args.  This
#   is provided as something easy to link to by programs that do not wish to
#   know much about how SISR works and for archiving, where the pipeline
#   configuration could change and this provides a shorter URL.

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

use CGI;
require "sisr_utils.pl";

# get parameters of the invocation
$input= new CGI;
foreach (@ARGV) {  # simulate field input if running on command line
  $input->param(split('=',$_,2));
}
$configfile= $input->param('configfile');
$setname= $input->param('setname');
$setfile= $input->param('setfile');

$path= &get_config_field($configfile,'module-path');
$url= &pipeline_submit_url("lab_set_view.pl $setname $setfile",$path,'configfile' => $configfile);
print $input->redirect($url);

1;

# $Id: lsetlist.pl,v 1.2 2000/06/14 18:39:47 jim Exp $
