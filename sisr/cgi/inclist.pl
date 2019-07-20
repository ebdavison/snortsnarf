#!/usr/bin/perl

# inclist.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# inclist.pl is a CGI script to generate a HTML list of labeled sets in a
#   database given a SISR configuration file.  This simply redirects to a
#   pipeline submit with appropriate args.  This is provided as something
#   easy to link to by programs that do not wish to know much about how
#   SISR works.

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
$incfile= $input->param('incfile');

$path= &get_config_field($configfile,'module-path');
if (defined($incfile)) {
    $url= &pipeline_submit_url("inc_list_view.pl $incfile",$path,'configfile' => $configfile);
} else {
    $url= &pipeline_submit_url("config_inc_flds_db.pl $configfile \$ifieldinfo \$incfile | inc_list_view.pl \$incfile",$path,'configfile' => $configfile);
}
print $input->redirect($url);

1;

# $Id: inclist.pl,v 1.2 2000/06/14 18:39:47 jim Exp $
