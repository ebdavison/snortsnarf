#!/usr/bin/perl

# text4sel.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# text4sel.pl is a CGI script that accepts an ip address in 'ip', an end
#   ('src' or 'dest') in 'end', a re-create string in 'sources' suitable
#   for passing to Input::recreate_input_mods(), and 'include' with 'g' to
#   grab general alerts and 'a' to grab anomaly alerts or 'ga' for both to
#   produce a text file showing the alerts with 'end' 'ip' in 'logs' to in
#   the given files.

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

######################################################################

# avoid needing to refer to SnortSnarf packages as SnortSnarf::*, even if
# that is where they really are:
sub BEGIN { push(@INC,map("$_/SnortSnarf",grep(-d "$_/SnortSnarf",@INC))); }

use CGI;
use Filter;
use Input;
use SnortFileInput;

# get parameters of the invocation
$input= new CGI;
foreach (@ARGV) {  # simulate field input if running on command line
  $input->param(split('=',$_,2));
}

# print out headers
print $input->header('text/plain');

@sources= ();

$end= $input->param('end');
$ip= $input->param('ip');
$sources= $input->param('sources');
if (defined($sources)) {
    @sources= &Input::recreate_input_mods($sources);
}
$logs= $input->param('logs');
if (defined($logs)) {
    push(@sources, SnortFileInput->new({},['all'],$Filter::true,split(',',$logs)));
}
$include= $input->param('include');

#@alerts= &grab_alerts_of_type($ip,$end,$include,@logs);
@alerts= &Input::grab_alerts_of_type_from_mods($ip,$end,$include,@sources);

@atypes= ();
push(@atypes,'standard') if $include =~ /g/;
push(@atypes,'anomaly') if $include =~ /a/;

print "# ip: $ip, end: $end, alert type(s): ",join(', ',@atypes),"\n";
print "# input sources searched: $sources";
print ' ,'.$logs if defined($logs);
print "\n# generated: ".localtime(time())."\n\n";


foreach $alert (@alerts) {
    $text= $alert->as_text();
    $text =~ s/\s+$//;
    print "$text\n";
    print "\n" if $text =~ /\n/; # trail with a newline if spans multiple lines
}
