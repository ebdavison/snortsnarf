#!/usr/bin/perl -w

#============================================================================#
# Name: IPAddrContact.pl, distributed as part of Snortsnarf v021111.1
# Author: Joe McAlerney, Silicon Defense, joey@silicondefense.com
# Copyright: (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
#            Released under GNU General Public License, see the COPYING file
#            included with the distribution or
#            http://www.silicondefense.com/snortsnarf/ for details.
# Purpose: This program provides a command line front-end to the 
#          IPAddrContact.pm module. It uses the lookup() function to return
#          one or many email address' of contact persons associated with
#          an Internet address.
# Usage: IPAddrContact.pl [options] <ip address>
#        Where <ip address> may be a FQDN or an address in dotted notation.
# Options: -v - Verbose mode.  Grabs all usefull e-mail addresses associated
#               with an Internet address.
#
# Please send complaints, kudos, and especially improvements and bugfixes to
# joey@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.
#============================================================================#
use IO::Socket;
require "IPAddrContact.pm";

$opt = 0;

if(@ARGV == 0) { 
  print STDERR "Usage: IPAddrContact.pl [options] <IP Address>\n" .
               "OPTIONS: -v verbose mode. Returns multiple addresses and extra information.\n";
  exit;
}

if(@ARGV == 2) {
    $opt = $ARGV[0];
    $opt =~ s/-//;
    $ip = $ARGV[1];
}
else{
    $ip = $ARGV[0];
}

@my_addresses = lookup($ip,$opt);
if($my_addresses[0] eq "0") {
    exit;
}
for($i = 0; $i < @my_addresses; $i++) {
    print $my_addresses[$i];
    if($i < @my_addresses) {             # just to be safe
        if($opt =~ /v/) {
            print " " . $my_addresses[$i+1];
            $i++;
        }
    }
    print "\n";
}

exit;


