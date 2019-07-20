#!/usr/bin/perl

# nmap2html.pl, distributed as part of Snortsnarf v021111.1
# Author: Joe McAlerney, Silicon Defense, joey@silicondefense.com
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# nmap2html.pl is a Nmap log output script to html.  A large amount of code
#   was borrowed from the nlog tool, by spinux.

# Please send complaints, kudos, and especially improvements and bugfixes to
# joey@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.


# grab our parameters from cmd line

$datefile = $ARGV[0];
$dbfile = $ARGV[1];
$cgidir = "/cgi-bin";

if ($dbfile eq "" ) {
        print "Usage: # nmaplog <log2dbfile> [<nmap log file>]\n" .
              "Note: optional second parameter needed to extract the " .
              "scan date and time\n";
        exit 1;
}
# <1> Sean Boran: improve Title
if ($datefile ne "" ) {
   # Unfortunately, log2db.pl does not preserve the scan date and time.
   # We are forced to extract that information out of the original log file.
   open(DATEFILE,"<$datefile") 
       || warn "Can't open $datefile: $!\n";
   $dateline = <DATEFILE>;
    # <1> better title
   while (<DATEFILE>) {  # catch first and last line
     if(/^#\s(.+)\sas/)  {
     $dateline=$dateline . $1 . ",";
     }
     elsif (/^#\sNmap run completed at(.+) scanned in \d+ seconds/) {
     $dateline=$dateline . $1;
     }
   }
   close(DATEFILE);
}
else { 
    # <1> can't get date from DATEFILE; so use today
    $dateline = "Nmap scan results on `date`\n";
}

# open the index.html file, and print header info
open(INDEX,">index.html");
print INDEX      "<html><head>".
                 "<style>\n" .
         "<!--\n" .
         "A:link        { text-decoration: none; }\n" .
         "A:active      { text-decoration: none; }\n" .
         "A:visited     { text-decoration: none; }\n" .
         "A:hover       {COLOR = #FFFF00 }\n" .
         "//-->\n" .
         "</style>\n" .
                 "<title>Nmap scan results" .
                 "</title></head><body bgcolor=\"#E7DEBD\">\n" .
                 "<center>$dateline</center>\n" .
                 "<b>IP Address</b>\n" .
                 "<hr size=\"1\" color=\"808080\">\n";

# open our database and loop through it by line
open(NDB, $dbfile) || die "Can't open database: $!\n";

while (<NDB>){

(@db_parse) = split(/\|/,$_);

$ch_ipaddress = $db_parse[0];
$ch_portnum = $db_parse[1];
$ch_ports = $db_parse[2];
$ch_status = $db_parse[3];
$ch_seqindex = $db_parse[4];
$ch_os = $db_parse[5];

@ch_ports = split(/,/,$ch_ports);

if($ch_ipaddress ne "") {

   open(HOSTFILE,">$ch_ipaddress.html") || die "can't open $ch_ipaddress file\n";

  print INDEX    "<a href=\"$ch_ipaddress.html\">$ch_ipaddress</a><br>\n";
  print HOSTFILE
                 "<html><head>".
                 "<style>\n" .
         "<!--\n" .
         "A:link        { text-decoration: none; }\n" .
         "A:active      { text-decoration: none; }\n" .
         "A:visited     { text-decoration: none; }\n" .
         "A:hover       {COLOR = #FFFF00 }\n" .
         "//-->\n" .
         "</style>\n" .
                 "<title>Nmap scan of host $ch_ipaddress" .
                 "</title></head><body bgcolor=\"#E7DEBD\">\n" .
                 "<center>$dateline</center>\n" .
                 "<hr size=\"1\" color=\"808080\">\n" .
                 "<font size=\"5\">$ch_ipaddress</font>\n" .
                 "<a href=\"$cgidir/nmaplog-dns.pl?$ch_ipaddress\">" .
                 "<small><b> (resolve address)</b></small></a>\n" .
                 "<hr size=\"1\" color=\"808080\">\n";

  printheaders(HOSTFILE);
}


#print ("db_parse = @db_parse\nch_ports = @ch_ports\n");

foreach $port (@ch_ports) {

    @ch_port = split(/\./,$port);
    $cp_num   = $ch_port[0];
    $cp_state = $ch_port[1];
    $cp_proto = $ch_port[2];
    $cp_serv  = $ch_port[3];
        $cp_rpc   = $ch_port[4];

    if ($cp_serv eq "www") {
       $cp_serv = "<font color=\"darkblue\">http</font>";
    }
        elsif ($cp_serv eq "telnet") {
       $cp_serv = "<font color=\"green\">telnet</font>";
        }            
        elsif ($cp_serv eq "ftp") {
       $cp_serv = "<font color=\"purple\">ftp</font>";
        }            
        elsif ($cp_serv eq "NetBIOS") {
       $cp_serv = "<font color=\"red\">NetBIOS</font>";
        }            

        # print the info to the file
        print HOSTFILE "<tr><td>$cp_num</td>\n<td>";
        print HOSTFILE "$cp_proto</td>\n<td>";
        print HOSTFILE "$cp_state</td>\n<td>";
        print HOSTFILE "$cp_serv</td>\n<td>";
        print HOSTFILE "$ch_seqindex</td>\n<td>";
        print HOSTFILE "$ch_os</td></tr>\n";
}

if($ch_ipaddress ne "") {
   print HOSTFILE "</table>" .
                  "<br><a href=\"index.html\">scan index</a>\n" .
                  "</body></html>\n";
}

}
print INDEX "<hr size=\"1\" color=\"808080\">\n" .
            "</body></html>\n";
close NDB;

sub printheaders {

   my $file = shift;
   print $file <<TABLEHEADER

 <table border="1" width="100%">
   <tr>
      <td align="left"><font face="Verdana"><b>port</b></font></td>
      <td align="left"><font face="Verdana"><b>proto</b></font></td>
      <td align="left"><font face="Verdana"><b>state</b></font></td>
      <td align="left"><font face="Verdana"><b>service</b></font></td>
      <td align="left"><font face="Verdana"><b>sequence</b></font></td>
      <td align="left"><font face="Verdana"><b>os matches</b></font></td>
    </tr>

TABLEHEADER
;

} 
exit 0; 













