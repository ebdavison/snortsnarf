#!/usr/bin/perl
#
#
# This script converts nmap log files (-m type)
# to a database file that can be used by the
# nlog analyzer scripts.  
#

$logfile = shift;
$outfile = shift;
$version = "1.6.0";
$hostcount = 0;

# usage...
if ($logfile eq "" || $outfile eq "") {
	print "\nnlog v$version by HDM <hdm\@secureaustin.com>\n\n";
        print "usage $0 <logfile> <dbfile>\n";

	exit 1;
}

# open our output file
open(OUTDB, ">>".$outfile) || die "Cant open output file: $!\n";

# open our log file and loop through it by line
open(LOGDATA, $logfile) || die "Can't open log file: $!\n";
while (<LOGDATA>){

 chomp;
 # for OS type, change pipes to ' '
 $_ =~ s/\|/' '/g;

 # remove the commas
 $_ =~ s/\,//g;

 # change Seq Index to SeqIndex
 $_ =~s/Seq\sIndex\:/SeqIndex\:/g;

 #split the line into fields
 (@logline) = split(/\s/,$_);

 $hostcount++;

 # reset variables
 undef $portindex;
 @myports =();
 undef $hostname;
 undef $OS;
 undef $SeqIndex;
 undef $Status;

 foreach $word (@logline) {

  # these are our headers (how we split up the fields)

  $cheader = "HOST" if ($word eq "Host:");
  $cheader = "PORTS" if ($word eq "Ports:");
  $cheader = "SEQ" if ($word eq "SeqIndex:");
  $cheader = "STATUS" if ($word eq "Status:");
  $cheader = "OS" if ($word eq "OS:");

  if ($cheader eq "HOST" && $word ne "Host:" ) {
   @testvar = split('',$word);
   if ($testvar[0] ne '(' ) 
   { 
   	$hostname = $word;   
   
   } else {
   
   	$fqdn = $word;
	$fqdn =~ s/\(//g;
	$fqdn =~ s/\)//g;
	print $fqdn . "\n";
   }
  }

  if ($cheader eq "PORTS" && $word ne "Ports:"  ) {
   (@theport) = split(/\//,$word);
   if ($theport[0] > 0 && $theport[0] < 65536 ) {
    
    # if nmap could not determine what service it was, check our local service list
    if ($theport[3] eq "" ) 
    {
        $service = getservbyport($theport[0], $theport[2]);
        if ($service eq ''){ $service = "unknown"; }
        $theport[3] = $service;
    }

    $portindex++;
    $myports[$portindex] = "$theport[0].$theport[1].$theport[2].$theport[3].$theport[5]";
    # stored in format: port.state.protocol.service.rpc_program_number
   }
  } 

  # Sequence Number Index
  if ($cheader eq "SEQ" && $word ne "SeqIndex:"  ) { $SeqIndex = $word; }

  # Operating System 
  if ($cheader eq "OS" && $word ne "OS:"  ) { $OS = "$OS $word"; }

  # Status
  if ($cheader eq "STATUS" && $word ne "Status:"  ) { $Status = "$Status $word"; }

 # and onward to the next line
 }

 # print the current line of host info

 print( OUTDB "$hostname|$portindex|");
 for($item=0;$item<=$portindex;$item++)  {
  if ($item ne 0) {
   print  OUTDB "$myports[$item]";
   if ($item ne $portindex) {
    print  OUTDB ",";
   }
  }
 }
 $Status =~ s/Smurf\s\(//g; 
 $Status =~ s/\sresponses\)//g;
 $Status =~ s/\s//g;
 print( OUTDB "|$Status|$SeqIndex|$OS\n");

# close and cleanup
}
close LOGDATA;
close OUTDB;

print "nlog v$version:  read $hostcount hosts from $logfile.\n";

exit 0;
