#!/usr/bin/perl -w

#=============================================================================#
# Name: IPAddrContact.pm, distributed as part of Snortsnarf v021111.1
# Author: Joe McAlerney, Silicon Defense, joey@silicondefense.com
# Copyright: (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
#            Released under GNU General Public License, see the COPYING file
#            included with the distribution or
#            http://www.silicondefense.com/snortsnarf/ for details.
# Created: 5-25-00
# Purpose: This module is a collection of subroutines, centered around the
#          lookup() subroutine. The lookup() subroutine attempts to find the
#          e-mail address of a contact person mapped to an IP address.  It 
#          will query the ARIN, APNIC, and RIPE databases to locate one.
#
# TODO: Implement a way to query other *nic databases.  For now, just be aware
#       that the return results MAY NOT BE THE ADDRESS' YOU ARE LOOKING FOR.
#
# Please send complaints, kudos, and especially improvements and bugfixes to
# joey@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.
#=============================================================================#

use IO::Socket;
my @all_addresses;
my $ip = 0;
my $opt = 0;

#===========================================================================#
# Name: lookup
# Purpose: The lookup() subroutine attempts to find the
#          e-mail address of a contact person mapped to an IP address.  It 
#          will query the ARIN, APNIC, and RIPE databases to locate one.
# Arguments: $ip: The IP address to be queried (FQDN, or dotted)
#            $opt: options that may be passed in by command line
# Return Val: Depending on whether or not the -v argument was used, whois
#             will either return an array containing a single e-mail address,
#             or an multiple e-mail address and description of e-mail
#             address pairs.
# NOTE: If a FQDN is input, we will only query on the first address that is
#       returned from the gethostbyname() call.
#============================================================================#

sub lookup {
    $ip = $_[0];
    $opt = $_[1];

   # Check for FQDN input
   if($ip =~ /^[a-zA-Z]/) {
       (@addrs) = (gethostbyname($ip))[4];
       if(@addrs == 0) {
       print STDERR "** Error: Could not resolve $ip **\n";
       return 0;
       }       
       $ip = join('.', unpack('C4', $addrs[0]));
   }

   $sock = IO::Socket::INET->new(Proto=>"tcp",      
                 PeerAddr=>"whois.arin.net",
                 PeerPort=>"43") || die $!;
   print $sock "$ip\n";                                  # Query ARIN
   @result = <$sock>;
   close $sock;

   my $address = 0;

   if($result[0] =~ /No\sMatch/i) {
       failure($ip);
       return 0;
   }
   elsif(check_apnic_and_ripe($result[0],$ip,\@all_addresses)) {
       return @all_addresses;
   }
   else{  # Handle the ARIN query result
       my $handle = 0;
       my $header = "";
       my $checked_handle = 0;

       # Use the results of the first query to search for a Coordinator
       for($i = scalar(@result) - 1; $i >= 0; $i--) {
       if($result[$i] =~ /.*Coordinator:.*/mi) {
           if($result[$i+1] =~ /\[No mailbox\]/i) { # contact, but no mail
           failure($ip);
           return 0;;
           }
           ($address) = $result[$i+1] =~ /([^\s]+)\s*$/;
               push(@all_addresses,$address);
               if($opt =~ /v/) {
          $header = $result[0];
                  chomp($header);
                  push(@all_addresses,":whois.arin.net:Coordinator under $header");  
               }
           return @all_addresses;
       }
       elsif($result[$i] =~ /.*\((.+)\).*/m) {
           $handle = 1;
       }
       }

       # Sometimes we have to dig deeper to find a Coordinator
     LOOP2: for($i = (scalar(@result)-1); $i >= 0; $i--) {
        # Sometimes a RIPE or APNIC entry will not be the first line
        # in an ARIN query, so we must check EVERY line... bah
         if(check_apnic_and_ripe($result[$i],$ip,\@all_addresses)) {
         ;
             #return @all_addresses;
         }
     elsif($result[$i] =~ /.*\((.+)\).*$ip.*/mi) {
     # This is ideal - a handle on the same line as the ip address
         if($address = grep_contact($1,"whois.arin.net")) {
           $handle = $1;
               push(@all_addresses,$address);
               if($opt =~ /v/) {push(@all_addresses,":whois.arin.net:Coordinator $handle for $ip");}
               else{
                   # I don't really like this part, but I can't seem to
                   # find another way to do it - at least not now.  Basically,
                   # there is a chance that we gather addresses from
                   # different handles (done in the last elsif down there).
                   # When we finally work our way from the bottom - up, we
                   # may find an EXACT match for this ip address.  In that
                   # case, _that_ respective coodinator's e-mail address
                   # will be returned.  So, we wipe out the other addresses
                   # we collected, and return one... pretty inefficient huh?
                   @all_addresses = ($address);
                   return @all_addresses;
               }
               $handle = 0; # because, we don't want to add it again down below
         }
     }
         elsif($result[$i] =~ /(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\s-\s(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)/) # IP address - IP address  (a range of ip's)
     {
             $range = "$1.$2.$3.$4 - $5.$6.$7.$8";

         # If the handle was on the line above, it should already be
         # filled.  But, it could very well be on this same line
         if($result[$i] =~ /.*\((.+)\).*/m) {
         if($address = grep_contact($1,"whois.arin.net")) {
              push(@all_addresses,$address);
                      if($opt =~ /v/) {
             push(@all_addresses,":whois.arin.net:Coordinator for netblock $range");
              }
                      else { return @all_addresses; }
                 }                     
         }
         elsif($i > 0) {  # make sure we don't try to access array[-1]
                 # is this an APNIC or RIPE entry?  We have to check the line
                 # above to see. If so, don't do anything with this IP range.
                 # We'll query APNIC or RIPE in the next loop through.
                 if(($result[$i-1] =~ /Asia\sPacific\sNetwork\sInformation\sCenter.*/mi) || ($result[$i-1] =~ /European\sRegional\sInternet\sRegistry.*/mi)){
                ;                                          # do nothing
                 }
         elsif($result[$i-1] =~ /.*\((.+)\).*/m) {
              if($address = grep_contact($1,"whois.arin.net")) {
               $checked_handle = 1;
                   push(@all_addresses,$address);
                           if($opt =~ /v/) {
                  push(@all_addresses,":whois.arin.net:Coordinator for netblock $range");
                   }
                           else { return @all_addresses; }
                      }
                 }                     
         }
     }
     elsif($result[$i] =~ /.*\((.+)\).*/m) { # a single handle
             # If we haven't queried with this handle yet
             if(!$checked_handle) {
             if($address = grep_contact($1,"whois.arin.net")) {
                    $handle = $1;
                    push(@all_addresses,$address);
                     if($opt =~ /v/) {push(@all_addresses,":whois.arin.net:Coordinator $handle");}
             }       
         }
             else {  # Ok, we won't query.  Reset the flag.
                 $checked_handle = 0;
             }                 
     }
     }  # end LOOP2
   }   
   close $sock;
   return @all_addresses;
}

#============================================================================#
# Name: grep_contact
# Purpose: This function queries a whois server with a supplied argument, and
#          attempts to find a party to contact in the query results.  If one is
#          found, the address is returned.  Otherwise, the function returns 0.
#============================================================================#

sub grep_contact {

   my $arg = $_[0];
   my $whois_server = $_[1];
   my $query_result = \[];  # references array that will store the query result

   if(@_ == 3) {            # was a refrence passed in?
      $query_result = $_[2];
   }
   else {                   # fine then, we'll use our OWN array.
      my @results;
      $query_result = \@results;
   } 

   my $address = 0;
   my ($i,$j);
   my $handle = 0;
   my $sock = IO::Socket::INET->new(Proto=>"tcp",
                                 PeerAddr=>$whois_server,
                                 PeerPort=>"43") || die $!;
   print $sock "$arg\n";
   @$query_result = <$sock>;
   close $sock;

   # Look for a Coordinator in the query results from ARIN
   if($whois_server eq "whois.arin.net") {
      for($i = 0; $i < scalar(@$query_result); $i++) {
         if(@$query_result[$i] =~ /.*Coordinator:.*/mi) {
             ($address) = @$query_result[$i+1] =~ /([^\s]+)$/;
             return $address;
         }
      }
   }
   return 0;
}

#============================================================================#
# Name: query_apnic_or_ripe
# Purpose: This subroutine takes advantage of the common query result format
#          of the RIPE and APNIC databases to search for a contact person
#          for a supplied IP address.
#============================================================================#

sub query_apnic_or_ripe {

   my $ip = $_[0];
   my $whois_server = $_[1];
   my $all_addresses = $_[2];
   my (@query_result,@query_result2);
   my $result;
   my $admin = 0; 
   my $heading = "";
   my $retval = 0;

   my $sock = IO::Socket::INET->new(Proto=>"tcp",
                                 PeerAddr=>$whois_server,
                                 PeerPort=>"43") || die $!;
   print $sock "$ip\n";
   @query_result = <$sock>;
   close $sock;

    # Look for a "notify" or "abuse@" person in RIPE or APNIC results
   for($i = 0; $i < scalar(@query_result); $i++) {
      chomp($query_result[$i]);
      if($query_result[$i] =~ /notify:[\s]+(.+)/mi) {
      push(@$all_addresses,$1);
          if($opt =~ /v/) { 
          push(@$all_addresses,":$whois_server:Notify address under [$heading]");   
          }
          else { return 1; } # If this isn't verbose mode, return on first match
      $retval = 1;          
      }
      elsif($query_result[$i] =~ /\s(abuse\@[^\s]+).*/mi) {
      push(@$all_addresses,$1);
          if($opt =~ /v/) { 
              push(@$all_addresses,":$whois_server:Abuse address under [$heading]");
      }
          else { return 1; }
      $retval = 1;
      }
      elsif($query_result[$i] =~ /admin.*:[\s]+(.+)/mi) {
         if(!$admin) { $admin = $1; }    # only keep the first one
      }
      elsif($query_result[$i] =~ /e-mail:[\s]+(.+)/mi) {
      push(@$all_addresses,$1);
          if($opt =~ /v/) { 
              push(@$all_addresses,":$whois_server:e-mail address under [$heading]");
      }
          else { return 1; }
      $retval = 1;
      }
      elsif($query_result[$i] eq "") {           # blank line?
         if($i < (scalar(@query_result) - 1)) { # don't go out of bounds
             $heading = $query_result[$i+1];
             chomp($heading);
             $heading =~ s/\s+/ /;
         }
      }
   }

   if($admin) { # no notify or abuse, but we did find an admin
      # Not really sure the best way to do this.  If we get here, then we
      # must not have found someone to notify.  Lets look for an "admin",
      # and query again with the admin's handle.  What bothers me is that
      # we potentially already have the admin's e-mail in the body of the
      # original query results.  I'm not sure if any fancy code to extract
      # the correct e-mail will be guarenteed to work every time.  At least
      # querying again will reduce the chance that we get the wrong address.
      #
      
      # query with this admin's handle
      $sock = IO::Socket::INET->new(Proto=>"tcp",
                                    PeerAddr=>$whois_server,
                                    PeerPort=>"43") || die $!;
      print $sock "$admin\n";
      @query_result2 = <$sock>;
      close $sock;
             
      # search for an e-mail address in the query results
      for($j = 0; $j < scalar(@query_result2); $j++) {
          chomp($query_result2[$j]);
          if($query_result2[$j] =~ /e-mail:[\s]+(.+)/mi) {
              push(@$all_addresses,$1);
              if($opt =~ /v/) { 
                  push(@$all_addresses,":$whois_server:Admin's e-mail address under [$heading]");
          }
              else { return 1; } # for non-verbose mode, return on first match
          $retval = 1;
          }
          elsif($query_result2[$j] eq "") {           # blank line?
              if($j < (scalar(@query_result2) - 1)) {
                  $heading = $query_result2[$j+1];
                  chomp($heading);
                  $heading =~ s/\s+/ /;
              }
          }
      }             
   }
   return $retval;
}

#=========================================================================#
# Name: check_apnic_and_ripe
# Purpose: This subroutine checks a line for strings indicating that the
#          address we queried on is registered in the APNIC or RIPE databases.
#          If a line matches the pattern, the appropriate whois server
#          is queried, via the query_apnic_or_ripe subroutine.
#=========================================================================#

sub check_apnic_and_ripe {

   my $line = $_[0];
   my $arg = $_[1];
   my $all_addresses = $_[2];  # array reference to the all_addresses array

   my ($result,$address,$descr);
   
   if($line =~ /Asia\sPacific\sNetwork\sInformation\sCenter.*/mi)
   {
      if(query_apnic_or_ripe($arg,"whois.apnic.net",$all_addresses)) {
      return 1;
      }
      else{
          failure($arg);
      }
   }
   elsif($line =~ /European\sRegional\sInternet\sRegistry.*/mi){
      if(query_apnic_or_ripe($arg,"whois.ripe.net",$all_addresses)) {
           return 1;      
      }
      else{
     failure($arg);
      }
   }
   return 0;
}

sub failure {
    my $ip = $_[0];
    print STDERR "** Error: could not find a contact address for $ip **\n";
}

1;
