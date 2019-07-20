#!/usr/bin/perl
#
# nlog dns wrapper
#
##

require "nlog-config.ph";
umask($umask);

my $results;
my $ipaddr;

printheader("n-log nameserver query results");

print <<HEADER
<strong>Nameserver Query Results
</strong>
<hr size="1" color="#808080"><br><br>

HEADER
;

# Filter out shell escapes and such from the query string


$ipaddr = $ENV{'QUERY_STRING'};
$results = resolveip($ipaddr);
$results =~ s/\</&lt\;/g;
$results =~ s/\>/&gt\;/g;
$results =~ s/\n/<br>/g;

print "<pre>\n$results<pre>\n";

print "</body></html>\n";

sub printheader {

($title) = @_;

print <<THEHEADER
<html>

<head>
<style>
<!--
A:link        { text-decoration: none; }
A:active      { text-decoration: none; }
A:visited     { text-decoration: none; }
A:hover       {COLOR = #FFFF00 }
//-->
</style>
<title>$title</title>
</head>
<body BGCOLOR="#E7DEBD">

THEHEADER
;

}

sub resolveip {
    my $results;
    my ($ip) = @_;
    my $binip = gethostbyname($ip);
    my $oip, $nip;
    
    my ($hostname) = gethostbyaddr($binip,AF_INET);
    if ($hostname && $binip && length($binip) == 4) {
        my $newip = gethostbyname($hostname);
        my ($newhost) = gethostbyaddr($newip,AF_INET);
        
        if ($newip ne $binip || $hostname ne $newhost) {
            $results .= "The re-resolved ip addresses do not match:\n";
            if (length($newip) != 4) 
            {
               $results .= "gethostbyname() returned NULL for $hostname (" . inet_ntoa($binip)  . ").\n";   
            } else {
               $results .= inet_ntoa($binip)  . " ($hostname) is not " . inet_ntoa($newip) . " ($newhost)\n";
            }
        } else {
            $results .= "The address $ip resolved to $hostname (" . inet_ntoa($binip) . ")\n";
        }
    } else {
        if ($binip) {
            $results .= "That address (" . inet_ntoa($binip) . ") has no hostname associated with it.\n";
        } else {
            $results .="That address does not exist.\n";
        }
    }
    return $results;
}

exit 0;

