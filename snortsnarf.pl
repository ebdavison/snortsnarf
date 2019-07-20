#!/usr/bin/perl -w

# SnortSnarf, a utility to convert snort log files to HTML pages
# Authors: Stuart Staniford, Silicon Defense (stuart@SiliconDefense.com)
#          James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000-2002 by Silicon Defense (http://www.silicondefense.com/)

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.  

# SnortSnarf description:
#
# Code to parse files of snort alerts and portscan logs, and produce
# HTML output intended to allow an intrusion detection analyst to
# engage in diagnostic inspection and tracking down problems.  
# The model is that one is using a cron job or similar to
# produce a daily/hourly/whatever file of snort alerts.  This script
# can be run on each such file to produce a convenient HTML breakout
# of all the alerts.
#
# The idea is that the analyst can click around the alerts instead
# of wearily grepping and awking through them.

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com. This is a quick hack with features added and
# may only be worth what you paid for it.  It is still under active
# development and may change at any time.

# this file (snortsnarf.pl) is part of SnortSnarf v021111.1

##############################################################################

# Usage:

# SnortSnarf.pl <options> <input1 input2 ...>

# The script will produce a directory snfout.file1 (by default) full of
# a large number of html files.  These are placed under the current
# directory.  It also produces a file index.html in that directory.  
# This is a good place to start with a browser.

# The usage file describes the command line options

##############################################################################

# Credits, etc

# Initial alert parsing code borrowed from Joe McAlerney, Silicon 
# Defense.
# A couple of ideas were stolen from Snort2html by Dan Swan.
# Thanks to SANS GIAC and Donald McLachlan for a paper with ideas 
# on how to look up IP addresses.

# Huge thanks to DARPA for supporting us for part of the time developing
# this code.  Major thanks to Paul Arabelo for being our test customer
# while we learned to do operational intrusion detection instead of being
# only a researcher.

# Shouts to Marty Roesch and Patrick Mullen and the rest of the snort
# community for developing snort and the snort portscan preprocessor.  

# Kudos to Steve Northcutt who has taught us all what an intrusion
# detection analyst should be.

# Version control info: $Id: snortsnarf.pl,v 1.16 2000/06/14 18:40:45 jim Exp $

use lib qw(./include);
use Cwd;

# avoid needing to refer to SnortSnarf packages as SnortSnarf::*, even if
# that is where they really are:
sub BEGIN { push(@INC,map("$_/SnortSnarf",grep(-d "$_/SnortSnarf",@INC))); }

use AllMods;
# list here the specific module files we know we need, others will be loaded with AllMods::load_module_named()
use Filter;
use BasicFilters;
use TimeFilters;
use Input;
use SnortRules;
use IPObfuscater;
use HTMLMemStorage;
use HTMLAnomMemStorage;
use HTMLOutput;


$html = 'html';         # usually html or htm
$os = 'unix';  # Either 'windows' or 'unix'



$script = "<a href=\"http://www.silicondefense.com/software/snortsnarf/\">".
                        "SnortSnarf</a>";
$version = "v021111.1";
#$author_email = "hoagland\@SiliconDefense.com";
$author = "<a href=\"mailto:hoagland\@SiliconDefense.com\">Jim Hoagland</a>".
 " and <a href=\"mailto:stuart\@SiliconDefense.com\">Stuart Staniford</a>";

$foot= "<CENTER>$script brought to you courtesy of ".
 "<A HREF=\"http://www.silicondefense.com/\">Silicon Defense</A><BR>\n".
 "Authors: $author<BR>\nSee also the <a href=\"http://www.snort.org/\">".
 "Snort Page</a> by Marty Roesch\n";
$prog_line= "$script $version";

##############################################################################

# input params for SnortFileInput
%SFI_in_params= ('year' => 'rec'); # can also specify alert and packet id sources

# input params for SnortDBInput
%SDI_in_params= (); 

# output params for HTMLOutput
%out_params= (
    'html' => $html,
    'dirsep' => "\/",
    'root' => "\/",
    'logfileext' => '',
    'logfileprototerm' => ':',
    'gmt' => 0,
    'mostsigfirst' => 0, # should the signature with the most alerts appear first (versus last)
    'foot' => $foot, # footer text
    'prog_line' => $prog_line # fixed line of text for the bottom of the header
);



# Main program

@SFIsources= ();
@SDIsources= ();
@dispSFIsources= ();
@dispSDIsources= ();
$rules_file= undef;
$rules_cacheall= 0;

#&AllMods::load_all_modules();
&process_options();
exit 0 if $ss_no_run;

# portability stuff - toggle for Unix/Windows.
if ($os eq 'windows') {
    $dirsep= $out_params{'dirsep'}= "\\";       
    $root= $out_params{'root'}= "e:\\"; # Do not make this your system drive;
                                        # don't want it to fill up
    $out_params{'logfileext'}= '.ids';
    $out_params{'logfileprototerm'}= '_';
    $def_source= $root."util".$dirsep."snort".$dirsep."log".$dirsep."alert.ids"; # default input file
} elsif ($os eq 'unix') {
    $dirsep= $out_params{'dirsep'}= "\/";
    $root= $out_params{'root'}= "\/";
    $out_params{'logfileext'}= '';
    $out_params{'logfileprototerm'}= ':';
    # default input file
    $def_source= $root."var".$dirsep."log".$dirsep."snort.alert"; 
}

&initialize();
@ins= (); # input module instances
%disp_in_sources= (); # input sources

# create SnortFileInput module if needed
if (@SFIsources) {
    &AllMods::load_module_named('SnortFileInput');
    @in_tasks= qw(snort spp_portscan spp_portscan2 spade);
    $in= SnortFileInput->new(\%SFI_in_params,[@in_tasks],$in_filter,@SFIsources);
    $disp_in_sources{'SnortFileInput'}= [@dispSFIsources];
    push(@ins,$in);
    $in_without_filter= SnortFileInput->new(\%SFI_in_params,[@in_tasks],$Filter::true,@SFIsources);
    push(@ins_without_filter,$in_without_filter);
}

# create SnortDBInput module if needed
if (@SDIsources) {
    &AllMods::load_module_named('SnortDBInput');
    @in_tasks= qw(snort spp_portscan spp_portscan2 spade);
    $in= SnortDBInput->new(\%SDI_in_params,[@in_tasks],$in_filter,@SDIsources);
    $disp_in_sources{'SnortDBInput'}= [@dispSDIsources];
    push(@ins,$in);
    $in_without_filter= SnortDBInput->new(\%SDI_in_params,[@in_tasks],$Filter::true,@SDIsources);
    push(@ins_without_filter,$in_without_filter);
}

# strings to recreate the input modules
$in_recreate= Input::stringify_input_mods(@ins);
$in_without_filter_recreate= Input::stringify_input_mods(@ins_without_filter);

# create HTMLMemStorage and HTMLAnomMemStorage storage modules
%store_params= ();
$gstore= HTMLMemStorage->new(%store_params);
$astore= HTMLAnomMemStorage->new(%store_params);
%stores= (  'snort' => $gstore, # where different types are to be stored
            'spp_portscan' => $gstore,
            'spp_portscan2' => $gstore,
            'spade' => $astore);

# go through each input module grabbing all alerts and adding them to the
# approriate storage module
foreach $in (@ins) {
    while ($alert= $in->get()) {
        $stores{$alert->type()}->store($alert);
    }
}

# create HTMLOutput output module
$out= HTMLOutput->new(%out_params);
%output_per_params= ( # output paramaters for a call to "output"
    'insources_str' => $in_recreate,
    'insources_str_noinfilter' => $in_without_filter_recreate,
    'insources' => \%disp_in_sources
);
$out->output(\%output_per_params,%stores);


##############################################################################

# process the command line options and leave @ARGV with just the input files
# at the end
sub process_options
{
    my $arg;
    my(@in_filters)= ();
    my $want_min_prio_filter=0;
    my $min_prio_filter_num;
    @SFIsources= ();
    @SDIsources= ();

    # go through arguments
    while(@ARGV) {
        $arg = shift @ARGV;
        if ($arg eq '-dns') {
            if (!@ARGV || $ARGV[0] !~ /^\d/ ) { $out_params{'dnslookupnet'}= '0.0.0.0'; }
            else { $out_params{'dnslookupnet'} = shift @ARGV; }
        } elsif ($arg eq '-ldir') {
            $out_params{'log_base'} = shift @ARGV;
            $out_params{'log_base'}.='/'
                unless $out_params{'log_base'} =~ /\/$/;
        } elsif ($arg eq '-homenet') {
            $out_params{'homenet'}= shift @ARGV;
        } elsif ($arg =~ s/^-color//) {    
            if ($arg =~ /=(.*)/) {
                $out_params{'color_opt'}= ($1 eq 'yes')?'rotate':$1;
            } else {
                $out_params{'color_opt'}= 'rotate';
            }
        } elsif ($arg =~ s/^-split=//) {    
            $out_params{'split_thresh'}= $arg;
        } elsif ($arg =~ s/^-top=//) {    
            $out_params{'topquant'}= $arg;
        } elsif ($arg eq '-d') {
            $out_params{'output_dir'}= shift @ARGV;
        } elsif ($arg eq '-cgidir') {
            $out_params{'cgi_dir'}= shift @ARGV;
            $out_params{'cgi_dir'}=~ s/\/$//;
        } elsif ($arg eq '-db') {
            $out_params{'db_file'}= shift @ARGV;
        } elsif ($arg eq '-nmapdir') {
            $out_params{'nmap_dir'}= shift @ARGV;
        } elsif ($arg eq '-nmapurl') {
            $out_params{'nmap_url'}= shift @ARGV;
            $out_params{'nmap_url'}.='/'
                unless $out_params{'nmap_url'} =~ /\/$/;
        } elsif ($arg eq '-sisr') {
            $out_params{'sisr_config'}= shift @ARGV;
        } elsif ($arg eq '-rulesfile') {
            $rules_file= shift @ARGV;
        } elsif ($arg eq '-rulesdir') {
            $rules_dir= shift @ARGV;
        } elsif ($arg eq '-rulesscanonce') {
            $rules_cacheall= 1;
        } elsif ($arg eq '-onewindow') {
            $out_params{'onewindow'} = 1;
        } elsif ($arg =~  /^-win/) {
            $os = 'windows';
        } elsif ($arg =~  /^-obfuscateip/) {
            $SFI_in_params{'remapip'}= IPObfuscater->new();
        } elsif ($arg eq '-rs') {
            $out_params{'mostsigfirst'}= 1;
        } elsif ($arg eq '-hiprioisworse') {
            $out_params{'hiprioisworse'}= 1;
        } elsif ($arg eq '-sortsigcount1st') {
            $out_params{'sortsigcountfirst'}= 1;
        } elsif ($arg =~ s/^-minprio(|ity)=//) {
            $want_min_prio_filter=1;
            $min_prio_filter_num=$arg;
        } elsif ($arg =~ s/^-sipin=//) {
            push(@in_filters,HasSourceIPInFilter->new($arg));
        } elsif ($arg =~ s/^-dipin=//) {
            push(@in_filters,HasDestIPInFilter->new($arg));
        } elsif ($arg =~ s/^-mintime=//) {
            my $filter= MinTimeFilter->new($arg);
            unless (defined($filter)) {
                warn "invalid time specification for -mintime: $arg; ignoring -mintime\n";
            } else {
                push(@in_filters,$filter);
            }
        } elsif ($arg =~ s/^-maxtime=//) {
            my $filter= MaxTimeFilter->new($arg);
            unless (defined($filter)) {
                warn "invalid time specification for -mintime: $arg; ignoring -mintime\n";
            } else {
                push(@in_filters,$filter);
            }
        } elsif ($arg =~ s/^-Xsid=//) {
            push(@in_filters,Filter::to_exclude_sids(split(',',$arg)));
        } elsif ($arg =~ s/^-refresh=//) {
            unless ($arg =~ /^\d+\s*$/) {
                warn "\"$arg\" does not look like a number of seconds for use with -refresh; skipping\n";
            } else {
                $out_params{'refreshsecs'}= $arg;
            }
        } elsif ($arg =~ s/^-year=//) {
            $arg= 'rec' if $arg =~ /^rec\w+/;  
            $arg= 'cur' if $arg =~ /^cur\w+/;
            unless ($arg =~ /(rec|cur|\d+)/) {
                warn "year option \"$arg\" not recognized, skipping\n";
            } else {
                $SFI_in_params{'year'}= $arg;
            }
        } elsif ($arg =~ /^-gmt$/) {
            $out_params{'gmt'} = 1;
        } elsif ($arg =~ /^-ymd$/) {
            $out_params{'ymd'} = 1;
        } elsif ($arg eq '-modpath') {
            print "This is the path SnortSnarf will use to look for it's components, in order:\n    ";
            print join("\n    ",map($_.(-e "$_/web_utils.pl" || -e "$_/HTMLOutput.pm"?' *':''),@INC)),"\n";
            print "  A * denotes that you have components in that directory\n";
            print "    (not all component's existance was tested)\n";
            print "  This is based mainly on your Perl include path, e.g., \$PERL5LIB\n";
            $ss_no_run = 1;
        } elsif ($arg eq '-usage' || $arg =~ /^-h($|elp)/ || $arg eq '-?') {
            &usage();
            $ss_no_run = 1;
        } elsif ($arg eq '-v') {
            print "SnortSnarf version $version\n";
            $ss_no_run = 1;
        } elsif ($arg =~ /^-/) {
            warn "Unknown option $arg\n";
        } elsif ($arg =~ /^([\w\-]+|[\w\-]+:.*)@/ && $arg !~ /.log$/) {
            push(@SDIsources,$arg);
        } else {
            push(@SFIsources,$arg);
        }
    }
    
    if ($want_min_prio_filter) {
        if ($out_params{'hiprioisworse'}) {
            unshift(@in_filters,&Filter::for_minprioritynum($min_prio_filter_num));
        } else {
            unshift(@in_filters,&Filter::for_maxprioritynum($min_prio_filter_num));
        }
    }
    if (@in_filters > 1) {
        $in_filter= AndFilter->new(@in_filters);
    } elsif (@in_filters) {
        $in_filter= shift(@in_filters);
    } else {
        $in_filter= $Filter::true;
    }
}

##############################################################################

sub initialize
{
    # Setup to use default file if no args
    unless (@SFIsources || @SDIsources) {
        warn "Warning: no input sources specified, so we are using the default ($def_source); you can remove this warning by explicitly indicating input source(s) you want on the command line\n";
        @SFIsources= ($def_source);
    }
    
    @dispSFIsources= @SFIsources;
    # fully qualify file names for SnortFileInput
    if (@SFIsources) {
        my $cwd= getcwd();
        # fully qualify file names
        if ($os eq 'unix') {
            @SFIsources= map((/^\// ? $_ : "$cwd/$_"),@SFIsources);
        } else {
            $cwd =~ s:/:\\:g; # convert forward slashes in getcwd output to backslashes
            @SFIsources= map((/^\w+\:/ ? $_ : "$cwd$dirsep$_"),@SFIsources);
        }
    }
    
    my $i;
    foreach $i (0 .. $#SDIsources) {
        ($lhs,$rhs)= split('@',$SDIsources[$i],2);
        ($user,$pass)= split(':',$lhs);
        if (!defined($pass)) { # no password provided; prompt for it
            $dispSDIsources[$i]= $SDIsources[$i];
            print STDOUT "Please provide a password for $SDIsources[$i]: ";
            my $pass= <>;
            chomp $pass;
            $SDIsources[$i]= "$user:$pass\@$rhs";
        } else {
            $dispSDIsources[$i]= "$user:$rhs"; # cut out password for display purposes
        }
    }
    
    if (defined($rules_file)) {
        my $rulesource= SnortRules->new($rules_file,$rules_dir,$dirsep,$rules_cacheall);
        $SFI_in_params{'rulessource'}= $rulesource;
        $out_params{'rulessource'}= $rulesource;
    }
}

##############################################################################
sub usage {
    print <<">>";
snortsnarf.pl { OPTION | FILE | user[:passwd][\@dbname\@host[:port] }
FILE is a text file containing snort alerts in full alert, fast alert, syslog,
 portscan log, or portscan2 log format
user[:passwd][\@dbname]\@host[:port] is a Snort database
OPTION is one of the following:
-d <dir>        Set the output directory to <dir>
-win            Run in windows mode (required on Windows)
-hiprioisworse  Consider higher priority #'s to indicate higher priority
-cgidir <URL>   Indicate that SnortSnarf's CGI scripts are in <URL>, for links
-homenet <net>  Match <net> to snort -h <net>.  For -ldir
-ldir <URL>     Enable log linking; <URL> is base URL for the log files
-dns [<net>]    Show hostnames for IPs, or only IPs in <net> (can be slow)
-rulesfile <file>  Set base Snort rules to <file>. For sig. display and X-refs
-rulesdir <dir>  Set current directory for rule files from -rulesfile
-rulesscanonce  Save read Snort rules in memory.  Might save CPU
-db <path>      Enable annotations; <path> is full path to ann. file from CGI
-sisr <file >   Enable incident storage and reporting; <file> is SISR's config
-nmapurl <URL>  Enable linking to nmap2html output; <URL> is base URL
-nmapdir <dir>  For -nmapurl, verify page for IP exists in <dir> before linking
-color=<opt>    Set alert background color scheme. <opt> is yes, no, or rotate
-top=<N>        <N> entries on top source and dest reports are shown
-onewindow      Do not open new browser windows
-rs             Reverse signature listing order, put most interesting first
-refresh=<secs>  Cause pages to refresh every <secs> seconds
-split=<N>      Change split threshold for alert pages to <N>. 0=never split
-obfuscateip    Anonymize IPs by remapping addrs in alerts (file input only)
-ymd            Show dates outside alerts in year/month/day order
-gmt            Show dates outside alerts in your local TZ (for snort -g only)
-minprio=<min>  Don't show alerts with priority higher than <min>
-mintime=<time> Don't show alerts occuring later than <time> (various formats)
-maxtime=<time> Don't show alerts occuring earlier than <time> (var. formats)
-sipin=<net>    Don't show alerts with sources outside <net> (CIDR notation)
-dipin=<net>    Don't show alerts with destinations outside <net> (CIDR)
-Xsid=<sid>[,<sid>]  Don't show alerts with a snort id in the given list
-year=<opt>     Says how to infer an absent alert year; 'cur', 'rec', or a year
-modpath        List SnortSnarf's include search path and where its modules are
-v              Show the version number ($version)
-usage          Shows this information
>>
}