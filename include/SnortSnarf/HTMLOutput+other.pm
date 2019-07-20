#!/usr/bin/perl

# HTMLOutput.pm, distributed as part of Snortsnarf v021111.1
# Authors: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
#          Stuart Staniford, Silicon Defense (stuart@SiliconDefense.com)
# copyright (c) 2000,2001 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# HTMLOutput.pm is an implementation of the Output API which produces a set of interlinked HTML pages from alerts, allowing the analyst to conveniently browse through them; see the code below for the many configuration parameters

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

package HTMLOutput;

use Socket;
use Filter;
require "web_utils.pl";

sub BEGIN {
    %defaults= ( # default 'new' params
        'html' => 'html', # file extension for HTML; usually html or htm
        'output_dir' => undef, # root output directory
        'output_url' => undef, # root output directory URL
        'dns_option' => undef, # do DNS lookup if true
        'log_base' => '', # URL prefix for the logging directory
        'homenet' => undef, # string specifying homenet
        'color_opt' => 'rotate', # the color option
        'cgi_dir' => '/cgi-bin', # cgi directory
        'db_file' => '', # annotations database file
        'split_thresh' => 100, # threshold for splitting long alert listings to multiple pages
        'nmap_dir' => undef, # the file directory containing nmap2html pages
        'nmap_url' => undef, # the URL prefix for nmap2html pages
        'sisr_config' => undef, # SISR configuration file
        'rulessource' => undef, # the way to get to the rules source, a SnortRules instance
        'notarget_option' => 0, # if true, keep all pages in one browser window
        'mostsigfirst' => 0, # if true, sort the signature index page to show the signatures with the most alerts first
        'refreshsecs' => undef, # refresh frequency encoding for pages
        'dirsep' => "\/", # path separators for the file system
        'root' => "\/", # root of the file system
        'logfileext' => '', # suffix for log files
        'logfileprototerm' => ':', # the separator following the protocol in log file names
        'foot' => '', # footer text
        'prog_line' => '' # fixed line of text for the bottom of the header
    );
    
    # Various global variables

    # maps the text for ICMP messages found in an alert message to its component
    # in a file name for an snort log of the connection
    %ICMP_text_to_filename= ( 
        'ECHO REPLY' => 'ICMP_ECHO_REPLY',
        'DESTINATION UNREACHABLE: NET UNREACHABLE' => 'ICMP_NET_UNRCH', 
        'DESTINATION UNREACHABLE: HOST UNREACHABLE' => 'ICMP_HST_UNRCH', 
        'DESTINATION UNREACHABLE: PROTOCOL UNREACHABLE' => 'ICMP_PROTO_UNRCH', 
        'DESTINATION UNREACHABLE: PORT UNREACHABLE' => 'ICMP_PORT_UNRCH', 
        'DESTINATION UNREACHABLE: FRAGMENTATION NEEDED' => 'ICMP_UNRCH_FRAG_NEEDED', 
        'DESTINATION UNREACHABLE: SOURCE ROUTE FAILED' => 'ICMP_UNRCH_SOURCE_ROUTE_FAILED', 
        'DESTINATION UNREACHABLE: NET UNKNOWN' => 'ICMP_UNRCH_NETWORK_UNKNOWN', 
        'DESTINATION UNREACHABLE: HOST UNKNOWN' => 'ICMP_UNRCH_HOST_UNKNOWN', 
        'DESTINATION UNREACHABLE: HOST ISOLATED' => 'ICMP_UNRCH_HOST_ISOLATED', 
        'DESTINATION UNREACHABLE: NET ANO' => 'ICMP_UNRCH_NET_ANO',
        'DESTINATION UNREACHABLE: HOST ANO' => 'ICMP_UNRCH_HOST_ANO',
        'DESTINATION UNREACHABLE: NET UNREACHABLE TOS' => 'ICMP_UNRCH_NET_UNR_TOS', 
        'DESTINATION UNREACHABLE: HOST UNREACHABLE TOS' => 'ICMP_UNRCH_HOST_UNR_TOS', 
        'DESTINATION UNREACHABLE: PACKET FILTERED' => 'ICMP_UNRCH_PACKET_FILT', 
        'DESTINATION UNREACHABLE: PREC VIOLATION' => 'ICMP_UNRCH_PREC_VIOL', 
        'DESTINATION UNREACHABLE: PREC CUTOFF' => 'ICMP_UNRCH_PREC_CUTOFF', 
        'DESTINATION UNREACHABLE: UNKNOWN' => 'ICMP_UNKNOWN', 
        'SOURCE QUENCH' => 'ICMP_SRC_QUENCH', 
        'REDIRECT' => 'ICMP_REDIRECT', 
        'ECHO' => 'ICMP_ECHO', 
        'TTL EXCEEDED' => 'ICMP_TTL_EXCEED', 
        'PARAMETER PROBLEM' => 'ICMP_PARAM_PROB', 
        'TIMESTAMP REQUEST'=> 'ICMP_TIMESTAMP', 
        'TIMESTAMP REPLY' => 'ICMP_TIMESTAMP_RPL', 
        'INFO REQUEST' => 'ICMP_INFO_REQ', 
        'INFO REPLY' => 'ICMP_INFO_RPL', 
        'ADDRESS REQUEST'=> 'ICMP_ADDR', 
        'ADDRESS REPLY' => 'ICMP_ADDR_RPL', 
        'UNKNOWN' => 'ICMP_UNKNOWN' 
    );

    # the colors to cycle through for displayed alerts
    @color= ('#E7DEBD','#E0CDD0','#D5E2CE');

    $normbgcol= '#E7DEBD'; # normal background color
    $anombgcol= '#B0E0F0'; # background color for anomaly pages

    $logo_filename= 'SDlogo.gif';
    
    $fhnonce='HOfh00';
}

# API 'new' method to create an instance of HTMLOutput
sub new {
    my($class,%params)= @_;
    
    # debugging output
    # foreach (sort keys %params) {
    #     print "\$params{$_}= ".(defined($params{$_})?$params{$_}:'*undef*')."\n";
    # }

    # is the a CGI directory in use
    $params{'cgiavail'}= defined($params{'cgi_dir'});

    # copy over defaults parameters
    foreach (keys %defaults) {
        $params{$_}= $defaults{$_} unless defined($params{$_});
    }
    
    # calculate/clean up certain other parameters
    $params{'log_base'}.='\/' if $params{'log_base'} ne '' && $params{'log_base'} !~ /\/$/;
    $params{'nmap_url'}.='\/' if defined($params{'nmap_url'}) && $params{'nmap_url'} !~ /\/$/;
    $params{'color_opt'}= 'rotate' if $params{'color_opt'} eq 'yes';
    $params{'cgi_dir'} =~ s/\/$//;
 
    # set up homenet mask and address parameters
    my $homenet= delete $params{'homenet'};
    if (defined($homenet)) {
        my($addr,$bits)= split('/',$homenet);
        my(@bytes)= split('\.',$addr);
        warn "HTMLOutput: $homenet does not seem to be a valid homenet, but proceeding\n" if (@bytes <= 1 || @bytes > 4);
        $params{'homenetaddr'}= &bytenums2bits(@bytes);
        unless (defined($bits)) {
            if ($addr =~ /^0\.0\.0\.0$/) {
                $bits= 0;
            } elsif ($addr =~ /\.0\.0\.0$/) {
                $bits= 8;
            } elsif ($addr =~ /\.0\.0$/) {
                $bits= 16;
            } elsif ($addr =~ /\.0$/) {
                $bits= 24;
            } else {
                $bits= 32;
            }
        }
        my (@bytembits)= ();
        foreach (1..4) {
            if ($bits <= 0) {
                push(@bytembits,0);
            } else {
                $bits-= 8;
                if ($bits >= 0) {
                    push(@bytembits,255);
                } else {
                    push(@bytembits,(0x80,0xC0,0xE0,0xF0,0xF8,0xFC,0xFE)[$bits+7]);
                }
            }
        }
        $params{'homenetmask'}= &bytenums2bits(@bytembits);
        $params{'homenetaddr'} &= $params{'homenetmask'};
    }

    # initial storage used across multiple calls to 'output'
    $params{'signum'}= 0;
    $params{'signame'}= {};
    $params{'sig1link'}= {};
    $params{'siglinks'}= {};
    $params{'long_siglinks'}= {};

    return bless \%params, $class;
}

# API 'output' method to produce a complete set of HTML pages
sub output {
    my($self,$params,%sources)= @_;
    
    # debugging output
    # foreach (sort keys %{$params}) {
    #     print "\$params->{$_}= ".(defined($params->{$_})?$params->{$_}:'*undef*')."\n";
    # }

    # 'cur' section will only survive for this call to output and can be used for temporary storage or data to be shared across multiple functions

    # move the two defined parameters to 'cur'
    $self->{'cur'}{'insources_str'}= $params->{'insources_str'}; # encoded input recreation string to be given to external scripts
    $self->{'cur'}{'insources'}= $params->{'insources'}; # input sources in the form of {input module => [source1,source2], ...} to list for reporting on web pages
    
    # choose a representative input source for the title string and default output directory
    my $in_mod= defined($params->{'insources'}{'SnortFileInput'}) ? 'SnortFileInput' : (keys %{$params->{'insources'}})[0];
    my $repr_insource= $params->{'insources'}{$in_mod}[0];
    my $count= 0;
    foreach (keys %{$params->{'insources'}}) {
        $count+= $params->{'insources'}{$_};
        last if $count > 1;
    }
    my $multi= ($count > 1);

    foreach (qw(foot prog_line mostsigfirst output_url)) { # copy params over from "new" params unless provided
        $self->{'cur'}{$_}= defined($params->{$_}) ? $params->{$_} : $self->{$_};
    }
    # set up the output directory paths
    $self->{'cur'}{'g'}{'outdir'}= defined($params->{'outdir'}) ? $params->{'outdir'} : $self->{'output_dir'};
    unless (defined($self->{'cur'}{'g'}{'outdir'})) {
        $repr_insource =~ /([^$self->{'dirsep'}]+)$/; # extract file name from path
        $self->{'cur'}{'g'}{'outdir'}= "snfout.".$1;
    }
    $self->{'cur'}{'a'}{'outdir'}= $self->{'cur'}{'g'}{'outdir'}.$self->{'dirsep'}.'anomrep';

    # set up the title string
    if ($multi) {
        $self->{'cur'}{'insources_titlestr'}= $repr_insource;
    } else {
        $self->{'cur'}{'insources_titlestr'}= $repr_insource." et al";
    }
    # produce some HTML to describe all the input sources
    my @html= ();
    foreach $in_mod (keys %{$params->{'insources'}}) {
        push(@html,"$in_mod, with sources:\n<font size=\"-1\"><ul>\n<li>".join("\n<li>",@{$params->{'insources'}{$in_mod}})."\n</ul></font>\n");
    }
    if (@html > 1) {
        $self->{'cur'}{'insources_html'}= "using the input modules:\n<UL><LI>".join("\n<LI>",@html)."\n</UL>\n";
    } else {
        $self->{'cur'}{'insources_html'}= "using input module $html[0]";
    }

    # set up for same_in_otherrun.pl
    if ($self->{'cgiavail'} && defined($self->{'cur'}{'output_url'})) {
         && $self->{'cur'}{'output_url'} ne '/'
    
    }


    # find all anom stores and all general stores
    my @astores= ();
    my @gstores= ();
    my %gadded= ();
    my $store;
    foreach (keys %sources) {
        $store= $sources{$_};
        if ($_ eq 'spade') {
            push(@astores,$store);
        } else {
            unless ($gadded{$store}) {
                push(@gstores,$sources{$_});
                $gadded{$store}= 1;
            }
        }
    }
    # consolidate the respective stores if needed
    if (@astores > 1) {
        $astores[0]= MultiStore->new(@astores); # we are not adding, so don't care in what order the stores are in
    }
    $self->{'cur'}{'a'}{'store'}= $astores[0];
    if (@gstores > 1) {
        $gstores[0]= MultiStore->new(@gstores); # we are not adding, so don't care in what order the stores are in
    }
    $self->{'cur'}{'g'}{'store'}= $gstores[0];

    # make the output directory
    if(-e $self->{'cur'}{'g'}{'outdir'}) {
        $self->clear_dir($self->{'cur'}{'g'}{'outdir'});
    } else {
        mkdir($self->{'cur'}{'g'}{'outdir'},0755);
    }
    
    # debugging output
#     foreach (sort keys %{$self}) {
#         print "\$self->{$_}= ".(defined($self->{$_})?$self->{$_}:'*undef*')."\n";
#     }
#     foreach (sort keys %{$self->{'cur'}}) {
#         print "\$self->{'cur'}{$_}= ".(defined($self->{'cur'}{$_})?$self->{'cur'}{$_}:'*undef*')."\n";
#     }
#     foreach (sort keys %{$self->{'cur'}{'g'}}) {
#         print "\$self->{'cur'}{'g'}{$_}= ".(defined($self->{'cur'}{'g'}{$_})?$self->{'cur'}{'g'}{$_}:'*undef*')."\n";
#     }
#     foreach (sort keys %{$self->{'cur'}{'a'}}) {
#         print "\$self->{'cur'}{'a'}{$_}= ".(defined($self->{'cur'}{'a'}{$_})?$self->{'cur'}{'a'}{$_}:'*undef*')."\n";
#     }
        
    # produce the output files!
    $self->write_logo_file($self->{'cur'}{'g'}{'outdir'},$logo_filename);
    $self->gen_general_pages();
    $self->gen_anom_pages() if $self->{'cur'}{'a'}{'store'}->count($Filter::true) > 0;

    delete $self->{'cur'};
}

##############################################################################

# produce the general pages
sub gen_general_pages {
    my $self= shift;
    
    $self->{'cur'}{'bgcol'}= $normbgcol;
    $self->{'cur'}{'logo_url'}= $logo_filename;
    $self->make_sig_indexes();
    $self->output_main_sig_page();
    
    # if there are any alerts, make the signature and IP pages
    if ($self->{'cur'}{'g'}{'store'}->count($Filter::true) > 0) {
        $self->output_per_sig();
        $self->output_per_source();
        $self->output_per_dest();
    }
}

##############################################################################

# give each signature html, cannonical internal names and sets of links
sub make_sig_indexes {
    my $self= shift;
    my($sig,@refs,$first,$last,$refstr,$id,$url,$cite,$text,$longtext,$name,$html);
    my $store= $self->{'cur'}{'g'}{'store'};
    foreach $sig ($store->alert_field_set($Filter::true,'message')) {
        unless (defined($self->{'signame'}{$sig})) {
            $html= &sightml($sig);
            $text= '';
            $longtext= '';
            if ($sig ne '*undef*') {
                ($first,$last)= $store->first_last(AlertFieldEq->new("message=$sig"),$Sort::bytime); # get an alert of with this signature
            } else {
                ($first,$last)= $store->first_last($Filter::nosig,$Sort::bytime); # get an alert of with no signature
            }
            next unless defined($first);
            #$first->debug_print();
            @refs= sort $first->references();
            if (@refs) {
                ($id,$url)= $first->reference($refs[0]);
                $name= $self->signame($refs[0],$id);
                $self->{'sig1link'}{$sig}= "<A HREF=\"$url\"".$self->target('siginfo').">$html</A>";
                
                foreach $cite (@refs) {
                    my ($id,$url)= $first->reference($cite);
                    if (defined($url) && $url =~ /^\w+:/) { # a URL available
                        $text.= "<A HREF=\"$url\"".$self->target('siginfo').">[".&cite_text($cite,$id)."]</A> ";
                        $longtext.= "<A HREF=\"$url\"".$self->target('siginfo').">[".&long_cite_text($cite,$id)."]</A> ";
                    }
                }
                chop $text;
                chop $longtext;
            } else {
                $name= $sig ne '*undef*' ? ++$self->{'signum'} : 'undef';
                $self->{'sig1link'}{$sig}= $html;
            }
            $self->{'signame'}{$sig}= $name;

            $self->{'sightml'}{$sig}= $html;
            $self->{'siglinks'}{$sig}= $text;
            $self->{'long_siglinks'}{$sig}= $longtext;
        }
    }
    my %usedname=();
    foreach (keys %{$self->{'signame'}}) {
        $name= $self->{'signame'}{$_};
        if (defined($usedname{$name})) { # need to find a n\ew name since overlaps
            do {
                $usedname{$name}++;
            } while ($usedname{$name.'-'.$usedname{$name}});
            $self->{'signame'}{$_}= $name.'-'.$usedname{$name};
        } else {
            $usedname{$name}= 1;
        }
    }
}

# return the signature as it should be inserted in out HTML output
sub sightml {
    return '(no sig)' if $_[0] eq '*undef*';
    $_= shift;
    s/&/&amp;/g;
    s/</&lt;/g;
    s/>/&gt;/g;
    s/\"/&quot;/g;
    return $_;
}

# return a unique name for a signature based on a certain citation and id
sub signame {
    my($self,$cite,$id)= @_;
    if ($cite eq 'arachnids') {
        return "IDS$id";
    } elsif ($cite eq 'cve') {
        return $id;
    } elsif ($cite eq 'bugtraq') {
        return "BID$id";
    } elsif ($cite eq 'url') {
        return 'url'.++$self->{'signum'};
    } else {
        return &cite_text($cite,$id)."-$id";
    }
}

# return the long version of some text describing a citation and ID
sub long_cite_text {
    my($cite,$id)= @_;
    if ($cite eq 'url') {
        return "url:$id";
    } else {
        return &cite_text($cite,$id).":$id";
    }
}

# return the short version of some text describing a citation (with ID)
sub cite_text {
    my($cite,$id)= @_;
    my $text;
    if ($cite eq 'arachnids') {
        return 'arachNIDS';
    } elsif ($cite eq 'cve') {
        return 'CVE';
    } elsif ($cite eq 'bugtraq') {
        return 'BUGTRAQ';
    } elsif ($cite eq 'mcafee') {
        return 'McAfee';
    } elsif ($cite eq 'url' && $id =~ m|^(\w+\:/?/?)?(([\w+\-]+\.)+\w+)|) {
        $text= $2;
    } else {
        $text= $cite;
    }
    return defined($text) ? $text : '';
}
##############################################################################

# produce the main signature index page
sub output_main_sig_page {
    my($self)= shift;
    my $store= $self->{'cur'}{'g'}{'store'};
    my $sig;
    my $page_h2 = "All Snort signatures";
    my $page_title = "SnortSnarf: Snort signatures in $self->{'cur'}{'insources_titlestr'}";

    my $PAGE=$self->open_file($self->{'cur'}{'g'}{'outdir'},$self->siglist_page());
    select($PAGE);
    my $base;
    $self->{'cur'}{'base'}= $base=&siglist_base();
    $self->print_page_head($page_title,'start page',$page_h2);
    my $gcount= $store->count($Filter::true);
    print "$gcount alerts found ".$self->{'cur'}{'insources_html'};
    if ($gcount) {
        my($earliest,$latest)= $store->first_last($Filter::true,$Sort::bytime);
        print "Earliest alert at ".&pretty_time(&earliest_packet($earliest))."<br>\n";
        print "Latest alert at ".&pretty_time(&latest_packet($latest))."</p>\n";
    }
    
    my $acount= $self->{'cur'}{'a'}{'store'}->count($Filter::true);
    if ($acount) {
        print "<p>The ".$acount." reports from the <A HREF=\"http:\/\/www.silicondefense.com/spice/\">Spade anomaly sensor</A> are in a separate section: <A HREF=\"$base"."anomrep/\">visit it</a></p>\n";
    }

    if ($self->{'cgiavail'}) {
        my $url= $self->otherrun_url('sigindex','');
        print "<p><A HREF=\"$url\">Find other SnortSnarf runs</A>\n";
    }
    if ($gcount) {
        print "<TABLE BORDER CELLPADDING = 5>\n";
        print "<TR><TD>Signature (click for sig info)</TD><TD>\# Alerts</TD>".
                    "<TD>\# Sources</TD><TD>\# Destinations</TD><TD>Detail link</TD></TR>\n";

        my %sig_count= $store->alert_field_multiset($Filter::true,'message');
        my @sigs= $self->{'cur'}{'mostsigfirst'} ?
            (sort {$sig_count{$b} <=> $sig_count{$a}} keys %sig_count) :
            (sort {$sig_count{$a} <=> $sig_count{$b}} keys %sig_count);
        foreach $sig (@sigs) {
            my $sigfilter= &Filter::for_sig($sig);
            my $siglinks= $self->{'siglinks'}{$sig};
            print "<TR><TD>",$self->{'sightml'}{$sig};
            if (length($siglinks)) {
                print " $siglinks";
            }
            print "</TD><TD>$sig_count{$sig}</TD><TD>".
                    $store->distinct_packet_fields($sigfilter,'sip')."</TD><TD>".
                    $store->distinct_packet_fields($sigfilter,'dip').
                    "</TD><TD><a href=\"$base".$self->sig_page($self->{'signame'}{$sig})."\">Summary</a></TD></TR>\n";
        }
        print "</TABLE>\n\n";
    }
    
    if ($self->{'db_file'} ne '') {
        print "<FORM ACTION=\"$self->{'cgi_dir'}/view_annotations.pl\"><INPUT TYPE=hidden NAME=\"file\" VALUE=\"$self->{'db_file'}\">View/add annotations of type <SELECT NAME=\"type\">";
        foreach ('IP','network','snort message') {
            print "<OPTION VALUE=\"$_\"> $_";
        }
        print "</SELECT> for key : <INPUT NAME=\"key\" SIZE=15><INPUT TYPE=\"submit\" VALUE=\"View\"></FORM>";
    }

    $self->print_page_foot();
    close($PAGE);
}

sub otherrun_url {
    my($self,$pagetype,$pageinfo)= @_;
    return "$self->{'cgi_dir'}/same_in_otherrun.pl\?".join('&', 'basedir='.&url_encode($self->{'basedir'}), 'baseurl='.&url_encode($self->{'baseurl'}), 'pagetype='.&url_encode($pagetype), 'pageinfo='.&url_encode($pageinfo), 'dirsep='.&url_encode($self->{'dirsep'})));
}

##############################################################################

# output the page for each signature
sub output_per_sig {
    my $self= shift;
    my($sig,$sig_file,$src,$dest,$early,$late);
    my $page_title;
    my $store= $self->{'cur'}{'g'}{'store'};

    my %sig_count= $store->alert_field_multiset($Filter::true,'message');
    my %sip_count= $store->packet_field_multiset($Filter::true,'sip'); # overall count of packet for ip
    my %dip_count= $store->packet_field_multiset($Filter::true,'dip');
    foreach $sig (keys %sig_count) {
        my $sigfilter= &Filter::for_sig($sig);
        # Sort out the file
        my $PAGE=$self->open_file($self->{'cur'}{'g'}{'outdir'},$self->sig_page($self->{'signame'}{$sig}));
        select($PAGE);

        # Print page head stuff
        $page_title = "Summary of alerts in $self->{'cur'}{'insources_titlestr'} for signature: ".($sig ne '*undef*'?$sig:'(no sig)');
        my $base;
        $self->{'cur'}{'base'}= $base=&sig_base($self->{'signame'}{$sig});
        $self->print_page_head($page_title,'signature page',$self->{'sig1link'}{$sig});
        #print "<h3>$self->{'sig1link'}{$sig}</h3>";
        print "<p>".$sig_count{$sig}." alerts with this signature ".$self->{'cur'}{'insources_html'};

        my($earliest,$latest)= $store->first_last($sigfilter,$Sort::bytime);
        print "Earliest such alert at ".&pretty_time(&earliest_packet($earliest))."<br>\n";
        print "Latest such alert at ".&pretty_time(&latest_packet($latest))."</p>\n";

        my %src_count= $store->packet_field_multiset($sigfilter,'sip');
        my $num_srcs= scalar(keys %src_count);
        my %dest_count= $store->packet_field_multiset($sigfilter,'dip');
        my $num_dests= scalar(keys %dest_count);
        
        # print page head table stuff
        print "<table border cellpadding = 3>\n";
        print "<tr><td>",$self->{'sightml'}{$sig},"</td>\n";
        print "<td><A HREF=#srcsect>$num_srcs sources</A></td>\n";
        print "<td><A HREF=#destsect>$num_dests destinations</A></td></tr>\n";
        if (length($self->{'long_siglinks'}{$sig})) {
            print "<tr><td colspan=3>",$self->{'long_siglinks'}{$sig},"</td></tr>\n";
        }
        if ($self->{'db_file'} ne '') { #link to annotations
            print "<tr><td colspan=3 align=center><A HREF=\"",$self->view_ann_url('snort message',$sig),"\">View/add annotations for this signature</A></td></tr>\n";
        }
        if (defined($self->{'rulessource'}) && $earliest->type() eq 'snort') { # by using $earliest, assumes messages do not overlap between types; we only want pure snort messages and not e.g., spp_portscan
            # show rule file entries for signature
            my(@rules_html)= $self->get_rules_html_for_sig($sig);
            if (@rules_html) {
                print "<tr bgcolor=\"#D5E2CE\"><td colspan=3 align=center>Rules with message \"",$self->{'sightml'}{$sig},"\":</td></tr>\n";
                foreach (@rules_html) {
                    print "<tr bgcolor=\"#D5E2CE\"><td colspan=3 align=left>$_</td></tr>\n";
                }
            }
        }
        print "</table>";

        # Print the sources section
        print "<hr><h3><A NAME=srcsect>Sources triggering this attack signature</A></h3>\n";
        print "<TABLE BORDER CELLPADDING = 5>\n";
        print "<tr><td>Source</td><td>\# Alerts (sig)</td>".
                    "<td>\# Alerts (total)</td><td>\# Dsts (sig)</td>".
                    "<td>\# Dsts (total)</td></tr>\n";
        foreach $src (sort {$src_count{$b} <=> $src_count{$a}} keys %src_count) {
#print STDOUT "$sig; printing src $src\n";
            my $anysip_filter= &Filter::for_anysip($src);
            print "<tr><td><a href=\"$base".$self->host_page($src,'src')."\">".&ip_text($src)."</a></td>".
                "<td>$src_count{$src}</td>".
                "<td>".$sip_count{$src}."</td><td>".
                $store->distinct_packet_fields(&Filter::for_sig_anysip($sig,$src),'dip')."</td><td>".
                $store->distinct_packet_fields($anysip_filter,'dip')."</td></tr>\n";
        }
        print "</TABLE>\n";
#print STDOUT "done with sources\n";
        
        # Print the destinations section
        print "<hr><h3><A NAME=destsect>Destinations receiving this attack signature</A></h3>\n";
        print "<TABLE BORDER CELLPADDING = 5>\n";
        print "<tr><td>Destinations</td><td>\# Alerts (sig)</td>".
                "<td>\# Alerts (total)</td><td>\# Srcs (sig)</td>".
                "<td>\# Srcs (total)</td></tr>\n";
        foreach $dest (sort {$dest_count{$b} <=> $dest_count{$a}} keys %dest_count) {
#print STDOUT "$sig; printing dest $dest\n";
            my $anydip_filter= &Filter::for_anydip($dest);
            print "<tr><td><a href=\"$base".$self->host_page($dest,'dest')."\">".&ip_text($dest)."</a></td>".
                "<td>$dest_count{$dest}</td>".
                "<td>".$dip_count{$dest}."</td><td>".
                $store->distinct_packet_fields(&Filter::for_sig_anydip($sig,$dest),'sip')."</td><td>".
                $store->distinct_packet_fields($anydip_filter,'sip')."</td></tr>\n";
        }
        print "</TABLE>\n"; 
        $self->print_page_foot();
        close($PAGE);
    }
}

##############################################################################

# make a page for each source IP
sub output_per_source
{
    my($self)= shift;
    my($src);
 
    foreach $src ($self->{'cur'}{'g'}{'store'}->packet_field_set($Filter::true,'sip')) {
        $self->{'cur'}{'ip'}= $src;
        $self->{'cur'}{'end'}= 'src';
        $self->{'cur'}{'type'}= 'g';
        $self->{'cur'}{'filter'}= &Filter::for_anysip($src);
        $self->output_per_host("from ".&ip_text($src));
    }
}

##############################################################################

# make a page for each destination IP
sub output_per_dest
{
    my($self)= shift;
    my($dest);

    foreach $dest ($self->{'cur'}{'g'}{'store'}->packet_field_set($Filter::true,'dip')) {
        $self->{'cur'}{'ip'}= $dest;
        $self->{'cur'}{'end'}= 'dest';
        $self->{'cur'}{'type'}= 'g';
        $self->{'cur'}{'filter'}= &Filter::for_anydip($dest);
        $self->output_per_host("going to ".&ip_text($dest));
    }
}

##############################################################################

# produce the anomaly section
sub gen_anom_pages {
    my($self)= shift;
    my $outdir= $self->{'cur'}{'a'}{'outdir'};

    $self->{'cur'}{'bgcol'}= $anombgcol;
    $self->{'cur'}{'logo_url'}= "../$logo_filename";

    # clear the anomaly output directory if it exists
    if (-e $outdir) {
        $self->clear_dir($outdir);
    }
    unless (-e $outdir && -d $outdir) {
        mkdir($outdir,0755) || die "could not make directory $outdir for the anomaly report section";
    }
    
    my $page_title = "Snortsnarf: Main Spade report page for $self->{'cur'}{'insources_titlestr'}";

    my $PAGE= $self->open_file($outdir,$self->anomindex_page());
    select($PAGE);
    $self->{'cur'}{'base'}= &anomindex_base();
    $self->print_page_head($page_title,'Spade report main page',$self->{'cur'}{'a'}{'store'}->count($Filter::true).' anomaly reports');
    $self->output_anom_header();
    $self->print_page_foot();
    close($PAGE);

    $self->output_all_anom_page("score",$Sort::byhighestanom);
    $self->output_all_anom_page("time",$Sort::bytime);
    $self->output_anom_src_page();
    $self->output_anom_dest_page();
    $self->output_anom_per_source();
    $self->output_anom_per_dest();
}

##############################################################################
# make a page listing all anomaly alerts
sub output_all_anom_page {
    my($self,$sortbytext,$sorter)= @_;
    # args are:
    # + the text for "sorted by..."
    # + a sorter module to use to sort the alerts
    my @alerts= $self->{'cur'}{'a'}{'store'}->list($Filter::true,$sorter);
    my $num_alerts= @alerts;
    my $PAGE= $self->open_file($self->{'cur'}{'a'}{'outdir'},$self->anomall_page($sortbytext));
    my $prevsel= select($PAGE);
        
    $self->{'cur'}{'base'}= &anomall_base($sortbytext);
    $self->print_page_head("All $num_alerts Anomaly reports, sorted by $sortbytext",'Spade report listing',"All $num_alerts reports sorted by $sortbytext");
    $self->output_anom_header();
    $self->output_alert_table(\@alerts);
    
    $self->print_page_foot();
    close($PAGE); select($prevsel);
}

##############################################################################
# display the pages with anomaly source IPS
sub output_anom_src_page
{
    my $self= shift;
    my $store= $self->{'cur'}{'a'}{'store'};
    my $PAGE= $self->open_file($self->{'cur'}{'a'}{'outdir'},$self->anomsrcs_page());
    select($PAGE);

    # Print page head stuff
    my $page_title = "Source IPs of anomaly reports in ".$self->{'cur'}{'insources_titlestr'};
    my $base;
    $self->{'cur'}{'base'}= $base= &anomsrcs_base();
    $self->print_page_head($page_title,'Spade report IP list','All source IPs');
    $self->output_anom_header();
    
    my %anom_src_count= $store->packet_field_multiset($Filter::true,'sip');
    my $ipcount= keys %anom_src_count;
    print "<p>$ipcount distinct source IPs are present in the anomaly reports.</p>\n";

    # Print the sources section
    print "<hr><h3>Source IPs in anomaly reports</h3>\n";
    print "<TABLE BORDER CELLPADDING = 5>\n";
    print "<tr><td>Source</td><td>\# Alerts</td>".
                "<td>\# Anom Dsts</td>".
                "<td>\# Other Alerts </td></tr>\n";
    my $src;
    foreach $src (sort {$anom_src_count{$b} <=> $anom_src_count{$a}} keys %anom_src_count) {
        my $anysip_filter= &Filter::for_anysip($src);
        print "<tr><td><a href=\"$base".$self->host_page($src,'src')."\">".&ip_text($src)."</a></td>".
            "<td>$anom_src_count{$src}</td><td>".
            $store->distinct_packet_fields($anysip_filter,'dip')."</td>".
            "<td>".$self->{'cur'}{'g'}{'store'}->count($anysip_filter)."</td></tr>\n";
    }
    print "</TABLE>\n";
        
    $self->print_page_foot();
    close($PAGE);
}

# display the pages with anomaly destination IPS
sub output_anom_dest_page
{
    my $self= shift;
    my $store= $self->{'cur'}{'a'}{'store'};
    my $PAGE= $self->open_file($self->{'cur'}{'a'}{'outdir'},$self->anomdests_page());
    select($PAGE);

    # Print page head stuff
    my $page_title = "Destination IPs of anomaly reports in $self->{'cur'}{'insources_titlestr'}";
    my $base;
    $self->{'cur'}{'base'}= $base= &anomdests_base();
    $self->print_page_head($page_title,'Spade report IP list','All destination IPs');
    $self->output_anom_header();
    
    my %anom_dest_count= $store->packet_field_multiset($Filter::true,'dip');
    my $ipcount= keys %anom_dest_count;
    print "<p>$ipcount distinct destination IPs are present in the anomaly reports.</p>\n";

    # Print the dests section
    print "<hr><h3>Destination IPs in anomaly reports</h3>\n";
    print "<TABLE BORDER CELLPADDING = 5>\n";
    print "<tr><td>Destination</td><td>\# Alerts</td>".
                "<td>\# Anom Srcs</td>".
                "<td>\# Other Alerts </td></tr>\n";
    my $dest;
    foreach $dest (sort {$anom_dest_count{$b} <=> $anom_dest_count{$a}} keys %anom_dest_count) {
        print "<tr><td><a href=\"$base".$self->host_page($dest,'dest')."\">".&ip_text($dest)."</a></td>".
            "<td>$anom_dest_count{$dest}</td><td>".
            $store->distinct_packet_fields(&Filter::for_anydip($dest),'sip')."</td>".
            "<td>".$self->{'cur'}{'g'}{'store'}->count(&Filter::for_anydip($dest))."</td></tr>\n";
    }
    print "</TABLE>\n";
        
    $self->print_page_foot();
    close($PAGE);
}

##############################################################################

# make a page for each anomaly source IP
sub output_anom_per_source
{
    my $self= shift;
    my($src);
 
    foreach $src ($self->{'cur'}{'a'}{'store'}->packet_field_set($Filter::true,'sip')) {
        $self->{'cur'}{'ip'}= $src;
        $self->{'cur'}{'end'}= 'src';
        $self->{'cur'}{'type'}= 'a';
        $self->{'cur'}{'filter'}= &Filter::for_anysip($src);
        $self->output_per_host("from ".&ip_text($src));
    }
}

# make a page for each anomaly destination IP
sub output_anom_per_dest
{
    my $self= shift;
    my($dest);
 
    foreach $dest ($self->{'cur'}{'a'}{'store'}->packet_field_set($Filter::true,'dip')) {
        $self->{'cur'}{'ip'}= $dest;
        $self->{'cur'}{'end'}= 'dest';
        $self->{'cur'}{'type'}= 'a';
        $self->{'cur'}{'filter'}= &Filter::for_anydip($dest);
        $self->output_per_host("to ".&ip_text($dest));
    }
}

##############################################################################

# print out the anomaly specific header
sub output_anom_header {
    my ($self)= @_;
    my $totcount= $self->{'cur'}{'a'}{'store'}->count($Filter::true);
    print "$totcount anomaly reports found ".$self->{'cur'}{'insources_html'};
    $self->output_anom_pagelist();
}

# print out the list of top-level anomaly section pages with links
sub output_anom_pagelist {
    my $self= shift;
    my $base= $self->{'cur'}{'base'};
    my $store= $self->{'cur'}{'a'}{'store'};
    my $srccount= $store->distinct_packet_fields($Filter::true,'sip');
    my $destcount= $store->distinct_packet_fields($Filter::true,'dip');
    print "There are 4 top level pages for alerts produced by the <A HREF=\"http:\/\/www.silicondefense.com/spice/\">Spade anomaly sensor</A>:\n<UL>";
    print "<LI><A HREF=\"$base".$self->anomall_page('score')."\">All alerts sorted by score\n";
    print "<LI><A HREF=\"$base".$self->anomall_page('time')."\">All alerts sorted by time\n";
    print "<LI><A HREF=\"$base".$self->anomsrcs_page()."\">A list of the $srccount source IP addresses in the alerts\n";
    print "<LI><A HREF=\"$base".$self->anomdests_page()."\">A list of the $destcount destination IP addresses in the alerts\n";
    print "</UL>\n<P><A HREF=\"$base../\">See also the main signature page</A>\n";
}

##############################################################################

# make page(s) listing the alerts for an IP address
sub output_per_host {
    my($self,$al_descr,$alfilter)= @_;
    # this is a very general function.  The args are:
    # + the description of the alerts
    # + the filter to apply to the storage module
    # in addition, these are obtained from $self->{'cur'}:
    #   ip: the IP address the page is about
    #   end: the end this page is about ('src' or 'dest')
    #   type: the type of page to produce ('g' or 'a')
    #   filter: the filter to use (to select the host with the end
    my $ip= $self->{'cur'}{'ip'};
    my $end= $self->{'cur'}{'end'};
    my $type= $self->{'cur'}{'type'};
    my $outdir= $self->{'cur'}{$type}{'outdir'};
    my $thresh= $self->{'split_thresh'};
    #print STDOUT "starting host page for $type $end $ip\n";
    
    my @alerts= $self->{'cur'}{$type}{'store'}->list($self->{'cur'}{'filter'},$Sort::bytime);
    #print STDOUT "alerts for $type $end $ip are (",join(',',@alerts),")\n";
    my $num_alerts= @alerts;
    my $ip_file = $self->host_page($ip,$end);
    $self->{'cur'}{'base'}= $host_base= &host_base($ip,$end);
    my $PAGE= $self->open_file($outdir,$ip_file);
    my $prevsel= select($PAGE);
    
    $al_descr= ($type eq 'g'?'':'anomaly ')."alerts $al_descr in ".$self->{'cur'}{'insources_titlestr'};
    my $page_type= $self->alert_type_text($type)."alert page";
    my $end_ip;
    if ($end eq 'src') {
	    $end_ip= "Source: <EM>".&ip_text($ip)."</EM>";
    } else {
	    $end_ip= "Destination: <EM>".&ip_text($ip)."</EM>";
    }
    if ($thresh == 0 || $num_alerts <= $thresh) {
        # start the page
        $self->print_page_head("All $num_alerts $al_descr",$page_type,$end_ip);
        $self->output_per_host_header($alerts[0],$alerts[$#alerts],$num_alerts);
        $self->output_alert_table(\@alerts);
    } else {  # need to split
        # make the page containing the overview the alerts
        $self->print_page_head("Overview of $num_alerts $al_descr",$page_type,"$end_ip: overview");
        $self->output_per_host_header($alerts[0],$alerts[$#alerts],$num_alerts);

        my $all_file = $self->host_page($ip,$end,'all');

        print "<hr>This listing contains $num_alerts alerts.  You can:\n";
        print "<UL><LI><A HREF=\"$host_base$all_file\">view the whole listing</A>\n";
        print "<LI>view a range of alerts <A HREF=#rangelist>(see table below)</A></UL>\n";

        print "<hr><A NAME=rangelist>Alert ranges (sorted by time):</A>\n";
        print "<table border cellpadding = 3><TR align=center><B><TD>alert #'s</TD><TD>first time</TD><TD>last time</TD></B></TR>\n";
        my($first,$last);
        foreach ($first=1; $first <= $num_alerts; $first+=$thresh) { # segment the alerts
            $last= $first+$thresh-1;
            $last= $last < $num_alerts ? $last : $num_alerts;
            my(@alertsub)= @alerts[($first-1)..($last-1)];
            my $early= $alertsub[0];
            my $late= $alertsub[$#alertsub];
            my $range_file = $self->host_page($ip,$end,$first);
            # print this to the "all" page
            print "<tr><td><A HREF=\"$host_base$range_file\">$first to $last</A></td><td>",&pretty_time(&earliest_packet($early)),"</td><td>",&pretty_time(&latest_packet($late)),"</td></tr>\n";

            # create page for the range
            my $RANGE=$self->open_file($outdir,$range_file);
            my $prevsel= select($RANGE);
            $self->print_page_head("$first to $last of $num_alerts $al_descr",$page_type,"$end_ip: #$first-$last");
            $self->output_per_host_header($early,$late);
            print "<hr>";
            my $nav= "Go to: ".
                ($first == 1?'':"<A HREF=\"$host_base".$self->host_page($ip,$end,($first-$thresh))."\">previous range</A>, ").
                (($first+$thresh >= $num_alerts)?'':"<A HREF=\"$host_base".$self->host_page($ip,$end,($first+$thresh))."\">next range</A>, ").
                " <A HREF=\"$host_base$all_file\">all alerts</A>, <A HREF=\"$host_base$ip_file\">overview page</A>";
            print $nav;
            $self->output_alert_table(\@alertsub);
            print $nav;
            $self->print_page_foot();
            close($RANGE); select($prevsel);
        }       
        print "</table>\n";
        
        # now make the page for all the alerts
        my $ALL= $self->open_file($outdir,$all_file);
        my $prevsel= select($ALL);
        $self->print_page_head("All $num_alerts $al_descr",$page_type,$end_ip);
        $self->output_per_host_header($alerts[0],$alerts[$#alerts],$num_alerts);
        my $nav= "Go to: <A HREF=\"$host_base$ip_file\">overview page</A>";
        print $nav;
        $self->output_alert_table(\@alerts);
        print $nav;
        $self->print_page_foot();
        close($ALL); select($prevsel);
    }
    
    # finish the page we started with
    $self->print_page_foot();
    close($PAGE); select($prevsel);
}

##############################################################################

# make the header section at the top of a host page
sub output_per_host_header
{
    my ($self,$early,$late,$num_alerts)= @_;
    # the args are:
    # + the earliest alert for the page
    # + the latest alert
    # + the number of alerts this page is about (optional)
    # in addition, these are obtained from $self->{'cur'}:
    #   ip: the IP address the header is about
    #   end: the end this page is about ('src' or 'dest')
    #   type: the type of page to produce ('g' or 'a')
    my $ip= $self->{'cur'}{'ip'};
    my $end= $self->{'cur'}{'end'};
    my $type= $self->{'cur'}{'type'};
    my $base= $self->{'cur'}{'base'}; # path to the base directory of this page type
    
    $store= $self->{'cur'}{$type}{'store'};
    my %filter;
    $filter{'src'}= &Filter::for_anysip($ip);
    $filter{'dest'}= &Filter::for_anydip($ip);
    
    if (defined($num_alerts)) {
        print (0+$num_alerts);
        print " such alerts found ";
    } else {
        print "Looking ";
    }
    print $self->{'cur'}{'insources_html'};     
    print "<br>Earliest: ".&pretty_time(&earliest_packet($early))."<br>\n";
    print "Latest: ".&pretty_time(&latest_packet($late))."\n<P>";
    
    $self->output_host_siglist() if $type eq 'g';
    
    my $distinct_ips= ($end eq 'src') ?
            $store->distinct_packet_fields($filter{'src'},'dip')." distinct destination" :
            $store->distinct_packet_fields($filter{'dest'},'sip')." distinct source";
    print "There are $distinct_ips IPs in the alerts of the type on this page.<P>\n";

    $self->output_anom_pagelist() if $type eq 'a';
    
    # start the table and get the width
    print "<table border cellpadding = 3>\n";
    my $cols= $self->print_ip_lookup($ip);
    $cols= 3 if $cols < 3;

    # find the relative paths to the general and anomaly directories
    my(%path);
    if ($type eq 'g') {
        $path{'g'}= $base;
        $path{'a'}= "$base"."anomrep/";
    } else {
        $path{'g'}= "$base../";
        $path{'a'}= $base;
    }
    
    my(@seealso)= (); # make a list of "see also"s that we want
    my($count,$t,$e);
    my %ttext= ('g' => 'alert', 'a' => 'anomaly');
    my %etext= ('src' => 'source', 'dest' => 'destination');
    my @othertypes= (); # the other types of alerts with same IP and end?  (used by SISR links)
    foreach $t (qw(g a)) {
        foreach $e (qw(src dest)) {
            unless (($type eq $t) && ($end eq $e)) {
                $count= $self->{'cur'}{$t}{'store'}->count($filter{$e});
                if ($count > 0) {
                    push(@othertypes,$t) if $end eq $e;
                    push(@seealso,"<A HREF=\"$path{$t}".$self->host_page($ip,$e)."\">an $ttext{$t} $etext{$e}</A> [$count alerts]");
                }
            }
        }
    }
    if (@seealso == 1) { # print this with one row
        print "<tr bgcolor=\"#E0CDD0\"><td align=center colspan=$cols>See also ",&ip_text($ip)," as $seealso[0]</td></tr>\n";
    } elsif (@seealso) { # make a common first 2 columns and distinct last columns
        my $colwidth=$cols-2;
        print "<tr bgcolor=\"#E0CDD0\"><td rowspan=".(0+@seealso)." align=center colspan=2>See also ",&ip_text($ip)," as:</td>";
        print "<td colspan=$colwidth align=left>$seealso[0]</td></tr>\n";
        foreach (@seealso[1..$#seealso]) {
            print "<tr bgcolor=\"#E0CDD0\"><td colspan=$colwidth align=left>$_</td></tr>\n";
        }
    }
    
    if ($self->{'db_file'} ne '') {
        # generate links to annotations
        print "<tr><td colspan=$cols align=center><A HREF=\"",$self->view_ann_url('IP',$ip),"\">View/add annotations for this IP address</A></td></tr>\n";
        if ($ip ne '*undef*') {
	        $ip =~ /^(\d+\.\d+\.\d+)/;
	        my $netkey= "$1.0/24";
	        print "<tr><td colspan=$cols align=center><A HREF=\"",$self->view_ann_url('network',$netkey),"\">View/add annotations for $netkey</A></td></tr>\n";
	        $ip =~ /^(\d+\.\d+)/;
	        $netkey= "$1.0.0/16";
	        print "<tr><td colspan=$cols align=center><A HREF=\"",$self->view_ann_url('network',$netkey),"\">View/add annotations for $netkey</A></td></tr>\n";
        }
    }
    
    if (defined($self->{'nmap_url'}) && ($ip ne '*undef*') && (!defined($self->{'nmap_dir'}) || -e "$self->{'nmap_dir'}/$ip.html")) {
        # generate links to the corresponding nmap2html page
        print "<tr bgcolor=\"#DDDDDD\"><td colspan=$cols align=center><A HREF=\"$self->{'nmap_url'}$ip.html\">View nmap log page for $ip".(defined($self->{'nmap_dir'})?'':' (if any)')."</A></td></tr>\n";
    }
    
    my $endip= (($end eq 'src') ? "from " : "to ").&ip_text($ip);
    my $typefulldescr= $self->alert_type_text($type)."alerts $endip";
    if ($self->{'cgiavail'} && ($ip ne '*undef*')) {
        print "<td colspan=$cols align=center><A HREF=\"$self->{'cgi_dir'}/text4sel.pl?".join('&',"end=$end","ip=$ip","include=$type",'sources='.&url_encode($self->{'cur'}{'insources_str'})).'"',">Fresh grab of all $typefulldescr (as text)</A></td></tr>\n";
    }
    
    if (defined($self->{'sisr_config'}) && ($ip ne '*undef*')) {
        # make links to SISR
        my $encconfig= &url_encode($self->{'sisr_config'});
        # we want to "create" links if there are some anom entries and some normal ones for this IP and end 
        my $showcreate2= @othertypes;
        my $rows= 3+ ($showcreate2 ? 1 : 0);
        my $colwidth=$cols-1;
        print "<tr bgcolor=\"#D5E2CE\"><td rowspan=$rows align=center>Incident handling</td>";
        my $linktext= "Add some of the $typefulldescr to a labeled set";
        print "<td colspan=$colwidth align=center><A HREF=\"$self->{'cgi_dir'}/sel_to_add.pl?".join('&',"configfile=$encconfig","end=$end","ip=$ip",'include='.($type eq 'g'?'g':'a'),'sources='.&url_encode($self->{'cur'}{'insources_str'})).'"',$self->target('sisrwin'),">$linktext</A></td></tr>\n";
        if ($showcreate2) {
            $linktext= "Add some of both type alerts $endip to a labeled set";
            print "<tr bgcolor=\"#D5E2CE\"><td colspan=$colwidth align=center><A HREF=\"$self->{'cgi_dir'}/sel_to_add.pl?".join('&',"configfile=$encconfig","end=$end","ip=$ip",'include=ga','sources='.&url_encode($self->{'cur'}{'insources_str'})).'"',$self->target('sisrwin'),">$linktext</A></td></tr>\n";
        }
        print "<tr bgcolor=\"#D5E2CE\"><td colspan=$colwidth align=center><A HREF=\"$self->{'cgi_dir'}/lsetlist.pl?configfile=$encconfig\"",$self->target('sisrwin'),">List stored sets</td></tr>\n";
        print "<tr bgcolor=\"#D5E2CE\"><td colspan=$colwidth align=center><A HREF=\"$self->{'cgi_dir'}/inclist.pl?configfile=$encconfig\"",$self->target('sisrwin'),">List stored incidents</td></tr>\n";
    }
    print "</table>\n";
}

# print a list of the signatures to or from an IP and their frequency
sub output_host_siglist {
    my($self)= @_;
    my $ip= $self->{'cur'}{'ip'};
    my $end= $self->{'cur'}{'end'};
    my(%sigcount)= $self->{'cur'}{'g'}{'store'}->alert_field_multiset($self->{'cur'}{'filter'},'message');
    my @sigs= keys %sigcount;
    print 0+@sigs," different signatures are present for <EM>",&ip_text($ip),"</EM> as a ",($end eq 'src' ? 'source' : 'destination'),"\n<UL>";
    foreach (sort {$sigcount{$a} <=> $sigcount{$b}} @sigs) {
        print "<LI>$sigcount{$_} instances of <a href=\"".$self->{'cur'}{'base'}.$self->sig_page($self->{'signame'}{$_})."\"><EM>",$self->{'sightml'}{$_},"</EM></A></LI>\n";
    }
    print "</UL>";
}

sub ip_text {
    return $_[0] ne '*undef*' ? $_[0] : "(no IP)";
}

sub alert_type_text {
    return $_[0]->{'cur'}{'a'}{'store'}->count($Filter::true)?(($_[1] eq 'g')?'standard ':'anomaly '):'';
}


# return a URL to view annotations for and type and key
sub view_ann_url {
    my($self,$type,$key)= @_;
    $key= 'undef' if $key eq '*undef*';
    return "$self->{'cgi_dir'}/view_annotations.pl\?".join('&', 'file='.&url_encode($self->{'db_file'}), 'type='.&url_encode($type), 'key='.&url_encode($key));
}


##############################################################################

# output a table of alerts
sub output_alert_table {
    my($self,$alertsref)= @_;
    $old_alert= undef; # init color rotation
    print "<HR>";
    print "<table border cellpadding = 3>\n";
    for (my $i=0; $i <= $#{$alertsref}; $i++) {
        $self->output_table_entry($alertsref->[$i]);
     }
    print "</table>\n";
}

# output a table entry for a given alert
sub output_table_entry { 
    my($self,$alert)= @_;
    my $tdopts= $self->{'color_opt'} eq 'rotate'?" bgcolor=".&alert_color($alert):'';
    print "<tr><td$tdopts>".$self->alert_as_html($alert)."</td></tr>\n";
}

##############################################################################

# find a color to use as the background for an alert
sub alert_color { 
    my($alert)= @_;
    return $color[$old_color] if (defined($old_alert) && (($old_alert->message() eq $alert->message()) || defined($alert->anom())) && &same_sets([$old_alert->packet_fields('sip')],[$alert->packet_fields('sip')]) && &same_sets([$old_alert->packet_fields('dip')],[$alert->packet_fields('dip')]));
    $::old_color= ++$::old_color % +@color;
    $::old_alert= $alert;
    return $color[$::old_color];
}

sub same_sets {
    my($list1,$list2)= @_;
    my($found,$e);
    foreach $e (@{$list1}) {
        $found= 0;
        foreach (@{$list2}) {
            if ($e eq $_) {
                $found=1;
                last
            }
        }
        return 0 unless $found;
    }
    return 1;
}

##############################################################################

# make an alert into HTML
sub alert_as_html { 
    my($self,$alert)= @_;
    my $base= $self->{'cur'}{'base'};
    $append= '';
    $text= $alert->{'text'};
    my $sig= $alert->message();
    if ($alert->type() ne 'spade' && defined($sig)) {
        my $sigre= $sig;
        $sigre =~ s/([^\w ])/\\$1/g;
        $sigurl= $self->sig_page($self->{'signame'}{$sig});
        $text =~ s/(\[\*\*\]\s*)($sigre)(\s*\[\*\*\])/$1<a href=\"$base$sigurl\">$2<\/A>$3/;
    }
    if ($text =~ /:\d+ \->/) {
        my $newwindow = $self->target('lookup'); # Port lookup code contrib by Mike Biesele
        $text =~ s/(\d+\.\d+\.\d+\.\d+):(\d+) ->/"<A HREF=\"$base".$self->host_page($1,'src')."\">$1<\/A>:<A HREF=\"http:\/\/www.snort.org\/database\/portsearch3.asp?port=$2\" $newwindow>$2<\/A> ->"/e;
        $text =~ s/->(\s*)(\d+\.\d+\.\d+\.\d+):(\d+)/"->$1<A HREF=\"$base".$self->host_page($2,'dest')."\">$2<\/A>:<A HREF=\"http:\/\/www.snort.org\/Database\/portsearch.asp?Port=$3\" $newwindow>$3<\/A>"/e;
    } else {
        $text =~ s/(\d+\.\d+\.\d+\.\d+)(.*)->/"<A HREF=\"$base".$self->host_page($1,'src')."\">$1<\/A>$2->"/e;
        $text =~ s/->(\s*)(\d+\.\d+\.\d+\.\d+)/"->$1<A HREF=\"$base".$self->host_page($2,'dest')."\">$2<\/A>"/e;
    }
    $text =~ s/[\n\r]+/<br>/g;

    if ($self->{'log_base'} ne '') {
        my $url= $self->get_alert_logpage($alert);
        $append.= " <A HREF=\"$url\">[Snort log]</A>\n" if defined($url);
    } 
    return "<code>$text</code>$append";
}

##############################################################################

# text to add to use a given locatation as a target link or '' if -onewindow was given
sub target {
    return '' if $_[0]->{'notarget_option'};
    return " target=$_[1]";
}

##############################################################################

# given a snort message, generate HTML for each snort rule with the given msg.
sub get_rules_html_for_sig {
    my ($self,$sig)= @_;
    return map("<SMALL>".$_->text()."</SMALL> (from <EM>".$_->location()."</EM>)",$self->{'rulessource'}->get_rules_for_msg($sig));
}

##############################################################################

# return the page in the full snort logs that corresponds to a given alert, provided the alert is from snort and the alert contains enough info (e.g., the protocol)
sub get_alert_logpage {
    my($self,$alert)=@_;
    return undef if $alert->type() eq 'spp_portscan'; # no log for portscan alerts
    my @pkts= $alert->packets();
    return undef if @pkts != 1;
    my $pkt= $pkts[0];
    
    my $src=$pkt->sip();
    my $dest=$pkt->dip();
    my $proto=$pkt->protocol();
    return undef unless defined($proto) && defined($src) && defined($dest);
    my $sport=$pkt->sport();
    my $dport=$pkt->dport();
    my ($ip,$port1,$port2);

    my $srcishome= $self->in_homenet($src);
    my $destishome= $self->in_homenet($dest);

    if (defined($sport) && defined($dport)) {
	    if ($destishome && !$srcishome) {
	        $ip= $src;
	    } elsif ($srcishome && !$destishome) {
	        $ip= $dest;
	    } elsif ($sport >= $dport) {
	        $ip= $src;
	    } else {
	        $ip= $dest;
	    }
	    if ($sport >= $dport) {
	        $port1= $sport;
	        $port2= $dport;
	    } else {
	        $port1= $dport;
	        $port2= $sport;
	    }
    } else {
	    if ($srcishome && !$destishome) {
	        $ip= $dest;
	    } else {
	        $ip= $src;
	    }
    }
    
    # win32 version of snort uses different file name; contrib by silverdragon
    if ($proto eq 'ICMP') {
        my $ICMP_type= $pkt->flags();
        return undef unless defined($ICMP_type);
        print STDOUT "Warning: \"$ICMP_type\" text not found in \%ICMP_text_to_filename table\n" unless defined($ICMP_text_to_filename{$ICMP_type});
        return $self->{'log_base'}.$ip.'/'.$ICMP_text_to_filename{$ICMP_type}.$self->{'logfileext'};
    } elsif (defined($sport) && defined($dport)) {
        my $prototext= ($proto eq 'UDP')?'UDP':'TCP';
        return $self->{'log_base'}.$ip."/".$prototext.$self->{'logfileprototerm'}.$port1."-".$port2.$self->{'logfileext'};
    } else {
        return undef;
    }

}

##############################################################################

# print the line of a table to look up an IP address in whois databases;
# returns the number of columns used
sub print_ip_lookup
{
    my($self,$ip) = @_;
 
    return 0 unless defined($ip) && $ip ne '*undef*'; # no IP to look up
    
    my $host= undef;
    $host= gethostbyaddr(inet_aton($ip), AF_INET) if defined $self->{'dns_option'};
    
    my $target= $self->target('lookup');
    print "<tr><td rowspan=2>$ip</td>\n";
    print "<td rowspan=2>($host)</td>\n" if defined $host;
    print "<td>Whois lookup at:</td>\n";
    print "<td><a href=\"http://www.arin.net/cgi-bin/whois.pl".
                "?queryinput=$ip&B1=Submit+Query\"$target>ARIN</a></td>\n";
    print "<td><a href=\"http://www.ripe.net/cgi-bin/whois".
                "?query=$ip&.=Submit+Query\"$target>RIPE</a></td>\n";
    print "<td><a href=\"http://www.apnic.net/apnic-bin/whois.pl".
                "?search=$ip\"$target>APNIC</a></td>\n";
    print "<td><a href=\"http://www.geektools.com/cgi-bin/proxy.cgi".
                    "?query=$ip&targetnic=auto\"$target>Geektools</a></td>\n";
                    # thanks to Dr. Paul Mitchell for this add
    print "</tr>\n<tr>\n";
    print "<td>DNS lookup at:</td>\n";
    my(@ipparts)= split(/\./,$ip);
    print "<td><a href=\"http://www.amnesi.com/hostinfo/ipinfo.jhtml?Search=Lookup+Name&wholeIp=$ip&ip1=".$ipparts[0]."&ip2=".$ipparts[1]."&ip3=".$ipparts[2]."&ip4=".$ipparts[3]."\"$target>Amenesi</a></td>\n";
    # GET method doesn't work: print "<td><a href=\"http://www.infiltration.net/cgi-bin/dnsptr.cgi?ipaddr=$ip\"$target>Infiltration</a></td>\n";
    print "<td><a href=\"http://andrew.triumf.ca/cgi-bin/gethost?$ip\"$target>TRIUMF</a></td>\n";
    # 404'ing: print "<td><a href=\"http://riherds.com/cgi-bin/cgiwrap/riherds/rns?ip=$ip\"$target>Riherds</a></td>\n";
    print "<td><a href=\"http://wwwnet.princeton.edu/cgi-bin/dnslookup.pl?verbose=on&type=any&target=$ip\"$target>Princeton</a></td>\n";
#    print "<td><a href=\"http://wwwnet.princeton.edu/cgi-bin/dnslookup.pl?advanced_output=on&target=$ip\"$target>Princeton</a></td>\n";
    print "</tr>\n";
    return 6 + (defined $host ? 1: 0); # (number of cols used)

#                alias jpnic  "/usr/ucb/whois -h whois.nic.ad.jp"
#                alias aunic  "/usr/ucb/whois -h whois.aunic.net"
#                alias milnic "/usr/ucb/whois -h whois.nic.mil"
#                alias govnic "/usr/ucb/whois -h whois.nic.gov"
#                alias krnic  "/usr/ucb/whois -h whois.krnic.net"
}

##############################################################################

# prints out a standard SnortSnarf HTML header
sub print_page_head {
    my($self,$page_title,$page_type,$page_h2) = @_;
    
    print "<html>\n<head>\n";
    print "<title>$page_title</title>\n";
    print "<META HTTP-EQUIV=\"refresh\" CONTENT=\"$self->{'refreshsecs'};\">" if defined($self->{'refreshsecs'});
    print "</head>\n<body BGCOLOR=\"".$self->{'cur'}{'bgcol'}."\">\n";
    print "<table><tr>\n";
    print "<td width=130><A HREF=\"http://www.silicondefense.com/\"><IMG BORDER=0 width=123 height=72 SRC=\"".$self->{'cur'}{'base'}.$self->{'cur'}{'logo_url'}."\" ALT=\"[Silicon Defense logo]\"></A></td>\n";
    print "<td><CENTER><h1>SnortSnarf $page_type</h1><h2>$page_h2</h2>$self->{'prog_line'}</CENTER></td></tr></table><hr>\n";
    print "\n\n";
}


##############################################################################

# prints out a standard SnortSnarf HTML footer
sub print_page_foot {
    my $self= shift;
    print "<hr>\n".$self->{'cur'}{'foot'}."<BR>";
    print "Page generated at ".localtime(time())."</CENTER></html>";
}

##############################################################################

# find the earlist packet in an alert
sub earliest_packet {
    my $alert= shift;
    my @pkts= $alert->packets();
    return @pkts if @pkts <= 1;
    @pkts= sort {$a->time_cmp($b)} @pkts;
    return $pkts[0];
}

# find the latest packet in an alert
sub latest_packet {
    my $alert= shift;
    my @pkts= $alert->packets();
    return @pkts if @pkts <= 1;
    @pkts= sort {$b->time_cmp($a)} @pkts;
    return $pkts[0];
}

# return HTML to pretty-print a packet's time
sub pretty_time {
    my($pkt) = @_;
    return "<b>(none)</b>\n" unless defined($pkt);
    my $todtext= $pkt->tod_text();
$pkt->debug_print($pkt,STDOUT) unless defined($todtext);
    my($tod,$secfrac) = split(/\./,$todtext);
    return "<b>$tod</b>".
        (defined($secfrac)&&($secfrac ne '')?".$secfrac":'').
        " <i>on ".$pkt->month()."/".$pkt->day()."/".$pkt->year()."</i>";
}

##############################################################################

# make a bit mask/array out of a list of 4 byte-size ints, where the first
#  element is the most significant
# really this should adjust for big endian/little endian, but this is fine
#  for our purposes
sub bytenums2bits {
    return ($_[0] << 24) | ($_[1] << 16) | ($_[2] << 8) | $_[3];
}

# is the IP in our homenet?
sub in_homenet {
    my($self,$ip)= @_;
    return 0 unless defined($self->{'homenetaddr'});
    my $ipaddr= &bytenums2bits(split('\.',$ip));
    return ($ipaddr & $self->{'homenetmask'}) == $self->{'homenetaddr'};
}

##############################################################################

# open a file in the given base directory, creating subdirectories of the base as needed
sub open_file {
    my ($self,$basedir,$file,$isbinary)= @_;
    my $fh= $fhnonce++;
    my $path=$basedir;
    my $filepath= $file;
    $filepath =~ s:[^/]+$::;
    foreach (split(/\//,$filepath)) {
        $path.= $self->{'dirsep'}.$_;
        if (-e $path) {
            unless (-d $path) {
                die "$path exists but is not a directory (trying to create $file)";
            }
        } else {
            mkdir($path,0755) || die "could not make directory $path to store $file in";
        }
    }
    open($fh,">$basedir".$self->{'dirsep'}.$file) || 
                                die("Couldn't create file $file in $basedir\n");
    binmode($fh) if (defined($isbinary) && $isbinary); # for DOS
    return $fh;
}

# lookup the name of a page and how to get from there to the base directory
sub siglist_page {
    return "index.$_[0]->{'html'}";
}
sub siglist_base {
    return '';
}
sub sig_page {
    my($self,$signame)= @_;
    return "sig/sig$signame.$self->{'html'}";
}
sub sig_base {
    return '../';
}
sub host_page {
    my($self,$ip,$dir,$sub)= @_;
    $ip='0.0.0.0' if $ip eq '*undef*';
    my(@ippcs)= split(/\./,$ip);
    my $ipdir= join('/',@ippcs[0..2]);
    my $suffix= defined($sub) ? "-$sub" : '';
    return "$ipdir/$dir$ip$suffix.$self->{'html'}";
}
sub host_base {
    return '../../../';
}
sub anomindex_page {
    return "index.$_[0]->{'html'}";
}
sub anomindex_base {
    return '';
}
sub anomall_page {
    my($self,$sortby)= @_;
    return "allby$sortby.$self->{'html'}";
}
sub anomall_base {
    return '';
}
sub anomsrcs_page {
    return "srcips.$_[0]->{'html'}";
}
sub anomsrcs_base {
    return '';
}
sub anomdests_page {
    return "destips.$_[0]->{'html'}";
}
sub anomdests_base {
    return '';
}



##############################################################################

# clear a directory of files that it looks like we created
sub clear_dir {
    my($self,$dirpath)= @_;
    my $fh= $fhnonce++;
    my ($file,$fullpath);
    die("$dirpath already exists and is not a directory\n")
        unless -d $dirpath;
    if (opendir($fh,$dirpath)) {
        while ($file=readdir($fh)) {
            $fullpath= "$dirpath$self->{'dirsep'}$file";
            if ($file =~ /^(\d{1,3}|sig)$/ && -d $fullpath) {
                $self->clear_dir($fullpath);
                rmdir($fullpath); # || warn "could not delete directory $fullpath";
            } elsif ($file =~ /^((src|dest)\d+\.\d+\.\d+\.\d+.*|(sig.*)|allbyscore|allbytime|srcips|destips|index)\.$self->{'html'}/) {
                # looks like a file we created, so delete it
                unlink($fullpath) || warn "could not clear $file in $dirpath";
            }
        }
        closedir($fh);
    } else {
        warn "could not open output directory $dirpath to clear it";
    }
}

##############################################################################

# produce the logo file
sub write_logo_file {
    my ($self,$dir,$file)= @_;
    return if -e "$dir/$file" && (-s "$dir/$file" == 4229);
    my $LOGO= $self->open_file($dir,$file,1);
    print $LOGO unpack("u",
'M1TE&.#EA>P!(`/<`,?___^_U^<S__]_K],;U][_O[\_D\\\\_<Y[SDZ;_>\KC>
MY;_9[+;:X;_5YJ_6\+_-V[#1VJ7.SI_)Y:_"U9;+[9_%WZ"^U:2\R8G$ZIF_
MOZ&WQ7^^YI*WMY"SSINNOG^TV&JUY7^MSHJLK)6DMG^EPY*>L82EI7^?O8V6
MJV"CT7Z>GF^9O(F/I8>,HV^0LG62DC^=VH*#G%"5Q7&-C4"5SG]_?R^7VGQZ
ME4",PFB"@GEUD4^#K2"-U&)[>T"`L\'1MBC"#O1&)UEQS<V]D@P"#UT!NFC!S
MIU5J:FI;?`!]SF=6>$!DCTYB8C-FF611=`!UP@!RO@!ONF%-<4M;73!=C`!L
MME]);5Y(;5M#:0!DJA!;E0!AIC]/3UD_90!>H@!9FE4Y82!,?@!3D@!3BE`Q
M6C-`0P!+B`!)A`!$@"XZ.DHF40!#>S,S,R`T1P`\:0`Y<P`W6@`S9D$712`J
M,``O6B`H*``J3@@G0CH+/!HA(1,8&``<,P\/#P`2)`<)"P```/X!`@``````
M````````````````````````````````````````````````````````````
M````````````````````````````````````````````````````````````
M````````````````````````````````````````````````````````````
M````````````````````````````````````````````````````````````
M````````````````````````````````````````````````````````````
M````````````````````````````````````````````````````````````
M````````````````````````````````````````````````````````````
M````````````````````````````````````````````````````````````
M`````````````````````"\'Y!`$```(`+`````![`$@```C_``4(\',@@1YD_
M?\IPR3!00(0<$"&**$!0142(#!L*+"#B8HX(&AN*$%*&#T(^"G.("+E1!9<Y
M".>4R<&`I<V;.!M&X)-\'188,7/[DT%C`I%"6.4Y2O"D"X9^E(47D^9,GQ\\\\,
M+Y@X93F##Q\A5X48+5.391F0-AD(B3A#Q<VB?\H*Y.)6X\$_&35F0%@FYUZ$
M-I/^><&R`,R06N=`W:CU#Q^T=A_C5(%P<<@7"?7F\'7AW\\\\"_?7\'^_8,4(6&;
M135JS6-Y8&/)=AU##EF`:LZD?"Q[%M"9)>B<#+9JC,`W9VB!3?_4+3PU<VS9
M-YW?%,PD)V^$NP7\SAD3,<+E-C<W_\])&>\'LZR?/#Y1NDSC"ZCA[A]R.LWC#
MV@CE6G=_\'+73H0V5,0=,5+4F`\'LV!<67@0+)IY=]]2$XFG4-888@2P3VQQM9
M1BD6TH6T$4B5>@UBYQN$T2%H(6D4"B28ABQ-@>*&#G5H&8@A.@7;<PQY1A]+
M?!R(H&`LMG@7C"&]J%$>H>T4TV(XTJ9@@2\'U5D!_/P[\'T(SE%4FADK?-*)V3
M?W@H4)0L-398E28*$.1G,S8$X(RC96?3BM;)>%1#[(UF)IHL"1&G?%C&R=F9
M%QHE1(L..64G9^9IA&"7\'C*9DWI3Y<$F7@(M"B>.AB$*HV!\Z)<3@5-P9YND
M;S;4)1<TUO\74E`PRO<"9%D*4),(&<4)%YK@)<>I3>6M)*F7`W7)1!E(\CGK
M\'YX&V"96GVJJT:)"4#1A2&0RP>`<JCW)W!_P\'4NL4X"N.1!QI6Z:40\'6"B#L
M;!&`:^VV`RU%YAR>%<`$N.%2U2],Y9I[+D*P1CB%3V+MF*]3T;8JJ%,R,9L0
M`]9V.5NY_CJ5QQ00E40N2R]TF(,**HB5A[$L5793>0#>E,&RS);Q`D6\#M21
M1VZ5D4$!\'@6=0<H"!/V1=OVF7#.S7-S\,LW,"L\'RB>J>&S.CA^:T%H5,G&83
MP%B\'75C0)`J$LM@$17LGV#CQ\>@+IJ(M]]QBTR3:4Y?B71C;=/?_[7=.5^)4
MV]0DMXK8HW\G_K<(!8?$1^-5-IL!WXI7KG@9X-FEQPQ3+,WLR<&IW=`<F5=.
M@`(09,#!ZAQD$`$#!%A.(0,."Q3!%\'Z@BU`>S2&D1QF$"_!"O*AAS0`\'G)?!
MNQY^-)^[4W[P5,84+W`0N^PA"6&F=G=1A>X#``!P`$)I&%55645Y79CH+"%@
MPA3+ZR[__\']$SP<;0G"`?;Z/ZWH7\'T<PC%-J$+[PL>`/L,K!@!`R!08P(3<W
MB0#[!D*`",Q`>7J@GP8WZ!@_<"%XB:-,4/A@E2`%QRD7*"``+@"8VN@J!\WI
M0003%A($J*`,S..@#CG(!ST(`0)84P$(_^]CDAQHJR^C^4,:5#BQFN0A+R*H
M@Q]`&($RM`8H>C#*#NGGE2WZ(0],*!L!@*B3JPUG#FF0BT&THSLA#&``-1".
MS_2BD,6H(`_GN6,&MSB_C]6@!![0DPGNR(4RU"&+6G3*[]23%"%<SW9GX18?
MU,<]`>!\'@];B%TM4,`>T4(9E!##!(?FHR#2@*P\!"%\`,B60)PIDC"J8PARZ
MJ$@NZ$<%)JD#O>9PM0C@D5O64M/\YL2@`@BA+7LB@`C2L$<^ZJ$.[1(F\'VI0
M@^8,Q86%R8">GK>Y9,UA#\V;`E0,TTE+SB%N`I$,[>C\'&GE13B\#LAT7FKG#
M+_8`).I,Y"DIPO_)MZ0A#SWHP_.4"!).QF$/ONL!`C9R$`4RJ&CP(=,IT4(Z
MZQ3@"!#@PD#K60<3/%(($=5GF=#2D_9PH0YT>$`<XF`\'@=;O9\'-8J1V<EX<?
M"H0):7BH)=W&F.9492G#HQ`"A)##+:)$/45Y%Q-\:D2!!)4E$4A#\'>S@@@,4
M80DKC0,=^L`&%>QAI6&@`Q]RYX<Z\'"$"/[&."&JG$5R6;2`0P-U&>3@%,K)D
MK6\5@%LWF89O+F$";W`!5K-J!R:HH`]O>,,)$HM0\'<WA!8]\V1]F,#:>,@6\'
M<Z6K)E_&!\K2)@=L-68=N\'"\'Q!X@`"Y(K&H+>]C$+C:Q<=AH\QZK`)S_5+$J
M&6``6H7`)!(1(`.\I><.^T`\'.Z0!AG-LSQQPJUO@\'G4^>9!J:=]`A24\8`E+
M4.T;6(O8-P!6NW=H\'KJ\DH<CB&"A=_T77\"B$0(P0`138(-PATL\'U=(A#UPX
M0D(>Q;@,L5<C##@(3NV@W3<\H,#;-2QB-?"`\':16NWV@GQ[R,`<NG"P#$(BL
M1A`0`1/D0)9YF*\._?!5*B`XO!>DR@S0F1,1\'`2,>:AO@5^K7=:VH0@=`,`$
MBE"$-?C8QVZ(\`;U\$S>I>\'(2.9=B$7LQ3VH]@0_CG(<[C"3N_#R9X(;R50`
M6`8G1_G+7V;M\'M9P`@!`&<P^?D-C2<EF#1(W_\I-Z,`.>@SF.,CDPUIDTEHB
M0I+>/4Y[<$"SH-=`!\/NH0D[.$`3FH"&1COZT6B8:9LG_8<^V`\'2:#!#F1_`
M:$PW>LIZ.$(.CM"[^?&!"ST00AM*6P1/NQH-A?9JHQ_P:DR[`9R4UN&;7UV$
M`W2@UHZVPQP\*(07>&0M/?C7\'`B,AB:<H`FM!G:C8[V\',YSA`=;.MK:WK>WM
MNC37"+&T&]#`[7*3H-SH/@.A[Q!B/Q`Y>G.X`QW6D.TBD$!\.TCWMJEM[7/K
M^]]OH,,=!"I>A#@/>G[H@Z7K^V]SZUL+__:QOGMM@89G&PZ&-H,9?*#QCGO\
MXR`/N<;7X(:2PZ\'D;O_PL<A7\'G(2L\'P%\'&>YS+6P`RTT0>8=Q[@*VB"&GOO\
MYT`/NM"\'3O2B&YT$13\`THUN=!\P\'>B&UH(/2$#UJEL=YD.7NM6WW@`C^-P\'
M*]AZU3O0@9YK7>Q4;T`3Q.!T,1@A`%H`^@1VT\'.P5WT\':_^Y%DAP@/`=``).
M=[H17(!V$EA@Z6*(@Z\'-7L`&4+T##2A@`"P0]Z!K(97B:X#F!P"`MIN=\YG7
M?.01+P8M%/``HN=\W>L.@`8`W?,]C[P%@O[V`<#<!Q```-+S+H8<`R``HA^]
MS]U@Z"\8/_*=-[[R5P#Z`.Q`^=!\'O@^@#P\'H\'S]\TU>^#RQ@_0)FW_@\'L+[_
M#\+\'?>A__PLA`$`(K*\%SAL!^A98/_33WWKH[T#^7R#^#.Z@?.E;_PM:8`\'>
M]W_^IWPR0(#89WT-T\'T):(#B5T#E]W_HIW[6)P._9WU&$(\'&1W\+&\'W*IW_\
M=WW))X&Y]WM;H(`-*($B>\'X2.(`J^`7C!X$JF\'[XMX\'A<X+F9WT<^(+Z9P=>
M\(/(AP,_.(1#F`68%P)$Z`5!F(1,N(1,2(2@)X1/^(,X```54$`5\(0TF(0I
M$#Y9.(4_R(%@N`9,,`-VL`5HN`#A@P-HV(9NZ\'L#X(9;H(8`P(9R*(=T:(=W
MV(9YN(=M6(4XT(5>>(?IIX=H:`18F`5^N`46"``+_["(9&B&63")>3B)EGB)
M0%!`0\'")E6B),G")E+B&F`B*6=")D_B)EPB(67"%X=,!H-B%.$"*O@<`!K")
MI)@%5>B(H(B*61")=F")IGB+!12+P!@^!K``R#@`"T"*=\'B,R*B&S&B,SZB,
MH*B*JUA`*9"*=4B*56``DF>+U:A*SZB&Q-B+96@\'59".>9B.[-B.53",[4B\'
M$O`!](B,[E@%\DB/\'R`!`\'"/^5B/$N".5?@![,B/X9,"[`B(]YB.WJA*0\'"/
MN3@`^O@!`?"0Z8@&Y\B.=$@#"\F.\*B1:]B.`^"/(<F.!D"2==B._=B.`]F.
M!@D`"%D%"MF1+QD`4""0X?^S`.U(D.QX!N<8!4"YD4`YE$09!054E$(YE"E0
ME%&0E$!)`TSIE%\'P`45)`P!`E43YDDMIE5#)E$I90%@YE%;IB$39E4!Y!E,P
M`W0`!6R9`.%#`VP9EW*9B0#@`\'()!6X)`\'!YEW>9EWO)EW\'IEX`9EU;Y`7RI
ME5PYF\'$)`L9XEV.9`(HY!FD)!T]0F7Y9F9B9F8*8`IGY!)?9F9WYF:")F:(Y
MFC```!LPFB_)CS30F38`FJ#7F:<)``DPFI4IF3-`F9;YEK;Y!)Q7FZ$9/C#0
MF4$0G``PG+WIF\+9F3R0F1N`FK;YDL?9F0$`FL\Y`)WYG+0)FJWY!+@)!TD0
MGJ#_!P/A69[ER8\!$`3F&9YY29[F*0\'KF9<@L)[T64#N69X)8)[/N0\'T>9[V
MN9X`0)_\")_Z&3[Y:9XPX)[?69X%-)_KR0,.0(L\T)\-R9_E:0,&$)_A8Z\']
M&9X-:IXV,``%2J`=:I#WZ:$DF@0V$``!,*$%"@`#H)[EZ0`V$)YBD)9N$)XV
MH$(.L`$^N@%N.0`<NIY!H$(#D`!(6I?F6:3AXP`=&IZS:8Q(ZHU#&J$Q^J1)
M0`\'\'":"T"0(P0`$L6J,:JDI(F@"I5)XW.@-A$`0@@`%NZJ8.4*8.@`$P$`1V
M>J=WVJ9ONJ=N6J=VJJ=[N@%XFJ=\RJ=^"@.%.JB#2@$V8C"H7UJF";`!/#"H
M-E"H@7JG33"91+"IG-JIGOJIH!JJHCJJI%JJIGJJI_H%FHJJK-JJKOJJL&JJ
LJIJ;L5JKMGJKN-JIL[H\'<-"KOOJKP!JLPCJLQ%JLQGJLR)JLR7H\'4Q`0`#L`
');
    close $LOGO;
}

1;