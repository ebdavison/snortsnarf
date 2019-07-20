#!/usr/bin/perl

# SnortFileInput.pm, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2001 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# SnortFileInput is an implentation of the SnortSnarf Input API which reads
# its input from files produced by Snort.  Presently it can read snort alerts
# (fast and full), portscan logs, and syslog files.

# Portions of this file are based on code in snortsnarf.pl by Stuart
#   Staniford that was based on code wrttien by Joe McAlerney.

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

package SnortFileInput;

use MemAlert;
use MemPacket;
use Filter;

sub BEGIN {
    @cap_tasks= qw(snort spp_portscan spp_portscan2 spade);
    %cap_tasks= ();
    foreach (@cap_tasks) {
        $cap_tasks{$_}= 1;
    }
    $fhnonce= 'inputfile001';
    $alnum= 0;
    $pktnum= 0;
    %alertidsrc= ();
    $alertidsrc{'default'}= \&default_alertidsrc;
    %pktidsrc= ();
    $pktidsrc{'default'}= \&default_pktidsrc;
}

# call to register an alert id source with a given name
sub register_alert_id_src {
    my($name,$functref)= @_;
    $alertidsrc{$name}= $functref;
}

# call to register an packet id source with a given name
sub register_pkt_id_src {
    my($name,$functref)= @_;
    $pktidsrc{$name}= $functref;
}


sub default_alertidsrc {
    return "SFIalert".++$alnum;
}

sub default_pktidsrc {
    return "SFIpacket".++$pktnum;
}


sub ref_to_url {
    my($cite,$id)= @_;
    if ($cite eq 'arachnids') {
        $id =~ s/^0+//;
        return "http://www.whitehats.com\/IDS\/IDS$id";
    } elsif ($cite eq 'bugtraq') {
        return "http://www.securityfocus.com/bid/$id";
    } elsif ($cite eq 'cve') {
        return "http://cve.mitre.org/cgi-bin/cvename.cgi?name=$id";
    } elsif ($cite eq 'mcafee') {
        return "http://vil.nai.com/vil/content/v_$id.htm";
    } elsif ($cite eq 'sid') {
        return "http://www.snort.org/snort-db/sid.html?id=$id";
    } elsif ($cite eq 'url') {
        return "http://$id";
    } else {
        return undef;
    }
}

sub url_to_ref {
    $_= $_[0]; # the URL to convert to a reference
    if (m!http://www\.whitehats\.com/info/(IDS|)(.*)!) {
        return ('arachnids',$2);
    } elsif (m!http://www\.securityfocus\.com/bid/(.*)!) {
        return ('bugtraq',$1);
    } elsif (m!http://cve\.mitre\.org/cgi-bin/cvename\.cgi\?name=(.*)!) {
        return ('cve',$1);
    } elsif (m!http://vil\.nai\.com/vil/dispVirus\.asp\?virus_k=(.*)!) {
        return ('mcafee',$1);
    } elsif (m!http://vil\.nai\.com/vil/content/v_(.*).htm!) {
        return ('mcafee',$1);
    } elsif (m!http://www\.snort\.org/snort-db/sid\.html\?id=(.*)!) {
        return ('sid',$1);
    } elsif (m!http://www\.snort\.org/snort-db/sid\.html\?sid=(.*)!) {
        return ('sid',$1);
   } elsif (m!http://(.*)!) {
        return ('url',$1);
    } else {
        return ();
    }
}

########## API functions ##############

# API 'new' function to create an instance
sub new {
    my($class,$paramsref,$tasksref,$filter,@files)= @_;
    my(%tasks)= ();
    foreach (@{$tasksref}) {
        $tasks{$_}= 1 if $_ eq 'all' || defined($cap_tasks{$_});
    }
    my $self= bless {
        'tasks' => \%tasks, # requested tasks are the keys
        'filter' => $filter, # filter to apply
        'str' => undef, # recreate string
        'filesleft' => \@files, # files not yet read
        'fh' => undef, # file handle for currently open file, or undef if none
        'line_buf' => [], # list of lines read in early from the current file
        'alert_buf' => [], # list of alerts already produced
        'remapip' => undef # IP remapper
    }, $class;

    # default option values
    $self->{'opt'}{'year'}= 'rec';
    $self->{'opt'}{'ais'}= 'default';
    $self->{'opt'}{'pis'}= 'default';
    $self->{'opt'}{'rulessource'}= undef;

    # get opts
    my @params= ();
    foreach (keys %$paramsref) {
        if (/^(year|ais|pis|rulessource)$/) {
            $self->{'opt'}{$_}= $paramsref->{$_};
            next if $_ eq 'rulessource'; # hide this from the recreate string
        } elsif (/^remapip$/) {
            $self->{'opt'}{'remapip'}= $paramsref->{'remapip'};
            next; # hide this from the recreate string
        } else {
            warn "new: paramater $_ with value $paramsref->{$_} not understood, ignoring\n";
            next;
        }
        push(@params,"$_:".$paramsref->{$_});
    }
    # make the recreate string
    my $paramstr= &Filter::join_strs(@params);
    $self->{'str'}= &Filter::join_strs(join(',',keys %tasks),&Filter::as_str($filter),$paramstr,@files);

    # set up per opts
    
    return $self;
}

sub recreate {
    my($class,$recreate_str)= @_;
    my($tasks,$filterstr,$params,@files)= &Filter::unjoin_strs($recreate_str);
    my @tasks= split(',',$tasks);
    my $filter= &Filter::from_str($filterstr);
    die "failed to recreate filter from string: $filterstr\n" unless defined($filter);
    my %params= map(split(':',$_,2),&Filter::unjoin_strs($params));
    return $class->new(\%params,\@tasks,$filter,@files);
}

sub recreate_str {
    return $_[0]->{'str'};
}

sub task_capability {
    return @cap_tasks;
}

sub get {
    my $self= shift;
    my $done= 0;
    my ($file,$fh,$alert,$format,$alertsource);
    unless (defined($self->{'fh'})) {
        do {
            my $curfile= $self->{'curfile'}= shift(@{$self->{'filesleft'}});
            $fh= $fhnonce++;
            return undef unless defined($curfile);
            if (! -e $curfile) {
                warn "SnortFileInput: input file $curfile does not exist; skipping it\n";
            } elsif (-z $curfile) {
                warn "SnortFileInput: input file $curfile exists but is length 0; skipping it\n";
            } elsif (open($fh,"<$curfile")) {
                $done= 1;
                $self->{'fh'}= $fh;
                $self->{'filepos'}= 0;
            } else {
                warn "SnortFileInput: could not open $curfile for alert input; skipping it\n";
            }
        } while (!$done);
    }
    # fh is open at this point
    $done= 0;
    do {
        my($text,$format)= $self->next_alert();
        unless (defined($text)) {
 			close( $self->{'fh'} );
            $self->{'fh'}= undef;
            return $self->get(); # recurse
        }
        $self->{'filepos'}++;
        $alertsource= $self->{'curfile'}.':'.$self->{'filepos'};
        if (!@{$self->{'alert_buf'}}) {
	        @{$self->{'alert_buf'}}= $self->make_alert($text,$format,$alertsource);
        }
        $alert= shift(@{$self->{'alert_buf'}});
        $done= defined($alert);
        $done&&= (defined($self->{'tasks'}{'all'}) || defined($self->{'tasks'}{$alert->type()})) && $self->{'filter'}->test($alert);
    } while (!$done);
    return $alert;
}

########## end of API functions ##############

my %monthnum=('Jan' => 1,
             'Feb' => 2,
             'Mar' => 3,
             'Apr' => 4,
             'May' => 5,
             'Jun' => 6,
             'Jul' => 7,
             'Aug' => 8,
             'Sep' => 9,
             'Oct' => 10,
             'Nov' => 11,
             'Dec' => 12);

# next_alert takes a file handle and returns the next snort alert found by reading that file handle
# along with the format of the alert ('fullalert', 'fastalert', 'syslog', 'idmef', or
# 'portscan') or returns undef if EOF was encountered (i.e., there are no more
# alerts)
sub next_alert {
    my($self)= @_;
    
    my $fh= $self->{'fh'};
    while (1) {
        if (@{$self->{'line_buf'}}) {
            $_= shift(@{$self->{'line_buf'}});
        } else {
            $_= <$fh>;
        }
        return undef unless defined($_);
        next if /^\s*$/;      # ignore blank lines
        next if /^\s*#/;      # ignore comment lines
#         if (/^\s*\<IDMEF-Message/) { # IDMEF format
#             my $alert= $_;
#             while (<$fh>) {
#                 if (s:^(.*</IDMEF-Message>)[\f\s]*(.*):$1:) {
#                     unshift(@{$self->{'line_buf'},$2);
#                     return ($alert.$_,'idmef');
#                 }
#                 $alert.= $_;
#             }
#         } 
        s/\0+$//;
        if (/^\s*\[\*\*\]/) { # full alert format
            my $alert= $_;
            while (<$fh>) {
                s/\0+$//;
                if (/^\s*$/) {
                    last;
                } elsif (/^\s*\[\*\*\]/) { # must be a missing newline between two alerts
                    unshift(@{$self->{'line_buf'}}, $_);
                    last;
                }
                $alert.= $_;
            }
            # need to peek at line ahead to work around a bug in Snort
            # 1.8.6- in which there is sometimes an extraneous newline before
            # the original packet part of an alert
            unless (@{$self->{'line_buf'}}) {
                $_= <$fh>;
                if (!defined($_)) {
                } elsif (/^\s*\*\*\s*ORIGINAL/) { # found a second part of alert
                    $alert.= $_;
                    while (<$fh>) {
                        s/\0+$//;
                        if (/^\s*$/) {
                            last;
                        } elsif (/^\s*\[\*\*\]/) { # must be a missing newline between two alerts
                            unshift(@{$self->{'line_buf'}}, $_);
                            last;
                        }
                        $alert.= $_;
                    }
                } elsif (!/^\s*$/) {
                    unshift(@{$self->{'line_buf'}}, $_);
                }
            }
            $alert =~ s/\s+$//;
            return ($alert,'snort-full');
        } 
        if (/last message repeated/) {
            next;
        }
        if (/^\s*\d+\/\d+(|\/\d+)\-[\d\:\.]+\s+\[\*\*\]/) { # fast alert format
            s/\s+$//;
            return ($_,'snort-fast');
        }
        # 10/14-22:30:39.889550  TCP src: 66.28.69.136 dst: 192.168.1.20 sport: 80 dport: 1804 tgts: 1 ports: 21 flags: ***A**S* event_id: 0
        if (/^\s*\d+\/\d+(|\/\d+)\-[\d\:\.]+\s+\w+\s+src:/) { # portscan2 log format
            s/\s+$//;
            return ($_,'spp_portscan2');
        }
        if (/^\w+\s+\d+\s+\d\d\:\d\d:\d\d\s+\d+\.\d+\.\d+\.\d+\:\d+\s+->/) { # portscan log format
            s/\s+$//;
            return ($_,'spp_portscan');
        }
        # May 16 14:52:45 netmon snort: IDS177/netbios-name-query: xxx.xxx.xxx.xxx -> xxx.xxx.xxx.xxx
        # this regexp is the least specific so it appears last
        if (/\w+\s+\d+\s+[\d:]+\s+\S+\s+([^\[]+)/) { # syslog format
            my $prog= $1;
            next unless $prog =~ /snort/;
            s/\s+$//;
            return ($_,'snort-syslog');
        }
        warn "unknown alert format for line: $_; skipping\n";
    }
}


# parses given alert text assuming that it is in a given format ('fullalert',
# 'fastalert', 'syslog', 'idmef', or 'portscan').  An instance of MemAlert is returned.
sub make_alert {
    my($self,$alerttext,$format,$alertsource)= @_;
    
    #return $self->make_idmef_alert($alerttext,$alertsource) if $format eq 'idmef';
    my $aid= &{$alertidsrc{$self->{'opt'}{'ais'}}}();
    my $pid= &{$pktidsrc{$self->{'opt'}{'pis'}}}();
    my $alert= MemAlert->new($aid,$alerttext,$format,undef,$alertsource);
    my $pkt= MemPacket->new('id' => $pid);
    $alert->add_packets($pkt);
    
    $_= $alerttext;
    
    my $year= undef;
    my ($src,$dest,$sport,$dport,$month,$day,$time,$sig,$prioritynum,$classificationtext); # these get added to the packet at the bottom of the function
    $prioritynum= undef;
    $classificationtext= undef;
    my %refs= ();
    if ($format eq 'snort-full') {
        # print "processing: >>\n$alerttext\n<<\n";
        my(@lines)= split("\n",$alerttext);
        $_= shift(@lines);
        return undef unless (@lines > 2); # no packet mentioned
        
        # ---- Process the first line -----
        #
        # the first line holds the attack id and other junk added over the years
        s/\<\S+\>\s*//; # strip the interface name produced by -I if it is present, e.g., <hme1>
        s/^\[\*\*\]\s*//; s/\s*\[\*\*\]\s*$//;
        if (s/\[(\d+):(\d+):\d+\]//) { # capture originator, capture sid, discard revision info
            $refs{'sid'} = $2 if ($1 == 1);
        }
        $sig = $_;
            # Note: does not handle preprocessor log output

        # extract cross references from [Xref => http://www.whitehats.com/info/IDS199] type lines
        #   also new style (1.9): [Xref => arachnids 162]
        my($line,$l);
        my ($cite,$id,$reftext);
        foreach $line (@lines) {
            $l= $line;
            while ($l =~ s/\[Xref\s*=>\s*(.*)\]//) {
                my $reftext= $1;
                if ($reftext =~ /^(\w+)\s+(\w+)\s*$/) { # newer style
                    ($cite,$id)= ($1,$2);
                } else {
                    ($cite,$id)= &url_to_ref($1);
                }
                $refs{$cite}= $id if defined($cite);
            }
            if ($l =~ s/\[Priority\s*:\s*(\d+)//) {
                $prioritynum= $1;
            }
            if ($l =~ s/\[Classification\s*:\s*([^\]]+)\]//) {
                $classificationtext= $1;
            }
        }
        
        
        # remove all lines past the first the begin with '['
        @lines= grep(!m/^\[/,@lines);
        
        # ---- Process the second line -----        
        #
        $_= shift(@lines);
        s/^(\d+)\/(\d+)//;
        ($month,$day)= ($1,$2);
        if (s/^\/(\d+)//) { # year was included
            $year= $1;
        }
        s/^\-([\d\:\.]+)\s*//;
        $time= $1;
        my $remainder =  $_;     # grab the rest for regex matching

        my $e_option;
        if ($remainder =~ /^[\dA-Fa-f]+\:/)
        {
            # Looks like an ethernet address - assume -e was set in snort command line
            $e_option = 1;
            # We could parse for ethernet stuff here but we don't 
            # feel like it right now.
        }
        else
        {
            # No -e option
            $e_option = 0;
            $remainder =~ s/ \-\> /-/; 
            my ($source,$destination) = split('-',$remainder);
            ($src,$sport) = split(':',$source);
            ($dest,$dport) = split(':',$destination);
        }
                 
        # ---- Process the third line -----
        #
        $_= shift(@lines);
                
        if($e_option)
        {
            # Ethernet stuff was on the previous line and now the IP source
            # and destination are here at the beginning of the third line.
            ($src,$sport,$dest,$dport,$remainder) = /^(\d+\.\d+\.\d+\.\d+)\:(\d+)\s+\-\>\s+(\d+\.\d+\.\d+\.\d+)\:(\d+)\s+(.*)$/;
            unless(defined $src)
            {
                #ICMP case
                ($src,$dest,$remainder) = /^(\d+\.\d+\.\d+\.\d+)\s+\-\>\s+(\d+\.\d+\.\d+\.\d+)\s+(.*)$/;
            }          
            $_ = $remainder;              
        }
        $pkt->set('protocol' => $1) if (/^(\S*)\s+/);
        #my($ttl,$tos,$id,$df); # not stored
        # new format: TCP TTL:60 TOS:0x0 ID:3260 IpLen:20 DgmLen:77 DF
        # old format: TCP TTL:128 TOS:0x0 ID:50079  DF
        #($alert{'proto'},$ttl,$tos,$id,$df) = /^(\w*)\sTTL\:(\d*)\sTOS\:(\w*)\sID\:(\d*)\s?\s?(DF)?$/;

        # ---- Process the fourth line -----
        #
        $_= shift(@lines);              
                
        if ($pkt->protocol() eq "TCP") {
            $pkt->set('flags' => $1) if (/^([SFRUAP12\*]*)\s+/);
            #my($seq,$ack,$win); # not stored
            # old format: *****PA* Seq: 0x82A8A42   Ack: 0xDA791923   Win: 0x2238
            # new format: ***AP*** Seq: 0xBDEE451F  Ack: 0xAC995B17  Win: 0x3EBC  TcpLen: 20
            #($alert{'flags'},$seq,$ack,$win) = /^([SFRUAP12\*]*)\sSeq\:\s(\w*)\s*Ack\:\s(\w*)\s*Win\:\s(\w*)$/;
        } elsif ($pkt->protocol() eq "UDP") {
            # my($UDPlength); # not stored
            # ($UDPlength) = /^Len\:\s(\d*)$/;
        } elsif ($pkt->protocol() eq "ICMP") {
            # old format contains nothing before ICMP type string or ID: and Seq:
            # new format (1.7) may have e.g., Type:8  Code:0  ID:39612   Seq:57072  ECHO
            #print STDOUT "$_ => ";
            while (s/^([A-Z]{1,3}|[A-Z][a-z]*)\:\w+\s+//) {}  # get rid of everything that looks like ID:, Type:, etc; what we are looking for may itself contain multiple words and a colon so we can't just grab the end.  This is a try at removing whatever might be prefixed in the future.
            my ($ICMP_type) = /^(.*)/;
            $ICMP_type =~ s/ROUTER ADVERTISMENTROUTER ADVERTISMENT/ROUTER ADVERTISMENT/; # work around bug in Snort 1.9
            $ICMP_type =~ s/\s*NEW GW\s*:.*//; # get rid of NEW GW: xx.xxx.xx.xxx in Snort 1.9
            $ICMP_type =~ s/:\s*([A-Z]*[a-z]+).*//; # get rid of Num addrs: ..., etc in Snort 1.9
            $ICMP_type =~ s/\s*\d+\s*$//; # get rid of int at end in Snort 1.9
            $ICMP_type =~ s/\s*0x[0-9A-Fa-f]\s*$//; # get rid of hex num at end in Snort 1.9
            #print STDOUT "$ICMP_type\n";
            $pkt->set('flags' => $ICMP_type);
        }

        # ---- Process the fifth line if there is one -----
        #
        $_= shift(@lines);              
                
        #if(defined($_) && $_ ne '') {
            #my $TCPoptions = "";  # not stored
            #$TCPoptions = substr($line5,16,(length $line5));
        #}
    } elsif ($format eq 'snort-fast') {
        my $proto= undef;
        s/^\s*(\d+)\/(\d+)//;
        ($month,$day)= ($1,$2);
        if (s/^\/(\d+)//) { # year was included
            $year= $1;
        }
        s/^\-(\S*)//;
        $time= $1;
        s/\<\S+\>\s*//; # strip the interface name produced by -I if it is present, e.g., <hme1>
        if (s/\[Classification\s*:\s*([^\]]+)\]//) { # extract class and priority
            $classificationtext= $1;
        }
        if (s/\[Priority\s*: (\d+)*\]//) {
            $prioritynum= $1;
        }
        if (s/{([A-Z_\-]+)}//) {
            $proto= $1;
        }
        if (s/\[(\d+):(\d+):\d+\]//) { # capture originator, capture sid, discard revision info
            $refs{'sid'} = $2 if ($1 == 1);
        }
        s/^\s+\[\*\*\]\s*(.+)\s*\[\*\*\]\s*//;
        $sig= $1;
        if (/:/) { 
            ($src,$sport,$dest,$dport)= /^([\d\.]+):(\d+)\s*->\s*([\d\.]+):(\d+)/;
        } else { # just addresses
            ($src,$dest)= /^([\d\.]+)\s*->\s*([\d\.]+)/;
            $proto= 'ICMP' unless defined($proto); # guess that the protocol is ICMP
        }
        $pkt->set('protocol' => $proto) if defined($proto);
    } elsif ($format eq 'snort-syslog') {
        my $proto= undef;
        s/(\w+)\s+(\d+)\s+([\d:]+)\s+(\S+)\s+[^:]+:\s*//;
        ($month,$day,$time)= ($1,$2,$3);
        $month= $monthnum{$1};

        s/^\[\S+\s+\d+\s+\S+\]\s*//; # strip info between []'s, e.g. from solaris 8, that might appear here.  E.g., [ID 521392 auth.alert]
       
        if (s/([\d\.]+)\:(\d+)\s*->\s*([\d\.]+)\:(\d+)\s*$//) {
            ($src,$sport,$dest,$dport)= ($1,$2,$3,$4);
        } elsif (s/([\d\.]+)\s*->\s*([\d\.]+)\s*$//) {
            ($src,$dest)= ($1,$2);
            $proto= 'ICMP' unless defined($proto); # guess that the protocol is ICMP
        } else {
            # must be just a message (not really handled)
            return undef;
        }
        s/\s*:\s*$//;
        if (s/{([A-Z_\-]+)}\s*$//) {
            $proto= $1;
        }
        s/\<\S+\>\s*//; # strip the interface name produced by -I if it is present, e.g., <hme1>
        if (s/\[Classification\s*:\s*([^\]]+)\]//) { # extract class and priority
            $classificationtext= $1;
        }
        if (s/\[Priority\s*: (\d+)*\]//) {
            $prioritynum= $1;
        }
        if (s/\[(\d+):(\d+):\d+\]//) { # capture originator, capture sid, discard revision info
            $refs{'sid'} = $2 if ($1 == 1);
        }
        $sig= $_;
        $pkt->set('protocol' => $proto) if defined($proto);
    } elsif ($format eq 'spp_portscan') {
        my ($proto,$flags);
        ($month,$day,$time,$src,$sport,$dest,$dport,$proto,$flags) = /^(\w+)\s+(\d+)\s+(\d\d\:\d\d:\d\d)\s+(\d+\.\d+\.\d+\.\d+)\:(\d+)\s+\-\>\s+(\d+\.\d+\.\d+\.\d+)\:(\d+)\s+(\w+)\s*(\S*)/;
        $month= $monthnum{$month};
        $proto= 'TCP' unless ($proto eq 'UDP') || ($proto eq 'ICMP');  # was SYN, etc
        $pkt->set('protocol' => $proto,'flags' => $flags);
        
        $sig = "spp_portscan: $proto";
        $sig.= " $flags" if (defined($flags));
        $sig.= " scan";
    } else { # $format eq 'spp_portscan2'
        my ($proto,$flags);
        s/^\s*(\d+)\/(\d+)//;
        ($month,$day)= ($1,$2);
        if (s/^\/(\d+)//) { # year was included
            $year= $1;
        }
        s/^\-(\S*)\s+(\w+)//;
        $time= $1;
        $proto= $2;
       
        $src = (s/src:\s*(\S+)\s*//) ? $1 : undef;
        $dest = (s/dst:\s*(\S+)\s*//) ? $1 : undef;
        $sport = (s/sport:\s*(\S+)\s*//) ? $1 : undef;
        $dport = (s/dport:\s*(\S+)\s*//) ? $1 : undef;
        $flags = (s/flags:\s*(\S+)\s*//) ? $1 : undef;
        $pkt->set('protocol' => $proto,'flags' => $flags);
        
        $sig = "spp_portscan2: $proto";
        $sig.= " $flags" if (defined($flags));
        $sig.= " scan";
    }

    # normalize the signature    
    my $rawsig= $sig;
    $sig= $1 if $sig =~ /^\s*((?:Spade|spp_anomsensor)\s*:\s*[^:]+)/;
    $sig =~ s/\s+$//;
    $sig =~ s/^\s+//;
    $sig= '(spp_portscan2) Portscan detected' if $sig =~ /^\(spp_portscan2\)\s*Portscan\s+detected/;
    
    if (defined($self->{'opt'}{'remapip'})) {
        $src= $self->{'opt'}{'remapip'}->remap($src);
        $dest= $self->{'opt'}{'remapip'}->remap($dest);
        $sig= $self->{'opt'}{'remapip'}->remap_all($sig);
        $alert->set('text',$self->{'opt'}{'remapip'}->remap_all($alerttext));
    }

    $alert->set('message' => $sig);
    $alert->set('priority_num' => $prioritynum) if defined($prioritynum);
    $alert->set('classification_text' => $classificationtext) if defined($classificationtext);
    $pkt->set('sip' => $src, 'dip' => $dest,
        'sport' => $sport, 'dport' => $dport,
        'month' => $month, 'day' => $day,
        'tod_text' => $time
    );

    my $anom= &is_anom_rept($rawsig);
    if (defined($anom)) {
        $pkt->set('anom' => $anom);
        $alert->set('type' => 'spade');
    } else {
        $pkt->set('anom' => undef);
        if ($format eq 'spp_portscan' || $format eq 'spp_portscan2') {
            $alert->set('type' => $format);
        } else {
            $alert->set('type' => 'snort');
        }
    }

    if (defined($year)) {
        $pkt->set('year' => $year);
    } else {
        my $yearopt= $self->{'opt'}{'year'};
        if ($yearopt eq 'rec' || $yearopt eq 'cur') {
            # cur assumes current year, rec assumes it is within the last year
            my $now= time();
            $pkt->set('year' => ((localtime($now))[5] + 1900));
            if ($yearopt eq 'rec' && $pkt->utime() > $now) {
                # must have been last year
                $pkt->set('year' => $pkt->year() - 1);
            }
        } else {
            $pkt->set('year' => $yearopt); # unless $pkt->is_set('year')
        }
    }
    $alert->set('utime' => $pkt->utime());
    
    # try to get references from the source rules
    my ($cite,$id);
    if ($alert->type() eq 'snort' && defined($self->{'opt'}{'rulessource'})) {
        my $rule;
        my %newrefs;
        foreach $rule ($self->{'opt'}{'rulessource'}->get_rules_for_msg($sig)) {
            %newrefs= $rule->references();
            foreach $cite (keys %newrefs) {
                $cite= lc($cite);
                unless (exists $refs{$cite}) {
                    $refs{$cite}= $newrefs{$cite};      
                }       
            }
        }
    }
    if ($sig =~ /IDS(\d+)/ && !defined($refs{'arachnids'})) {
        $refs{'arachnids'}= $1;
     }
     my $url;
     foreach $cite (keys %refs) {
        my $id= $refs{$cite};
        $url= &ref_to_url($cite,$id);
        $alert->add_ref($cite,$id,$url);
     }
    
    return ($alert);
}

# if this parsed or unparsed alert is an anomaly report, return the anomaly
# score otherwise return undef
sub is_anom_rept {
    my($alert)= shift;
    my $text= ref($alert) ? $alert->{'sig'} : $alert;
    if ($text =~ /Spade:\s*[^:]*:\s*[^:]*:\s*(\d+\.\d+)/i) { # Spade 021008.1 and on
        return $1;
    } elsif ($text =~ /(Spade|spp_anomsensor):\s*Anom[ao]ly threshold exceeded:\s*(\d+\.\d+)/i) { # Spade before 021008.1
        return $2;
    } else {
        return undef;
    }
}

1;
