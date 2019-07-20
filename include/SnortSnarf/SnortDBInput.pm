#!/usr/bin/perl 

# The SnortDBInput v.3
# original author Ed Davison [Ed.Davison@bus.utexas.edu]
# modified by Aaron DeLashmutt [awd@awdonline.com]
# modified and 2003-02-13

# SnortDBInput is an implentation of the SnortSnarf Input API which reads
# its input from databases produced by Snort using the database output plugin.
# Currently SnortDBInput is capable of accessing MySQL and Oracle through the
# DBI/DBD perl interface modules.
# http://search.cpan.org/author/TIMB/DBI-1.30/DBI.pm
# http://search.cpan.org/author/TIMB/DBD-Oracle-1.12/Oracle.pm
# http://search.cpan.org/author/JWIED/Msql-Mysql-modules-1.2219/mysql/lib/DBD/mysql.pm

# To use SnortDBInput, pass database information to SnortSnarf in the format
# user:password@database@host:port
# EX : snortsnarf.pl snort:@snort18@1.2.3.4
# if port is not specifiied, it will default to 3306 for MySQL

# Please send complaints, kudos, and especially 
# improvements and bugfixes to ed.davison@bus.utexas.edu

# -SnortSnarf-
# copyright (c) 2001 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.


package SnortDBInput;

use MemAlert;
use MemPacket;
use Filter;
use DBI;
use Socket;
use Time::ParseDate;

sub BEGIN {
    @cap_tasks= qw(snort spp_portscan spade);
    %cap_tasks= ();
    foreach (@cap_tasks) {
        $cap_tasks{$_}= 1;
    }
}

sub ref_to_url {
    my($cite,$id)= @_;
    return undef unless defined($cite) && defined($id);
    if ($cite eq 'arachnids') {
        $id =~ s/^0+//;
        return "http://whitehats.com\/IDS\/IDS$id";
    } elsif ($cite eq 'bugtraq') {
        return "http://www.securityfocus.com/bid/$id";
    } elsif ($cite eq 'cve') {
        return "http://cve.mitre.org/cgi-bin/cvename.cgi?name=$id";
    } elsif ($cite eq 'mcafee') {
        return "http://vil.nai.com/vil/dispVirus.asp?virus_k=$id";
    } elsif ($cite eq 'sid') {
        return "http://www.snort.org/snort-db/sid.html?id=$id";
    } elsif ($cite eq 'url') {
        return "http://$id";
    } else {
        return undef;
    }
}

########## API functions ##############

# API 'new' function to create an instance
sub new {
    my($class,$paramsref,$tasksref,$filter,@inputs)= @_;
    my(%tasks)= ();
    foreach (@{$tasksref}) {
        $tasks{$_}= 1 if $_ eq 'all' || defined($cap_tasks{$_});
    }

    my $dbmin = undef;
    my $dbmax = undef;
    
    my @filters= (ref($filter) eq 'AndFilter') ? @{$filter} : ($filter);
    my @unhfilters= ();
    foreach (@filters) {
        my $time= &Filter::known_mintime_filter($_);
        if (defined($time)) {
            $dbmin= $time;
            next;
        }
        $time= &Filter::known_maxtime_filter($_);
        if (defined($time)) {
            $dbmax= $time;
            next;
        }
        push(@unhfilters,$_);
    }
    my $myfilter= @unhfilters
        ? (@unhfilters > 1
            ? AndFilter->new(@unhfilters)
            : $unhfilters[0])
        : TrueFilter->new();
    
    my @ins= ();
    # @inputs is the text list of databases to grab stuff from, each in the form user:passwd@name@host:port
    my($lhs,$rhs,$user,$pass,$dbname,$hostport,$host,$port);
    foreach (@inputs) {
        ($lhs,$rhs)= split('@',$_,2);
        ($user,$pass)= split(':',$lhs,2);
        $pass= '' unless defined($pass);
        ($lhs,$rhs)= split('@',$rhs,2);
        if (defined($rhs)) {
            $dbname= $lhs;
            $hostport= $rhs;
        } else {
            $dbname= 'snort'; 
            $hostport= $lhs;
        }
        if ($hostport =~ /^(.*)\:(\d+)$/) {
            $host= $1;
            $port= $2;
        } else {
            $host= $hostport;
	    # need to default to specific database port
        }
        #encode the password by replacing ';' with \001; we assume \001 is not in the password string
        $pass =~ tr/\;/\001/;
        push(@ins,join(';',$user,$pass,$dbname,$host,$port));
    }
    
    my $self= bless {
        'tasks' => \%tasks, # requested tasks are the keys
        'filter' => $filter, # original filter
        'myfilter' => $filter, # filter to apply
        'str' => undef, # recreate string
        'inputsleft' => \@ins, # databases not yet processed, each in the form user;passwd;name;host;port
        'dbh' => undef,
        'dbmin' => $dbmin,
        'dbmax' => $dbmax,
        'dbtext' => '' # for alert 'source' fields
    }, $class;

    # get opts
    my @params= ();
    
    # if at some point there is a general user specified option not tied to a particular 
    # input source (for example in SnortFileInput the user can indicate how to infer an i
    # alerts year), e.g. 'foo', you would put that into the 'opts' hash with something like this
#    foreach (keys %$paramsref) {
#        if (/^foo$/) {
#            $self->{'opt'}{$_}= $paramsref->{$_};
#        } else {
#            warn "new: paramater $_ with value $paramsref->{$_} not understood, ignoring\n";
#            next;
#        }
#        push(@params,"$_:".$paramsref->{$_});
#    }
    
    # make the recreate string
    my $paramstr= &Filter::join_strs(@params);
    $self->{'str'}= &Filter::join_strs(join(',',keys %tasks),&Filter::as_str($filter),$paramstr,@inputs);

    # set up per opts

    # don't do much here, we don't even know if get() is going to be called, maybe on recreate_str() is

    return $self;
}


sub recreate {
    my($class,$recreate_str)= @_;
    my($tasks,$filterstr,$params,@inputs)= &Filter::unjoin_strs($recreate_str);
    my @tasks= split(',',$tasks);
    my $filter= &Filter::from_str($filterstr);
    die "failed to recreate filter from string: $filterstr\n" unless defined($filter);
    my %params= map(split(':',$_,2),&Filter::unjoin_strs($params));
    return $class->new(\%params,\@tasks,$filter,@inputs);
}

sub recreate_str {
    return $_[0]->{'str'};
}

sub task_capability {
    return @cap_tasks;
}

sub get {
    my $self= shift;

# debug EBD
# print "* Entering get() routine\n";
# my $a = `free | grep Mem`;
# print "* $a";
    
    my $got_an_alert= 0;
    do {
        # open a new input source unless one is open (indicated by !defined($self->{'dbh'}))
        while (!defined($self->{'dbh'})) {
            # need to move to a new input source
            my $curinput= $self->{'curinput'}= shift(@{$self->{'inputsleft'}});
            return undef if (!defined($curinput)); # ran out of inputs; we're done!
            
# log the new data source
# open D, ">>.SnortDBInput.log";
# print D "--------------------------------------\n";
# my $d = `date`;
# print D $d . "\n\n";
# print D "Starting new DB data source: " . $curinput . "\n";
# print D "Filter specified: " . $self->{'filter'} . "\n";
# close D;

            my ($user,$pwd,$db,$host,$port)= split(';',$curinput);
            $pwd =~ tr/\001/\;/; # decode encoded password
            $self->{'dbtext'}= "$user\@$db\@$host:$port";

# debug EBD
print "* Connecting to $host, database $db, as $user\n";

# this assumes an argument was passed with the default port
# specific to the database. 

	#if the port is not specified, then it needs to default to something, choosing MySQL
	if (!defined $port) {
		$port = 3306;
	}

	if ($port == 3306) {
		$dbtype = "mysql";
		$dbh = DBI->connect("DBI:$dbtype:$db:$host:$port",$user, $pwd);
# debug EBD
print "* Decided to connect to MySQL\n";

	} elsif ($port == 1521) {
		$dbtype = "Oracle"; 
		$dbh = DBI->connect("DBI:$dbtype:host=$host;sid=$db;port=$port", $user, $pwd);
# debug EBD
print "* Decided to connect to Oracle\n";

	} elsif ($port == 5432) {
		$dbtype = "Pg"; 
		$dbh = DBI->connect("DBI:$dbtype:host=$host;dbname=$db;port=$port", $user, $pwd);
# debug EBD
print "* Decided to connect to PostgreSQL\n";

	}

            if (!defined $dbh) {
                warn "Error connecting to $host as $user; skipping\n";
		warn "Error text: $DBI::errstr\n";
                next;
            }
            # got it open okay
            $self->{'dbh'} = $dbh;
            
            # possible todo: check to see if the database follows the expected schema
            # if ($db_schema != $our_schema) {
            #     warn "$curinput has schema $db_schema, but we only know $our_schema, we'll see how well this works";
            # }
            
            # get sth_event, num_rows, rowcount ready for cycling through the database

            $q_event = "select sid, cid from event";
	    my $whereClause='';
# debug EBD
print "* Staring query: $q_event $whereClause\n";
            if (defined($self->{'dbmin'})) {
                #if ($q_event =~ /where/) {
                if ($whereClause =~ /where/) {
	             $whereClause .= " and ";	
                } else { 
		     $whereClause .= " where "; 
		}
# debug EBD
print "* Staring query: $q_event $whereClause\n";
# modify query format specific to the database.
	        if ($dbtype eq "mysql") {
                    $whereClause .= "unix_timestamp(timestamp) >= " . $self->{'dbmin'};
	        } elsif ($dbtype eq "Oracle") {
		    $whereClause .= "(to_char(timestamp,'J') -
        		to_char(to_date('01-JAN-1970','DD-MON-YYYY'),'J'))*86400 +
        		to_char(timestamp, 'SSSSS') >= " . $self->{'dbmin'};
	        } elsif ($dbtype eq "Pg") {
		    $whereClause .= "(to_char(timestamp,'J') -
        		to_char(to_date('01-JAN-1970','DD-MON-YYYY'),'J'))*86400 +
        		to_char(timestamp, 'SSSSS') >= " . $self->{'dbmin'};
	        }
            }

# debug EBD
print "* Staring query: $q_event $whereClause\n";

            if (defined($self->{'dbmax'})) {
                #if ($q_event =~ /where/) {
                if ($whereClause =~ /where/) {
                     $whereClause .= " and ";
                } else {
                     $whereClause .= " where ";
                }

# debug EBD
print "* Staring query: $q_event $whereClause\n";
	        if ($dbtype eq "mysql") {
	    	    #$q_event .= " unix_timestamp(timestamp) <= " . $self->{'dbmax'};
	    	    $whereClause .= " unix_timestamp(timestamp) <= " . $self->{'dbmax'};
	    	} elsif ($dbtype eq "Oracle") {
                    $whereClause .= "(to_char(timestamp,'J') -
                    	to_char(to_date('01-JAN-1970','DD-MON-YYYY'),'J'))*86400 +
		        to_char(timestamp, 'SSSSS') >= " . $self->{'dbmax'};
	    	} elsif ($dbtype eq "Pg") {
                    $whereClause .= "(to_char(timestamp,'J') -
                    	to_char(to_date('01-JAN-1970','DD-MON-YYYY'),'J'))*86400 +
		        to_char(timestamp, 'SSSSS') >= " . $self->{'dbmax'};
		}
            }

# debug EBD
print "* Staring query: $q_event $whereClause\n";

	    $sth_event = $dbh->prepare("$q_event $whereClause");
            $sth_event->execute();

# debug EBD
# print "* Complete with query\n";
# my $a = `free | grep Mem`;
# print "* $a";
# $state = "SELECT COUNT(*) FROM event $whereClause";
# $sth = $dbh->prepare($state);
# $sth->execute();
# $total_rows = $sth->fetchrow;
        
# debug EBD
# print "Total rows: $total_rows\n";
# open D, ">>.SnortDBInput.log";
# print D "Total rows in event table: " . $total_rows . "\n";
# close D;

            $self->{'sth_event'} = $sth_event;
            $self->{'num_rows'} = $total_rows;
            $self->{'rowcount'} = 0;
        } #end of do

        my $total_rows = $self->{'num_rows'};
        my $rowcount = $self->{'rowcount'};
        my $sth_event = $self->{'sth_event'};

# debug EBD
# printf "* Current row = %d (%5.2f %%)\n", $rowcount, ($rowcount/$total_rows);
 
        @query_results = $sth_event->fetchrow_array;
        $self->{'rowcount'} = $rowcount + 1;
    
# debug EBD
# if ($rowcount > 500000) {
#     return undef;
# }

# debug EBD
# if (!($rowcount % 50000)) {
# 	open D, ">>.SnortDBInput.log";
# 	print D "* Current row:" . $rowcount . "\n";
# 	close D;
# }

        unless (@query_results) { # ran out of events here
            # clean up database here
            $self->{'sth_event'}= undef;
            $self->{'dbh'}= undef; # indicate that we need a new input source
        } else {
            $alert = $self->make_alert($query_results[0],$query_results[1]);
            if (defined $alert) {
# debug EBD
# print "* Alert is valid\n";
# print "* Alert: ".$alert."\n";
# $alert->debug_print('*   ',STDOUT);
                $got_an_alert=
                    (defined($self->{'tasks'}{'all'})
                    || defined($self->{'tasks'}{$alert->type()})) # make sure it matches one of our tasks
                    && $self->{'myfilter'}->test($alert); # make sure it passes our filter too
            } else {
            $got_an_alert = undef;
            }
            unless ($got_an_alert) {
# debug EBD
# open D, ">>.SnortDBInput.log";
# print D "* alert did not pass type test of the filter test\n";
# close D;
            }
        }
    } until ($got_an_alert);

# debug EBD
# if (!defined $alert) {
# 	open D, ">>.SnortDBInput.log";
# 	print D "* alert undefined\n";
# 	close D;
# }
        
    return $alert;
}

########## end of API functions ##############


# if this parsed or unparsed alert is an anomaly report, return the anomaly
# score otherwise return undef
sub is_anom_rept {
    my($alert)= shift;
    my $text= ref($alert) ? $alert->{'sig'} : $alert;
    $text = " ";
    if ($text =~ /(spp_anomsensor|Spade):\s*Anom[ao]ly threshold exceeded:\s*(\d+\.\d+)/i) {
        return $2;
    } else {
        return undef;
    }
}

# parses given sid, cid in snort db into an instance of MemAlert
sub make_alert {
    my($self,$sid,$cid)= @_;

# debug EBD
# print "** Entering make_alert() routine\n";

    my $aid = "snortdb:".$sid.":".$cid;
    my $dbh = $self->{'dbh'};

    #some default values
    my $src_port = 0;
    my $dst_port = 0;

    my $alert = MemAlert->new($aid);
    my $pkt = MemPacket->new();
    $alert->add_packets($pkt);
    $alert->set('source' => $self->{'dbtext'}.'-'."$sid:$cid");

# debug EBD
# print "** Grabbing alert for cid = $cid and sid = $sid\n";
    my $q;
    if ($dbtype eq "mysql") {
   	 $q = "select * from event where cid = $cid and sid = $sid";
    } elsif ($dbtype eq "Oracle") {
    	$q = "select sid,cid,signature,to_char(timestamp, 'yyyy-mm-dd hh24:mi:ss') 
		from event where cid = $cid and sid = $sid";
    } elsif ($dbtype eq "Pg") {
    	$q = "select sid,cid,signature,to_char(timestamp, 'yyyy-mm-dd hh24:mi:ss') 
		from event where cid = $cid and sid = $sid";
    }
    $sth = $dbh->prepare($q);
    $sth->execute();
    my @event = $sth->fetchrow_array;
    my ($datetext,$timetext) = split / /, $event[3];
    my ($year,$month,$day) = split /-/, $datetext;
    my $utime = Time::ParseDate::parsedate($event[3], 'FUZZY' => 1);
    $alert->set('utime' => $utime);

# debug EBD
# open D, ">>.TimeFilter.log";
# print D "** utime real: ".$utime." alert value: ".$alert->utime()."\n";
# close D;
        
# debug EBD
# print "SID: ".$event[0]."\n";
# print "CID: ".$event[1]."\n";
# print "Date: ".$datetext."\n";
# print "Time: ".$timetext."\n";

# debug EBD
# print "** Grabbing signature data for sig_id = $event[2]\n";

    $q = "select * from signature where sig_id = $event[2]";
    $sth = $dbh->prepare($q);
    $sth->execute();
    @signature = $sth->fetchrow_array;
    my $sig_text = $signature[1];
    my $priority = $signature[3];
# look for snort signature reference (sid)
# add the reference to the alert
    if (defined($signature[5])) {
	my $url= &ref_to_url('sid',$signature[5]);
        $alert->add_ref('sid',$signature[5],$url);
    }

# additional code to look for other site references such
# as arachnids, cve, bugtraq, etc
    $q = "select reference.ref_tag, ref_system_name
    from reference_system, sig_reference, reference, signature
    where signature.sig_id=$event[2] and
    sig_reference.ref_id=reference.ref_id and
    signature.sig_id=sig_reference.sig_id and
    reference.ref_system_id=reference_system.ref_system_id";
    $sth = $dbh->prepare($q);
    $sth->execute();
    my @extranfo;
    while ((@extranfo) = $sth->fetchrow_array) {
	if (defined($extranfo[1])) {
		my $url= &ref_to_url($extranfo[1],$extranfo[0]);
		$alert->add_ref($extranfo[1],$extranfo[0],$url);
        }
    }
    
# debug EBD
# print "** Signature: ".substr($sig_text,0,50)."\n";

    my $anom= &is_anom_rept($sig_text);
    if (defined($anom)) {
        $pkt->set('anom' => $anom);
        $alert->set('type' => 'spade');
    } else {
        $pkt->set('anom' => undef);
        if ($sig_text =~ /spp_portscan/) {
            $alert->set('type' => 'spp_portscan');
            return undef;
        } else {
            $alert->set('type' => 'snort');
        }
    }

# debug EBD
# print "** Grabbing iphdr info for cid = $cid and sid = $sid\n";

    $q = "select sid,cid,ip_src,ip_dst,ip_ver,ip_hlen,ip_tos,ip_len,
	  ip_id,ip_flags,ip_off,ip_ttl,ip_proto,ip_csum from 
	  iphdr where cid = $cid and sid = $sid";
    $sth = $dbh->prepare($q);
    $sth->execute();
    my @iphdr = $sth->fetchrow_array;
    my $src_address = $iphdr[2];
    my $dst_address = $iphdr[3];
# convert the hex value ip address
# to decimal
    my $convert;
    $convert = sprintf "%08lx", $src_address;
    my $a = hex (substr ($convert,0,2));
    my $b = hex (substr ($convert,2,2));
    my $c = hex (substr ($convert,4,2));
    my $d = hex (substr ($convert,6,2));
    $src_address = "$a\.$b\.$c\.$d";
    $convert = sprintf "%08lx", $dst_address;
    $a = hex (substr ($convert,0,2));
    $b = hex (substr ($convert,2,2));
    $c = hex (substr ($convert,4,2));
    $d = hex (substr ($convert,6,2));
    $dst_address = "$a\.$b\.$c\.$d";

    my $protocol = $iphdr[12];
    my $ttlstuff = "TTL:" . $iphdr[11] . " TOS:" . $iphdr[6] . " ID:" . $iphdr[8];
    $ttlstuff = $ttlstuff . " IpLen:" . $iphdr[5] . " DgmLen:" . $iphdr[7];

    my $otheropts= '';
    my $prototext= "PROT$protocol";
    $src_port= undef;
    $dst_port= undef;

# debug EBD
if (!defined $protocol) {
	print "** PROTOCOL not defined \n";
	print "** sid: $iphdr[0]\n";
	print "** cid: $iphdr[1]\n";
}

    if ($protocol == 1) {
# ICMP protocol
# debug EBD
# print "** Grabbing icmphdr for cid = $cid and sid = $sid\n";

        $q = "select * from icmphdr where cid = $cid and sid = $sid";
        $sth = $dbh->prepare($q);
        $sth->execute();
        my @icmphdr = $sth->fetchrow_array;
        $pkt->set('protocol' => 'ICMP');
        $prototext = "ICMP";
        # add code to decode icmp_type into string
        $pkt->set('flags' => $icmphdr[2]);
        $otheropts = "Type:" . &numtext($icmphdr[2]) . " Code:" . &numtext($icmphdr[3]);
        $otheropts = $otheropts . " ID:" . &numtext($icmphdr[5]) .
                                " Seq:" . &numtext($icmphdr[6]);
    } #end of ICMP protocol

    if ($protocol == 6) {
# TCP protocol
# debug EBD
# print "** Grabbing tcphdr for cid = $cid and sid = $sid\n";

        $q = "select * from tcphdr where cid = $cid and sid = $sid";
        $sth = $dbh->prepare($q);
        $sth->execute();
        my @tcphdr = $sth->fetchrow_array;
        $src_port = $tcphdr[2];
        $dst_port = $tcphdr[3];
        $pkt->set('protocol' => 'TCP');
        $prototext = "TCP";
        my $flags= &tcpflags_num_to_str($tcphdr[8]);
        $pkt->set('flags' => $flags);
        $otheropts = $flags . " Seq:" . &numtext($tcphdr[4]) . " Ack:" . &numtext($tcphdr[5]);
        $otheropts = $otheropts . " Win:" . &numtext($tcphdr[9]);
    } #end of TCP protocol
    
    if ($protocol == 17) {
# UDP protocol
# debug EBD
# print "** Grabbing udphdr for cid = $cid and sid = $sid\n";

        $q = "select * from udphdr where cid = $cid and sid = $sid";
        $sth = $dbh->prepare($q);
        $sth->execute();
        my @udphdr = $sth->fetchrow_array;
        $src_port = $udphdr[2];
        $dst_port = $udphdr[3];
        $pkt->set('protocol' => 'UDP');
        $prototext = "UDP";
        $otheropts = "";
    } #end of UDP protocol

    if (defined($signature[2])) {
# debug EBD
# print "** Grabbing sig_class for sig_class_id = $signature[2]\n";

        $q = "select * from sig_class where sig_class_id = $signature[2]";
        $sth = $dbh->prepare($q);
        $sth->execute();
        my @classinfo = $sth->fetchrow_array;
        my $classification = $classinfo[1];
        $alert->set('classification_text' => $classification);
    }

    $alert->set('message' => $sig_text);
    $alert->set('priority_num' => $priority);
    $pkt->set('sip' => $src_address, 'dip' => $dst_address, 
        'sport' => $src_port, 'dport' => $dst_port,
        'month' => $month, 'day' => $day, 'tod_text' => $timetext,
        'year' => $year
    );

    #my $anom = <something>;
#    if ($sig_text =~ /(spp_anomsensor|Spade):\s*Anom[ao]ly threshold exceeded:\s+(\d+\.\d+)/i) {
#        $anom = $2;
#    } else {
#        $anom = undef;
#    }

#    if (defined($anom)) {
#        $pkt->set('anom' => $anom);
#        $alert->set('type' => 'spade');
#    } else {
#        $pkt->set('anom' => undef);
        # if ($format eq 'spp_portscan') {
        #     $alert->set('type' => 'spp_portscan');
        # } else {
#             $alert->set('type' => 'snort');
        # }
#    }
    
    my $alert_text = "[**] $sig_text [**]\n";
    #push (@ptext, "[**] $sig_text [**]");
    my $pkt_text = "$datetext:$timetext ";#[smac] -> [dmac] type:[val] len:[val]\n";
    #push (@ptext, "$datetext:$timetext [smac] -> [dmac] type:[val] len:[val]");
    $pkt_text = $pkt_text . "$src_address";
    $pkt_text = $pkt_text . ":$src_port" if defined($src_port);
    $pkt_text = $pkt_text . " -> $dst_address";
    $pkt_text = $pkt_text . ":$dst_port" if defined($src_port);
    $pkt_text = $pkt_text . "\n";
    #push (@ptext, "$src_address:$src_port -> $dst_address:$dst_port ");
    $pkt_text = $pkt_text . $prototext . " " . $ttlstuff;
    #push (@ptext, $prototext . " " . $ttlstuff);
    $pkt_text = $pkt_text . "\n" . $otheropts if length($otheropts);
    #push (@ptext, $otheropts);
    $alert_text.= $pkt_text;
# print "got: $alert_text\n";
    
    $pkt->set('text' => $pkt_text, 'text_format' => 'snortdb-full-pkt');
    $alert->set('text' => $alert_text, 'text_format' => 'snortdb-full-alert');
    # $pkt->set('as_text' => @ptext);
    # $alert->set('text_format' => $pkt_text);
    
#    $alert->add_packets($pkt);

# debug EBD
# print "** Leaving make_alert() routine\n";

    return($alert);
}

sub tcpflags_num_to_str {
    my $flagnum= shift;
    return '' unless defined($flagnum);
    my $str= '';
    $str.= ($flagnum & 0x80) ? '1' : '*';
    $str.= ($flagnum & 0x40) ? '2' : '*';
    $str.= ($flagnum & 0x20) ? 'U' : '*';
    $str.= ($flagnum & 0x10) ? 'A' : '*';
    $str.= ($flagnum & 0x08) ? 'P' : '*';
    $str.= ($flagnum & 0x04) ? 'R' : '*';
    $str.= ($flagnum & 0x02) ? 'S' : '*';
    $str.= ($flagnum & 0x01) ? 'F' : '*';
    return $str;
}

sub numtext {
    my $num= shift;
    return $num if defined($num);
    return '';
}

1;
