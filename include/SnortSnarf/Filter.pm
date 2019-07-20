#!/usr/bin/perl

# Filter.pm, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2001 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# This file contains a set of helper functions and instances of common filters
# for users of filter modules.

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

package Filter;
use BasicFilters;
use TimeFilters;
use AllMods;

sub BEGIN {
	# some static filters
    $true= TrueFilter->new();
    $snort_gen_alert= OrFilter->new(
        AlertFieldEq->new("type=snort"),
        AlertFieldEq->new("type=spp_portscan"),
        AlertFieldEq->new("type=spp_portscan2")
    );
    $anom_rept= AnyPacketFilter->new(FieldDefPktFilter->new('anom'));
    $nosig= AlertFieldDef->new('!message');
    $alert_nosip= AllPacketFilter->new(FieldDefPktFilter->new('!sip'));
    $alert_nodip= AllPacketFilter->new(FieldDefPktFilter->new('!dip'));
    $anynosip= AnyPacketFilter->new(FieldDefPktFilter->new('!sip'));
    $anynodip= AnyPacketFilter->new(FieldDefPktFilter->new('!dip'));
}


# return a filter to match a particular signature
sub for_sig {
	return $Filter::nosig if !defined($_[0]) || $_[0] eq '*undef*';
    return AlertFieldEq->new("message=$_[0]");
}

# return a filter to match a particular source IP in any packet
sub for_anysip {
	return $Filter::anynosip if !defined($_[0]) || $_[0] eq '*undef*';
    return AnyPacketFilter->new(FieldComparePktFilter->new("sip=$_[0]"));
}

# return a filter to match a particular dest IP in any packet
sub for_anydip {
	return $Filter::anynodip if !defined($_[0]) || $_[0] eq '*undef*';
    return AnyPacketFilter->new(FieldComparePktFilter->new("dip=$_[0]"));
}

# return a filter to match a particular signature in the alert and a source IP in any packet
sub for_sig_anysip {
    return AndFilter->new(&for_sig($_[0]),&for_anysip($_[1]));
}

# return a filter to match a particular signature in the alert and a dest IP in any packet
sub for_sig_anydip {
    return AndFilter->new(&for_sig($_[0]),&for_anydip($_[1]));
}
 
# return a filter to match a an alert if it has priority number above the given or if it has no priority defined
sub for_minprioritynum {
   return OrFilter->new(AlertFieldDef->new('!priority_num'),AlertFieldNumCompare->new("priority_num >= $_[0]"));
}
 
# return a filter to match a an alert if it has priority number below the given or if it has no priority defined
sub for_maxprioritynum {
   return OrFilter->new(AlertFieldDef->new('!priority_num'),AlertFieldNumCompare->new("priority_num <= $_[0]"));
}

# return a filter to match a an alert if it has no known snort id (sid) or if the sid is not one of a given set
sub to_exclude_sids {
   return NotRefSourceIDsFilter->new('sid',@_);
}


# if this is a recognized filter for a particular signature, return the signature it is looking for
sub known_sig_filter {
    my($filter)= @_;
	return '*undef*' if $_[0] == $Filter::nosig;
    return 0 unless ref($filter) eq 'AlertFieldEq';
    return 0 unless $filter->[0] eq 'message';
    return $filter->[1];
    # should also handle AlertFieldCompare
}

# if this is a recognized filter for a particular sip appearing in any packet of an alert, return the sip being looking for
sub known_anysip_filter {
    my($filter)= @_;
	return '*undef*' if $_[0] == $Filter::anynosip;
    return 0 unless ref($filter) eq 'AnyPacketFilter';
    my $pktfilter= ${$filter};
    return 0 unless ref($pktfilter) eq 'FieldComparePktFilter';
    return 0 unless $pktfilter->[1] eq 'sip' && $pktfilter->[0] eq '=';
    return $pktfilter->[2];
}

# if this is a recognized filter for a particular dip appearing in any packet of an alert, return the dip being looking for
sub known_anydip_filter {
    my($filter)= @_;
	return '*undef*' if $_[0] == $Filter::anynodip;
    return 0 unless ref($filter) eq 'AnyPacketFilter';
    my $pktfilter= ${$filter};
    return 0 unless ref($pktfilter) eq 'FieldComparePktFilter';
    return 0 unless $pktfilter->[1] eq 'dip' && $pktfilter->[0] eq '=';
    return $pktfilter->[2];
}

# if this is a recognized filter for a particular signature and a particular sip appearing in any packet of an alert, return the signagure and sip being looking for
sub known_sig_anysip_filter {
    my($filter)= @_;
    my($sig,$sip);
    return () unless ref($filter) eq 'AndFilter';
    return () unless @{$filter} == 2;
    my($f1,$f2)= @{$filter};
    if ($sig= &known_sig_filter($f1)) {
        if ($sip= &known_anysip_filter($f2)) {
            return ($sig,$sip);
        }
    } elsif ($sig= &known_sig_filter($f2)) {
        if ($sip= &known_anysip_filter($f1)) {
            return ($sig,$sip);
        }
    }
    return ();
}

# if this is a recognized filter for a particular signature and a particular dip appearing in any packet of an alert, return the signagure and dip being looking for
sub known_sig_anydip_filter {
    my($filter)= @_;
    my($sig,$dip);
    return () unless ref($filter) eq 'AndFilter';
    return () unless @{$filter} == 2;
    my($f1,$f2)= @{$filter};
    if ($sig= &known_sig_filter($f1)) {
        if ($dip= &known_anydip_filter($f2)) {
            return ($sig,$dip);
        }
    } elsif ($sig= &known_sig_filter($f2)) {
        if ($dip= &known_anydip_filter($f1)) {
            return ($sig,$dip);
        }
    }
    return ();
}

# if this is a recognized filter for a minimum time, return the time in question
sub known_mintime_filter {
    my($filter)= @_;
    return undef unless ref($filter) eq 'MinTimeFilter';
    return ${$filter};
}

# if this is a recognized filter for a maximum time, return the time in question
sub known_maxtime_filter {
    my($filter)= @_;
    return undef unless ref($filter) eq 'MaxTimeFilter';
    return ${$filter};
}



# this method creates a cannonical name for a filter (or anything with a as_str method that returns a string form of the filter)
sub as_str {
    my($filter)= shift;
    return ref($filter).':'.$filter->as_str();
}

# this method produces a filter (or anything encoded that recreates itself from a string argument to new) from a string returned by Filter::as_str; if the running of 'new' fails on the indicated class (did you remember to load the class?), returns undef
sub from_str {
    my($filterstr)= shift;
    my($class,$str)= split(':',$filterstr,2);
    my $obj;
    return undef unless &AllMods::load_module_named($class);
    eval { $obj= $class->new($str); };
    return undef if(@$);
    return $obj;
}

# this is a utility function to join filter string specifications as produced by Filter::as_str in such a way as they can be extracted by Filter::unjoin_strs
sub join_strs {
    return join(',',map("($_)",@_));    
}

# this is a utility function to split filter string specifications that have been encoded by Filter::join_strs
sub unjoin_strs {
    my @list= ();
    my $tok;
    foreach $tok (&paren_split(',',$_[0])) {
        $tok =~ s/^\(//; $tok =~ s/\)$//;
        push(@list,$tok);
    }
    return @list;
}

# split on a separator at the top level (with respect to parenthesis)
sub paren_split {
    my($sep,$str)= @_;
    my $depth= 0;
    my @list= ('');
    my $pos= 0;
    while ($str =~ s/^([^$sep]*)$sep//) {
        my $text= $1;
        $depth+= &check_parens($text); # update depth of paren nesting as of last separator found
        if ($depth == 0) { # balanced so this separator counts
            $list[$pos].= $text;
            $pos++;
            $list[$pos]= '';
        } else { # unbalanced, so ignore this separator
            $list[$pos].= "$text$sep";
        }
    }
    # no more seperators
    $list[$pos].= $str;
    return @list;
}

# return the balance of parentheses (starting with 0, add one for each '(' and subtract one for each ')')
sub check_parens {
    $_= shift;
    my $balance= 0;
    while (1) {
        if (s/^[^\(\)]*\(//) {
            $balance++;
        } elsif (s/^[^\(\)]*\)//) {
            $balance--;
        } else {
            last; # no more parens
        }
    }
    return $balance;
}




sub raw_as_str {
    my $thing= shift;
    return $thing unless ref($thing);
    my $out= ref($thing).'(';
    if ($thing =~ /SCALAR/) {
        return $out.&raw_as_str($$thing).')';
    } elsif ($thing =~ /ARRAY/) {
        return $out.join(',',map(&raw_as_str($_),@{$thing})).')';
    } elsif ($thing =~ /HASH/) {
        return $out.join(',',map("$_ => ".&raw_as_str($thing->{$_}),keys %{$thing})).')';
    }
    return $thing;
}

1;
