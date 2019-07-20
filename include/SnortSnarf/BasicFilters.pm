#!/usr/bin/perl

# BasicFilters.pm, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2001 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# this file contains a set of basic implementations of the SnortSnarf
# Filter API

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.


use Filtering;
use KnownEquiv;

##########################################################

package TrueFilter;

# the all-inclusive filter that rejects nothing

@ISA= (qw(ScalarKE));

sub new {
	my $true= 'True';
	return bless \$true,$_[0]; # no need for instance storage
}

sub as_str {
	return '1';
}

sub test {
	return 1;
}

##########################################################

package FalseFilter;

# the all-hating filter that rejects everything

@ISA= (qw(ScalarKE));

sub new {
	my $false= 'False';
	return bless \$false,$_[0]; # no need for instance storage
}

sub as_str {
	return '0';
}

sub test {
	return 0;
}

##########################################################

package NotFilter;

# a filter class that returns opposite of another alert filter

@ISA= (qw(ScalarKE));

sub new {
	my($filter);
	my($class)= shift;
	if (ref($_[0])) {
		$filter= $_[0];
	} else {
		my($strspec)= shift;
		$filter= Filter::from_str($strspec);
	}
	return bless \$filter,$class; 
}

sub as_str {
	return Filter::as_str(${$_[0]});
}

sub test {
	my($self,$alert)= @_;
	return !${$self}->test($alert);
}

##########################################################

package AndFilter;

# a filter class that returns true iff all the enclosed filters evalute to true

@ISA= (qw(ArrayKE));

sub new {
	my($class)= shift;
	my(@filters);
	if (@_ > 1 || @_ == 1 && ref($_[0])) {
		@filters= @_;
	} else {
		my($strspec)= shift;
		my @filterstrs= Filter::unjoin_strs($strspec);
		@filters= map(Filter::from_str($_),@filterstrs);
	}
	return bless \@filters,$class; 
}

sub as_str {
	my(@filterstrs)= map(Filter::as_str($_),@{$_[0]});
	return Filter::join_strs(@filterstrs);
}

sub test {
	my($self,$alert)= @_;
	my $filter;
	foreach $filter (@{$self}) {
		return 0 unless $filter->test($alert);
	}
	return 1;
}

##########################################################

package OrFilter;

# a filter class that returns false iff all the enclosed filters evalute to false

@ISA= (qw(ArrayKE));

sub new {
	my(@filters);
	my($class)= shift;
	if (@_ > 1 || @_ == 1 && ref($_[0])) {
		@filters= @_;
	} else {
		my($strspec)= shift;
		my @filterstrs= Filter::unjoin_strs($strspec);
		@filters= map(Filter::from_str($_),@filterstrs);
	}
	return bless \@filters,$class; 
}

sub as_str {
	my(@filterstrs)= map(Filter::as_str($_),@{$_[0]});
	return Filter::join_strs(@filterstrs);
}

sub test {
	my($self,$alert)= @_;
	my $filter;
	foreach $filter (@{$self}) {
		return 1 if $filter->test($alert);
	}
	return 0;
}

##########################################################

package AlertFieldDef;

# a filter class that matches iff a certain alert field is defined (or undefined)

@ISA= (qw(ArrayKE));

sub new {
	my($class)= shift;
	my($strspec)= shift;
	my $tense = ($strspec =~ s/^!//) ? 0 : 1;
	$strspec =~ s/\s+$//;
	return bless [$tense,$strspec],$class; 
}

sub as_str {
	my($tense,$field)= @{$_[0]};
	return ($tense?'':'!').$field;
}

sub test {
	my($self,$alert)= @_;
	my $meth=$self->[1];
	my $def= defined($alert->$meth());
	return $self->[0] ? $def : !$def;
}

##########################################################

package AlertFieldEq;

# a filter class that matches iff a certain alert field has a certain value (stringwise comparison)

@ISA= (qw(ArrayKE));

sub new {
	my($class)= shift;
	my($strspec)= shift;
	my($field,$val)= split(/\s*=\s*/,$strspec,2);
	$val =~ s/\s+$//;
	return bless [$field,$val],$class; 
}

sub as_str {
	my($field,$val)= @{$_[0]};
	return "$field=$val";
}

sub test {
	my($self,$alert)= @_;
	my $meth=$self->[0];
	return $alert->$meth() eq $self->[1];
}


##########################################################

package AlertFieldCompare;

# a filter class that matches if a certain string comparison operation with given alert field on the right and a certain string on the left evaluates to true

@ISA= (qw(ArrayKE));

sub new {
	my($class)= shift;
	my($strspec)= shift;
	my($field,$op,$val)= split(/\s*$Filtering::strcmpops_regex\s*/,$strspec,2);
	$val =~ s/\s+$//;
	return bless [$op,$field,$val],$class; 
}

sub as_str {
	my($op,$field,$val)= @{$_[0]};
	return "$field $op $val";
}

sub test {
	my($self,$alert)= @_;
	my($op,$field,$val)= @{$self};
	return &Filtering::strcmpops($op,$alert->$field(),$val);
}


##########################################################

package AlertFieldNumCompare;

# a filter class that matches if a certain numeric comparison operation with given alert field on the right and a certain number on the left evaluates to true

@ISA= (qw(ArrayKE));

sub new {
	my($class)= shift;
	my($strspec)= shift;
	my($field,$op,$val)= split(/\s*$Filtering::numcmpops_regex\s*/,$strspec,2);
	$val =~ s/\s+$//;
	return bless [$op,$field,$val],$class; 
}

sub as_str {
	my($op,$field,$val)= @{$_[0]};
	return "$field $op $val";
}

sub test {
	my($self,$alert)= @_;
	my($op,$field,$val)= @{$self};
	return &Filtering::numcmpops($op,$alert->$field(),$val);
}

##########################################################

package AnyPacketFilter;

# a filter class that matches iff the provided packeet filter matches any packet in the given alert

@ISA= (qw(ScalarKE));

sub new {
	my($class)= shift;
	my($pktfilter)= shift;
	unless (ref($pktfilter)) {
		$pktfilter= Filter::from_str($pktfilter);
	}
	return bless \$pktfilter,$class; 
}

sub as_str {
	return Filter::as_str(${$_[0]});
}

sub test {
	my($self,$alert)= @_;
	foreach ($alert->packets()) {
		return 1 if ${$self}->test($_);
	}
	return 0;
}

##########################################################

package AllPacketFilter;

# a filter class that matches iff the provided packeet filter matches all packets in the given alert

@ISA= (qw(ScalarKE));

sub new {
	my($class)= shift;
	my($pktfilter)= shift;
	unless (ref($pktfilter)) {
		$pktfilter= Filter::from_str($pktfilter);
	}
	return bless \$pktfilter,$class; 
}

sub as_str {
	return Filter::as_str(${$_[0]});
}

sub test {
	my($self,$alert)= @_;
	foreach ($alert->packets()) {
		return 0 if !${$self}->test($_);
	}
	return 1;
}

##########################################################

package FieldDefPktFilter;

# a packet filter class that matches if a certain string comparison operation with given packet field on the right and a certain string on the left evaluates to true

@ISA= (qw(ArrayKE));

sub new {
	my($class)= shift;
	my($strspec)= shift;
	my $tense = ($strspec =~ s/^!//) ? 0 : 1;
	$strspec =~ s/\s+$//;
	return bless [$tense,$strspec],$class; 
}

sub as_str {
	my($tense,$field)= @{$_[0]};
	return ($tense?'':'!').$field;
}

sub test {
	my($self,$packet)= @_;
	my $meth=$self->[1];
	my $def= defined($packet->$meth());
	return $self->[0] ? $def : !$def;
}

##########################################################

package FieldComparePktFilter;

# a packet filter class that matches if a certain string comparison operation with given packet field on the right and a certain string on the left evaluates to true

@ISA= (qw(ArrayKE));

sub new {
	my($class)= shift;
	my($strspec)= shift;
	my($field,$op,$val)= split(/\s*$Filtering::strcmpops_regex\s*/,$strspec,2);
	$val =~ s/\s+$//;
	return bless [$op,$field,$val],$class; 
}

sub as_str {
	my($op,$field,$val)= @{$_[0]};
	return "$field $op $val";
}

sub test {
	my($self,$packet)= @_;
	my($op,$field,$val)= @{$self};
	return &Filtering::strcmpops($op,$packet->$field(),$val);
}


##########################################################

package FieldNumComparePktFilter;

# a packet filter class that matches if a certain numeric comparison operation with given packet field on the right and a certain number on the left evaluates to true

@ISA= (qw(ArrayKE));

sub new {
	my($class)= shift;
	my($strspec)= shift;
	my($field,$op,$val)= split(/\s*$Filtering::numcmpops_regex\s*/,$strspec,2);
	$val =~ s/\s+$//;
	return bless [$op,$field,$val],$class; 
}

sub as_str {
	my($op,$field,$val)= @{$_[0]};
	return "$field $op $val";
}

sub test {
	my($self,$packet)= @_;
	my($op,$field,$val)= @{$self};
	return &Filtering::numcmpops($op,$packet->$field(),$val);
}


##########################################################

package IPFilterBase;

# a base class for a filter class that matches IPs

@ISA= (qw(ArrayKE));

sub new {
	my($class)= shift;
	my($strspec)= shift;
	my($ip,$masksize)= split('/',$strspec);
	$masksize= 32 unless defined($masksize);
    my(@bytes)= split('\.',$ip);
    my $homenetaddr= ($bytes[0] << 24) | ($bytes[1] << 16) | ($bytes[2] << 8) | $bytes[3];
    my (@bytembits)= ();
    foreach (1..4) {
        if ($masksize <= 0) {
            push(@bytembits,0);
        } else {
            $masksize-= 8;
            if ($masksize >= 0) {
                push(@bytembits,255);
            } else {
                push(@bytembits,(0x80,0xC0,0xE0,0xF0,0xF8,0xFC,0xFE)[$masksize+7]);
            }
        }
    }
    my $homenetmask= ($bytembits[0] << 24) | ($bytembits[1] << 16) | ($bytembits[2] << 8) | $bytembits[3];
    $homenetaddr &= $homenetmask;
	return bless [$homenetaddr,$homenetmask,$strspec],$class; 
}

sub as_str {
	return $_[0]->[2];
}

sub test_ip {
    my($self,$ip)= @_;
    my $homenetaddr= $self->[0];
    my $homenetmask= $self->[1];
    return 0 unless defined($ip) && length($ip);
    my @ipbytes= split('\.',$ip);
    push(@ipbytes,0,0,0,0) unless @ipbytes >= 4; # just in case the IP addr wasn't long enough for some reason
    my $ipbits= ($ipbytes[0] << 24) | ($ipbytes[1] << 16) | ($ipbytes[2] << 8) | $ipbytes[3];
    return ($ipbits & $homenetmask) == $homenetaddr;
}

package HasSourceIPInFilter;

# a filter class that matches if any of the source IPs in the alert are in the given subnet

@ISA= (qw(IPFilterBase));

sub test {
	my($self,$alert)= @_;
	my($sip);
	foreach $sip ($alert->packet_fields('sip')) {
	    return 1 if $self->test_ip($sip);
    }
    return 0;
}

package HasDestIPInFilter;

# a filter class that matches if any of the destination IPs in the alert are in the given subnet

@ISA= (qw(IPFilterBase));

sub test {
	my($self,$alert)= @_;
	my($dip);
	foreach $dip ($alert->packet_fields('dip')) {
	    return 1 if $self->test_ip($dip);
    }
    return 0;
}

##########################################################


package NotRefSourceIDsFilter;

# a filter class that matches if a given reference type is not present or is not one of a set of ids

@ISA= (qw(ArrayKE));

sub new {
	my($class)= shift;
	my($refname)= shift;
    my @parts= split('!=',$refname);
    if (@parts > 1) {
        $refname= $parts[0];
        @_=split(',',$parts[1]);
    }
    my %ids;
    foreach (@_) { $ids{$_}= 1; }
	return bless [$refname,%ids],$class; 
}

sub as_str {
	my($refname,%ids)= @{$_[0]};
	return "$refname!=".join(',',keys %ids);
}

sub test {
	my($self,$alert)= @_;
	my($refname,%ids)= @{$self};
	my $refid;
	($refid,undef)= $alert->reference($refname);
	return !defined($refid) || !defined($ids{$refid});
}


1;
