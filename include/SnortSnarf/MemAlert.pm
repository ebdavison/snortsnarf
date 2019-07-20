#!/usr/bin/perl

# MemAlert.pm, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2001 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# MemAlert is a simple implementation of the Alert API, storing everything
# in memory inside a class instance.

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.


package MemAlert;

use AlertBase;
use MemTimeBase;

@ISA= qw(MemTimeBase AlertBase);

# create a new alert
sub new {
    my($class,$id,$altext,$format,$type,$source,$message,$time,$packets,$refhash)= @_;
    $packets= [] unless defined($packets);
    $refhash= {} unless defined($refhash);
    my $self= bless {
        'id' => $id,
        'message' => $message,
        'source' => $source,
        'type' => $type,
        'utime' => $time,
        'packets' => $packets,
        'text' => $altext,
        'text_format' => $format,
        'refs' => $refhash}, $class;
    return $self;
}

# set some fields to the given values
sub set {
    my($self,%fields)= @_;
    foreach (keys %fields) {
        $self->{$_}= $fields{$_};
        if ($_ eq 'year' || $_ eq 'month' || $_ eq 'day' || $_ eq 'tod_text') {
        	delete $self->{'utime'}; # updated year, month, day, or tod_text invalidates utime
        } elsif ($_ eq 'utime') {
        	delete $self->{'year'}; # updated utime invalidates year, month, day, and tod_text
        	delete $self->{'month'};
        	delete $self->{'day'};
        	delete $self->{'tod_text'};
        }
    }
}

# add a reference
sub add_ref {
    my($self,$refname,$id,$url)= @_;
    $self->{'refs'}{$refname}= [$id,$url];
}

# add references
sub add_refs {
    my($self)= @_;
    while (@_) {
    	my $refname= shift(@_);
	    $self->{'refs'}{$refname}= [shift(@_),shift(@_)];
	}
}

# add a list of packets to the alert
sub add_packets {
    my($self)= shift;
    push(@{$self->{'packets'}},@_);
}

# print a summary of the alert
sub debug_print {
    my($self,$ind,$fh)= @_;
    my $prev=select($fh) if defined($fh);
    foreach (qw(id message source type text text_format utime)) {
        print "$ind$_: ".(defined($self->{$_}) ? $self->{$_} : '*undef*')."\n";
    }
    print "$ind"."refs: {".join(', ',map("$_=[".$self->{'refs'}{$_}[0].",".$self->{'refs'}{$_}[1]."]",keys %{$self->{'refs'}}))."}\n";
    print "$ind"."packets (ids): ".join(',',map($_->id(),@{$self->{'packets'}}))."\n";
    select($prev) if defined($fh);
}


# API routines

sub packets {
    return @{$_[0]->{'packets'}};
}

sub id {
    return $_[0]->{'id'};
}

sub type {
    return $_[0]->{'type'};
}

sub message {
    return $_[0]->{'message'};
}

sub references {
    return keys %{$_[0]->{'refs'}};
}

sub reference {
    return () unless defined($_[0]->{'refs'}{$_[1]});
    return @{$_[0]->{'refs'}{$_[1]}};
}

sub source {
    return $_[0]->{'source'};
}

sub as_text {
    return $_[0]->{'text'} if defined($_[0]->{'text'});
    return $_[0]->AlertBase::as_text();
}

sub text_format {
    return $_[0]->{'text_format'} if defined($_[0]->{'text'});
    return $_[0]->AlertBase::text_format();
}

sub priority_num {
    return $_[0]->{'priority_num'};
}

sub classification_text {
    return $_[0]->{'classification_text'};
}

1;
