#!/usr/bin/perl


# MemPacket.pm, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2001 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# MemPacket is a simple implementation of the Packet API, storing everything
# in memory inside a class instance.

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

package MemPacket;

use PacketBase;
use MemTimeBase;

@ISA= qw(MemTimeBase PacketBase);

# create a new packet starting with the given fields
sub new {
    my($class,%fields)= @_;
    # valid field names are: id, source, sip, sport, dip, dport, protocol, flags, anom, text, format, utime, year, month, date, hour, min, sec
    my $self= bless \%fields;
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

# return whether the given field is set
sub is_set {
    return defined($_[0]->{$_[1]});
}

sub get { # raw access to what has been added
    return $_[0]->{$_[1]};
}

sub debug_print {
    my($self,$ind,$fh)= @_;
    my $prev=select($fh) if defined($fh);
    foreach (keys %{$self}) {
        print "$ind$_: ".(defined($self->{$_}) ? $self->{$_} : '*undef*')."\n";
    }
    select($prev) if defined($fh);
}


# API methods
sub id {
    return $_[0]->{'id'};
}

sub souce {
    return $_[0]->{'souce'};
}

sub sip {
    return $_[0]->{'sip'};
}

sub sport {
    return $_[0]->{'sport'};
}

sub dip {
    return $_[0]->{'dip'};
}

sub dport {
    return $_[0]->{'dport'};
}

sub protocol {
    return $_[0]->{'protocol'};
}

sub flags {
    return $_[0]->{'flags'};
}

sub anom {
    return $_[0]->{'anom'};
}

sub as_text {
    return $_[0]->{'text'} if defined($_[0]->{'text'});
    return $_[0]->PacketBase::as_text();
}

sub text_format {
    return $_[0]->{'text_format'} if defined($_[0]->{'text'});
    return $_[0]->PacketBase::text_format();
}


1;
