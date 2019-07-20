#!/usr/bin/perl

# MemStorage.pm, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2001 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# MemStorage is a simple implementation of the SnortSnarf Storage API.  All
# alerts are stored in memory.  This class is designed to be friendly to being
# a base class to classes that might want to, e.g., optimize certain accesses.

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

package MemStorage;

@ISA= (qw(StorageBase));

use StorageBase;

########## API functions ##############

sub new {
    my($class,%params)= @_;
    my $self= bless {},$class;
    $self->{'al_by_id'}= {};
    return $self;
}

sub type_capability {
    return (qw(any));
}

sub type_capable {
    return 1;
}

sub store {
    my($self)= shift;
    foreach (@_) {
        $self->{'al_by_id'}{$_->id()}= $_;
    }
}

sub forget {
    my($self,$filter)= @_;
    my $alert;
    foreach (keys %{$self->{'al_by_id'}}) {
        $alert= $self->{'al_by_id'}{$_};
        if ($filter->test($alert)) {
            delete $self->{'al_by_id'}{$_}; # bye bye
        }
    }
}

sub alert_by_id {
    my($self,$id)= @_;
    return $self->{'al_by_id'}{$id};
}

sub set {
    my($self,$filter)= @_;
#print STDOUT "MemStorage: $self->set(".&Filter::as_str($filter).")\n";
    return grep($filter->test($_),values %{$self->{'al_by_id'}});
}

sub count {
    my($self,$filter)= @_;
#print STDOUT "MemStorage: $self->count(".&Filter::as_str($filter).")\n";
    my $count= 0;
    foreach (values %{$self->{'al_by_id'}}) {
        $count++ if ($filter->test($_));
    }
    return $count;
}

1;
