#!/usr/bin/perl

# MultiStore.pm, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2001 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# MultiStore is an implementation of the SnortSnarf Storage API that is simply
# a container for a list of other Storage modules.  Results of API method calls
# are obtained by calling API method calls of the the contained Storage
# modules.  New additions are stored in the first contained module that is
# capable of storing the alert type.  It is assumed that alerts are only stored
# once among the modules.

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

package MultiStore;

use StorageBase;

@ISA= qw(StorageBase);

sub new {
    my($class,%params)= @_;
    my @stores= @{delete $params{'cont'}};
    my $self= bless \@stores,$class;
    return $self;
}

# non API method:  add a storage module to the start of the list of the stores this instance contains
sub add {
    push(@{$_[0]},$_[1]);
}

sub type_capability {
    return (qw(any));
}

sub type_capabible {
    return 1;
}

sub store {
    my($self)= shift;
    my($store,$type);
    foreach (@_) {
        $type= $_->type();
        foreach $store (@{$self}) {
            if ($store->type_capable($type)) {
                $store->store($_);
                last;
            }
        }
    }
}

sub forget {
    my($self,$filter)= @_;
    my $alert;
    foreach (@{$self}) {
        $_->forget($filter);
    }
}

sub alert_by_id {
    my($self,$id)= @_;
    my $alert;
    foreach (@{$self}) {
        $alert= $_->alert_by_id($id);
        return $alert if defined($alert);
    }
    return undef;
}

sub set {
    my($self,$filter)= @_;
    my(@set)= ();
    foreach (@{$self}) {
        push(@set,$_->set($filter));
    }
    return @set;
}

sub count {
    my($self,$filter)= @_;
    my $count= 0;
    foreach (@{$self}) {
        $count+= $_->count($filter);
    }
    return $count;
}

sub list {
    my($self,$filter,$sorter)= @_;
    my($list)= [$self->[0]->list($filter,$sorter)];
    foreach (@{$self}[1..$#{$self}]) {
        $sorter->merge($list,$_->list($filter,$sorter));
    }
    return @{$list};
}

sub first_last {
    my($self,$filter,$sorter)= @_;
    my(@alerts)= ();
    foreach (@{$self}) {
        push(@alerts,$_->first_last($filter,$sorter));
    }
    return $sorter->first_last(@alerts);
}

sub list_range {
    my($self,$filter,$sorter,$first,$last)= @_;
    my(@list)= $self->list($filter,$sorter);
    my $end= $last-1;
    $end= $#list if ($end > $#list);
    return @list[($first-1)..$end];
}

sub alert_field_set {
    my($self,$filter,$field)= @_;
    my $val;
    my(%vals)= ();
    foreach (@{$self}) {
        foreach $val ($_->alert_field_set($filter,$field)) {
            $vals{$val}= 1;
        }
    }
    return keys %vals;
}

sub alert_field_multiset {
    my($self,$filter,$field)= @_;
    my %count=();
    foreach (@{$self}) {
        my %subcount= $_->alert_field_multiset($filter,$field);
        foreach $val (keys %subcount) {
            $count{$val}+= $subcount{$val};
        }
    }
    return %count;
}

sub packet_field_set {
    my($self,$filter,$field)= @_;
    my $val;
    my(%vals)= ();
    foreach (@{$self}) {
        foreach $val ($_->packet_field_set($filter,$field)) {
            $vals{$val}= 1;
        }
    }
    return keys %vals;
}

sub packet_field_multiset {
    my($self,$filter,$field)= @_;
    my %count=();
    foreach (@{$self}) {
        my %subcount= $_->packet_field_multiset($filter,$field);
        foreach $val (keys %subcount) {
            $count{$val}+= $subcount{$val};
        }
    }
    return %count;
}

1;
