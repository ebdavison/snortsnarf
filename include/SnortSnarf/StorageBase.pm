#!/usr/bin/perl

# StorageBase.pm, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2001 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# StorageBase is a partial base class for implementations of the SnortSnarf
# Storage API.  All defined methods are in terms of others that the derived
# class must provide.

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

package StorageBase;

sub type_capable {
    my ($self,$type)= @_;
    foreach ($self->type_capability()) {
        return 1 if $_ eq 'any' || $_ eq $type;
    }
    return 0;
}

sub count {
    my($self,$filter)= @_;
#print STDOUT "StorageBase: $self->count(".&Filter::as_str($filter).")\n";
    return scalar($self->set($filter));
}

sub list {
    my($self,$filter,$sorter)= @_;
#print STDOUT "StorageBase: $self->list(".&Filter::as_str($filter).",".&Filter::as_str($sorter).")\n";
    return $sorter->sort($self->set($filter));
}

sub first_last {
    my($self,$filter,$sorter)= @_;
#print STDOUT "StorageBase: $self->first_last(".&Filter::as_str($filter).",".&Filter::as_str($sorter).")\n";
    return $sorter->first_last($self->set($filter));
}

sub list_range {
    my($self,$filter,$sorter,$first,$last)= @_;
#print STDOUT "StorageBase: $self->list_range(".&Filter::as_str($filter).",".&Filter::as_str($sorter).",$first,$last)\n";
    my(@list)= $self->list($filter,$sorter);
    my $end= $last-1;
    $end= $#list if ($end > $#list);
    return @list[($first-1)..$end];
}

sub distinct_alert_fields {
    my($self,$filter,$field)= @_;
#print STDOUT "StorageBase: $self->distinct_alert_fields(".&Filter::as_str($filter).",$field)\n";
    return scalar($self->alert_field_set($filter,$field));
}

sub alert_field_set {
    my($self,$filter,$field)= @_;
#print STDOUT "StorageBase: $self->alert_field_set(".&Filter::as_str($filter).",$field)\n";
    my %mset= $self->alert_field_multiset($filter,$field);
    return keys %mset;
}

sub alert_field_multiset {
    my($self,$filter,$field)= @_;
#print STDOUT "StorageBase: $self->alert_field_multiset(".&Filter::as_str($filter).",$field)\n";
    my %count=();
    my $val;
    foreach ($self->set($filter)) {
       	$val= $_->$field();
        $val= '*undef*' unless defined($val);
        $count{$val}++;
    }
    return %count;
}

sub distinct_packet_fields {
    my($self,$filter,$field)= @_;
#print STDOUT "StorageBase: $self->distinct_packet_fields(".&Filter::as_str($filter).",$field)\n";
    return scalar($self->packet_field_set($filter,$field));
}

sub packet_field_set {
    my($self,$filter,$field)= @_;
#print STDOUT "StorageBase: $self->packet_field_set(".&Filter::as_str($filter).",$field)\n";
    my %mset= $self->packet_field_multiset($filter,$field);
    return keys %mset;
}

sub packet_field_multiset {
    my($self,$filter,$field)= @_;
#print STDOUT "StorageBase: $self->packet_field_multiset(".&Filter::as_str($filter).",$field)\n";
    my %count=();
    my($alert,$val);
    foreach $alert ($self->set($filter)) {
        foreach ($alert->packets()) {
            $val= $_->$field();
            $val= '*undef*' unless defined($val);
            $count{$val}++;
        }
    }
    return %count;
}

1;
