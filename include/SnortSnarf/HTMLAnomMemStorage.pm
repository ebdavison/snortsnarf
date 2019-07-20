#!/usr/bin/perl

# HTMLAnomMemStorage.pm, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2001 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# HTMLAnomMemStorage is an implementation of the SnortSnarf Storage API
# optimized to store anomaly reports for the traditional SnortSnarf HTML page
# uses.  All alerts are stored in memory.

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.


package HTMLAnomMemStorage;

# more to optimize yet

# not yet optimized:
#  + regarding anom dest H alerts: [filter=AnyPacketFilter(FieldComparePktFilter('dip=H'))]
#    + quantity of distinct source IPs
#       0+packet_field_set(filter,'sip')
#  + regarding anom source H alerts: [filter=AnyPacketFilter(FieldComparePktFilter('sip=H'))]
#    + quantity of distinct dest IPs
#       0+packet_field_set(filter,'dip')


use MemStorage;
use BasicFilters;
use Sort;
use Filter;

@ISA=(MemStorage);

########## API creation/addition/deletion functions ##############

sub new {
    my($class,%params)= @_;
    my $self= bless $class->MemStorage::new(%params),$class;
    $self->{'lt'}= []; # list of alerts, kept sorted by alert time
    $self->{'la'}= []; # list of alerts, kept sorted by highest anomaly score
    $self->{'l_sip'}= {}; # per-sip list of alerts, kept sorted by alert time
    $self->{'l_dip'}= {}; # per-dip list of alerts, kept sorted by alert time
    $self->{'c_sip'}= {}; # per-sip count of alerts
    $self->{'c_dip'}= {}; # per-dip count of alerts
    return $self;
}

sub store {
    my($self,@alerts)= @_;
    my($alert,$pkt,$sip,$dip,@salerts,$pos);
    my %sip_alerts= ();
    my %dip_alerts= ();
    $self->MemStorage::store(@alerts);

    @salerts= sort {$a->utime() <=> $b->utime()} @alerts;
    $pos= $#{$self->{'lt'}};
    while ($alert= pop(@salerts)) {
        while ($pos >= 0 && $alert->time_cmp($self->{'lt'}[$pos]) == -1) {
            $pos--;
        }
        if ($pos < 0) { # hit the front
            unshift(@{$self->{'lt'}},@salerts,$alert);
            last;
        }
        splice(@{$self->{'lt'}},$pos+1,0,$alert);
    }
    
    @salerts= $Sort::byhighestanom->sort(@alerts);
    $pos= $#{$self->{'la'}};
    while ($alert= pop(@salerts)) {
        while ($pos >= 0 && $Sort::byhighestanom->cmp($alert,$self->{'la'}[$pos]) == -1) {
            $pos--;
        }
        if ($pos < 0) { # hit the front
            unshift(@{$self->{'la'}},@salerts,$alert);
            last;
        }
        splice(@{$self->{'la'}},$pos+1,0,$alert);
    }
    
    foreach $alert (@alerts) {
        foreach $pkt ($alert->packets()) {
            $sip= $pkt->sip();
            $sip= '*undef*' unless defined($sip);
            $dip= $pkt->dip();
            $dip= '*undef*' unless defined($dip);
            push(@{$sip_alerts{$sip}},$alert);
            push(@{$dip_alerts{$dip}},$alert);
            $self->{'c_sip'}{$sip}++;
            $self->{'c_dip'}{$dip}++;
        }
    }
    
    foreach $sip (keys %sip_alerts) {
        # add @sipalerts to $arr in time-sorted order by walking backward from end of $arr and splicing in alerts at the appropiate spots
        $self->{'l_sip'}{$sip}= [] unless defined($self->{'l_sip'}{$sip}); # init the storage, so we can make changes to it
        my $arr= $self->{'l_sip'}{$sip};
        #print "arr[$sip]= (",join(',',map($_->utime(),@{$arr})),")\n";
        @sipalerts= sort {$a->utime() <=> $b->utime()} @{$sip_alerts{$sip}};
        $pos= $#{$arr};
        while ($alert= pop(@sipalerts)) {
            while ($pos >= 0 && $alert->time_cmp($arr->[$pos]) == -1) {
                #print "pos: $pos; curr alert (",$arr->[$pos]->utime(),") is after $alert (",$alert->utime(),")\n";
                $pos--;
            }
            if ($pos < 0) { # hit the front
                #print "hit front, unshifting rest\n";
                unshift(@{$arr},@sipalerts,$alert);
                last;
            }
            #print "splice(\@{\$arr},",$pos+1,",0,$alert)\n";
            splice(@{$arr},$pos+1,0,$alert);
        }
        #print "arr[$sip]= (",join(',',map($_->utime(),@{$arr})),")\n";
    }
    
    foreach $dip (keys %dip_alerts) {
        $self->{'l_dip'}{$dip}= [] unless defined($self->{'l_dip'}{$dip}); # init the storage, so we can make changes to it
        my $arr= $self->{'l_dip'}{$dip};
        @dipalerts= sort {$a->utime() <=> $b->utime()} @{$dip_alerts{$dip}};
        $pos= $#{$arr};
        while ($alert= pop(@dipalerts)) {
            while ($pos >= 0 && $alert->time_cmp($arr->[$pos]) == -1) {
                $pos--;
            }
            if ($pos < 0) { # hit the front
                unshift(@{$arr},@dipalerts,$alert);
                last;
            }
            splice(@{$arr},$pos+1,0,$alert);
        }
    }
}

sub forget {
    my($self,$filter)= @_;
    my($alert,$pkt,$sip,$id);
    my %al_to_del= ();
    my %sip_to_del= ();
    my %dip_to_del= ();
    foreach $id (keys %{$self->{'al_by_id'}}) {
        $alert= $self->{'al_by_id'}{$id};
        if ($filter->test($alert)) {
            delete $self->{'al_by_id'}{$id}; # bye bye
            $al_to_del{$id}= 1;
            foreach $pkt ($alert->packets()) {
                $sip= $pkt->sip();
	            $sip= '*undef*' unless defined($sip);
                $dip= $pkt->dip();
	            $dip= '*undef*' unless defined($dip);
                $sip_to_del{$sip}{$id}= 1;
                $dip_to_del{$dip}{$id}= 1;
                $self->{'c_sip'}{$sip}--;
                delete $self->{'c_sip'}{$sip} unless $self->{'c_sip'}{$sip} > 0;
                $self->{'c_dip'}{$dip}--;
                delete $self->{'c_dip'}{$dip} unless $self->{'c_dip'}{$dip} > 0;
            }
        }
    }
    
    $self->{'lt'}= [grep(!defined($al_to_del{$_->id()}),@{$self->{'lt'}})];
    $self->{'la'}= [grep(!defined($al_to_del{$_->id()}),@{$self->{'la'}})];

    foreach $sip (keys %sip_to_del) {
        $self->{'l_sip'}{$sip}= [grep(!defined($sip_to_del{$sip}{$_->id()}),@{$self->{'l_sip'}{$sip}})];
        delete $self->{'l_sip'}{$sip} unless @{$self->{'l_sip'}{$sip}}; # spring cleaning
    }
    foreach $dip (keys %dip_to_del) {
        $self->{'l_dip'}{$dip}= [grep(!defined($dip_to_del{$dip}{$_->id()}),@{$self->{'l_dip'}{$dip}})];
        delete $self->{'l_dip'}{$dip} unless @{$self->{'l_dip'}{$dip}}; # spring cleaning
    }
}

########## API access functions ##############
# generally these check to see if the access is optimized and if not default
# to scanning the full list of alerts by using the MemStorage function

sub first_last {
    my($self,$filter,$sorter)= @_;
    my $arr= undef;
    my($sip,$dip);
    if ($sip= &Filter::known_anysip_filter($filter)) {
        $arr= $self->{'l_sip'}{$sip};
    } elsif ($dip= &Filter::known_anydip_filter($filter)) {
        $arr= $self->{'l_dip'}{$dip};
    }
    if (defined($arr)) {
        return () unless defined($arr) && @{$arr};
        return ($arr->[0],$arr->[$#{$arr}]);
    }
    # can optimize with 'lt' and 'la' too but don't feel like it now
    return $self->MemStorage::first_last($filter,$sorter);
}

sub set {
    my($self,$filter)= @_;
    my $arr= undef;
    if ($filter->known_equiv($Filter::true)) {
        return @{$self->{'lt'}};
    }
    if ($sip= &Filter::known_anysip_filter($filter)) {
        $arr= $self->{'l_sip'}{$sip};
    } elsif ($dip= &Filter::known_anydip_filter($filter)) {
        $arr= $self->{'l_dip'}{$dip};
    } else {
        # can optimize access to 'c_*' but don't feel like it now
        return $self->MemStorage::set($filter);
    }
    return () unless defined($arr);
    return @{$arr};
}

sub list {
    my($self,$filter,$sorter)= @_;
    my($sip,$dip);
    my $arr= 0;
    if ($filter->known_equiv($Filter::true)) {
        if ($sorter->known_equiv($Sort::bytime)) {
            $arr= $self->{'lt'};
        } elsif ($sorter->known_equiv($Sort::byhighestanom)) {
            $arr= $self->{'la'};
        } 
    }
    if ($sorter->known_equiv($Sort::bytime)) {
        if ($sip= &Filter::known_anysip_filter($filter)) {
            # already sorted
            $arr= $self->{'l_sip'}{$sip};
        } elsif ($dip= &Filter::known_anydip_filter($filter)) {
            # already sorted
           $arr= $self->{'l_dip'}{$dip};
        }
    }
    return @{$arr} if (ref($arr)); # found a array ref with the info
    return () unless defined($arr); # there was a designated storage location but it had never been used and was undefined
    return $self->MemStorage::list($filter,$sorter);
}

sub list_range {
    my($self,$filter,$sorter,$first,$last)= @_;
    my $arr= 0;
    my($sip,$dip);
    if ($filter->known_equiv($Filter::true)) {
        if ($sorter->known_equiv($Sort::bytime)) {
            $arr= $self->{'lt'};
        } elsif ($sorter->known_equiv($Sort::byhighestanom)) {
            $arr= $self->{'la'};
        } 
    } elsif ($sip= &Filter::known_anysip_filter($filter)) {
        if ($sorter->known_equiv($Sort::bytime)) {
            $arr= $self->{'l_sip'}{$sip};
        }
    } elsif ($dip= &Filter::known_anydip_filter($filter)) {
        if ($sorter->known_equiv($Sort::bytime)) {
            $arr= $self->{'l_dip'}{$sip};
        }
    }
    if (ref($arr)) {
        # already sorted
        my $end= $last-1;
        $end= $#{$arr} if ($end > $#{$arr});
        return @arr->[($first-1)..$end];
    } elsif (!defined($arr)) { # storage space had never been used
    	return ();
    }
    return $self->MemStorage::list_range($filter,$sorter,$first,$last);
}

sub count {
    my($self,$filter)= @_;
    if ($filter->known_equiv($Filter::true)) {
        return 0+ @{$self->{'lt'}};
    }
    my($sip,$dip,$arr);
    if ($sip= &Filter::known_anysip_filter($filter)) {
        $arr= $self->{'l_sip'}{$sip};
    } elsif ($dip= &Filter::known_anydip_filter($filter)) {
        $arr= $self->{'l_dip'}{$dip};
    } else {
        # can optimize access to 'c_*' but don't feel like it now
        return $self->MemStorage::count($filter);
    }
    return 0 unless defined($arr);
    return 0+ @{$arr};
}

sub packet_field_multiset {
    my($self,$filter,$field)= @_;
    my $hash= 0;
    if ($field eq 'sip') {
        if ($filter->known_equiv($Filter::true)) {
            $hash= $self->{'c_sip'};
        }
    } elsif ($field eq 'dip') {
        if ($filter->known_equiv($Filter::true)) {
            $hash= $self->{'c_dip'};
        }
    }
    return %{$hash} if (ref($hash)); # found a hash ref with the info
    return () unless defined($hash); # there was a designated storage location but it had never been used and was undefined
    return $self->MemStorage::packet_field_multiset($filter,$field);
}

1;
