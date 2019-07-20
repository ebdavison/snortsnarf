#!/usr/bin/perl

# HTMLMemStorage.pm, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2001 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# HTMLMemStorage is an implementation of the SnortSnarf Storage API optimized
# for the traditional SnortSnarf HTML page uses.  All alerts are stored in
# memory.

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

package HTMLMemStorage;

# more to optimize yet

# not yet optimized:
# ->packet_field_set($Filter::true,'sip')
# ->packet_field_set($Filter::true,'dip')

use MemStorage;
use BasicFilters;
use Sort;
use Filter;

@ISA=(MemStorage);

########## API creation/addition/deletion functions ##############

sub new {
    my($class,%params)= @_;
    my $self= bless $class->MemStorage::new(%params),$class;
    $self->{'earliest'}= ''; # overall earliest and latest alert ids; it is out of date iff the indicated alert is no longer one that is stored
    $self->{'latest'}= '';
    $self->{'count'}= 0; # overall storage count
    $self->{'c_sig'}= {}; # per-signature count
    $self->{'l_sig_ids'}= {}; # per-signature list of alert IDs
    $self->{'c_sig_sip'}= {}; # per-signature, per-sip count
    $self->{'c_sig_dip'}= {}; # per-signature, per-dip count
    $self->{'c_sip_dip'}= {}; # per-sip, per-dip count
    $self->{'c_dip_sip'}= {}; # per-dip, per-sip count
    $self->{'c_sip_sig'}= {}; # per-sip, per-signature count
    $self->{'c_dip_sig'}= {}; # per-dip, per-signature count
    $self->{'l_sip'}= {}; # per-sip list of alerts, kept sorted by alert time
    $self->{'l_dip'}= {}; # per-dip list of alerts, kept sorted by alert time
    $self->{'c_sip_sig_dip'}= {}; # per-sip, per-signature, per-dip count
    $self->{'c_dip_sig_sip'}= {}; # per-dip, per-signature, per-sip count
    return $self;
}

sub store {
    my($self,@alerts)= @_;
    my($alert,$pkt,$sig,$sip,$dip,@sipalerts,$pos);
    my %sip_alerts= ();
    my %dip_alerts= ();
    $self->MemStorage::store(@alerts);

    $self->{'count'}+= @alerts;
    foreach $alert (@alerts) {
        my $sig= $alert->message();
        $sig= '*undef*' unless defined($sig);
        $self->{'c_sig'}{$sig}++;
        push(@{$self->{'l_sig_ids'}{$sig}},$alert->id());
        foreach $pkt ($alert->packets()) {
            $sip= $pkt->sip();
            $sip= '*undef*' unless defined($sip);
            $dip= $pkt->dip();
            $dip= '*undef*' unless defined($dip);
            $self->{'c_sig_sip'}{$sig}{$sip}++;
            $self->{'c_sig_dip'}{$sig}{$dip}++;
            $self->{'c_sip_dip'}{$sip}{$dip}++;
            $self->{'c_dip_sip'}{$dip}{$sip}++;
            $self->{'c_sip_sig'}{$sip}{$sig}++;
            $self->{'c_dip_sig'}{$dip}{$sig}++;
            push(@{$sip_alerts{$sip}},$alert);
            push(@{$dip_alerts{$dip}},$alert);
            $self->{'c_sip_sig_dip'}{$sip}{$sig}{$dip}++;
            $self->{'c_dip_sig_sip'}{$dip}{$sig}{$sip}++;
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
    
    $alert= shift(@alerts);
    my $earliest= $self->{'al_by_id'}{$self->{'earliest'}};
    $earliest= $alert if !defined($earliest) || $earliest->time_cmp($alert) == 1;
    my $latest= $self->{'al_by_id'}{$self->{'latest'}};
    $latest= $alert if !defined($latest) || $latest->time_cmp($alert) == -1;
    foreach $alert (@alerts) {
        if ($earliest->time_cmp($alert) == 1) {
            $self->{'earliest'}= $alert;
        }
        if ($latest->time_cmp($alert) == -1) {
            $self->{'latest'}= $alert;
        }
    }
    $self->{'earliest'}= $earliest->id();
    $self->{'latest'}= $latest->id();
}

sub forget {
    my($self,$filter)= @_;
    my($alert,$sig,$pkt,$sip,$id);
    my %sig_to_del= ();
    my %sip_to_del= ();
    my %dip_to_del= ();
    foreach $id (keys %{$self->{'al_by_id'}}) {
        $alert= $self->{'al_by_id'}{$id};
        if ($filter->test($alert)) {
            delete $self->{'al_by_id'}{$id}; # bye bye
            $self->{'count'}--; # overall storage count
            $sig= $alert->message();
            $sig= '*undef*' unless defined($sig);
            $self->{'c_sig'}{$sig}--;
            $sig_to_del{$sig}{$id}= 1;
            foreach $pkt ($alert->packets()) {
                $sip= $pkt->sip();
          		$sip= '*undef*' unless defined($sip);
                $dip= $pkt->dip();
          		$dip= '*undef*' unless defined($dip);
                $self->{'c_sig_sip'}{$sig}{$sip}--;
                delete $self->{'c_sig_sip'}{$sig}{$sip} unless $self->{'c_sig_sip'}{$sig}{$sip} > 0;
                $self->{'c_sig_dip'}{$sig}{$dip}--;
                delete $self->{'c_sig_dip'}{$sig}{$dip} unless $self->{'c_sig_dip'}{$sig}{$dip} > 0;
                $self->{'c_sip_dip'}{$sip}{$dip}--;
                delete $self->{'c_sip_dip'}{$sip}{$dip} unless $self->{'c_sip_dip'}{$sip}{$dip} > 0;
                $self->{'c_dip_sip'}{$dip}{$sip}--;
                delete $self->{'c_dip_sip'}{$dip}{$dip} unless $self->{'c_dip_sip'}{$dip}{$sip} > 0;
                $self->{'c_sip_sig'}{$sip}{$sig}--;
                delete $self->{'c_sip_sig'}{$sip}{$sig} unless $self->{'c_sip_sig'}{$sip}{$sig} > 0;
                $self->{'c_dip_sig'}{$dip}{$sig}--;
                delete $self->{'c_dip_sig'}{$dip}{$sig} unless $self->{'c_dip_sig'}{$dip}{$sig} > 0;
                $sip_to_del{$sip}{$id}= 1;
                $dip_to_del{$dip}{$id}= 1;
                $self->{'c_sip_sig_dip'}{$sip}{$sig}{$dip}--;
                delete $self->{'c_sip_sig_dip'}{$sip}{$sig}{$dip} unless $self->{'c_sip_sig_dip'}{$sip}{$sig}{$dip} > 0;
                $self->{'c_dip_sig_sip'}{$dip}{$sig}{$sip}--;
                delete $self->{'c_dip_sig_sip'}{$dip}{$sig}{$aip} unless $self->{'c_sip_sig_dip'}{$dip}{$sig}{$aip} > 0;
            }
        }
    }
    foreach $sig (keys %sig_to_del) {
        $self->{'l_sig_ids'}{$sig}= [grep(!defined($sig_to_del{$sig}{$_}),@{$self->{'l_sig_ids'}{$sig}})];
        delete $self->{'l_sig_ids'}{$sig} unless @{$self->{'l_sig_ids'}{$sig}}; # spring cleaning
    }
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
    if ($filter->known_equiv($Filter::true)) {
        if ($sorter->known_equiv($Sort::bytime)) {
            my $earliest= $self->{'al_by_id'}{$self->{'earliest'}};
            my $latest= $self->{'al_by_id'}{$self->{'latest'}};
            unless (defined($earliest) && defined($latest)) { # out of date
                ($earliest,$latest)= $self->MemStorage::first_last($filter,$sorter);
                $self->{'earliest'}= $earliest->id();
                $self->{'latest'}= $latest->id();
            }
            return ($earliest,$latest);
        }
    } else {
        my(@ids,$sig);
        if ($sig= &Filter::known_sig_filter($filter)) {
            @ids= @{$self->{'l_sig_ids'}{$sig}};
            return $sorter->first_last(map($self->{'al_by_id'}{$_},@ids));
        }
        my $arr= undef;
        my($sip);
        if ($sip= &Filter::known_anysip_filter($filter)) {
            $arr= $self->{'l_sip'}{$sip};
        }
        my($dip);
        if ($dip= &Filter::known_anydip_filter($filter)) {
            $arr= $self->{'l_dip'}{$dip};
        }
        if (defined($arr)) {
            return () unless defined($arr) && @{$arr};
            return ($arr->[0],$arr->[$#{$arr}]);
        }
    }
    return $self->MemStorage::first_last($filter,$sorter);
}

sub set {
    my($self,$filter)= @_;
    my($sig);
    if ($sig= &Filter::known_sig_filter($filter)) {
        return map($self->{'al_by_id'}{$_},@{$self->{'l_sig_ids'}{$sig}});
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
    my $sip;
    if (($sip= &Filter::known_anysip_filter($filter)) && $sorter->known_equiv($Sort::bytime)) {
        $arr= $self->{'l_sip'}{$sip};
    }
    my $dip;
    if (($dip= &Filter::known_anydip_filter($filter)) && $sorter->known_equiv($Sort::bytime)) {
        $arr= $self->{'l_dip'}{$sip};
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
        return $self->{'count'};
    }
    my $sig;
    if ($sig= &Filter::known_sig_filter($filter)) {
        return $self->{'c_sig'}{$sig};
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

sub alert_field_multiset {
    my($self,$filter,$field)= @_;
    my $hash= 0;
    my($sip,$dip);
    if ($field eq 'message') {
        if ($filter->known_equiv($Filter::true)) {
            $hash= $self->{'c_sig'};
        }
        if ($sip= &Filter::known_anysip_filter($filter)) {
            $hash= $self->{'c_sip_sig'}{$sip};
        }
        if ($dip= &Filter::known_anydip_filter($filter)) {
            $hash= $self->{'c_dip_sig'}{$dip};
        }
    }
    return %{$hash} if (ref($hash)); # found a hash ref with the info
    return () unless defined($hash); # there was a designated storage location but it had never been used and was undefined
    return $self->MemStorage::alert_field_multiset($filter,$field);
}

sub packet_field_set {
    my($self,$filter,$field)= @_;
    if ($field eq 'sip') {
        if ($filter->known_equiv($Filter::true)) {
            return keys %{$self->{'l_sip'}};
        }
    } elsif ($field eq 'dip') {
        if ($filter->known_equiv($Filter::true)) {
            return keys %{$self->{'l_dip'}};
        }
    }
    return $self->MemStorage::packet_field_set($filter,$field);
}

sub packet_field_multiset {
    my($self,$filter,$field)= @_;
    my($sig,$sip,$dip);
    my $hash= 0;
    if ($field eq 'sip') {
        if ($filter->known_equiv($Filter::true)) {
            my %set= ();
            foreach (keys %{$self->{'l_sip'}}) {
                $set{$_}= scalar(@{$self->{'l_sip'}{$_}});
            }
            return %set;
        }
        if ($sig= &Filter::known_sig_filter($filter)) {
        	$hash= $self->{'c_sig_sip'}{$sig};
        }
        if ($dip= &Filter::known_anydip_filter($filter)) {
            $hash= $self->{'c_dip_sip'}{$dip};
        }
        ($sig,$dip)= &Filter::known_sig_anydip_filter($filter);
        if (defined($sig)) {
            $hash= $self->{'c_dip_sig_sip'}{$dip}{$sig};
        }
    } elsif ($field eq 'dip') {
        if ($filter->known_equiv($Filter::true)) {
            my %set= ();
            foreach (keys %{$self->{'l_dip'}}) {
                $set{$_}= @{$self->{'l_dip'}{$_}};
            }
            return %set;
        }
        if ($sig= &Filter::known_sig_filter($filter)) {
            $hash= $self->{'c_sig_dip'}{$sig};
        }
        ($sig,$sip)= &Filter::known_sig_anysip_filter($filter);
        if (defined($sig)) {
            $hash= $self->{'c_sip_sig_dip'}{$sip}{$sig};
        }
    }
    return %{$hash} if (ref($hash)); # found a hash ref with the info
    return () unless defined($hash); # there was a designated storage location but it had never been used and was undefined
    return $self->MemStorage::packet_field_multiset($filter,$field);
}

1;
