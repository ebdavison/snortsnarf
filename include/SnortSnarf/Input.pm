#!/usr/bin/perl

# Filter.pm, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2001,2002 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# This file provides some routines to help stringify and recreate modules
# conforming to the Input API and to work with input modules to grab
# certain alerts.

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.


use Filter;
use Sort;
use AllMods;

package Input;

sub stringify_input_mods {
    my @recreate_strs= map(ref($_).':'.$_->recreate_str(),@_);
    return Filter::join_strs(@recreate_strs);
}

sub recreate_input_mods {
    my($recr_string)= shift;
    my($mod,$str);
    my(@ins)= ();
    foreach (Filter::unjoin_strs($recr_string)) {
        ($mod,$str)= split(':',$_,2);
        next unless &AllMods::load_module_named($mod);
        push(@ins,$mod->recreate($str));
    }
    return @ins;
}

sub grab_alerts_of_type_from_mods {
    my($ip,$end,$include,@sources)= @_;
    my @filters= ();
    my (@source,$filter);
    my @alerts= ();
    
    if ($end eq 'src') {
        push(@filters,&Filter::for_anysip($ip));
    } else {
        push(@filters,&Filter::for_anydip($ip));
    }
    if ($include !~ /g/ || $include !~ /a/) { # don't want all
        if ($include =~ /g/) { # want general
            push(@filters,$Filter::snort_gen_alert);
        }
        if ($include =~ /a/) { # want anom
            push(@filters,$Filter::anom_rept);
        }
    }
    if (@filters > 1) {
        $filter= AndFilter->new(@filters);
    } else {
        $filter= $filters[0];
    }

    @alerts= ();
    foreach $source (@sources) {
        while ($alert= $source->get()) {
            push(@alerts,$alert) if ($filter->test($alert));
        }
    }
    return $Sort::bytime->sort(@alerts);
}


sub grab_alert_ids_from_mods {
    my($ids,@sources)= @_;
    my($id,$source,$alert);

    my %wantid= ();
    foreach $id (@{$ids}) {
        $wantid{$id}= 1;
        #warn "grab_alert_ids_from_mods: id $id requested\n";
    }
    my @alerts= ();
    foreach $source (@sources) {
        while ($alert= $source->get()) {
            $id= $alert->id();
            push(@alerts,$alert) if (defined($id) && $wantid{$id});
        }
    }
    #warn "grab_alert_ids_from_mods: found alerts with id's: ".join(',',map($_->id(),@alerts))."\n";
    return $Sort::bytime->sort(@alerts);
}

1;
