#!/usr/bin/perl

# BasicSorters.pm, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2001 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# this file contains a set of basic implementations of the SnortSnarf
# Sorter API

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.


use SorterBase;
use KnownEquiv;

##########################################################

package FieldSorter;

# a sorter class that sorts on the value of a particular alert field stringwise

@ISA= (qw(ScalarKE SorterBase));

sub new {
    my($class)= shift;
    my($field)= shift;
    return bless \$field,$class; 
}

sub cmp {
    my($self,$alert1,$alert2)= @_;
    my $field=${$self};
    return $alert1->$field() cmp $alert2->$field();
}

sub sort {
    my($self,@alerts)= @_;
    my $field=${$self};
    return sort {$a->$field() cmp $b->$field()} @alerts;
}

##########################################################

package NumFieldSorter;

# a sorter class that sorts on the value of a particular alert field numerically

@ISA= (qw(ScalarKE SorterBase));

sub new {
    my($class)= shift;
    my($field)= shift;
    return bless \$field,$class; 
}

sub cmp {
    my($self,$alert1,$alert2)= @_;
    my $field=${$self};
    return $alert1->$field() <=> $alert2->$field();
}

sub sort {
    my($self,@alerts)= @_;
    my $field=${$self};
    return sort {$a->$field() <=> $b->$field()} @alerts;
}

##########################################################

package RevSorter;

# a sorter class that reverses the order returned by the provided Sorter

@ISA= (qw(ScalarKE SorterBase));

sub new {
    my($class)= shift;
    my($sorter)= shift;
    if (ref($sorter)) {
        return bless \$sorter,$class;
    } else {
        # standard interface not yet implemented
    }
}

sub cmp {
    my($self,$alert1,$alert2)= @_;
    return -1 * (${$self}->cmp($alert1,$alert2));
}

sub sort {
    my($self)= shift;
    return reverse(${$self}->sort(@_));
}

##########################################################

package FirstPktFieldSorter;

# a sorter class that sorts on the value of a particular packet field stringwise, using the first packet of the alert according to a provided packet sorter

@ISA= (qw(ArrayKE SorterBase));

sub new {
    my($class,$field,$pktsorter)= @_;
    if (ref($pktsorter)) {
        return bless [$field,$pktsorter],$class; 
    } else {
        # standard interface not yet implemented
    }
}

sub cmp {
    my($self,$alert1,$alert2)= @_;
    my($field,$pktsorter)= @{$self};
    my $pkt1= ($pktsorter->sort($alert1->packets()))[0];
    my $pkt2= ($pktsorter->sort($alert2->packets()))[0];
    return $pkt1->$field() cmp $pkt2->$field();
}


##########################################################

package FirstPktFieldNumSorter;

# a sorter class that sorts on the value of a particular packet field numerically, using the first packet of the alert according to a provided packet sorter

@ISA= (qw(ArrayKE SorterBase));

sub new {
    my($class,$field,$pktsorter)= @_;
    if (ref($pktsorter)) {
        return bless [$field,$pktsorter],$class; 
    } else {
        # standard interface not yet implemented
    }
}

sub cmp {
    my($self,$alert1,$alert2)= @_;
    my($field,$pktsorter)= @{$self};
    my $pkt1= ($pktsorter->sort($alert1->packets()))[0];
    my $pkt2= ($pktsorter->sort($alert2->packets()))[0];
    return $pkt1->$field() <=> $pkt2->$field();
}


##########################################################

package NumHighestPktFieldSorter;

# a sorter class that sorts alerts on the value of a particular packet field, where the representative packet from the alert is chosen on the basis of having the highest value for that field (numerically)

@ISA= (qw(ScalarKE SorterBase));

sub new {
    my($class)= shift;
    my($field)= shift;
    return bless \$field,$class; 
}

sub cmp {
    my($self,$alert1,$alert2)= @_;
    my $field=${$self};
    my($p1,@packets)= $alert1->packets();
    foreach (@packets) {
        $p1= $_ if $p1->$field() < $_->$field();
    }
    my($p2);
    ($p2,@packets)= $alert2->packets();
    foreach (@packets) {
        $p2= $_ if $p2->$field() < $_->$field();
    }
    return $p2->$field() <=> $p1->$field();
}

##########################################################
##########################################################

package FieldPktSorter;

# a packet sorter class that sorts on the value of a particular packet field stringwise

@ISA= (qw(ScalarKE));

sub new {
    my($class)= shift;
    my($field)= shift;
    return bless \$field,$class; 
}

sub cmp {
    my($self,$pkt1,$pkt2)= @_;
    my $field= ${$self};
    return $pkt1->$field() cmp $pkt2->$field();
}

sub sort {
    my($self,@packets)= @_;
    my $field= ${$self};
    return sort {$a->$field() cmp $b->$field()} @packets;
}

##########################################################

package NumFieldPktSorter;

# a packet sorter class that sorts on the value of a particular packet field numerically

@ISA= (qw(ScalarKE));

sub new {
    my($class)= shift;
    my($field)= shift;
    return bless \$field,$class; 
}

sub cmp {
    my($self,$pkt1,$pkt2)= @_;
    my $field= ${$self};
    return $pkt1->$field() <=> $pkt2->$field();
}

sub sort {
    my($self,@packets)= @_;
    my $field= ${$self};
    return sort {$a->$field() <=> $b->$field()} @packets;
}

1;
