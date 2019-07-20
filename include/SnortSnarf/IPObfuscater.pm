#!/usr/bin/perl

# IPObfuscater.pm, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2002 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# An instance of IPObfuscater represents a remapping between IP addresses in
# such a way as to obfuscate the original IP but keep the property that
# all hosts in a given class A/B/C stay in the same class A/B/C.

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

package IPObfuscater;

sub BEGIN {
}

# create a new SnortRules instance from a start rules file and an optional
# directory
sub new {
    my($class)= @_;
    my $self= bless {
        'Amap' => {'255' => '255'},
        'Bmap' => {},
        'Cmap' => {},
        'Hmap' => {},
        'Aused' => {},
        'Bused' => {},
        'Cused' => {},
        'Hused' => {}
    },$class;
    return $self;
}

sub remap {
    my($self,$ip)= @_;
    return $ip unless defined($ip) && $ip =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/;
    return $self->{'Hmap'}{$ip} if defined($self->{'Hmap'}{$ip});

    my ($A,$B,$C,$H)= ($1,$2,$3,$4);
    my $Bnet= "$A.$B";
    my $Cnet= "$Bnet.$C";
    
	my $Anew= $self->{'Amap'}{$A};
	unless (defined($Anew)) {
		do {
			$Anew= (int(rand(255)));
		} while (defined($self->{'Aused'}{$Anew}));
		$self->{'Amap'}{$A}= $Anew;
		$self->{'Aused'}{$Anew}= 1;
	}
	
	my $Bnew= $self->{'Bmap'}{$Bnet};
	unless (defined($Bnew)) {
	    if ($B == 255) {
	        $Bnew= "$Anew.255";
	    } else {
            do {
                $Bnew= $Anew.'.'.(int(rand(255)));
            } while (defined($self->{'Bused'}{$Bnew}));
        }
		$self->{'Bmap'}{$Bnet}= $Bnew;
		$self->{'Bused'}{$Bnew}= 1;
	}
	
	my $Cnew= $self->{'Cmap'}{$Cnet};
	unless (defined($Cnew)) {
	    if ($C == 255) {
	        $Cnew= "$Bnew.255";
	    } else {
            do {
                $Cnew= $Bnew.'.'.(int(rand(255)));
            } while (defined($self->{'Cused'}{$Cnew}));
        }
		$self->{'Cmap'}{$Cnet}= $Cnew;
		$self->{'Cused'}{$Cnew}= 1;
	}
	
	my $Hnew= $self->{'Hmap'}{$ip};
	unless (defined($Hnew)) {
	    if ($H == 255) {
	        $Hnew= "$Cnew.255";
	    } else {
            do {
                $Hnew= $Cnew.'.'.(int(rand(255)));
            } while (defined($self->{'Hused'}{$Hnew}));
        }
		$self->{'Hmap'}{$ip}= $Hnew;
		$self->{'Hused'}{$Hnew}= 1;
	}
	
	return $Hnew;
}

sub remap_all {
    my($self,$str)= @_;
    $str =~ s/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/$self->remap($1)/eg;
    return $str;
}

1;
