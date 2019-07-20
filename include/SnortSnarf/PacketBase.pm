#!/usr/bin/perl

# PacketBase.pm, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2001 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# PacketBase is a base class for Packet representation providing default
# implementations of standard methods

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

package PacketBase;

sub BEGIN {
    @req_attr_meths= (qw(id source sip sport dip dport protocol flags anom as_text text_format utime year month day tod tod_text));
    @opt_attr_meths= (qw());
    
    %ret_undef_meth= ();
    foreach (qw(id source sip sport dip dport protocol flags anom)) {
        $ret_undef_meth{$_}= 1;
    }
}

sub AUTOLOAD { # called if a requested method is not defined elsewhere
    my $attr= $AUTOLOAD;
    $attr =~ s/^.*:://g;
    return unless $attr =~ /[^A-Z]/; # skip special methods such as DESTROY
    unless ($ret_undef_meth{$attr}) { # not one of the methods we are supposed to return undef for
        warn "PacketBase: unknown method $attr on $_[0], returning undef\n";
    }
    return undef;
}

sub as_text {
    my ($self)= shift;
    my $year= $self->year();
    my $text= defined($year) ? $year.'/' : '';
    $text.= $self->month().'/'.$self->day().' '.$self->tod_text();
    $text.= ' '.$self->protocol().' '.$self->sip();
    $text.= ':'.$self->sport() if defined($self->sport);
    $text.= ' -> '.$self->dip();
    $text.= ':'.$self->dport() if defined($self->dport);
    return $text;
}

sub text_format {
    return 's1';
}

sub utime {
    my $self= shift;
    use Time::JulianDay;
    my ($hour,$min,$secs)= $self->tod();
    my $isecs= int($secs);
    return jd_timelocal($secs,$min,$hour,$self->day(),$self->month()-1,$self->year()-1900)+($secs-$isecs);
}

sub time_cmp {
    return $_[0]->utime() <=> $_[1]->utime();
}

sub year {
    my $utime= $_[0]->utime;
    #my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst)= localtime($utime);
    return (localtime(int($utime)))[5]+1900;
}

sub month {
    my $utime= $_[0]->utime;
    return (localtime(int($utime)))[4]+1;
}

sub day {
    my $utime= $_[0]->utime;
    return (localtime(int($utime)))[3];
}

sub tod {
    my $utime= $_[0]->utime;
    my $iutime= int($utime);
    my @time= localtime($iutime);
    return ($time[2],$time[1],$time[0]+($utime-$iutime));
}

sub tod_text {
    my $self= shift;
    return join(':',$self->tod);
}

1;
