#!/usr/bin/perl

# AlertBase.pm, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2001 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# AlertBase is a base class for Alert representations providing default
# implementations of standard methods

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

package AlertBase;

sub packets {
    return ();
}

sub packet_fields {
    my($self,$field)= @_;
    my %vals= ();
    my $has_undef=0;
    my @vals;
    foreach ($self->packets) {
        my $val= $_->$field();
        unless (defined($val)) {
            $has_undef=1;
        } else {
            $vals{$val}= 1;
        }
    }
    @vals= keys %vals;
    push(@vals,undef) if $has_undef;
    return @vals;
}

sub id {
    return undef;
}

sub type {
    return undef;
}

sub message {
    return undef;
}

sub as_text {
    my $self= shift;
    my $text= $self->id().': '.$self->message()."\n";
    $text.= join("\n",map($_->as_text(),$self->packets()));
    return $text;
}

sub text_format {
    return 's1';
}

sub references {
    return ();
}

sub reference {
    return ();
}

sub source {
    return undef;
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
    my (@tod)= $self->tod;
    my $text= sprintf("%02d:%02d:",$tod[0],$tod[1]);
    $text.= '0' if $tod[2] < 10.0;
    $text.= $tod[2];
    return $text;
}

1;
