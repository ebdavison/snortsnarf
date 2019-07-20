#!/usr/bin/perl

# inst_flds.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# inst_flds.pl is a Pipeline module to instantiate all fields with a given
#   prefix using other fields and environmental variables ("$field" in the
#   text gets translated into the value of that field, "$$" => "$", "%var"
#   => env. var 'var' contents, "%%" => "%")
# pipeline args: field prefix
# side effect: instantiates each field with the given prefix

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

sub process {
    require "sisr_utils.pl";
    my ($input)= shift;
    @_ == 1 || (&reporterr("inst_flds.pl takes 1 argument (field prefix), but got:".join(' ',@_),0) && return 0);
    
    my ($fldstart)= &arg_to_val($input,@_);

    foreach ($input->param()) {
        $input->param($_,&expand_vars($input->param($_))) if /^$fldstart/;
    }
};

# borrowed from formatted_mail.pl (part of HFPM), copyright Jim Hoagland (hoagland@cs.ucdavis.edu)
# instantiate variables in input string
sub expand_vars {
    my($text)=shift(@_);
    $text =~ s/\$\$/\xff/g;
    $text =~ s/\$(\w+)/join(';',$input->param($1))/eg;
    $text =~ s/\xff/\$/g;
    $text =~ s/\%\%/\xff/g;
    $text =~ s/\%(\w+)/$ENV{$1}/g;
    $text =~ s/\xff/\%/g;
    return $text;
}

\&process;

# $Id: inst_flds.pl,v 1.11 2001/10/18 18:23:25 jim Exp $
