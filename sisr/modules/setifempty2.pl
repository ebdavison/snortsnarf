#!/usr/bin/perl

# This is a slightly modified version of setifempty.pl version 1.0, part of
#   HFPM 1.0 for inclusion in SnortSnarf v021111.1.
# modifications by James Hoagland (hoagland@SiliconDefense.com)

### old headers

# $Id: setifempty2.pl,v 1.10 2001/10/18 18:23:25 jim Exp $

# setifempty.pl, by Jim Hoagland (hoagland@cs.ucdavis.edu) 11/95
# copyright (c) 1995 by Jim Hoagland

# This is release version 1.0 of this program, which is part of the HTML Form
# Processing Modules (<URL:http://seclab.cs.ucdavis.edu/~hoagland/hfpm/>).

# see "http://seclab.cs.ucdavis.edu/~hoagland/hfpm/setifempty.html"
# for more information.

### old headers end


# CGI Filter/Pipe Interface module to set some fields to an indicated value
# if not filled in.  These are specified as arguments in the form field=val.
# If val begins with a $ or a %, then the value of that field of env. var is used as the value.
# %% at the start maps to % and $$ maps to $.
sub process {
  my ($fld);
  my ($input,@args)= @_;
  foreach (@args) {
    ($fld,$_)= split('=',$_,2);
    s/^\$\$/\xFF/g; s/^\%\%/\xFE/g;
    $_= s/^\$// ? join(';',$input->param($_)) : (s/^\%// ? $ENV{$_} : $_);
    tr/\xFE\xFF/\%\$/;
    $input->param($fld,$_) unless (defined($input->param($fld)) && $input->param($fld));
  }
};

\&process;
