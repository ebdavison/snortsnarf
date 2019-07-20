#!/usr/bin/perl

# sisr_utils.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# sisr_utils.pl is assortment of routines that are used in SISR scripts and
#   modules

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

require 'web_utils.pl';


# map $field to the value of the field, %var to the value of the environmental
# variable, and anything else to itself, for each argument
sub arg_to_val {
    my ($input)= shift;
    return map((s/^\$//?join(';',$input->param($_)):(s/^\%//?$ENV{$_}:$_)),@_);
}

# takes 3 args, the CGI object, a output field spec, and a value
# writes the value to the named environmental variable if the output field
# name starts with % or to field in the CGI object if the field starts with $
# or with anything else
sub write_out_to_arg {
    $_[1] =~ s/^([\$\%])//;
    if ($1 eq '%') { # env. var
        $ENV{$_[1]}= $_[2];
    } else {
        $_[0]->param($_[1],$_[2]);
    }

}

# given a string with information about incident fields in the config file,
# returns a reference to a hash of field names to their description as well
# as a reference to a list of the fields in the order of their occurance
sub decode_fldinfo {
    my($incfldinfo)= shift;
    my (%flddescr)= ();
    my ($fld,$descr);
    my(@fldorder);
    foreach (split("\n",$incfldinfo)) {
        ($fld,$descr)= split(':',$_,2);
        $flddescr{$fld}= $descr;
        push(@fldorder,$fld);
    }
    return (\%flddescr,\@fldorder);
}

# from the configuration file name, extract the value of the given field
# If the field does not exist, a warning is issued and '' returned
sub get_config_field {
    my($configfile,$fld)= @_;
    open(C,"<$configfile") || die "could not open config file \"$configfile\"";
    while (<C>) {
        if (s/^$fld\s*:\s*//) {
            s/\s+$//;
            close C;
            return $_;
        }
    }
    warn "could not find '$fld' in config file \"$configfile\", assuming empty";
    return '';

}


# print the start of a HTML form that will use Pipeline with the given
# pipeline (list of modules and their args) and module path
sub pipeline_form_start {
    my($pipeline,$path)=@_;
print <<">>";
<FORM ACTION="pipeline.pl" METHOD="post">
<INPUT TYPE=hidden NAME="_pipeline" VALUE="$pipeline">
<INPUT TYPE=hidden NAME="_path" VALUE="$path">
>>

}

# given a pipeline, a path and a hash of additional fields to value mappings
# returns a properly encoded relative URL to run Pipeline
sub pipeline_submit_url {
    my($pipeline,$path,%rest)= @_;
    return 'pipeline.pl?'.join('&','_path='.&url_encode($path),'_pipeline='.&url_encode($pipeline),map($_.'='.&url_encode($rest{$_}),keys %rest));
}


# sort-compatable function to sort by increasing IP address, where the
# addresses are strings
sub sort_by_ip {
    my(@pieces1) = split('\.',$a);
    my(@pieces2) = split('\.',$b);
  
    foreach (0..$#pieces1) {
        return -1 if $pieces1[$_] < $pieces2[$_];
        return 1 if $pieces1[$_] > $pieces2[$_];
    }
    return 0;
}

1;
