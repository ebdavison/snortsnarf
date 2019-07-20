#!/usr/bin/perl

# parse_mailtempl.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# parse_mailtempl.pl is a Pipeline module to extract the mail header and
#   mail body from a given template file and to store these in fields
# pipeline args: mail template file path
# side effect: creates fields called 'mail-body' and 'mail-<hdr>' for each mail header in the template

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

sub process {
    require "sisr_utils.pl";
    my ($input)= shift;
    @_ == 1 || (&reporterr("parse_mailtempl.pl takes 1 argument (mail template file location), but got:".join(' ',@_),0) && return 0);
    
    my ($templfile)= &arg_to_val($input,@_);

    my $configfile= $input->param('configfile');
    my $dir= &get_config_field($configfile,'report-tmpl-dir-mail');
    $dir =~ /^\s*$/ && die "report-tmpl-dir-mail not found in $configfile; could not validate path to templ file $templfile";
    $dir.= '/' unless $dir =~ /\/$/; 
    $templfile =~ /^$dir/ || die "parse_mailtempl.pl: $templfile is not in mail templ directory; where did it come from?";

    open(T,"<$templfile") || die "could not open mail template file \"$templfile\"";
    while (<T>) { # skip past template information
        last if /^\s*$/; # partition
    }
    my $found= 0; # have any headers been found yet
    while (<T>) { # read headers and store to fields
        if (/^\s*$/) {
            last if $found; # partition after headers
            next;
        }
        $found++;
        chomp;
        s/^\s*([^:]+)\s*:?\s*//;
        $input->param("mail-$1",$_);
    }
    my $body= '';
    while (<T>) { # rest is body
        $body.= $_;
    }
    $input->param('mail-body',$body);
    close T;
};

\&process;

# $Id: parse_mailtempl.pl,v 1.11 2001/10/18 18:23:25 jim Exp $
