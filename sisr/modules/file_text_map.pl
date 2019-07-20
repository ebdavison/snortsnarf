#!/usr/bin/perl

# file_text_map.pl, distributed as part of Snortsnarf v041700.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/snortsnarf/ for
# details.

# file_text_map.pl is  ....
# this is a module for use with Pipeline (it is not a separate program).

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

sub process {
	require "mod_utils.pl";
	my ($input)= shift;
	@_ == 3 || (&reporterr("file_text_map.pl takes 3 arguments (input field,file path,output field), but got:".join(' ',@_),0) && return 0);
	my $outloc= pop(@_);	
	
	my ($key,$file)= &arg_to_val($input,@_);
	
	open(F,"<$file") || (warn "file_text_map.pl: could not open $file fo read" && return 0);
	my $text= '';
	while (<F>) {
		if (s/^\s*$key\s*:\s*//) {
			chomp;
			$text= $_;
			last;
		}
	}
	close F;

	&write_out_to_arg($input,$outloc,$text);
};

\&process;

# $Id: file_text_map.pl,v 1.1 2000/06/14 01:35:17 jim Exp $
