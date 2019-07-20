#!/usr/bin/perl

# wrap_fields.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# wrap_fields.pl is a Pipeline module to wrap fields or env. vars at a
#   certain length (but does not break words, words are separated by spaces
#   and tabs, commas and semicolons).  The text in the field is interpreted
#   as paragraphs separated by one or more newlines; these newlines are
#   preserved
# pipeline args: wrap length, field/envvar+
# side effect: modifies the given fields/envvars

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

sub process {
    require "sisr_utils.pl";
    my ($input)= shift;
    @_ => 2 || (&reporterr("wrap_fields.pl takes at least 2 arguments (wrap length,[text fields]), but got:".join(' ',@_),0) && return 0);
    
    my ($wraplen)= &arg_to_val($input,shift(@_));

    foreach $textfld (@_) {
        $textfld =~ s/^([\$\%])//;
        if ($1 eq '%') { # env. var
            $ENV{$textfld}= wrap($wraplen,$ENV{$textfld});
        } else {
            $input->param($textfld,wrap($wraplen,$input->param($textfld)));
        }
    }
};

sub wrap {
    my($wraplen,$text)= @_;
    my $t;
    my $parasep;
    my ($out,$line,$word,$sep);
    $text =~ s/^(\n*)//;
    $out= $1;  # preserve leading newlines
    while ($text =~ s/^(.+)(\n+|$)//) { # grab first para
        $t= $1;
        $parasep= $2;
        #$parasep.= "\n" if $parasep eq "\n"; # add a newline unless end of string or already separated by multiple

        my(@pcs)= split(/(\s+|,\s*|;\s*|--\s*)/,$t);
        $line= '';
        my(@paralines)= ();
        while (@pcs) {
            $word= shift(@pcs);
            $sep= @pcs ? shift(@pcs) : '';
            if (length($line.$word.$sep) <= $wraplen) {
                $line.= $word.$sep;
                next;
            } elsif (length($line.$word) <= $wraplen) {
                # might fit if $sep has spaces to kill at end
                my $s= $sep;
                $sep=~ s/\s+$//;
                if (length($line.$word.$sep) <= $wraplen) {
                    $line.= $word.$sep;
                    push(@paralines,$line);
                    $line= '';
                    next;
                }
            } 
            # not going to fit
            push(@paralines,$line) unless $line eq '';
            $line= $word.$sep;
            if (length $line > $wraplen) { # too long
                # try to get it under by trimming trailing whitespace for the separater, otherwise let if overflow
                $line =~ s/\s+$//;
                push(@paralines,$line);
                $line= '';
            }
        }
        push(@paralines,$line) unless $line eq '';
        $out.= join("\n",@paralines).$parasep;
    }
    $out.= $text; # might be some leftover newlines
    return $out;
}

\&process;

# $Id: wrap_fields.pl,v 1.11 2001/10/18 18:23:25 jim Exp $
