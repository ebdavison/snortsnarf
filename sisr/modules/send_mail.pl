#!/usr/bin/perl

# send_mail.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# send_mail.pl is a Pipeline module to send an e-mail message with the
#   given body and headers (whose contents are found in the like-named
#   field)
# pipeline args: mail body, header fields
# side effect: mail is sent using Mail::Sendmail

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

sub process {
    require "sisr_utils.pl";
    use Mail::Sendmail;
    my ($input,$body,@hdrflds)= @_;
    
    my ($body)= &arg_to_val($input,$body);
    my %mail=();
    foreach (@hdrflds) {
        $mail{$_}= $input->param($_);
    }
    $mail{'message'}= $body;

    unless (sendmail(%mail)) {
        my $mess= "Error sending mail: $Mail::Sendmail::error";
        print $input->header('text/html'),"<HTML><HEAD><TITLE>$mess</TITLE></HEAD><BODY>$mess</BODY><HTML>";
        die "$mess\n";
    }
};


\&process;

# $Id: send_mail.pl,v 1.11 2001/10/18 18:23:25 jim Exp $
