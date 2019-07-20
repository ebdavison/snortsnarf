#!/usr/bin/perl

# confirm_email.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# confirm_email.pl is a Pipeline module to take a result of a mail template
#   that has been filled in and produces HTML to allow the user to modify
#   this and then to send it off
# pipeline args: report template, mail field prefix
# side effect: displayes HTML on browser

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

sub process {
    require "sisr_utils.pl";
    my ($input)= shift;
    @_ == 2 || (&reporterr("confirm_email.pl takes 2 arguments (mail source,mail field prefix), but got:".join(' ',@_),0) && return 0);
    
    my ($mailsource,$fldprefix)= &arg_to_val($input,@_);

    my %hdrs= ('From' => '','Cc' => '','Bcc' => '','To'=>'','Subject' => '');
    my $body= '';
    my $bodyfield= $fldprefix.'body';
    my $fld;
    
    foreach $fld ($input->param()) {
        $_= $fld;
        if (s/^$fldprefix//) {
            $_= lc($_);
            $_= ucfirst($_);
            ucfirst($_);
            if ($_ eq 'Body') {
                $body= $input->param($fld);
            } else {
                $hdrs{$_}= $input->param($fld);
            }
        }
    }
    
    my @fixorder= qw(From To Cc Bcc Subject);
    my @hdrorder=@fixorder;
    my $oldhdr;
    FLD: foreach $fld (keys %hdrs) {
        foreach $oldhdr (@hdrorder) {
            next FLD if $fld eq $oldhdr;
        }
        push(@hdrorder,$fld);
    }
    
    # print out headers
    print $input->header(-header => 'text/html',-expires => '+0d');

    # probably really want to get these from the config file
    my($path)= $input->param('_path');
    
    my $configfile= $input->param('configfile');
    my $incname= $input->param('incname');
    my $incfile= $input->param('incfile');

    print "<HTML><HEAD><TITLE>Mail report page</TITLE></HEAD>\n";

    my $hdrs= join(' ',keys %hdrs);
    print <<">>";
<BODY bgcolor="#E7DEBD">
<H1>Mail a report</H1>
Use this form to create an e-mail report.  Fields have been tentatively filled out based on the report template chosen ($mailsource).  Inspect these carefully and choose the 'send' button to send e-mail.<P>
>>

    &pipeline_form_start("notempty.pl \$From \$To| wrap_fields.pl 75 \$body | send_mail.pl \$body $hdrs | add_inc_mail_annotation.pl $incfile $incname $mailsource | incident_view.pl $incname $incfile",$path);

    print <<">>";
<TABLE BORDER=3>
    <TR>
        <TH>Header</TH>
        <TH>Value (check carefully to avoid error and embarrassment)</TH>
    </TR>
>>

    my($curval,$size);
    foreach $fld (@hdrorder) {
        my $val= $hdrs{$fld};
        $val =~ s/\&/&amp;/g;
        $val =~ s/\"/&quot;/g;
        $val =~ s/\</&lt;/g;
        $val =~ s/\>/&gt;/g;
        print <<">>"
    <TR>
        <TD ALIGN=right>$fld</TD>
        <TD ALIGN=left><INPUT NAME="$fld" VALUE="$val" SIZE=65></TD>
    </TR>
>>
    }
    

    print <<">>";
</TABLE>
Message body:<BR>
<TEXTAREA name="body" wrap=yes cols=75 rows=25>$body</TEXTAREA><P>
<INPUT TYPE="submit" VALUE="Send mail">

<INPUT TYPE=hidden NAME="configfile" VALUE="$configfile">
<INPUT TYPE=hidden NAME="incname" VALUE="$incname">
<INPUT TYPE=hidden NAME="incfile" VALUE="$incfile">
</FORM>
</BODY>
</HTML>
>>
}


\&process;

# $Id: confirm_email.pl,v 1.12 2001/10/18 18:23:25 jim Exp $
