#!/usr/bin/perl

# incident_view.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# incident_view.pl is a Pipeline module to take an incident name and a path
#   to an incident file and show the incident on the browser
# pipeline args: incident name, incident file
# side effect: displayes HTML on browser

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

sub process {
    require "sisr_utils.pl";
    require "inc_xml.pl";
    my ($input)= shift;
    @_ == 2 || (&reporterr("incident_view.pl takes 2 arguments (inc name,inc file), but got:".join(' ',@_),0) && return 0);
    
    my ($incname,$incfile)= &arg_to_val($input,@_);
    
    # print out headers
    print $input->header(-header => 'text/html',-expires => '+0d');

    my $configfile= $input->param('configfile');

    # probably really want to get these from the config file
    my($path)= $input->param('_path');

    # get mail template file names and descriptions
    %mailtmpl= &get_mail_tmpl_hash($configfile);

    my $tree= &load_XML_tree($incfile);
    my $inc= &find_incident_named($tree,$incname);
    # should check if $inc= undef; indicates there is no such incident
    my %attrs= &incident_attrs($inc);
    my($fldsref,$notesref)= &incident_fields_and_notes($inc);
    my(@text_fields)= @{$fldsref};
    my(@notes)= @{$notesref};

    my $created= localtime($attrs{'created'});
    my $setfile= $attrs{'event-set-loc'};
    $setfile =~ s/^file:\/\///;
    my $seturl= &pipeline_submit_url("lab_set_view.pl $attrs{'event-set-name'} $setfile",$path,'configfile' => $configfile);
    my $setfileurl= &pipeline_submit_url("set_list_view.pl $setfile",$path,'configfile' => $configfile);
    print <<">>";
<HTML>
<HEAD>
    <TITLE>Listing of incident $incname</TITLE>
</HEAD>
<BODY bgcolor="#E7DEBD">
<H1>Incident $incname</H1>
Incident <B>$incname</B> was created on <B>$created</B> by <B>$attrs{'creator'}</B>.
<table border cellpadding = 3><CAPTION>Alert set location and text fields</CAPTION>
    <TR>
        <TH>Field</TH>
        <TH>Value</TH>
    </TR>
    <TR>
        <TD ALIGN=right>Alert set name</TD>
        <TD ALIGN=left><A HREF="$seturl">$attrs{'event-set-name'}</A></TD>
    </TR>
    <TR>
        <TD ALIGN=right>Alert set file location</TD>
        <TD ALIGN=left><A HREF="$setfileurl">$attrs{'event-set-loc'}</A></TD>
    </TR>
>>
    my($fldname,$descr,$val);
    foreach (@text_fields) {
        ($fldname,$descr,$val)= &get_incident_text_field_info($_);
        $val =~ s/\&/&amp;/g;
        $val =~ s/\</&lt;/g;
        $val =~ s/\>/&gt;/g;
        $val =~ s/\"/&quot;/g;
    print <<">>";
    <TR>
        <TD ALIGN=right>$descr</TD>
        <TD ALIGN=left>$val</TD>
    </TR>
>>
    }
    print "</table>\n";
    if (@notes) {
        print '<TABLE border CELLPADDING=5><TR ALIGN=center><CAPTION>Annotations</CAPTION><TD><B>Subject</B></TD><TD><B>Author</B></TD><TD><B>Date</B></TD><TD><B>Annotation</B></TD></TR>';
        foreach (@notes) {
            my ($author,$date,$subject,$note)= &get_note_info($_);
            $note =~ s/\&/&amp;/g;
            $note =~ s/\</&lt;/g;
            $note =~ s/\>/&gt;/g;
            $note =~ s/\"/&quot;/g;
            $note =~ s/[\n\r]/\<BR\>/g;
            print "\n<TR ALIGN=center><TD>$subject</TD><TD>$author</TD><TD>$date</TD><TD>$note</TD></TR>";
        }
        print "</table>\n";
    } else {
        print "<P>(No annotations found for $incname.)";
    }
    print <<">>";
<HR>
Add an annotation:
>>

    &pipeline_form_start("config_inc_flds_db.pl $configfile \$ifieldinfo \$incfile | add_annotation_to_inc_db.pl \$incfile $incname \$author \$subject \$note | incident_view.pl $incname \$incfile",$path);

    print <<">>";
<INPUT TYPE="hidden" NAME="configfile" VALUE="$configfile">
<INPUT TYPE="hidden" NAME="incname" VALUE="$incname">

<TABLE>
    <TR><TD align=right>Your name:</TD><TD align=left><INPUT TYPE="text" NAME="author" SIZE="12"></TD></TR>
    <TR><TD align=right>Subject:</TD><TD align=left><INPUT TYPE="text" NAME="subject" SIZE="20"></TD></TR>
    <TR><TD align=right>Note:</TD><TD align=left><TEXTAREA NAME="note" wrap=yes ROWS="6" COLS="60"></TEXTAREA></TD></TR>
</TABLE>
<INPUT TYPE="submit" VALUE="Add Annotation">
<HR>
</FORM>
>>
    # eventually want to add links to save selection, delete set, deleted selected, rename, arrange (listing) by field, etc.
    
    # link to create report
    
    #config_alert_set_db.pl $configfile \$setfile | set_list_view.pl \$setfile
    print '<A HREF="inclist.pl?configfile='.&url_encode($configfile),"\">List all incidents</A><P>";

    &pipeline_form_start("parse_mailtempl.pl \$reporttempl | load_inc_fields.pl $incname $incfile | inst_flds.pl mail- |confirm_email.pl \$reporttempl mail-",$path);

    print <<">>";
<INPUT TYPE="hidden" NAME="configfile" VALUE="$configfile">
<INPUT TYPE="hidden" NAME="incname" VALUE="$incname">
<INPUT TYPE="hidden" NAME="incfile" VALUE="$incfile">
Create a report from template: <SELECT NAME="reporttempl">
>>
    my $file;
    foreach $file (keys %mailtmpl) {
        print "\t<OPTION VALUE=\"$file\"> $mailtmpl{$file}\n";
    }
    print <<">>";
</SELECT>
<INPUT TYPE="submit" VALUE="Create">
</FORM>
</BODY>
</HTML>
>>
};

sub get_mail_tmpl_hash {
    my($configfile)= shift;
    
    my $maildir= &get_config_field($configfile,'report-tmpl-dir-mail');
    return undef if $maildir eq '';
    my %hash=();
    opendir(D,$maildir) || die "could not open mail report directory $maildir";
    while ($file=readdir(D)) {
        next if $file =~ /^\./ || ($file =~ /~$/);
        my $fullpath="$maildir/$file";
        next unless -f $fullpath; # exclude dirs, etc
        my $descr= $file;
        open(F,"<$fullpath") || die "could not open mail template file $fullpath";
        while (<F>) {
            last if /^\s*$/; # separation
            if (s/^Description\s*:\s*//i) {
                $descr= $_;
                last;
            }
        }
        close F;
        $hash{$fullpath}= $descr;
    }
    closedir(D);
    return %hash;
}

\&process;

# $Id: incident_view.pl,v 1.11 2001/10/18 18:23:25 jim Exp $
