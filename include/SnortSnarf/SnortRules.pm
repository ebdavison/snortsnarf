#!/usr/bin/perl

# SnortRules.pm, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2001 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# An instance of SnortRules represents a set of Snort rules originating from
# a given start file.  This can be used to e.g., find all those that match a
# certain message.  What would be returned from this is an instance of
# SnortRule.  This instance can be used to find the text of a rule and the
# references it contains.  Caching at various levels is used on the first
# occurance of a particular piece of data being needed.  These classes are
# pretty feature-poor right now.  Actually they contain pretty much exactly
# what we needed.  Assumes the files don't change (due to caching).

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

package SnortRules;

sub BEGIN {
    $fhnonce= 'srfh000';
}

# create a new SnortRules instance from a start rules file and an optional
# directory
sub new {
    my($class,$rulesfile,$rulesdir,$filesep,$cacheall)= @_;
    $rulesfile =~ s/\s+$//;
    my $self= bless {
        'rules_file' => $rulesfile, # snort configuration file used
        'rules_dir' => $rulesdir, # snort rules directory to look in unless full path is given
        'filesep' => $filesep, # the separator to use for file paths
        'cacheall' => $cacheall, # only scan the files once, caching all rules
        'scan_files' => 1,
        'for_msg' => {} # cache for the rules with a given message; index is the message string
    },$class;
    return $self;
}

# find all the rules that match contain a given 'msg' field and return these as instances of SnortRule.
sub get_rules_for_msg {
    my($self,$msg)= @_;
    if ($self->{'scan_files'} && !defined($self->{'for_msg'}{$msg})) {
        $self->cache_rules_for_msg_in_file($msg,$self->{'rules_file'});
        $self->{'scan_files'}= 0 if ($self->{'cacheall'});
    }
    if (!defined($self->{'for_msg'}{$msg})) {
        $self->{'for_msg'}{$msg}= []; # we've already scanned and don't know anything about this sig
    }
    return @{$self->{'for_msg'}{$msg}};
}

# given a snort message, dig through the given rules file and cache those that have the given message field.  A list is produced and included
# files are followed.
sub cache_rules_for_msg_in_file {
    my ($self,$msg,$rule_file)= @_;
    #print STDOUT "get_rules_for_msg_in_file($self,$msg,$rule_file)\n";
    my $fh= $fhnonce++;
    # file names assumed to be absolute or relative to the current directory
    # but if -rulesdir was given, always use that as the dirctory (with the
    # file name appended to make the file location)
    my $regex= $self->{'filesep_regex'};
    unless (defined($regex)) { # need to create the regex for the file separator
        $regex= $self->{'filesep'};
        $regex=~ s/([^\w])/\\$1/g;
        $self->{'filesep_regex'}= $regex;
    }   
    my($file)= $rule_file =~ /([^$regex]+)$/; 
    if (defined($self->{'rules_dir'})) {
        $rule_file= $self->{'rules_dir'}.$self->{'filesep'}.$file;
    }
    unless (open($fh,"<$rule_file")) {
        warn "could not open $rule_file to read rules from -- skipping\n";
        return ();
    }
    while (<$fh>) {
        next if /^(\#|\s*$)/;
        while (/\\\s*$/) { # while ends with a '\'
            $_.= <$fh>;
        }
        chomp;
        if (s/^\s*include\s+//) {
            s/\s+$//;
            $self->cache_rules_for_msg_in_file($msg,$_);
        } elsif (/\(.*msg\s*:\s*\"([^\"]*)\"/) {
            my $mess= $1;
            $mess =~ s/\\(.)/$1/g;
            $mess =~ s/^\s+//;
            $mess =~ s/\s+$//;
            if (($mess eq $msg) || $self->{'cacheall'}) {
                my $new= SnortRule->new('text' => $_, 'msg' => $mess, 'loc' => $file);
                push(@{$self->{'for_msg'}{$mess}},$new);
            }
        }
    }
    close $fh;
}


##################################################

package SnortRule;

sub new {
    my($class)= shift;
    return bless {@_}, $class;
}

# the original location of this rule
sub location {
    return $_[0]->{'loc'};
}

# the rule text
sub text {
    return $_[0]->{'text'};
}

# the rule msg
sub msg {
    unless (defined($_[0]->{'msg'})) {
        $_[0]->{'msg'}= $_[0]->get_ruleopt('msg');
    }
    return $_[0]->{'msg'};
}

# a hash of references => ids in the rule
sub references {
    my($cite,$id);
    unless (defined($_[0]->{'refs'})) {
        foreach ($_[0]->get_ruleopt_list('reference')) {
            ($cite,$id)= split(/\s*,\s*/,$_);
            #print STDOUT "found references in $_[0]: $cite -- $id\n";
            $_[0]->{'refs'}{$cite}= $id;
        }
    }
    return () unless defined($_[0]->{'refs'}); # couldn't find any
    return %{$_[0]->{'refs'}};
}

# find a rule option
sub get_ruleopt {
    my($self,$opt)= @_;
    $_= $_[0]->{'text'};
    return undef unless defined($_);
    if (/\b$opt\s*:\s*(.*)\;/) {
        my $val= $1;
        if ($val =~ s/^\"//) { # quoted string
            $val =~ s/\"\s*$//;
        }
        return $val;
    }
    return undef;
}

# return a list the values of a certain rule option in the rule
sub get_ruleopt_list {
    my($self,$opt)= @_;
    my(@vals)= ();
    $_= $_[0]->{'text'};
    return undef unless defined($_);
    
    my($val,$opttext);
    s/^[^\(]+\(\s*//;
    foreach $opttext (split(/\s*;\s*/,$_)) {
        next unless $opttext =~ s/^$opt\s*:\s*//;
        if ($opttext =~ s/^\"//) { # quoted string
            $opttext =~ s/\"\s*$//;
        }
        push(@vals,$opttext);
    }
    return @vals;
}


1;
