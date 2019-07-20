#!/usr/bin/perl

# alertset_xml.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# alertset_xml.pl contains useful functions in working with the alert set
#   database XML.

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program. 

require "xml_help.pl";

# if given an exisiting tree, returns it.  If given undef creates a new
# labeled event tree.
sub create_tree_unless_exists {
	my($tree)= shift;
	if (defined($tree) && @$tree) {
		return $tree;
	} else {
		return ['LABELED-EVENTS',[{}]];
	}
}

# return all EVENT-SET entries in the tree
sub get_all_sets {
	my($tree)= @_;
	my(@sets)= ();
	my @content= @{$tree->[1]};
	shift @content; # ignore LABELED-EVENTS attrs
	while (@content) {
 	   my $tagname=shift(@content);
 	   my $content=shift(@content);
 	   next unless $tagname eq 'EVENT-SET'; # should always be this actually
 	   push(@sets,$content);
	}
	return @sets;
}

# return the set with the given name in the tree, creating an empty new one
# if needed
sub get_set_named {
	my($tree,$setname)= @_;
	my $settree= &find_set_named($tree,$setname);
	unless (defined($settree)) {
		$settree=[{'name' => $setname, 'created' => time()}];
		push(@{$tree->[1]},'EVENT-SET',$settree);
	}
	return $settree;
}

# find and return the set in the tree with the given name else return undef
sub find_set_named {
	my($tree,$setname)= @_;
	my @content= @{$tree->[1]};
	shift @content; # ignore LABELED-EVENTS attrs
	while (@content) {
 	   my $tagname=shift(@content);
 	   my $content=shift(@content);
 	   next unless $tagname eq 'EVENT-SET'; # should always be this actually
 	   my @event_set_trees= @{$content};
 	   my %event_set_attrs= %{shift(@event_set_trees)};
 	   return $content if $event_set_attrs{'name'} eq $setname;
	}
	return undef;
}

# return a hash of attributes in the set
sub set_attrs {
	my($settree)= shift;
	return %{$settree->[0]};
}

# return a list of EVENTS for the given set name in the tree
sub set_events {
	my($root,$setname)= @_;
	my($tree)= &find_set_named($root,$setname);
	return undef unless defined($tree);
	my(@events)= ();
	my @content= @{$tree};
	shift @content; # ignore LABELED-EVENTS attrs
	while (@content) {
 		my $tagname=shift(@content);
 		my $content=shift(@content);
 		next unless $tagname eq 'EVENT'; # should always be this actually
		push(@events,$content);
	}
	return @events;
}

# given the root of a set and a list of parsed alerts, the alerts are
# incorporated in the set
sub add_events_to_set {
	my($setroot,@events)= @_;
	my $e;
	foreach $e (@events) {
		#&reporterr("add_events_to_set: $e\{msg}=".$e->{'sig'},0);
		push(@{$setroot},'EVENT',[
			{},
			'TEXT',[{'format' => $e->{'format'}},0,$e->{'text'}],
			'MESSAGE',[{},0,$e->{'sig'}],
			'DATE',[{},0,$e->{'date'}],
			'MONTH',[{},0,$e->{'month'}],
			'TIME',[{},0,$e->{'time'}],
			'PROTOCOL',[{},0,$e->{'proto'}],
			'SRCIP',[{},0,$e->{'src'}],
			'DESTIP',[{},0,$e->{'dest'}],
			'SRCPORT',[{},0,$e->{'sport'}],
			'DESTPORT',[{},0,$e->{'dport'}],
			'FLAGS',[{},0,$e->{'flags'}]
		]);
	}
}

# given the root of a set and a list of alert API instances, the alerts are
# incorporated in the set
sub add_alerts_to_set {
	my($setroot,@alerts)= @_;
	my $a;
	my(@packets);
	foreach $a (@alerts) {
		#&reporterr("add_events_to_set: $e\{msg}=".$e->{'sig'},0);
		@packets= $a->packets();
		$p= $packets[0]; # assume exactly one packet
		push(@{$setroot},'EVENT',[
			{},
			'TEXT',[{'format' => $a->text_format()},0,$a->as_text()],
			'MESSAGE',[{},0,$a->message()],
			'DATE',[{},0,$a->day()],
			'MONTH',[{},0,$a->month()],
			'TIME',[{},0,$a->tod_text()],
			'PROTOCOL',[{},0,$p->protocol()],
			'SRCIP',[{},0,$p->sip()],
			'DESTIP',[{},0,$p->dip()],
			'SRCPORT',[{},0,$p->sport()],
			'DESTPORT',[{},0,$p->dport()],
			'FLAGS',[{},0,$p->flags()]
		]);
	}
}

# for a given event tree, return a particular event field
sub event_field {
    my($eventtree,$fld)= @_;
    my @content= @{$eventtree};
    shift @content;
    my($tagname,$info);
    while (@content) {
        $tagname=shift(@content);
        $info= shift(@content);
        #print "tagname=$tagname; $info=(",join(',',@{$info}),")\n";
        if ($tagname eq $fld) {
            return $info->[2];
        }
    }      
    return undef;
}

# return a list of hash references to details of the set with the given name
# in the tree
sub get_set_event_details {
	my($root,$setname)= @_;
	return map(&event_details($_),&set_events($root,$setname));
}

# return a hash with the details of an event, given an event tree
# + all tags in the tree are assumed to contain text and are keyed in the
#   hash by the tag name
# + top level attributes are keyed as EVENT_<attrname>
# + attributes of lower tags are keyed as <tagname>_<attrname>
sub event_details {
    my($eventtree)= @_;
    my %info=();
    my @content= @{$eventtree};
    my %attrs= %{shift @content};
    my $attr;
    foreach $attr (keys %attrs) {
    	$info{"EVENT_$attr"}= $attrs{$attr};
    }
    my($tagname,$info);
#my $debug='';
	my($attrhash,$zero,$text,@should_be_empty);
    while (@content) {
        $tagname=shift(@content);
        ($attrhash,$zero,$text,@should_be_empty)= @{shift(@content)};
#$debug.= $info.'{'.$tagname."}= $text\n";
        $info{$tagname}= $text;
	    %attrs= %{$attrhash};
	    foreach $attr (keys %attrs) {
	    	$info{"$tagname_$attr"}= $attrs{$attr};
	    }
    }      
#&reporterr('debug event_details: '.$debug,0);
    return \%info;
}

1;

# $Id: alertset_xml.pl,v 1.2 2000/06/14 18:39:47 jim Exp $
