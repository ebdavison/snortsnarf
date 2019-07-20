#!/usr/bin/perl

# AllMods.pm, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2001 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# AllMods contains a list of available files holding instance of various
# SnortSnarf APIs and provides functions to load each of these into memory
# using 'require'.

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

package AllMods;

# list all available input module files here
@all_input_files= qw (
    SnortFileInput.pm
    SnortDBInput.pm
);
@all_storage_files= qw (
    MemStorage.pm
    HTMLMemStorage.pm
    HTMLAnomMemStorage.pm
);
@all_output_files= qw (
    HTMLOutput.pm
);

@all_filter_files= qw (
    BasicFilters.pm
    TimeFilters.pm
);
@all_sorter_files= qw (
    BasicSorters.pm
);
@all_alert_files= qw (
    MemAlert.pm
);
@all_packet_files= qw (
    MemPacket.pm
);

# the file locations for all module names should be listed here unless the
#   file is the module name plus '.pm'
%name_to_file= (
	'TrueFilter' => 'BasicFilters.pm',
	'FalseFilter' => 'BasicFilters.pm',
	'NotFilter' => 'BasicFilters.pm',
	'AndFilter' => 'BasicFilters.pm',
	'OrFilter' => 'BasicFilters.pm',
	'AlertFieldDef' => 'BasicFilters.pm',
	'AlertFieldEq' => 'BasicFilters.pm',
	'AlertFieldCompare' => 'BasicFilters.pm',
	'AlertFieldNumCompare' => 'BasicFilters.pm',
	'AnyPacketFilter' => 'BasicFilters.pm',
	'AllPacketFilter' => 'BasicFilters.pm',
	'FieldDefPktFilter' => 'BasicFilters.pm',
	'FieldComparePktFilter' => 'BasicFilters.pm',
	'FieldNumComparePktFilter' => 'BasicFilters.pm',
	'IPFilterBase' => 'BasicFilters.pm',
	'HasSourceIPInFilter' => 'BasicFilters.pm',
	'HasDestIPInFilter' => 'BasicFilters.pm',
	'NotRefSourceIDsFilter' => 'BasicFilters.pm',
	'MinTimeFilter' => 'TimeFilters.pm',
	'MaxTimeFilter' => 'TimeFilters.pm',
	'FieldSorter' => 'BasicSorters.pm',
	'NumFieldSorter' => 'BasicSorters.pm',
	'RevSorter' => 'BasicSorters.pm',
	'FirstPktFieldSorter' => 'BasicSorters.pm',
	'FirstPktFieldNumSorter' => 'BasicSorters.pm',
	'NumHighestPktFieldSorter' => 'BasicSorters.pm',
	'FieldPktSorter' => 'BasicSorters.pm',
	'NumFieldPktSorter' => 'BasicSorters.pm',
	'ScalarKE' => 'KnownEquiv.pm',
	'ArrayKE' => 'KnownEquiv.pm'
);

%already_loaded= ();
######### these 4 methods are generally deprecated; you probably know the name of the module you want, so use load_module_named;
sub load_all_input_modules {
    foreach (@all_input_files) {
        &do_load($_,"could not load input module file \"$_\"");
    }
}

sub load_all_storage_modules {
    foreach (@all_storage_files) {
        &do_load($_,"could not load storage module file \"$_\"");
    }
}

sub load_all_output_modules {
    foreach (@all_output_files) {
        &do_load($_,"could not load output module file \"$_\"");
    }
}

sub load_all_modules {
    foreach (@all_input_files,@all_storage_files,@all_output_files,@all_filter_files,@all_sorter_files,@all_alert_files,@all_packet_files) {
        &do_load($_,"could not load module file \"$_\"");
    }
}
########################

sub load_module_named {
    my $name= shift;
    my $file= $name_to_file{$name};
    $file= "$name.pm" unless defined($file);
    return &do_load($file,"could not load module \"$name\", looked for it in file called \"$file\"");
}

sub do_load {
    my ($file,$warntext)= @_;
    return 1 if $already_loaded{$file};
    eval { require "$file"; };
    if ($@) {
        warn "$warntext; could be an error in that file; try 'perl -c' on that file\n";
        return 0;
    } else {
        $already_loaded{$file}= 1;
        return 1;
    }
}

1;