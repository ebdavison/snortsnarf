#!/usr/bin/perl -w

# setup_sisrdb_dir.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# Usage: setup_sisrdb_dir.pl [-g group] sisrdb-directory [labeled-set-db [incident-db [setname-source]]]
#
# setup_sisrdb_dir.pl makes (if needed) a certain given directory indicated and
# empty SISR labeled set and incident db files and a default set name file
# in that directory.  
# If -g is not given, sets the permission of the directory to 777 and the
# files to 666, to allow anyone to write to it.
# If -g is provided, the following argument is a group name or gid to allow
# to access the annotations.  The group of all the files and directories are
# set to the given group, the permissions of the directory are set to 770 and
# the permissions of files to 660.

# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program.

$group= undef;
while ($ARGV[0] =~ /^-/) {
    $_= shift(@ARGV);
    if (/^-g/) {
        $groupname= shift(@ARGV);
        $group= $groupname =~ /^\d+$/ ? $groupname : getgrnam($groupname);
        die "specified group \"$groupname\" does not exist" unless defined($group);
    }
}

my($dir,$setfile,$incfile,$namefile)= @ARGV;
$setfile= 'labsetdb.xml' unless defined($setfile);
$incfile= 'incdb.xml' unless defined($incfile);
$namefile= 'setname.txt' unless defined($namefile);

if (defined($group)) {
    $fileperms= 0660;
    $dirperms= 0770;
} else {
    $fileperms= 0666;
    $dirperms= 0777;
}

unless (-e $dir) {
    mkdir($dir,$dirperms) || die "could not make $dir";
}
chmod($dirperms,$dir);
chdir($dir);

if (-e $setfile) {
    print "did not create $setfile in $dir since it already exists\n";
} else {
    open(F,">$setfile") || die "could not create $setfile -- skipping";
    print F "<LABELED-EVENTS></LABELED-EVENTS>";
    close F;
    chmod($fileperms,$setfile);
    print "* empty labeled set database $setfile created in $dir\n";
}

if (-e $incfile) {
    print "did not create $incfile in $dir since it already exists\n";
} else {
    open(F,">$incfile") || die "could not create $incfile -- skipping";
    print F "<INCIDENTS></INCIDENTS>";
    close F;
    chmod($fileperms,$incfile);
    print "* empty incident database $incfile created in $dir\n";
}

if (-e $namefile) {
    print "did not create $namefile in $dir since it already exists\n";
} else {
    open(F,">$namefile") || die "could not create $namefile -- skipping";
    print F <<">>";
# put the default name of the next labeled set on the first non-comment line
# if this name ends in an integer, the name in this file will be incremented each time a name is queried for
# comments in this file will be lost in that case
# if you want to use this file as your set name source, have this line in your SISR configuration file:
#    set-name-default: <the path to this file>
# here is the next default set name:
labset1
>>
    close F;
    chmod($fileperms,$namefile);
    print "* labeled set name source file database $namefile created in $dir; edit it if you wish to get default set names from there\n";
}

if (defined($group)) {
    foreach $file ($dir,$setfile,$incfile,$namefile) {
        chown((stat($file))[4],$group,$file) || warn "could not change gid for $file to $groupname ($group); you may need to run as root\n";
    }
}

# $Id: setup_anns_dir.pl,v 1.4 2000/06/14 18:40:45 jim Exp $
