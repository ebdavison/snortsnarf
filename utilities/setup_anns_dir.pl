#!/usr/bin/perl -w

# setup_anns_dir.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# Usage: setup_anns_dir.pl [-g group] annotation-directory {annotation-base-filename}
#
# setup_anns_dir.pl makes (if needed) a certain given directory indicated and
# empty Snortsnarf annotation base files with the given filenames, inside
# that directory.  
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
        $group= shift(@ARGV);
        $group= getgrnam($group) unless $group =~ /^\d+$/;
    }
}

my($dir,@files)= @ARGV;

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
chown((stat($dir))[4],$group,$dir) || die "could not change gid for $dir to $group" if defined($group);
chdir($dir);
foreach $file (@files) {
    if (-e $file) {
        die "cannot create $file in $dir since it already exists";
    } else {
        open(F,">$file") || die "could not create $file -- skipping";
        print F "<ANNOTATION-BASE></ANNOTATION-BASE>";
        close F;
        chmod($fileperms,$file);
        chown((stat($file))[4],$group,$file) || die "could not change gid for $file to $group"  if defined($group);
        print "empty annotation base $file created in $dir\n";
    }
}

# $Id: setup_anns_dir.pl,v 1.4 2000/06/14 18:40:45 jim Exp $
