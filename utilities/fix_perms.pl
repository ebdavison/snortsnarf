#!/usr/bin/perl -w

# fix_perms.pl, distributed as part of Snortsnarf v021111.1
# Author: James Hoagland, Silicon Defense (hoagland@SiliconDefense.com)
# copyright (c) 2000 by Silicon Defense (http://www.silicondefense.com/)
# Released under GNU General Public License, see the COPYING file included
# with the distribution or http://www.silicondefense.com/software/snortsnarf/
# for details.

# Usage: fix_perms.pl [-g group] {file|directory}
#
# fix_perms.pl recursively traverses the directories and files given on the
# command line.  (Symbolic links are followed, so be careful of infinite
# loops.)
# If -g is not given, sets the permission of the directory to 755 and the
# files to 644, to allow anyone to read it.
# If -g is provided, the following argument is a group name or gid to allow
# to access the files and directories.  The group of all the files and
# directories are set to the given group, the permissions of directories are
# set to 750 and the permissions of files to 640.

# for Snortsnarf, this is expected to be useful for changing the permissions
# of snort log directories so it can be viewed on a web browser when linked
# to.  From a security point of view, you should use -g to set the group to a
# group that only your web user (the user your web server runs as when
# accessing files) if your machine is available to persons that should not be
# able to see the alerts or the files live on a shared disk.
# 
# Please send complaints, kudos, and especially improvements and bugfixes to
# hoagland@SiliconDefense.com.  As described in GNU General Public License, no
# warranty is expressed for this program

$group= undef;
while ($ARGV[0] =~ /^-/) {
    $_= shift(@ARGV);
    if (/^-g/) {
        $group= shift(@ARGV);
        $group= getgrnam($group) unless $group =~ /^\d+$/;
    }
}

if (defined($group)) {
    $fileperms= 0640;
    $dirperms= 0750;
} else {
    $fileperms= 0644;
    $dirperms= 0755;
}

@q= @ARGV;

while ($file=pop(@q)) {
    if (-d $file) {
        chmod($dirperms,$file);
        opendir(D,$file) || die "could not open directory $file";
        while ($subfile=readdir(D)) {
            next if $subfile eq '.' || $subfile eq '..';
            push(@q,"$file/$subfile");
        }
        closedir(D);
    } else {
        chmod($fileperms,$file);
    }
    chown((stat($file))[4],$group,$file) || die "could not change gid for $file to $group" if defined($group);
} 

# $Id: fix_perms.pl,v 1.4 2000/06/14 18:39:47 jim Exp $
