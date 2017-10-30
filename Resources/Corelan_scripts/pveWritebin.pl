#!/usr/bin/perl
# Perl script written by Peter Van Eeckhoutte
# http://www.corelan.be:8800
# This script takes a filename as argument
# will write bytes in \x format to the file 
#
if ($#ARGV ne 0) { 
print "  usage: $0 ".chr(34)."output filename".chr(34)."\n"; 
exit(0); 
} 
system("del $ARGV[0]");
my $shellcode="You forgot to paste ".
"your shellcode in the pveWritebin.pl".
"file";
# Metasploit generated – calc.exe – x86 – Windows XP Pro SP2
$shellcode="\x68\x97\x4C\x80\x7C\xB8".
"\x4D\x11\x86\x7C\xFF\xD0";


#open file in binary mode
print "Writing to ".$ARGV[0]."\n";
open(FILE,">$ARGV[0]");
binmode FILE;
print FILE $shellcode;
close(FILE);

print "Wrote ".length($shellcode)." bytes to file\n";
