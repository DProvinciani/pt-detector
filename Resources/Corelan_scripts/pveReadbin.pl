#!/usr/bin/perl
# Perl script written by Peter Van Eeckhoutte
# http://www.corelan.be:8800
# This script takes a filename as argument
# will read the file 
# and output the bytes in \x format
#
if ($#ARGV ne 0) { 
print "  usage: $0 ".chr(34)."filename".chr(34)."\n"; 
exit(0); 
} 
#open file in binary mode
print "Reading ".$ARGV[0]."\n";
open(FILE,$ARGV[0]);
binmode FILE;
my ($data, $n, $offset, $strContent);
$strContent="";
my $cnt=0;
while (($n = read FILE, $data, 1, $offset) != 0) {
  $offset += $n;
}
close(FILE);

print "Read ".$offset." bytes\n\n";
my $cnt=0;
my $nullbyte=0;
print chr(34);
for ($i=0; $i < (length($data)); $i++) 
{
  my $c = substr($data, $i, 1);
  $str1 = sprintf("%01x", ((ord($c) & 0xf0) >> 4) & 0x0f);
  $str2 = sprintf("%01x", ord($c) & 0x0f);
  if ($cnt < 8)
  {
    print "\\x".$str1.$str2;
    $cnt=$cnt+1;	
  }
  else
  {
    $cnt=1;
    print chr(34)."\n".chr(34)."\\x".$str1.$str2;
  }
  if (($str1 eq "0") && ($str2 eq "0"))
	{
	  $nullbyte=$nullbyte+1;
	}
}
print chr(34).";\n";
print "\nNumber of null bytes : " . $nullbyte."\n";
