#!/usr/bin/perl

use CGI::Carp qw(fatalsToBrowser);
      use CGI qw(:standard);
	  use LWP::Simple qw(!head);
1;
	  
%FORM         = ();
my $q = new CGI;
%cgi_data = ();
foreach $key (sort { $a <=> $b } $q->param()) {
      my $val = $q->param($key);
      $cgi_data{$key} = $val;
#     $val =~ tr/+/ /;
#     $val =~ s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;
      $FORM{$key}     = $val;
      if (uc($key) eq "ACTION") {
            $FORM{'ACTION'} = uc($val);
      }
}


      binmode(STDOUT, ":utf8");    # if $uni;
	  $header_printed=0;
      eval {
            $CGIHML = CGI->new if !$CGIHML;
            my $type = 'text/plain';
            print STDOUT $CGIHML->header(-type => $type, -charset => 'utf-8', -author => 'vponos', -process => 'Update gravity db');
			$header_printed=1;
      };


##get data from https://phishing.army/download/phishing_army_blocklist.txt


@ACT=split/,/,"SMARTTV,TRACKING,BLACKLISTED_DOMAINS,REGEX,PHISHING,YTHOST,MALICIOUSIP,CRYPTO";
@ACT=grep{/^$FORM{'ACTION'}$/gi}@ACT;


if (@ACT) {
	if(lc($ACT[0]) eq 'ythost'){
	my $yt_sites='https://api.hackertarget.com/hostsearch/?q=googlevideo.com';
	$contents = get($yt_sites);
	my @ARR=split(/\n|\r/,$contents);
	my @CONT=();
	for(@ARR){
		next if $_!~/\,/;
		push @CONT,(split/,/,$_)[0];
	}
	my %SU=();
	@CONT=grep{!$SU{$_}++}@CONT;
	goto read_fi unless @CONT;
open $fh,'>','ythost.txt';
grep{print $fh $_."\n"}@CONT;
close $fh;

	}
	
		if(lc($ACT[0]) eq 'blacklisted_domains'){
			
	my $yt_sites='https://pgl.yoyo.org/adservers/serverlist.php?hostformat=raw&useip=&showintro=0';
	$contents = get($yt_sites);
	my @ARR=split(/\n|\r/,$contents);
	my @CONT=();
	for(@ARR){
		next if $_=~/^(#|\<|\s)|\>$/;
		$_=~s!(\n|\r|\s)$!!;
		$_=~s!^(\n|\r|\s)!!;
		next if !$_;
		push @CONT,$_;
	}
	
	
	my %SU=();
	@CONT=grep{!$SU{$_}++}@CONT;
	
	my @DIRS=('privacy','adblock','custom');
	
	foreach my $directory(@DIRS){
	my @FI=readDirFiles($directory);
	next unless @FI;
	foreach my $fd(@FI){
		my $fn=$directory.'/'.$fd;
		next if !-e $fn;
		open my $fh,$fn;
	while(<$fh>){
		next if $_=~/^#/ || !$_ || $_=~/^\s$/;
		$_=~s!(\n|\r|\s)$!!;
		$_=~s!^(\n|\r|\s)!!;
		next if $SU{$_};
		push @CONT,$_;
		$SU{$_}++;
	}
	close $fh;
	}
	}

	%SU=();
	@CONT=grep{!$SU{$_}++}@CONT;
	@CONT=sort {lc($a) cmp lc($b)}@CONT;
	
	goto read_fi unless @CONT;
my $files=lc($ACT[0]).'.txt';
unlink $files;
#print_plain("Unlink at file $files with ".scalar(@CONT));
unshift @CONT,"### updated file at ".time();
open $fhk,'>',$files || print_plain("Cannot Open file $files ".$!);
for(@CONT){print $fhk $_."\n"};
close $fhk;

#print_plain("Saved at file $files with ".scalar(@CONT));

	}
	
	
		if(lc($ACT[0]) eq 'maliciousip'){
		my $files=lc($ACT[0]).'.txt';
		my @CONT_firewall=();
	open my $fh,$files;
	while(<$fh>){
	next if $_=~/^#/ || !$_ || $_=~/^\s$/;
		$_=~s!(\n|\r|\s)$!!;
		$_=~s!^(\n|\r|\s)!!;
		
		my $fw_line='iptables -I FORWARD -s '.$_.' -j DROP';
		push @CONT_firewall,$fw_line;
	}
	close $fh;
	my %SU=();
	unshift @CONT_firewall,"### updated file at ".time();
	@CONT_firewall=grep{!$SU{$_}++}@CONT_firewall;
	if(@CONT_firewall){
		open my $fhd,'>',$files.'fw';
	grep{print $fhd $_."\n"}@CONT_firewall;
	close $fhd;
	}
	}
	
	
	if(lc($ACT[0]) eq 'phishing'){
		my $phishing_sites='https://phishing.army/download/phishing_army_blocklist.txt';

#getstore($phishing_sites,'phishing1.txt');
$contents = get($phishing_sites);
my @ARR=split(/(\n|\r)/,$contents);
print STDOUT "#total records : ".scalar(@ARR)."\n";
	my %SU=();
	@ARR=grep{!$SU{$_}++}@ARR;
print STDOUT "#total records after clear : ".scalar(@ARR)."\n";
goto read_fi unless @ARR;
print STDOUT "#save : ".scalar(@ARR)."\n";
open $fh,'>','phishing.txt' or print STDOUT "Cannot open file phishing ".$!;
grep{print $fh $_."\n"}@ARR;
close $fh;
	}
	
read_fi:
	my $file=lc($ACT[0]).'.txt';
	open my $fhr,$file;
	while(<$fhr>){
		next if $_=~/^#/ || !$_ || $_=~/^\s$/;
		print STDOUT $_;
	}
	close $fhr;
	
}else{
	print_plain('There is no ACTION for '.$FORM{'ACTION'});
}



exit;


sub print_plain {
      my $text = shift;
      binmode(STDOUT, ":utf8");    # if $uni;
      eval {
            $CGIHML = CGI->new if !$CGIHML;
            my $type = 'text/plain';
            print STDOUT $CGIHML->header(-type => $type, -charset => 'utf-8', -author => 'vponos', -process => 'API_monitor') unless $header_printed;
      };

      #print STDOUT $CWD;
      print STDOUT $text;

      #use File::chdir;
##$CWD = 'cgi-bin/';
      #print STDOUT $CWD;

      exit;
}

sub readDirFiles {
      my $mdir     = shift;
      my @contents = ();
      opendir(MYDIR, $mdir) or return $^E;
      @contents = grep !/^\.\.?$/, readdir MYDIR;
      closedir MYDIR;

      @contents = grep { !-d $_ } @contents;
      return @contents;
}

#you can test blocker on https://d3ward.github.io/toolz/adblock.html

