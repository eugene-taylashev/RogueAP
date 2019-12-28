#!/bin/perl
#==============================================================================
# Script to identify unauthorized WiFi APs 
#
# Usage: $0 [options] 
#   Where options: 
#       -h          this help
#       -l 2        enable debug with level X 0-3 (nothing-high)
#       -v          be verbose
#		-m normal|strict mode to report unauthorized  
#		-i url		URL to JSON with authorized/known APs
#       -o url      URL to report rogue APs
#       -s file     Text file with dump of `sudo iw wlan0 scan`
#
# See documentation at the bottom
#
# Author: Eugene Taylashev, under the MIT License
#
#Copyright (c) 2019-2020 Eugene Taylashev
#
#Permission is hereby granted, free of charge, to any person obtaining
#a copy of this software and associated documentation files (the
#"Software"), to deal in the Software without restriction, including
#without limitation the rights to use, copy, modify, merge, publish,
#distribute, sublicense, and/or sell copies of the Software, and to
#permit persons to whom the Software is furnished to do so, subject to
#the following conditions:
#
#The above copyright notice and this permission notice shall be
#included in all copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
#EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
#MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
#NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
#LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
#OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
#WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
#==============================================================================

use utf8;
use Getopt::Long;
use Data::Dumper;
use LWP::UserAgent;
use JSON;
#use URI::Encode qw(uri_encode uri_decode);

use strict;                 # Good practice
use warnings;               # Good practice

#==== Global vars ==========
my $gsScanCmd = 'sudo iw wlan0 scan'; #-- OS command to enumerate WiFi Access Points
my ($gsInURL, $gsOutURL, $gsScanFile);
my %gaAuthorized; 		#-- hash for authorized APs BSS->SSID
my %gaKnown;			#-- hash for known APs BSS->SSID
my %gaSSID;				#-- hash for SSID in scope SSID->1
my %gaReport;			#-- hash with report info
#my @gaUnAuthorized;	#-- list of hashes for unauthorized APs

#-- Logging and tracking vars
my $gisVerbose = 0;     #-- be Verbose flag. See sub dlog
my $giLogLevel = 0;     #  Debug level: 0 - no debug errors only, 1 - important only, 2 - also sub in/out, 3 - everything
my $gisTest = 0;        #-- flag to run self-tests (no useful activity)

my $gsLogFile;        #-- filename for logging/debugging
my $ghLogFile;        #-- file handler for logging/debugging
my @gaLogTime;          #-- array to store start time for subs
my $giLogIndent = 0;  #-- space indent for log formatting
$gaLogTime[0] = time(); 
my $giAPprocessed = 0;   #-- counter of processed APs

#-- Supporting vars
my $gsDirSeparator = '/';
my ($sec,$min,$hour,$day, $mon, $year) = (localtime)[0..5];     #-- get current date for log filename
my $curr_date = sprintf( "%04d%02d%02d", 1900+$year, 1+$mon, $day);
my $curr_time = sprintf( "%02d:%02d:%02d", $hour,$min,$sec);
my $help;


#--  command line options
my %args = ("help|h|?" => \$help,   #-- show help and exit
    "input|i=s" => \$gsInURL,       #-- input REST API URL or file with list of Authorized/known APs
    "output|o=s" => \$gsOutURL,     #-- reporting REST API URL or file with list of detected unauthorized APs
    "scan|s=s" => \$gsScanFile,     #-- file with WiFi scan results
    "log|l=i" => \$giLogLevel,    #-- set log/debug level
    "verbose|v"  => \$gisVerbose      #-- set flag to be verbose
);

#==== Constants for this script ==========
 use constant {
    DIR_LOGS    => 'logs',
	INI_BLK_AUTH => 'authorized',
	INI_BLK_KNWN => 'known',
	RPRT_HIGH	=> 'high',
	RPRT_MED	=> 'medium',
	RPRT_LOW	=> 'low',
	RPRT_INFO	=> 'info'
};#use constant

#====== Sub prototypes ======
sub verifyAPs();
sub readAPfile($);
sub countSecs($);
sub myFtest($$);
sub myFopen($$$);
sub getFileName($);
sub getFileBase($);
sub startDebug();
sub stopDebug();
sub dlog($;$$$);
sub exitApp($);
sub usage();

#-- Exit by Ctrl-C 
$SIG{INT} = sub { stopDebug(); die "Interrupted by user\n"; };
$| = 1;  # autoflush

#-- Capture warnings into the log file with debug level 2
local $SIG{__WARN__} = sub {
    my $message = shift;
    dlog('warn:'.$message,2);
};

#==============================================================================
# Start of MAIN()
#==============================================================================
#-- parse command line options
GetOptions (%args) or usage();
usage() if $help;

#-- prepare the report structure
$gaReport{RPRT_HIGH} = (); #-- anon list for high severity alarms
$gaReport{RPRT_MED}  = (); #-- anon list for medium severity alarms
$gaReport{RPRT_LOW}  = (); #-- anon list for low severity alarms
$gaReport{RPRT_INFO} = (); #-- anon list for other information


#-- Create filename for logs
$gsLogFile = getFileBase($0).'-'.$curr_date.'.log';
#-- modify path if DIR_LOGS exists
$gsLogFile = DIR_LOGS . $gsDirSeparator . $gsLogFile if( -d DIR_LOGS );

startDebug();       #-- Start debuging

#-- Report settings
dlog((defined $gsInURL?'':'not ')."ok - Input URL/file with authorized APs=$gsInURL", 1, __LINE__);
dlog("ok - Log level is $giLogLevel", 1, __LINE__) if $giLogLevel > 0;
dlog("ok - Log file is $gsLogFile", 1, __LINE__) if $giLogLevel > 0;
dlog((myFtest('s',$gsScanFile)?'':'not ')."ok - WiFi scan results is $gsScanFile", 1, __LINE__) if defined $gsScanFile;

readAPfile($gsInURL) if defined $gsInURL;
verifyAPs();

#-- We are done
dlog(($giAPprocessed > 0?'':'not ')."ok - Processed $giAPprocessed APs in ".
    countSecs(time()-$gaLogTime[0]), 1);

dlog( "ok - Done in ". countSecs(time()-$gaLogTime[0]), 1, __LINE__);
print "See logs in $gsLogFile\n" if $ghLogFile && $gisVerbose;
stopDebug(); #-- close the debug file
exit(0);
#==================================== End of MAIN =============================


#------------------------------------------------------------------------------
# Process the scan results to identify authorized/known/unauthorized APs
#------------------------------------------------------------------------------
sub verifyAPs(){
    my $sub_name = 'verifyAPs';  dlog("+++++ $sub_name: ", 2, __LINE__ );
    
    my $sScanRes = '';  #-- APs scan results

	#-- get scan results from a file or by running OS command
    if( defined $gsScanFile && myFtest('s',$gsScanFile) ){
		$sScanRes = readEntireFile($gsScanFile);
    } else {
		$sScanRes = `$gsScanCmd 2>&1`;
	} #if+else

	my ($iLines, $iSkiped, $sBSS, $sSSID, $iAuth, $iKnown, $iNew) 
	=  (0,0,'','',0,0,0);
	my $aAPinfo = {};  #-- anon hash
	my $isBSS = 0;
	while($sScanRes =~ /^(.*)$/gm ) {
		my $sLine = $1;
		chomp $sLine;
		++$iLines;
#$gaReport{RPRT_HIGH}, $gaReport{RPRT_MED},$gaReport{RPRT_LOW},$gaReport{RPRT_INFO}
#gaKnown gaSSID

		if( 	  $sLine =~ /^BSS\s+(\S+)\(/i ){
			my $sTmp = $1; 

			#-- close prev BSS block
			if( $isBSS ){

					#-- authorized BSS broadcasts protected SSID
				if(  	isKeyVal( \%gaAuthorized, $sBSS, $sSSID) && 
						isKeyVal( \%gaSSID, $sSSID, 1 ) ) {
					dlog( "ok - authorized $sBSS -> protected $sSSID", 2, __LINE__ );
					$$aAPinfo{'title'} = "Authorized AP ($sBSS) broadcasts protected SSID ($sSSID)";
					push @{$gaReport{RPRT_INFO}}, $aAPinfo;
					++$iAuth;

					#-- authorized BSS broadcasts wrong protected SSID
				} elsif( defined $gaAuthorized{$sBSS} && 
						 $gaAuthorized{$sBSS} ne $sSSID && 
						isKeyVal( \%gaSSID, $sSSID, 1 ) ) {
					dlog( "not ok - authorized $sBSS -> wrong protected $sSSID", 2, __LINE__ );
					$$aAPinfo{'title'} = "Authorized AP ($sBSS) broadcasts wrong protected SSID ($sSSID)";
					push @{$gaReport{RPRT_LOW}}, $aAPinfo;
					++$iAuth;

					#-- authorized BSS broadcasts unknown SSID
				} elsif( defined $gaAuthorized{$sBSS} && 
						 ! defined $gaSSID{$sSSID} ) {
					dlog( "not ok - authorized $sBSS -> unknown $sSSID", 2, __LINE__ );
					$$aAPinfo{'title'} = "Authorized AP ($sBSS) broadcasts unknown SSID ($sSSID)";
					push @{$gaReport{RPRT_LOW}}, $aAPinfo;
					++$iAuth;

					#-- known BSS broadcasts known SSID
				} elsif( isKeyVal( \%gaKnown, $sBSS, $sSSID) && 
						 isKeyVal( \%gaSSID, $sSSID, 2 ) ) {
					dlog( "ok - known $sBSS -> known $sSSID", 2, __LINE__ );
					$$aAPinfo{'title'} = "Known AP ($sBSS) broadcasts known SSID ($sSSID)";
					push @{$gaReport{RPRT_INFO}}, $aAPinfo;
					++$iKnown;

					#-- known BSS broadcasts unknown SSID
				} elsif( defined $gaKnown{$sBSS} && 
						 ! defined $gaSSID{$sSSID} ) {
					dlog( "not ok - known $sBSS -> unknown $sSSID", 2, __LINE__ );
					$$aAPinfo{'title'} = "Known AP ($sBSS) broadcasts unknown SSID ($sSSID)";
					push @{$gaReport{RPRT_LOW}}, $aAPinfo;
					++$iKnown;

					#-- known BSS broadcasts protected SSID
				} elsif( isKeyVal( \%gaKnown, $sBSS, $sSSID) && 
						 isKeyVal( \%gaSSID, $sSSID, 1 ) ) {
					dlog( "not ok - known $sBSS -> protected $sSSID", 1, __LINE__ );
					$$aAPinfo{'title'} = "Known AP ($sBSS) broadcasts protected SSID ($sSSID)";
					push @{$gaReport{RPRT_HIGH}}, $aAPinfo;
					++$iKnown;

					#-- unauthorized AP broadcasts protected SSID
				} elsif( isKeyVal( \%gaSSID, $sSSID, 1 ) && 
						 ! isKeyVal( \%gaAuthorized, $sBSS, $sSSID) ) {
					dlog( "not ok - unauthorized $sBSS -> protected $sSSID", 1, __LINE__ );
					$$aAPinfo{'title'} = "Unauthorized AP ($sBSS) broadcasts protected SSID ($sSSID)";
					push @{$gaReport{RPRT_HIGH}}, $aAPinfo;
					++$iNew;

					#-- unauthorized/unknown AP broadcasts unknown SSID
				} elsif( ! defined $gaSSID{$sSSID} &&
						 ! defined $gaKnown{$sBSS} && 
						 ! defined $gaAuthorized{$sBSS} ) {
					dlog( "not ok - unauthorized $sBSS -> unknown $sSSID", 2, __LINE__ );
					$$aAPinfo{'title'} = "Unauthorized AP ($sBSS) broadcasts unknown SSID ($sSSID)";
					push @{$gaReport{RPRT_MED}}, $aAPinfo;
					++$iNew;

					#-- undefined case
				} else {
					#-- unauthorized AP
					dlog( "not ok - combination is not defined $sBSS -> $sSSID", 1, __LINE__ );
					$$aAPinfo{'title'} = "Combination is not defined $sBSS -> $sSSID";
					push @{$gaReport{RPRT_MED}}, $aAPinfo;
					++$iNew;
				}#if + elsif + else 2
			}#if close prev BSS block

			#-- start new BSS
			$sBSS = $sTmp; $isBSS = 1; $sSSID ='';
			$aAPinfo = {};  $$aAPinfo{'BSS'} = $sBSS; 

		} elsif ( $sLine =~ /^\s+SSID: (.*)$/i && $isBSS ){
			$sSSID = $1; $$aAPinfo{'SSID'} = $sSSID;
		} elsif ( $sLine =~ /^\s+last seen:\s+(.*)$/i && $isBSS ){
			$$aAPinfo{'LastSeen'}  = $1;
		} elsif ( $sLine =~ /^\s+freq:\s+(\d+)$/i && $isBSS ){
			$$aAPinfo{'freq'}  = $1;
		} else {
			++$iSkiped;
		}#if+elsif+else 1

#		if( $isBSS ){
#			$$aAPinfo{'info'} .= "\n" . $sLine;
#		}#if

    }#while

    dlog("processed $iLines lines, skiped $iSkiped lines", 2, __LINE__ );
    dlog("ok - Identified $iAuth authorized, $iKnown known and $iNew new APs", 1, __LINE__ );
	$giAPprocessed = $iAuth + $iKnown + $iNew;
    dlog( 'gaReport: '.Dumper( \%gaReport ), 4, __LINE__ );
    dlog( "----- ok - $sub_name", 2);
    return 1;
}#sub verifyAPs()


#------------------------------------------------------------------------------
# Read a list of authorized and known BSS=SSIS arrays from a text file
#------------------------------------------------------------------------------
sub readAPfile($){
    my ( $sJFile) = @_;
    my $sub_name = 'readAPfile'; 
    dlog("+++++ $sub_name: from the file $sJFile", 2, __LINE__ );
    my ($fh, $iLine, $sLine, $iBSS, $sBSS, $sSSID, $sBlock);
    
    #-- check that input file exists
	if( ! myFtest('s',$sJFile) ){
		derr( "File $sJFile does NOT exist" );
	    dlog("----- not ok - $sub_name", 2, __LINE__ );
		return -1;
	}#if 

    #-- open the input file for read
    open( $fh, "<:encoding(utf8)", $sJFile );
	if( !$fh ) {
		derr( "Could not open the $sJFile file: $!" );
	    dlog("----- not ok - $sub_name", 2, __LINE__ );
		return -1;
	}#if 

    #-- for all records
    $iLine = 0;  $iBSS = 0; #-- set counters to 0
	$sBlock = INI_BLK_AUTH;
    while($sLine = <$fh>){
        chomp $sLine; ++$iLine;
        next if $sLine =~ /^\s*#/;        #-- skip comments
        next if $sLine =~ /^\s*$/;        #-- skip empty lines
		
		if(      $sLine =~ /^\s*\[(.*)\]/ ){
			#-- change block 
			$sBlock = lc($1); 
			dlog( "Processing the $sBlock block", 3, __LINE__ );
		} elsif( $sLine =~ /^([0-9a-f:]+)=(.*)$/i ){
			$sBSS = $1; $sSSID = $2; 
			if( $sBlock eq INI_BLK_AUTH ){
				if ( ! defined $gaAuthorized{$sBSS}){
					$gaAuthorized{$sBSS} = $sSSID;
					$gaSSID{$sSSID} = 1 if ! defined $gaSSID{$sSSID};
					dlog("Add $sBSS -> $sSSID as $sBlock", 3, __LINE__ );
					++$iBSS;
				#} else - repeated BSS
				}#if; 
			} elsif( $sBlock eq INI_BLK_KNWN ){
				if ( ! defined $gaKnown{$sBSS}){
					$gaKnown{$sBSS} = $sSSID;
					$gaSSID{$sSSID} = 2 if ! defined $gaSSID{$sSSID};
					dlog("Add $sBSS -> $sSSID as $sBlock", 3, __LINE__ );
					++$iBSS;
				#} else - repeated BSS
				}#if; 
			} else {
				dlog( "not ok - Unknown block $sBlock: $sBSS -> $sSSID", 2, __LINE__ );
			}#if+elsif
		} else {
			dlog( "not ok - Unknown line: $sLine", 2, __LINE__ );
		}#if+elsif
    }#while

    close( $fh )   if $fh;    #-- close JSON file
    dlog( "gaAuthorized: ".Dumper( \%gaAuthorized ), 4, __LINE__ );
    dlog( "gaKnown: ".Dumper( \%gaKnown ), 4, __LINE__ );
    dlog( "gaSSID: ".Dumper( \%gaSSID ), 4, __LINE__ );
    dlog(" processed $iLine lines, inserted $iBSS APs", 2, __LINE__ );
    dlog("----- ok - $sub_name", 2, __LINE__ );
    return $iLine;
}#sub readAPfile($)


sub trim($){my ($s)=@_; $s=~ s/^\s*//; $s=~ s/\s*$//; return $s;}#-- Trim edge spaces
sub removeLastComma($){my($s)=@_;$s =~ s/,\s*$//; return $s;}  #-- remove trail comma symbols
sub q2($){my $s=shift; return "'".$s."'"; }
sub q2c($){my $s=shift; return "'".$s.'\','; }
sub qq2($){my $s=shift; return '"'.$s.'"'; }
sub qq2c($){my $s=shift; return '"'.$s.'",'; }
sub isList($){my $r=shift; return (ref($r) eq 'ARRAY');}
sub isHash($){my $r=shift; return (ref($r) eq 'HASH');}

#------------------------------------------------------------------------------
# Converts MAC-48 as string into long int
# Source: https://www.perlmonks.org/?node_id=440768
#------------------------------------------------------------------------------
sub mac_to_num($) {
  my $mac_hex = shift;

  $mac_hex =~ s/://g;
  $mac_hex =~ s/-//g;
  $mac_hex =~ s/\.//g;

  $mac_hex = substr(('0'x12).$mac_hex, -12);
  my @mac_bytes = unpack("A2"x6, $mac_hex);

  my $mac_num = 0;
  foreach (@mac_bytes) {
    $mac_num = $mac_num * (2**8) + hex($_);
  }

  return $mac_num;
}#sub mac_to_num($)


#------------------------------------------------------------------------------
# Converts long int into MAC-48 as string with :
# Source: https://www.perlmonks.org/?node_id=440768
#------------------------------------------------------------------------------
sub num_to_mac($) {
  my $mac_num = shift;

  my @mac_bytes;
  for (1..6) {
    unshift(@mac_bytes, sprintf("%02x", $mac_num % (2**8)));
    $mac_num = int($mac_num / (2**8));
  }

  return join(':', @mac_bytes);
}#sub num_to_mac($)


#------------------------------------------------------------------------------
# Converts a decimal IP to a dotted IP
# Source: http://ddiguru.com/blog/25-ip-address-conversions-in-perl
#------------------------------------------------------------------------------
sub dec2ip ($) {
    join '.', unpack 'C4', pack 'N', shift;
}#sub dec2ip
 
#------------------------------------------------------------------------------
# Converts a dotted IP to a decimal IP
# Source: http://ddiguru.com/blog/25-ip-address-conversions-in-perl
#------------------------------------------------------------------------------
sub ip2dec ($) {
    unpack N => pack CCCC => split /\./ => shift;
}#sub ip2dec


#------------------------------------------------------------------------------
#  Check if a key in a hash by ref $ref has specified value $val
#  Returns: 1/true - key exists and has specified value, 0/false otherwise
#------------------------------------------------------------------------------
sub isKeyVal($$$) {
    my ($ref,$key,$val) = @_;
    if( exists $$ref{$key} ){
        if( defined $$ref{$key} ){ 
			my $tmp = $$ref{$key};
			if( $tmp =~ /^\d+$/ ) {
				#-- numeric scalar
				return $tmp == $val;
			} else {
				#-- string scalar
				return $tmp eq $val;
			}#if+else 3
		} else {
			return 0;
		} #if+else 2
	} else {
		return 0;
	} #if+else 1
    return 0;
}#sub isKeyVal


#------------------------------------------------------------------------------
# Private -X testing function to address long and UTF-16 names on Win32
# Input: $cmd - command line d/f/each
#        $obj - filename or handler
# Output: same as -X
# For Win32 requires: use Win32::LongPath;
# Updated on Jun 17, 2017 by Eugene Taylashev
#------------------------------------------------------------------------------
sub myFtest($$) {
    my ($cmd,$obj) = @_;
    if( $^O eq 'MSWin32' ){     #-- MS Windows approach
        return testL ($cmd, $obj);
    } else {
        return -d $obj if $cmd eq 'd';
        return -f $obj if $cmd eq 'f';
        return -s $obj if $cmd eq 's';
    } #if + else
    
}#sub myFtest


#------------------------------------------------------------------------------
# Private file opener to address long and UTF-16 names on Win32
# Input: for non-MS same as for open, 
#        for MS a reference: openL (\$FH, '>:encoding(UTF-8)', $file)
# Output: same as open
# For Win32 requires: use Win32::LongPath;
# Updated on Jun 20, 2019 by Eugene Taylashev
#------------------------------------------------------------------------------
sub myFopen($$$){
    my ($fh, $mode,@EXPR) = @_;
    return ($^O eq 'MSWin32'? openL($fh, $mode, @EXPR): open($$fh, $mode, @EXPR));
}#sub myFopen($$$)


#------------------------------------------------------------------------------
# Get file extension (suffix)
#------------------------------------------------------------------------------
sub getFileSuff($) {
    my ($f) = @_;
    return ( $f =~ /\.([^.]+)$/ )?$1:'';
#    my $ext = '';
#    $ext = $1
#        if( $f =~ /\.([^.]+)$/ );
#    return $ext;
}#sub getFileSuff


#------------------------------------------------------------------------------
# Get file name with extension (suffix) but without path 
# for MS Windows/Unix and ZIP#file formats
# Returns file name or original string
#------------------------------------------------------------------------------
sub getFileName($) {
    my ($f) = @_;
    $f =~ s/.*\\//; #-- remove MS Windows path
    $f =~ s/.*\///; #-- remove Unix path
    $f =~ s/.*#//;  #-- remove zip out of zip#file_name
    return $f;
}#sub getFileName


#------------------------------------------------------------------------------
# Get file name without last extension (suffix) and dir path
# Returns file name or original string
#------------------------------------------------------------------------------
sub getFileBase($) {
    my ($f) = @_; $f = getFileName($f); $f =~ s/\.[^.]+$//; #-- remove the last extension
    return $f;
}#sub getFileBase


#------------------------------------------------------------------------------
# Get dir path out of file name
# Returns dir path  or original string
#------------------------------------------------------------------------------
sub getFilePath($) {
    my ($f) = @_; $f =~ s/[^\/\\]+$//;  #-- remove everything after / or \
    return $f;
}#sub getFilePath


#------------------------------------------------------------------------------
#  Read entire file in one operation and return as string
#  ToDO: recognize Unicode or ASCII
#------------------------------------------------------------------------------
sub readEntireFile ($;$) {
    my ($sFileName, $sEncode) = @_;
    my $sRes = '';  my $fh;
    local $/ = undef;
    
    $sEncode = 'raw' if( !$sEncode);
    #-- try to open as raw
#'<:raw'; "<:utf8"; "<:encoding(UTF-16)"; "<:encoding(windows-1251)" "<:encoding(UCS-2le)"
    if( ! myFopen( \$fh, "<:$sEncode", $sFileName ) ) {
        dlog("Couldn't open file $sFileName: $!", 1, __LINE__);
        return undef;
    }#if
    
    #-- Read BOM - TBDef
                    
    binmode $fh;
    $sRes = <$fh>;
    close $fh;    
    
    #-- check that file is utf-8
#    return readEntireFile($sFileName, 'utf-8') if( is_utf8($sRes) and $sEncode ne 'utf-8' );
    return $sRes;
}#sub readEntireFile


#------------------------------------------------------------------------------
#  Convert number of seconds into string with hours, min and secs
#------------------------------------------------------------------------------
sub countSecs($) {
    my ($iSec) = @_;
    my $sRes = '';
    if( $iSec > 3600 ) {
        $sRes .= int($iSec/3600) . ' h ';
        $iSec = $iSec % 3600;
    }#if
    if( $iSec > 60 ) {
        $sRes .= int($iSec/60) . ' min ';
        $iSec = $iSec % 60;
    }#if
    $sRes .= $iSec . ' sec';
    return $sRes;
}#sub


#------------------------------------------------------------------------------
# Start logging/debugging by creating a log file
#------------------------------------------------------------------------------
sub startDebug() {
    return 0 if ( $giLogLevel <= 0 );           #-- debug is disabled
    return 0 if ( length($gsLogFile) < 3 ); #-- debug filename is not specified 
    return 0 if( $ghLogFile );              #-- file already opened
    #-- create or open for append the log file
    open( $ghLogFile, ">>:encoding(utf8)", $gsLogFile) 
            or exitApp( "Could not create/open the debug file $gsLogFile: $!" );
    print $ghLogFile "\n\n============================ $curr_date at $curr_time  =================================\n";
    return 1;
}#sub startDebug


#------------------------------------------------------------------------------
# Stop logging/debugging by closing the log file
#------------------------------------------------------------------------------
sub stopDebug(){
    close( $ghLogFile )   if $ghLogFile;    #-- close the debug file
}#sub stopDebug


#------------------------------------------------------------------------------
#  Output debug and verbose information based on debug level
#  Input: message to output,[optional]: debug level, default=1; code line; code file
#  Debug level: 0 - no debug errors only, 1 - important only, 2 - also sub in/out, 3 - everything
#------------------------------------------------------------------------------
sub dlog($;$$$) {
    my $message = shift;
    my $level = @_?shift:1;
    my ($ln,$fn) = @_;  #-- code line, code filename

    return undef if $giLogLevel < $level; #-- ignore everything where local level bigger than global level
    
    
    #-- check current indent
    $gaLogTime[++$giLogIndent] = time() if( $message =~ /\+\+\+\+\+/);
    $message = ('  ' x $giLogIndent) . $message;
    $message .=' in '. countSecs(time()-$gaLogTime[$giLogIndent--]) 
        if( $message =~ /\-\-\-\-\-/ && $giLogIndent>0);
    
    if( $gisVerbose && $level <= 1){
        my $s = trim($message);
        #-- encoding
        utf8::encode($s); # if utf8::is_utf8($s);
        print $s,"\n" ; # out message if beVerbose and level 1 or 0
    } #if gisVerbose
    
    #-- Add file name and line
    $message .= " [at line $ln" if (defined $ln);
    $message .= " in $fn" if (defined $fn);
    $message .= ']' if (defined $ln || defined $fn);
    
    if ($ghLogFile) {
        print $ghLogFile "$message\n" ; #decode_utf8()
    } else {
        print STDERR "$message\n" ;
    }#if
    
    #-- print errors to the screen
    print STDERR "$message\n"
        if ($ghLogFile and $level==0);
    return 1;
}#sub dlog


#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
sub derr($;$$$) {
    my $message = shift;
    my $level = @_?shift:0;
    dlog($message,0,@_);
}#sub derr


#------------------------------------------------------------------------------
#  Abort application execution with a message
#------------------------------------------------------------------------------
sub exitApp( $ ) {
    my ($sMsg) = @_;
    #dlog( $sMsg, 0);
    die "Critical error: $sMsg. Aborting...\n";
}#sub exitApp

#------------------------------------------------------------------------------
#  Output information about the script
#------------------------------------------------------------------------------
sub usage() {
    my $sTmp = <<EOBU;

Script to identify unauthorized (rogue) WiFi Access Points (APs)
    
Usage: $0 [options]

    [options]:
    -h | --help : this help
    -v | --verbose : be verbose
    -l | --log=1 : Enable logging with level 1-3. 1-few, 3-everything
    -c | --config=file.ini : specify configuration file
    -i | --input=url : REST API url to obtain authorized/known APs
    -o | --output=url : REST API url to report unauthorized APs
    -s | --scan=file.txt : file with WiFi scan results
EOBU
    print $sTmp,"\n";
    exit(0);

}#sub


=pod

=head 1 Installation on Arch Linux

sudo pacman -S perl-lwp-protocol-https
sudo pacman -Ss perl-json
sudo pacman -S perl-uri


=head1 Updates
  Dec 28, 2019 
   - add ScanCommand, 
   - convert to INI-style for input text with authorized/known APs, 
   - add 3 categories: authrozed, know, unauthorized
   - add 3 alarms with different severity: 
	high) An unauthorized AP broadcasts the protected SSID xxx
	medium) An unknown AP broadcasts an unknown SSID xxxx
	low) An unknown AP broadcasts the known SSID xxxx
   - add 2 modes: normal (reports only alarm high), strict (reports all 3 alarms)
  Dec 27, 2019 - add read authorized APs, report unauthorized
  Dec 25, 2019 - initial draft

=cut