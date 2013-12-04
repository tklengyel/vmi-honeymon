#!/usr/bin/perl
# This file is part of the VMI-Honeymon project.
#
# 2012-2013 University of Connecticut (http://www.uconn.edu)
# Tamas K Lengyel (tamas.k.lengyel@gmail.com)
#
#  VMI-Honeymon is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 3 of the License, or
#  (at your option) any later version.
# 
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
# 
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, see <http://www.gnu.org/licenses/>.

# perl -MCPAN -e 'install VT::API' 
# perl -MCPAN -e 'install IO::Socket::SSL'

 use VT::API;
 use DBI;
 use DBD::mysql;

my $api;
my $mysql_conn;
my $mysql_host="localhost";
my $mysql_user="honeymon";
my $mysql_pass="honeymon";
my $mysql_port=3306;
my $mysql_db="honeymon";
my $vt_key = "YOUR_KEY";

#if(!defined($version)) {
#	require "config.pl";
#	require "mysql.pl";
	$debug=1;
	$api = VT::API->new(key => $vt_key);
	standalone($ARGV);
#} else {
#	$api = VT::API->new(key => $vt_key);
#}

sub standalone {
        if($#ARGV==0) {
		print "Getting report for $ARGV[0]\n";
                vt_got_file($ARGV[0]);
        }
	# else {
        #        vt_process_backlog();
        #}
}


#Return the report associated with the hash if it exists
sub vt_check_file_hash {
	my $hash = $_[0];

	my $result = $api->get_file_report($hash);
	my %res_hash = % { $result };

	if($res_hash{'report'}) {
		print "Got report!\n";
		return $result;
	} else {
		print "Submitting file\n";
		return undef;
	}
}    

sub vt_save_results {

	my $hash = $_[0];
	my $got_report = 0;
	my $date = "-";

	my $url;
	my %results;
	my @report;
	my %scans;
	my $idx;

	if(defined($_[1])) {
		$got_report=1;
		%results = % { $_[1] };
		$url = $results{'permalink'};
		@report = @ { $results{'report'} };
		$date = $report[0];
		%scans = % { $report[1] };
		$idx=-1;
	}

	if($got_report) {
		print 	"[VT] URL: $url\n".
			"[VT] Date: $date\n";

		mysql_connect();
		my $test=0;
		$test=mysql_check($hash);
		if($test==0) {
		while (($AV, $scan_result) = each %scans) {
			if($debug) { print "[VT] $AV: $scan_result\n"; }

			mysql_save($hash, $AV, $scan_result);
		}
		}
		mysql_disconnect();
	}
}

sub vt_got_file {
	my $hash = $_[0];
	my $result = vt_check_file_hash($hash);
	
	if(defined($result)) {
       		vt_save_results($hash, $result);
	} else {
       		vt_save_results($hash, undef);
		$api->scan_file("./viruses/$hash");	
	}
}

sub vt_process_backlog {
	if(!$mysql_enable) { print "Can't process backlog without MySQL\n"; }

	my %backlog = mysql_get_vt_backlog();

	if($debug) { print "[VT] Processing ". keys(%backlog) ." backlog(s)\n"; }

	my $counter=0;
	while (($idx, $hash) = each %backlog) {
		print "[VT] Checking $hash\n";
		$counter++;
		my $result = vt_check_file_hash($hash);
		if(defined($result) && ref($result) eq "HASH") {
			#Got result
			if($debug) { print "[VT] Got results for IDX: $idx\n"; }
			vt_update_result($idx, $hash, $result);
		} else {
			print "[VT] No scan results yet, submit again just to be sure\n";
			$api->scan_file("$capture_path/$hash");
		}	

		#if($counter % 3 == 0) {
		#	print "Sleeping for a minute\n";
		#	sleep(60);
		#}
	}
}

sub mysql_connect {
	my $dsn = "DBI:mysql:database=$mysql_db;host=$mysql_host;port=$mysql_port";
        $mysql_conn = DBI->connect($dsn,$mysql_user,$mysql_pass);
}

sub mysql_check {
	my $hash = $_[0];
	my $sql =  "SELECT virustotal_IDX FROM `$mysql_db`.`virustotal` WHERE hash='$hash' LIMIT 0,1";
        my $sessionID=0;

        my $sql_st = $mysql_conn->prepare($sql);
        if(!$sql_st->execute()) {
                print "[MYSQL] Query failed: $DBI::errstr\n";
                return 0;
        }

        $sql_st->bind_columns(undef, \$sessionID);
        while($sql_st->fetch()) {
		print "Already have it: $sessionID\n";
                return $sessionID;
	}

	return 0;
}

sub mysql_save {
        $numParameters = @_;
        if($numParameters != 3) { return; }
        my $hash = $_[0];
        my $AV = $_[1];
        my $res = $_[2];

        my $sql =  "INSERT INTO `$mysql_db`.`virustotal` VALUES ('', \"$hash\", \"$AV\", \"$res\")";

        my $sql_st = $mysql_conn->prepare($sql);
        if(!$sql_st->execute()) {
		print "[MYSQL] Insert failed: $DBI::errstr\n";
        }
}

sub mysql_disconnect {
	$mysql_conn->disconnect();
}
