#!/usr/bin/perl

 require RPC::XML;
 require RPC::XML::Client;

$cli = RPC::XML::Client->new('http://localhost:4567/RPC2');
$resp = $cli->send_request('echo_test');

print "Server replied with: ".$resp->value."\n";
