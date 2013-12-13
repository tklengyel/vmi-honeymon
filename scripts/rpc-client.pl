#!/usr/bin/perl

 require RPC::XML;
 require RPC::XML::Client;

$cli = RPC::XML::Client->new('http://localhost:4567/RPC2');

print "echo_test()\n";
$resp = $cli->send_request('echo_test');
print "Server replied with: ".$resp->value."\n";

print "get_random_clone()\n";
$resp = $cli->send_request('get_random_clone');
print "Server replied with: ". @{$resp->value}[0] ." VLAN ". @{$resp->value}[1] ."\n";
