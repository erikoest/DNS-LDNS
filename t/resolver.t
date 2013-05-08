use Test::More tests => 3;

use FindBin qw/$Bin/;

use Net::LDNS ':all';

BEGIN { use_ok('Net::LDNS') };

my $r = new Net::LDNS::Resolver(filename => "/etc/resolv.conf");

$r->set_random(0);

my $p = $r->query(
   new Net::LDNS::RData(LDNS_RDF_TYPE_DNAME, 'org'),
   LDNS_RR_TYPE_SOA, LDNS_RR_CLASS_IN, LDNS_RD);

isa_ok($p, 'Net::LDNS::Packet', 'Make a simple query');

$r->set_rtt(2, 3);
my @rtt = $r->rtt;
is_deeply(\@rtt, [2, 3], "set_rtt and rtt");
