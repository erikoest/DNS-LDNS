use Test::More tests => 22;

use DNS::LDNS ':all';

BEGIN { use_ok('DNS::LDNS') };

my $rr1 = new DNS::LDNS::RR;
isa_ok($rr1, 'DNS::LDNS::RR', 'Create empty rr');

$rr1 = new DNS::LDNS::RR(
    type => LDNS_RR_TYPE_DNSKEY,
    class => LDNS_RR_CLASS_CH,
    ttl => 4321,
    flags => 257,
    protocol => 3,
    algorithm => 8,
    key => 'AwEAAcJxQ7AQ4fc5zvegukR+LEAMQ+w0ASD3n0Bmz2cmbIAFUYRoAzhPalQYXkI65iLHl7d7nDbDTiGgN+GoIogNdGzUIe7izg9XyjrWiZiCttysE6XPONN0Ccehd52/BI6cdnC3Xri7TtvKgLIcnlqO7XLMEZoSDUFsAk8G6Xj9VHb6WqLqLBiEein2tnxWsoNUerUd0bvEUEGNenQDbCeNUKF5PT6Mck4fSHCU0so4bpAlSEPsxrFl0F+36TlKLLEDEVspA3J1tyVV6tVhPueYrfXoWlbRRp/SZdl2KHJPY94f4xgH4LC5Frw8044fnk0DdbIwMZhZPsrDiXFDcIVPUdk='
);
isa_ok($rr1, 'DNS::LDNS::RR', 'Create DNSKEY rr shorthand');

$rr1 = new DNS::LDNS::RR(
    type => LDNS_RR_TYPE_NSEC,
    class => LDNS_RR_CLASS_CH,
    ttl => 4321,
    nxtdname => 'foo.bar.org.',
    typelist => 'A NS SOA MX NSEC DNSKEY'
);
isa_ok($rr1, 'DNS::LDNS::RR', 'Create NSEC rr shorthand');

$rr1 = new DNS::LDNS::RR(
    type => LDNS_RR_TYPE_NSEC3,
    class => LDNS_RR_CLASS_CH,
    ttl => 4321,
    hashalgo => 1,
    flags => 1,
    iterations => 5,
    salt => '215551b763398b60',
    hnxtname => '4po5kmooep0pdess24ia7d58clj7chcm',
    typelist => 'NS SOA RRSIG DNSKEY NSEC3PARAM'
);
isa_ok($rr1, 'DNS::LDNS::RR', 'Create NSEC3 rr shorthand');

$rr1 = new DNS::LDNS::RR(
    type => LDNS_RR_TYPE_NSEC3PARAM,
    class => LDNS_RR_CLASS_CH,
    ttl => 4321,
    hashalgo => 1,
    flags => 0,
    iterations => 5,
    salt => '215551b763398b60',
);
isa_ok($rr1, 'DNS::LDNS::RR', 'Create NSEC3PARAM rr shorthand');

$rr1 = new DNS::LDNS::RR(
    type => LDNS_RR_TYPE_RRSIG,
    class => LDNS_RR_CLASS_CH,
    ttl => 4321,
    coveredtype => 'NSEC3PARAM',
    algorithm => 8,
    labels => 1,
    orgttl => 0,
    sigexpiration => 20130618001403,
    siginception => 20130603200715,
    keytag => 26113,
    signame => 'no.',
    sig => 'PliK3avqlfn/b6hvZ8//VTZq/+Wdfge1iuW83S2BnZQcG2y6in9fPaPw1loxmJGRb7z9682p961j4bXInbBgZBgx2+9428xYqfO6uk5bJi+JlpTw0ZESRnzvr+bkTnsoGeGev1uJofS7xfela/V0v8J9hBCCjT0i1jIpMGP9RpI='
);
isa_ok($rr1, 'DNS::LDNS::RR', 'Create RRSIG rr shorthand');

$rr1 = new DNS::LDNS::RR(
    type => LDNS_RR_TYPE_MX,
    class => LDNS_RR_CLASS_CH,
    ttl => 4321,
    preference => 20,
    exchange => 'foo.bar.org.'
);
isa_ok($rr1, 'DNS::LDNS::RR', 'Create MX rr shorthand');

$rr1 = new DNS::LDNS::RR(
    type => LDNS_RR_TYPE_SRV,
    class => LDNS_RR_CLASS_CH,
    ttl => 4321,
    priority => 0,
    weight => 0,
    port => 1234,
    target => 'fooservice.foo.bar.',
);
isa_ok($rr1, 'DNS::LDNS::RR', 'Create SRV rr shorthand');

$rr1 = new DNS::LDNS::RR(
    type => LDNS_RR_TYPE_NAPTR,
    class => LDNS_RR_CLASS_CH,
    ttl => 4321,
    order => 100,
    preference => 10,
    flags => 'U',
    service => "fooservice",
    regexp => "(foo|bar)-service\@example.com",
    replacement => '.',
);
isa_ok($rr1, 'DNS::LDNS::RR', 'Create NAPTR rr shorthand');

$rr1 = new DNS::LDNS::RR(
    type => LDNS_RR_TYPE_SOA,
    class => LDNS_RR_CLASS_CH,
    ttl => 1234,
    owner => 'myzone.org',
    rdata => [
	new DNS::LDNS::RData(LDNS_RDF_TYPE_DNAME, 'hostmaster.myzone.org'),
	new DNS::LDNS::RData(LDNS_RDF_TYPE_DNAME, 'master.myzone.org'),
	new DNS::LDNS::RData(LDNS_RDF_TYPE_INT32, '2012113030'),
	new DNS::LDNS::RData(LDNS_RDF_TYPE_PERIOD, '12345'),
	new DNS::LDNS::RData(LDNS_RDF_TYPE_PERIOD, '1827'),
	new DNS::LDNS::RData(LDNS_RDF_TYPE_PERIOD, '2345678'),
	new DNS::LDNS::RData(LDNS_RDF_TYPE_PERIOD, '87654')
    ],
);
isa_ok($rr1, 'DNS::LDNS::RR', 'Create SOA rr with rdata');

like($rr1->to_string, qr/^myzone\.org\.\s+1234\s+CH\s+SOA\s+hostmaster\.myzone\.org\.\s+master\.myzone\.org\.\s+2012113030\s+12345\s+1827\s+2345678\s+87654$/,
     'Format SOA rr as string');

is($rr1->pop_rdata->to_string, '87654', 'pop rdata');
$rr1->push_rdata(new DNS::LDNS::RData(LDNS_RDF_TYPE_PERIOD, '55667'));
is($rr1->rdata(6)->to_string, '55667', 'push_rdata and access rdata by index');

my $rr2 = new DNS::LDNS::RR(str => 'myzone.org. 1234 IN SOA hostmaster.myzone.org. master.myzone.org. 2012 12345 1827 2345678 87654');
isa_ok($rr2, 'DNS::LDNS::RR', 'Create SOA rr from string');
like($rr2->to_string, qr/^myzone\.org\.\s+1234\s+IN\s+SOA\s+hostmaster\.myzone\.org\.\s+master\.myzone\.org\.\s+2012\s+12345\s+1827\s+2345678\s+87654$/,
     'Format it back to string');

ok($rr1->compare($rr2) > 0, 'Compare rr, greater than');
ok($rr2->compare($rr1) < 0, 'Compare rr, less than');
is($rr1->compare($rr1), 0, 'Compare rr, equal');

my $rr3 = new DNS::LDNS::RR(str => 'ozone.org. 1234 IN SOA hostmaster.ozone.org. master.ozone.org. 2012 12345 1827 2345678 87654');

ok($rr3->compare_dname($rr1) > 0, 'Compare dname, greater than');
ok($rr1->compare_dname($rr3) < 0, 'Compare dname, less than');
is($rr1->compare_dname($rr2), 0, 'Compare dname, equal');
