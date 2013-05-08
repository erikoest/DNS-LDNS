use Test::More tests => 13;

use Net::LDNS ':all';

BEGIN { use_ok('Net::LDNS') };

my $rr1 = new Net::LDNS::RR(
    type => LDNS_RR_TYPE_SOA,
    class => LDNS_RR_CLASS_CH,
    ttl => 1234,
    owner => new Net::LDNS::RData(LDNS_RDF_TYPE_DNAME, 'myzone.org'),
    rdata => [
	new Net::LDNS::RData(LDNS_RDF_TYPE_DNAME, 'hostmaster.myzone.org'),
	new Net::LDNS::RData(LDNS_RDF_TYPE_DNAME, 'master.myzone.org'),
	new Net::LDNS::RData(LDNS_RDF_TYPE_INT32, '2012113030'),
	new Net::LDNS::RData(LDNS_RDF_TYPE_PERIOD, '12345'),
	new Net::LDNS::RData(LDNS_RDF_TYPE_PERIOD, '1827'),
	new Net::LDNS::RData(LDNS_RDF_TYPE_PERIOD, '2345678'),
	new Net::LDNS::RData(LDNS_RDF_TYPE_PERIOD, '87654')
    ],
);

isa_ok($rr1, 'Net::LDNS::RR', 'Create SOA rr');

like($rr1->to_string, qr/^myzone\.org\.\s+1234\s+CH\s+SOA\s+hostmaster\.myzone\.org\.\s+master\.myzone\.org\.\s+2012113030\s+12345\s+1827\s+2345678\s+87654$/,
     'Format SOA rr as string');

is($rr1->pop_rdata->to_string, '87654', 'pop rdata');
$rr1->push_rdata(new Net::LDNS::RData(LDNS_RDF_TYPE_PERIOD, '55667'));
is($rr1->rdata(6)->to_string, '55667', 'push_rdata and access rdata by index');

my $rr2 = new Net::LDNS::RR(str => 'myzone.org. 1234 IN SOA hostmaster.myzone.org. master.myzone.org. 2012 12345 1827 2345678 87654');
isa_ok($rr2, 'Net::LDNS::RR', 'Create SOA rr from string');
like($rr2->to_string, qr/^myzone\.org\.\s+1234\s+IN\s+SOA\s+hostmaster\.myzone\.org\.\s+master\.myzone\.org\.\s+2012\s+12345\s+1827\s+2345678\s+87654$/,
     'Format it back to string');

ok($rr1->compare($rr2) > 0, 'Compare rr, greater than');
ok($rr2->compare($rr1) < 0, 'Compare rr, less than');
is($rr1->compare($rr1), 0, 'Compare rr, equal');

my $rr3 = new Net::LDNS::RR(str => 'ozone.org. 1234 IN SOA hostmaster.ozone.org. master.ozone.org. 2012 12345 1827 2345678 87654');

ok($rr3->compare_dname($rr1) > 0, 'Compare dname, greater than');
ok($rr1->compare_dname($rr3) < 0, 'Compare dname, less than');
is($rr1->compare_dname($rr2), 0, 'Compare dname, equal');
