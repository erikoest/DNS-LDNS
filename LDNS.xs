#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include "ldns/ldns.h"
#include "ldns/error.h"
#include "ldns/rr.h"
#include "ldns/keys.h"
#include "ldns/dname.h"
#include "ldns/host2str.h"
#include "ldns/rdata.h"
#include "ldns/rbtree.h"
#include "ldns/resolver.h"
#include "ldns/packet.h"
#include "ldns/dnssec.h"

#include "ldns/dnssec_zone.h"
#include "ldns/dnssec_verify.h"
#include "ldns/dnssec_sign.h"
#include "ldns/rr_functions.h"

#include "const-c.inc"

typedef ldns_zone *          Net__LDNS__Zone;
typedef ldns_rr_list *       Net__LDNS__RRList;
typedef ldns_rr *            Net__LDNS__RR;
typedef ldns_rr *            Net__LDNS__RR__Opt;
typedef ldns_rdf *           Net__LDNS__RData;
typedef ldns_rdf *           Net__LDNS__RData__Opt;
typedef ldns_dnssec_zone *   Net__LDNS__DNSSecZone;
typedef ldns_dnssec_rrsets * Net__LDNS__DNSSecRRSets;
typedef ldns_dnssec_rrs *    Net__LDNS__DNSSecRRs;
typedef ldns_dnssec_name *   Net__LDNS__DNSSecName;
typedef ldns_rbtree_t *      Net__LDNS__RBTree;
typedef ldns_rbnode_t *      Net__LDNS__RBNode;
typedef ldns_resolver *      Net__LDNS__Resolver;
typedef ldns_pkt *           Net__LDNS__Packet;
typedef ldns_key *           Net__LDNS__Key;
typedef ldns_key_list *      Net__LDNS__KeyList;
typedef ldns_dnssec_data_chain * Net__LDNS__DNSSecDataChain;
typedef ldns_dnssec_trust_tree * Net__LDNS__DNSSecTrustTree;
typedef const char *         Mortal_PV;

typedef ldns_pkt_opcode   LDNS_Pkt_Opcode;
typedef ldns_pkt_rcode    LDNS_Pkt_Rcode;
typedef ldns_pkt_section  LDNS_Pkt_Section;
typedef ldns_pkt_type     LDNS_Pkt_Type;
typedef ldns_rr_type      LDNS_RR_Type;
typedef ldns_rr_class     LDNS_RR_Class;
typedef ldns_rdf_type     LDNS_RDF_Type;
typedef ldns_hash         LDNS_Hash;
typedef ldns_status       LDNS_Status;
typedef ldns_signing_algorithm LDNS_Signing_Algorithm;

/* callback function used by the signing methods */
int sign_policy(ldns_rr *sig, void *n) {
    return *(int*)n;
}

/* utility methods */
void add_cloned_rrs_to_list(ldns_rr_list * list, ldns_rr_list * add) {
    size_t count;
    size_t i;

    count = ldns_rr_list_rr_count(add);

    for(i = 0; i < count; i++) {
        ldns_rr_list_push_rr(list, ldns_rr_clone(ldns_rr_list_rr(add, i)));
    }
}


MODULE = Net::LDNS           PACKAGE = Net::LDNS

INCLUDE: const-xs.inc

const char *
ldns_get_errorstr_by_id(s)
	LDNS_Status s
	ALIAS:
	errorstr_by_id = 1

Mortal_PV
ldns_rr_type2str(type)
	LDNS_RR_Type type;
	ALIAS:
	rr_type2str = 1

Mortal_PV
ldns_rr_class2str(class)
	LDNS_RR_Class class;
	ALIAS:
	rr_class2str = 1

Mortal_PV
ldns_pkt_opcode2str(opcode)
	LDNS_Pkt_Opcode opcode;
	ALIAS:
	pkt_opcode2str = 1

Mortal_PV
ldns_pkt_rcode2str(rcode)
	LDNS_Pkt_Rcode rcode;
	ALIAS:
	pkt_rcode2str = 1

LDNS_RR_Type
ldns_get_rr_type_by_name(name)
	char * name;
	ALIAS:
	rr_type_by_name = 1

LDNS_RR_Class
ldns_get_rr_class_by_name(name)
	char * name;
	ALIAS:
	rr_class_by_name = 1

Net__LDNS__RR
ldns_dnssec_create_nsec(from, to, nsec_type)
	Net__LDNS__DNSSecName from;
	Net__LDNS__DNSSecName to;
	LDNS_RR_Type nsec_type;
	ALIAS:
	dnssec_create_nsec = 1

Net__LDNS__RR
dnssec_create_nsec3(from, to, zone_name, algorithm, flags, iterations, salt)
	Net__LDNS__DNSSecName from;
	Net__LDNS__DNSSecName to;
	Net__LDNS__RData zone_name;
	uint8_t algorithm;
	uint8_t flags;
	uint16_t iterations;
	char * salt;
	CODE:
	RETVAL = ldns_dnssec_create_nsec3(from, to, zone_name, algorithm, flags, iterations, strlen(salt), (uint8_t*)salt);
	OUTPUT:
	RETVAL

Net__LDNS__RR
ldns_create_nsec(current, next, rrs)
	Net__LDNS__RData current;
	Net__LDNS__RData next;
	Net__LDNS__RRList rrs;
	ALIAS:
	create_nsec = 1

Net__LDNS__RR
create_nsec3(cur_owner, cur_zone, rrs, algorithm, flags, iterations, salt, emptynonterminal)
	Net__LDNS__RData cur_owner;
	Net__LDNS__RData cur_zone;
	Net__LDNS__RRList rrs;
	uint8_t algorithm;
	uint8_t flags;
	uint16_t iterations;
	char * salt;
	bool emptynonterminal;
	CODE:
	RETVAL = ldns_create_nsec3(cur_owner, cur_zone, rrs, algorithm, 
	    flags, iterations, strlen(salt), (uint8_t*)salt, emptynonterminal);
	OUTPUT:
	RETVAL

LDNS_Signing_Algorithm
ldns_get_signing_algorithm_by_name(name)
	const char * name;
	ALIAS:
	signing_algorithm_by_name = 1

int
ldns_key_algo_supported(algorithm)
	int algorithm;
	ALIAS:
	key_algorithm_supported = 1

Net__LDNS__RR
ldns_read_anchor_file(filename)
	char * filename;
	ALIAS:
	read_anchor_file = 1

MODULE = Net::LDNS           PACKAGE = Net::LDNS::GC

void
ldns_zone_deep_free(zone)
	Net__LDNS__Zone zone;
	ALIAS:
	_zone_deep_free = 1

void
ldns_rr_list_deep_free(list)
	Net__LDNS__RRList list;
	ALIAS:
	_rrlist_deep_free = 1

void
ldns_rr_free(rr)
	Net__LDNS__RR rr;
	ALIAS:
	_rr_free = 1

void
ldns_rdf_deep_free(rdf)
	Net__LDNS__RData rdf;
	ALIAS:
	_rdata_deep_free = 1

void
ldns_dnssec_zone_deep_free(zone)
	Net__LDNS__DNSSecZone zone;
	ALIAS:
	_dnssec_zone_deep_free = 1

void
ldns_dnssec_name_deep_free(name)
	Net__LDNS__DNSSecName name;
	ALIAS:
	_dnssec_name_deep_free = 1

void
ldns_resolver_deep_free(resolver)
	Net__LDNS__Resolver resolver;
	ALIAS:
	_resolver_deep_free = 1

void
ldns_pkt_free(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	_packet_free = 1

void
ldns_key_deep_free(key)
	Net__LDNS__Key key;
	ALIAS:
	_key_deep_free = 1

void
ldns_key_list_free(keylist)
	Net__LDNS__KeyList keylist;
	ALIAS:
	_keylist_free = 1

void
ldns_dnssec_data_chain_deep_free(chain)
	Net__LDNS__DNSSecDataChain chain;
	ALIAS:
	_dnssec_datachain_deep_free = 1

void
ldns_dnssec_trust_tree_free(tree)
	Net__LDNS__DNSSecTrustTree tree;
	ALIAS:
	_dnssec_trusttree_free = 1

MODULE = Net::LDNS		PACKAGE = Net::LDNS::Zone

PROTOTYPES: ENABLE

Net__LDNS__Zone
ldns_zone_new()
	ALIAS:
	_new = 1

Net__LDNS__Zone
_new_from_file(fp, origin, ttl, c, s, line_nr)
	FILE*         fp;
	Net__LDNS__RData__Opt origin;
	uint32_t      ttl = 0;
	LDNS_RR_Class c = LDNS_RR_CLASS_IN;
	LDNS_Status   s = 0;
	int           line_nr = 0;
        PREINIT:
            ldns_zone *z;
        CODE:
	RETVAL = NULL;
	s = ldns_zone_new_frm_fp_l(&z, fp, origin, ttl, c, &line_nr);

	if (s == LDNS_STATUS_OK) {
	    RETVAL = z;
	}

        OUTPUT:
        RETVAL
	s
	line_nr

void
print(zone, fp)
	Net__LDNS__Zone zone;
	FILE* fp;
	CODE:
	ldns_zone_print(fp, zone);

void
canonicalize(zone)
	Net__LDNS__Zone zone;
	PREINIT:
	    ldns_rr_list *list;
	    size_t count;
	    size_t i;
	CODE:
	list = ldns_zone_rrs(zone);
	count = ldns_rr_list_rr_count(list);

	ldns_rr2canonical(ldns_zone_soa(zone));
	for (i = 0; i < ldns_rr_list_rr_count(ldns_zone_rrs(zone)); i++) {
	    ldns_rr2canonical(ldns_rr_list_rr(ldns_zone_rrs(zone), i));
	}

void
ldns_zone_sort(zone)
	Net__LDNS__Zone zone;
	ALIAS:
	sort = 1

Net__LDNS__RR
ldns_zone_soa(zone)
	Net__LDNS__Zone zone;
	ALIAS:
	_soa = 1

void
ldns_zone_set_soa(zone, soa)
	Net__LDNS__Zone zone;
	Net__LDNS__RR soa;
	ALIAS:
	_set_soa = 1

Net__LDNS__RRList
ldns_zone_rrs(zone)
	Net__LDNS__Zone zone;
	ALIAS:
	_rrs = 1

void
ldns_zone_set_rrs(zone, list)
	Net__LDNS__Zone zone;
	Net__LDNS__RRList list;
	ALIAS:
	_set_rrs = 1

Net__LDNS__Zone
ldns_zone_sign(zone, keylist)
	Net__LDNS__Zone zone;
	Net__LDNS__KeyList keylist;
	ALIAS:
	sign = 1

Net__LDNS__Zone
sign_nsec3(zone, keylist, algorithm, flags, iterations, salt)
	Net__LDNS__Zone zone;
	Net__LDNS__KeyList keylist;
	uint8_t algorithm;
	uint8_t flags;
	uint16_t iterations;
	unsigned char * salt;
	CODE:
	RETVAL = ldns_zone_sign_nsec3(zone, keylist, algorithm, flags, iterations, strlen(salt), (uint8_t*)salt);
	OUTPUT:
	RETVAL


MODULE = Net::LDNS		PACKAGE = Net::LDNS::RRList

PROTOTYPES: ENABLE

Net__LDNS__RRList
ldns_rr_list_new()
	ALIAS:
	_new = 1

Net__LDNS__RRList
_new_hosts_from_file(fp, line_nr)
	FILE * fp;
	int line_nr;
	CODE:
	RETVAL = ldns_get_rr_list_hosts_frm_fp_l(fp, &line_nr);
	OUTPUT:
	RETVAL

Net__LDNS__RRList
ldns_rr_list_clone(list)
	Net__LDNS__RRList list;
	ALIAS:
	clone = 1

void
print(list, fp)
	Net__LDNS__RRList list;
	FILE* fp;
	CODE:
	ldns_rr_list_print(fp, list);

Mortal_PV
ldns_rr_list2str(list)
	Net__LDNS__RRList list;
	ALIAS:
	to_string = 1

Net__LDNS__RR
ldns_rr_list_rr(list, i)
	Net__LDNS__RRList list;
	size_t i;
	ALIAS:
	_rr = 1

Net__LDNS__RR
ldns_rr_list_pop_rr(list)
	Net__LDNS__RRList list;
	ALIAS:
	pop = 1

bool
ldns_rr_list_push_rr(list, rr)
	Net__LDNS__RRList list;
	Net__LDNS__RR rr;
	ALIAS:
	_push = 1

size_t
ldns_rr_list_rr_count(list)
	Net__LDNS__RRList list;
	ALIAS:
	rr_count = 1

int
ldns_rr_list_compare(list, otherlist)
	Net__LDNS__RRList list;
	Net__LDNS__RRList otherlist;
	ALIAS:
	compare = 1

Net__LDNS__RRList
ldns_rr_list_subtype_by_rdf(list, rdf, pos)
	Net__LDNS__RRList list;
	Net__LDNS__RData rdf;
	size_t pos;
	ALIAS:
	subtype_by_rdata = 1

Net__LDNS__RRList
ldns_rr_list_pop_rrset(list)
	Net__LDNS__RRList list;
	ALIAS:
	pop_rrset = 1

bool
ldns_is_rrset(list)
	Net__LDNS__RRList list;
	ALIAS:
	is_rrset = 1

bool
ldns_rr_list_contains_rr(list, rr)
	Net__LDNS__RRList list;
	Net__LDNS__RR rr;
	ALIAS:
	contains_rr = 1

Net__LDNS__RRList
ldns_rr_list_pop_rr_list(list, count)
	Net__LDNS__RRList list;
	size_t count;
	ALIAS:
	pop_list = 1

bool
_push_list(list, otherlist)
	Net__LDNS__RRList list;
	Net__LDNS__RRList otherlist;
	PREINIT:
	    bool ret;
	CODE:
	ret = ldns_rr_list_push_rr_list(list, otherlist);
	if (ret) {
	    ldns_rr_list_free(otherlist);
	}
	OUTPUT:
	RETVAL

LDNS_Status
_verify_rrsig_keylist(rrset, rrsig, keys, good_keys)
	Net__LDNS__RRList rrset;
	Net__LDNS__RR rrsig;
	Net__LDNS__RRList keys;
	Net__LDNS__RRList good_keys;
	PREINIT:
	    Net__LDNS__RRList gk;
	CODE:
	gk = ldns_rr_list_new();
	RETVAL = ldns_verify_rrsig_keylist(rrset, rrsig, keys, good_keys);
	add_cloned_rrs_to_list(good_keys, gk);
	ldns_rr_list_free(gk);
	OUTPUT:
	RETVAL

LDNS_Status
_verify_rrsig_keylist_notime(rrset, rrsig, keys, good_keys)
	Net__LDNS__RRList rrset;
	Net__LDNS__RR rrsig;
	Net__LDNS__RRList keys;
	Net__LDNS__RRList good_keys;
	PREINIT:
	    Net__LDNS__RRList gk;
	CODE:
	gk = ldns_rr_list_new();
	RETVAL = ldns_verify_rrsig_keylist_notime(rrset, rrsig, keys, NULL);
	add_cloned_rrs_to_list(good_keys, gk);
	ldns_rr_list_free(gk);
	OUTPUT:
	RETVAL

LDNS_Status
ldns_verify_rrsig(rrset, rrsig, key)
	Net__LDNS__RRList rrset;
	Net__LDNS__RR rrsig;
	Net__LDNS__RR key;
	ALIAS:
	_verify_rrsig = 1

LDNS_Status
_verify(rrset, rrsig, keys, good_keys)
	Net__LDNS__RRList rrset;
	Net__LDNS__RRList rrsig;
	Net__LDNS__RRList keys;
	Net__LDNS__RRList good_keys;
	PREINIT:
	    Net__LDNS__RRList gk;
	CODE:
	gk = ldns_rr_list_new();
	RETVAL = ldns_verify(rrset, rrsig, keys, gk);
	add_cloned_rrs_to_list(good_keys, gk);
	ldns_rr_list_free(gk);
	OUTPUT:
	RETVAL

LDNS_Status
_verify_notime(rrset, rrsig, keys, good_keys)
	Net__LDNS__RRList rrset;
	Net__LDNS__RRList rrsig;
	Net__LDNS__RRList keys;
	Net__LDNS__RRList good_keys;
	PREINIT:
	    Net__LDNS__RRList gk;
	CODE:
	gk = ldns_rr_list_new();
	RETVAL = ldns_verify_notime(rrset, rrsig, keys, gk);
	add_cloned_rrs_to_list(good_keys, gk);
	ldns_rr_list_free(gk);
	OUTPUT:
	RETVAL

Net__LDNS__RR
ldns_create_empty_rrsig(rrset, current_key)
	Net__LDNS__RRList rrset;
	Net__LDNS__Key current_key;
	ALIAS:
	create_empty_rrsig = 1

Net__LDNS__RRList
ldns_sign_public(rrset, keys)
	Net__LDNS__RRList rrset;
	Net__LDNS__KeyList keys;
	ALIAS:
	sign_public = 1

void
ldns_rr_list_sort(list)
	Net__LDNS__RRList list;
	ALIAS:
	sort = 1

void
ldns_rr_list_sort_nsec3(list)
	Net__LDNS__RRList list;
	ALIAS:
	sort_nsec3 = 1

void
ldns_rr_list2canonical(list)
	Net__LDNS__RRList list;
	ALIAS:
	canonicalize = 1

Net__LDNS__RR
ldns_dnssec_get_dnskey_for_rrsig(rr, rrlist)
	Net__LDNS__RR rr;
	Net__LDNS__RRList rrlist;
	ALIAS:
	_get_dnskey_for_rrsig = 1

Net__LDNS__RR
ldns_dnssec_get_rrsig_for_name_and_type(name, type, rrsigs)
	Net__LDNS__RData name;
	LDNS_RR_Type type;
	Net__LDNS__RRList rrsigs;
	ALIAS:
	_get_rrsig_for_name_and_type = 1


MODULE = Net::LDNS		PACKAGE = Net::LDNS::RR

PROTOTYPES: ENABLE

Net__LDNS__RR
ldns_rr_new()
	ALIAS:
	_new = 1

Net__LDNS__RR
ldns_rr_new_frm_type(t)
	LDNS_RR_Type t;
	ALIAS:
	_new_from_type = 1

Net__LDNS__RR
_new_from_str(str, default_ttl, origin, s)
	const char* str;
	uint32_t default_ttl = 0;
	Net__LDNS__RData__Opt origin;
	LDNS_Status s;
	PREINIT:
	    Net__LDNS__RR rr = NULL;
	CODE:
	s = ldns_rr_new_frm_str(&rr, str, default_ttl, origin, NULL);
	if (s == LDNS_STATUS_OK) {
	    RETVAL = rr;
	}
	OUTPUT:
	RETVAL
	s

Net__LDNS__RR
_new_from_file(fp, origin, default_ttl, s, line_nr)
	FILE*         fp;
	Net__LDNS__RData__Opt origin;
	uint32_t      default_ttl = 0;
	LDNS_Status   s = LDNS_STATUS_OK;
	int           line_nr = 0;
        PREINIT:
            ldns_rr *rr;
	    ldns_rdf *oclone = NULL;
        CODE:
	RETVAL = NULL;
	/* Clone the origin object because the call may change/replace it and 
	   then it must be freed */
	if (origin) {
	    oclone = ldns_rdf_clone(origin);
        }
	s = ldns_rr_new_frm_fp_l(&rr, fp, &default_ttl, &oclone, NULL, 
	    &line_nr);

	if (oclone) {
	    ldns_rdf_deep_free(oclone);
        }

	if (s == LDNS_STATUS_OK) {
	    RETVAL = rr;
	}

        OUTPUT:
        RETVAL
	s
	line_nr

Net__LDNS__RR
ldns_rr_clone(rr)
	Net__LDNS__RR rr;
	ALIAS:
	clone = 1

void
ldns_rr_set_owner(rr, owner)
	Net__LDNS__RR rr;
	Net__LDNS__RData owner;
	ALIAS:
	_set_owner = 1

void
ldns_rr_set_ttl(rr, ttl)
	Net__LDNS__RR rr;
	uint32_t ttl;
	ALIAS:
	set_ttl = 1

void
ldns_rr_set_type(rr, type)
	Net__LDNS__RR rr;
	LDNS_RR_Type type;
	ALIAS:
	set_type = 1

void
ldns_rr_set_class(rr, class)
	Net__LDNS__RR rr;
	LDNS_RR_Class class;
	ALIAS:
	set_class = 1

void
print(rr, fp)
	Net__LDNS__RR rr;
	FILE* fp;
	CODE:
	ldns_rr_print(fp, rr);

Mortal_PV
ldns_rr2str(rr)
	Net__LDNS__RR rr;
	ALIAS:
	to_string = 1

int
ldns_rr_compare(rr, otherrr)
	Net__LDNS__RR rr;
	Net__LDNS__RR otherrr;
	ALIAS:
	compare = 1

int
ldns_rr_compare_no_rdata(rr, otherrr)
	Net__LDNS__RR rr;
	Net__LDNS__RR otherrr;
	ALIAS:
	compare_no_rdata = 1

int
ldns_rr_compare_ds(rr, otherrr)
	Net__LDNS__RR rr;
	Net__LDNS__RR otherrr;
	ALIAS:
	compare_ds = 1

int
compare_dname(rr, otherrr)
	Net__LDNS__RR rr;
	Net__LDNS__RR otherrr;
	CODE:
	RETVAL = ldns_dname_compare(
	    ldns_rr_owner(rr), ldns_rr_owner(otherrr));
	OUTPUT:
	RETVAL

Net__LDNS__RData
ldns_rr_owner(rr)
	Net__LDNS__RR rr;
	ALIAS:
	_owner = 1

size_t
ldns_rr_rd_count(rr);
	Net__LDNS__RR rr;
	ALIAS:
	rd_count = 1

Net__LDNS__RData
ldns_rr_rdf(rr, i)
	Net__LDNS__RR rr;
	size_t i;
	ALIAS:
	_rdata = 1

Net__LDNS__RData
ldns_rr_set_rdf(rr, rdf, i)
	Net__LDNS__RR rr;
	Net__LDNS__RData rdf;
	size_t i;
	ALIAS:
	_set_rdata = 1

uint32_t
ldns_rr_ttl(rr)
	Net__LDNS__RR rr;
	ALIAS:
	ttl = 1

LDNS_RR_Class
ldns_rr_get_class(rr)
	Net__LDNS__RR rr;
	ALIAS:
	class = 1

LDNS_RR_Type
ldns_rr_get_type(rr)
	Net__LDNS__RR rr;
	ALIAS:
	type = 1

Net__LDNS__RData
ldns_rr_pop_rdf(rr)
	Net__LDNS__RR rr;
	ALIAS:
	pop_rdata = 1

bool
ldns_rr_push_rdf(rr, rdf)
	Net__LDNS__RR rr;
	Net__LDNS__RData rdf;
	ALIAS:
	_push_rdata = 1

Net__LDNS__RData
ldns_rr_rrsig_typecovered(rr)
	Net__LDNS__RR rr;
	ALIAS:
	_rrsig_typecovered = 1

bool
ldns_rr_rrsig_set_typecovered(rr, rdf)
	Net__LDNS__RR rr;
	Net__LDNS__RData rdf;
	ALIAS:
	_rrsig_set_typecovered = 1	 

Net__LDNS__RData
ldns_rr_rrsig_algorithm(rr)
	Net__LDNS__RR rr;
	ALIAS:
	_rrsig_algorithm = 1

bool
ldns_rr_rrsig_set_algorithm(rr, rdf)
	Net__LDNS__RR rr;
	Net__LDNS__RData rdf;
	ALIAS:
	_rrsig_set_algorithm = 1

Net__LDNS__RData
ldns_rr_rrsig_expiration(rr)
	Net__LDNS__RR rr;
	ALIAS:
	_rrsig_expiration = 1

bool
ldns_rr_rrsig_set_expiration(rr, rdf)
	Net__LDNS__RR rr;
	Net__LDNS__RData rdf;
	ALIAS:
	_rrsig_set_expiration = 1

Net__LDNS__RData
ldns_rr_rrsig_inception(rr)
	Net__LDNS__RR rr;
	ALIAS:
	_rrsig_inception = 1

bool
ldns_rr_rrsig_set_inception(rr, rdf)
	Net__LDNS__RR rr;
	Net__LDNS__RData rdf;
	ALIAS:
	_rrsig_set_inception = 1

Net__LDNS__RData
ldns_rr_rrsig_keytag(rr)
	Net__LDNS__RR rr;
	ALIAS:
	_rrsig_keytag = 1

bool
ldns_rr_rrsig_set_keytag(rr, rdf)
	Net__LDNS__RR rr;
	Net__LDNS__RData rdf;
	ALIAS:
	_rrsig_set_keytag = 1

Net__LDNS__RData
ldns_rr_rrsig_sig(rr)
	Net__LDNS__RR rr;
	ALIAS:
	_rrsig_sig = 1

bool
ldns_rr_rrsig_set_sig(rr, rdf)
	Net__LDNS__RR rr;
	Net__LDNS__RData rdf;
	ALIAS:
	_rrsig_set_sig = 1

Net__LDNS__RData
ldns_rr_rrsig_labels(rr)
	Net__LDNS__RR rr;
	ALIAS:
	_rrsig_labels = 1

bool
ldns_rr_rrsig_set_labels(rr, rdf)
	Net__LDNS__RR rr;
	Net__LDNS__RData rdf;
	ALIAS:
	_rrsig_set_labels = 1

Net__LDNS__RData
ldns_rr_rrsig_origttl(rr)
	Net__LDNS__RR rr;
	ALIAS:
	_rrsig_origttl = 1

bool
ldns_rr_rrsig_set_origttl(rr, rdf)
	Net__LDNS__RR rr;
	Net__LDNS__RData rdf;
	ALIAS:
	_rrsig_set_origttl = 1

Net__LDNS__RData
ldns_rr_rrsig_signame(rr)
	Net__LDNS__RR rr;
	ALIAS:
	_rrsig_signame = 1

bool
ldns_rr_rrsig_set_signame(rr, rdf)
	Net__LDNS__RR rr;
	Net__LDNS__RData rdf;
	ALIAS:
	_rrsig_set_signame = 1

Net__LDNS__RData
ldns_rr_dnskey_algorithm(rr)
	Net__LDNS__RR rr;
	ALIAS:
	_dnskey_algorithm = 1

bool
ldns_rr_dnskey_set_algorithm(rr, rdf)
	Net__LDNS__RR rr;
	Net__LDNS__RData rdf;
	ALIAS:
	_dnskey_set_algorithm = 1

Net__LDNS__RData
ldns_rr_dnskey_flags(rr)
	Net__LDNS__RR rr;
	ALIAS:
	_dnskey_flags = 1

bool
ldns_rr_dnskey_set_flags(rr, rdf)
	Net__LDNS__RR rr;
	Net__LDNS__RData rdf;
	ALIAS:
	_dnskey_set_flags = 1

Net__LDNS__RData
ldns_rr_dnskey_protocol(rr)
	Net__LDNS__RR rr;
	ALIAS:
	_dnskey_protocol = 1

bool
ldns_rr_dnskey_set_protocol(rr, rdf)
	Net__LDNS__RR rr;
	Net__LDNS__RData rdf;
	ALIAS:
	_dnskey_set_protocol = 1

Net__LDNS__RData
ldns_rr_dnskey_key(rr)
	Net__LDNS__RR rr;
	ALIAS:
	_dnskey_key = 1

bool
ldns_rr_dnskey_set_key(rr, rdf)
	Net__LDNS__RR rr;
	Net__LDNS__RData rdf;
	ALIAS:
	_dnskey_set_key = 1

size_t
ldns_rr_dnskey_key_size(rr)
	Net__LDNS__RR rr;
	ALIAS:
	dnskey_key_size = 1

uint16_t
ldns_calc_keytag(key)
	Net__LDNS__RR key;
	ALIAS:
	calc_keytag = 1

Net__LDNS__RData
ldns_nsec3_hash_name_frm_nsec3(rr, name)
	Net__LDNS__RR rr;
	Net__LDNS__RData name;
	ALIAS:
	_hash_name_from_nsec3 = 1

Net__LDNS__RData
_nsec3_hash_name(name, algorithm, iterations, salt)
	Net__LDNS__RData name;
	uint8_t algorithm;
	uint16_t iterations;
	char * salt;
	CODE:
	RETVAL = ldns_nsec3_hash_name(name, algorithm, iterations, 
	    strlen(salt), (uint8_t *)salt);
	OUTPUT:
	RETVAL

LDNS_Status
ldns_dnssec_verify_denial(rr, nsecs, rrsigs)
	Net__LDNS__RR rr;
	Net__LDNS__RRList nsecs;
	Net__LDNS__RRList rrsigs;
	ALIAS:
	_verify_denial = 1

LDNS_Status
ldns_dnssec_verify_denial_nsec3(rr, nsecs, rrsigs, packet_rcode, packet_qtype, packet_nodata)
	Net__LDNS__RR rr;
	Net__LDNS__RRList nsecs;
	Net__LDNS__RRList rrsigs;
	LDNS_Pkt_Rcode packet_rcode;
	LDNS_RR_Type packet_qtype;
	signed char packet_nodata;
	ALIAS:
	_verify_denial_nsec3 = 1

Net__LDNS__RR
_verify_denial_nsec3_match(rr, nsecs, rrsigs, packet_rcode, packet_qtype, packet_nodata, status)
	Net__LDNS__RR rr;
	Net__LDNS__RRList nsecs;
	Net__LDNS__RRList rrsigs;
	LDNS_Pkt_Rcode packet_rcode;
	LDNS_RR_Type packet_qtype;
	signed char packet_nodata;
	LDNS_Status status;
	PREINIT:
	    ldns_rr ** match;
	CODE:
	RETVAL = NULL;
	status = ldns_dnssec_verify_denial_nsec3_match(rr, nsecs, rrsigs, 
	    packet_rcode, packet_qtype, packet_nodata, match);
	if (status == LDNS_STATUS_OK) {
	    RETVAL = *match;
	}
	OUTPUT:
	status
	RETVAL

void
nsec3_add_param_rdfs(rr, algorithm, flags, iterations, salt)
	Net__LDNS__RR rr;
	uint8_t algorithm;
	uint8_t flags;
	uint16_t iterations;
	char * salt;
	CODE:
	ldns_nsec3_add_param_rdfs(rr, algorithm, flags, iterations, strlen(salt), (uint8_t*)salt);

uint8_t
ldns_nsec3_algorithm(nsec3)
	Net__LDNS__RR nsec3;
	ALIAS:
	nsec3_algorithm = 1

uint8_t
ldns_nsec3_flags(nsec3)
	Net__LDNS__RR nsec3;
	ALIAS:
	nsec3_flags = 1

bool
ldns_nsec3_optout(nsec3)
	Net__LDNS__RR nsec3;
	ALIAS:
	nsec3_optout = 1

uint16_t
ldns_nsec3_iterations(nsec3)
	Net__LDNS__RR nsec3;
	ALIAS:
	nsec3_iterations = 1

Net__LDNS__RData
ldns_nsec3_next_owner(nsec3)
	Net__LDNS__RR nsec3;
	ALIAS:
	_nsec3_next_owner = 1

Net__LDNS__RData
ldns_nsec3_bitmap(nsec3)
	Net__LDNS__RR nsec3;
	ALIAS:
	_nsec3_bitmap = 1

Net__LDNS__RData
ldns_nsec3_salt(nsec3)
	Net__LDNS__RR nsec3;
	ALIAS:
	_nsec3_salt = 1

Net__LDNS__RR
ldns_key_rr2ds(key, hash)
        Net__LDNS__RR key;
	LDNS_Hash hash;
	ALIAS:
	key_to_ds = 1

bool
ldns_rr_is_question(rr)
        Net__LDNS__RR rr;
	ALIAS:
	is_question = 1

uint8_t
ldns_rr_label_count(rr)
        Net__LDNS__RR rr;
	ALIAS:
	label_count = 1

MODULE = Net::LDNS		PACKAGE = Net::LDNS::RData

PROTOTYPES: ENABLE

Net__LDNS__RData
ldns_rdf_new_frm_str(type, str)
	LDNS_RDF_Type type;
	const char *str;
	ALIAS:
	_new = 1

Net__LDNS__RData
ldns_rdf_clone(rdf)
	Net__LDNS__RData rdf;
	ALIAS:
	clone = 1

const char*
ldns_rdf2str(rdf)
	Net__LDNS__RData rdf;
	ALIAS:
	to_string = 1

void
print(rdf, fp)
	Net__LDNS__RData rdf;
	FILE* fp;
	CODE:
	ldns_rdf_print(fp, rdf);

LDNS_RDF_Type
ldns_rdf_get_type(rdf)
	Net__LDNS__RData rdf;
	ALIAS:
	type = 1

void
ldns_rdf_set_type(rdf, type)
	Net__LDNS__RData rdf;
	LDNS_RDF_Type type
	ALIAS:
	set_type = 1

int
ldns_rdf_compare(rd1, rd2)
	Net__LDNS__RData rd1;
	Net__LDNS__RData rd2;
	ALIAS:
	compare = 1

Net__LDNS__RData
ldns_rdf_address_reverse(rdf)
	Net__LDNS__RData rdf;
	ALIAS:
	address_reverse = 1

uint8_t
ldns_dname_label_count(rdf)
	Net__LDNS__RData rdf;
	ALIAS:
	label_count = 1

Net__LDNS__RData
ldns_dname_label(rdf, labelpos)
	Net__LDNS__RData rdf;
	uint8_t labelpos;
	ALIAS:
	label = 1

int
ldns_dname_is_wildcard(rdf)
	Net__LDNS__RData rdf;
	ALIAS:
	is_wildcard = 1

int
ldns_dname_match_wildcard(rdf, wildcard)
	Net__LDNS__RData rdf;
	Net__LDNS__RData wildcard;
	ALIAS:
	matches_wildcard = 1

signed char
ldns_dname_is_subdomain(rdf, parent)
	Net__LDNS__RData rdf;
	Net__LDNS__RData parent;
	ALIAS:
	is_subdomain = 1

Net__LDNS__RData
ldns_dname_left_chop(rdf)
	Net__LDNS__RData rdf
	ALIAS:
	left_chop = 1

LDNS_Status
ldns_dname_cat(rdata, otherrd)
	Net__LDNS__RData rdata;
	Net__LDNS__RData otherrd;
	ALIAS:
	_cat = 1

int
ldns_dname_compare(dname, otherdname)
	Net__LDNS__RData dname;
	Net__LDNS__RData otherdname;
	ALIAS:
	compare = 1

LDNS_RR_Type
ldns_rdf2rr_type(rdf)
	Net__LDNS__RData rdf;
	ALIAS:
	to_rr_type = 1

Net__LDNS__RData
ldns_dname_reverse(rdf)
	Net__LDNS__RData rdf;
	ALIAS:
	dname_reverse = 1

void
ldns_dname2canonical(rdf)
	Net__LDNS__RData rdf;
	ALIAS:
	dname2canonical = 1

time_t
ldns_rdf2native_time_t(rdf)
	Net__LDNS__RData rdf;
	ALIAS:
	to_unix_time = 1
	2native_time_t = 2


MODULE = Net::LDNS		PACKAGE = Net::LDNS::DNSSecZone

PROTOTYPES: ENABLE

Net__LDNS__DNSSecZone
ldns_dnssec_zone_new()
	ALIAS:
	_new = 1

Net__LDNS__DNSSecZone
_new_from_file(fp, origin, ttl, c, s, line_nr)
	FILE*         fp;
	Net__LDNS__RData__Opt origin;
	uint32_t      ttl = 0;
	LDNS_RR_Class c = LDNS_RR_CLASS_IN;
	LDNS_Status   s = 0;
	int           line_nr = 0;
        PREINIT:
            ldns_dnssec_zone *z;
        CODE:
	RETVAL = NULL;
/* This method is not available before 1.6.16. In the meantime, use the
   create_from_zone method. */
/*	s = ldns_dnssec_zone_new_frm_fp_l(&z, fp, origin, ttl, c, &line_nr); */

	if (s == LDNS_STATUS_OK) {
	    RETVAL = z;
	}

        OUTPUT:
        RETVAL
	s
	line_nr

LDNS_Status
create_from_zone(dnssec_zone, zone)
	Net__LDNS__DNSSecZone dnssec_zone;
	Net__LDNS__Zone zone;
	PREINIT:
	    size_t i;
            ldns_rr *cur_rr;
            ldns_status status;
	    ldns_rr_list *failed_nsec3s;
	    ldns_rr_list *failed_nsec3_rrsigs;
            ldns_status result = LDNS_STATUS_OK;
	CODE:
	failed_nsec3s = ldns_rr_list_new();
        failed_nsec3_rrsigs = ldns_rr_list_new();

        status = ldns_dnssec_zone_add_rr(dnssec_zone, 
	             ldns_rr_clone(ldns_zone_soa(zone)));
	if (result == LDNS_STATUS_OK) {
	    result = status;
        }

        for (i = 0; i < ldns_rr_list_rr_count(ldns_zone_rrs(zone)); i++) {
            cur_rr = ldns_rr_list_rr(ldns_zone_rrs(zone), i);
            status = ldns_dnssec_zone_add_rr(dnssec_zone, 
                         ldns_rr_clone(cur_rr));
            if (status != LDNS_STATUS_OK) {
                if (LDNS_STATUS_DNSSEC_NSEC3_ORIGINAL_NOT_FOUND == status) {
                    if (ldns_rr_get_type(cur_rr) == LDNS_RR_TYPE_RRSIG
                        && ldns_rdf2rr_type(ldns_rr_rrsig_typecovered(cur_rr))
                        == LDNS_RR_TYPE_NSEC3) {
                        ldns_rr_list_push_rr(failed_nsec3_rrsigs, cur_rr);
                    } else {
                        ldns_rr_list_push_rr(failed_nsec3s, cur_rr);
                    }
                }
		if (result == LDNS_STATUS_OK) {
		    result = status;
                }
            }
        }

        if (ldns_rr_list_rr_count(failed_nsec3s) > 0) {
            (void) ldns_dnssec_zone_add_empty_nonterminals(dnssec_zone);
            for (i = 0; i < ldns_rr_list_rr_count(failed_nsec3s); i++) {
                cur_rr = ldns_rr_list_rr(failed_nsec3s, i);
                status = ldns_dnssec_zone_add_rr(dnssec_zone, 
                             ldns_rr_clone(cur_rr));
		if (result == LDNS_STATUS_OK) {
		    result = status;
                }
            }
            for (i = 0; i < ldns_rr_list_rr_count(failed_nsec3_rrsigs); i++) {
                cur_rr = ldns_rr_list_rr(failed_nsec3_rrsigs, i);
                status = ldns_dnssec_zone_add_rr(dnssec_zone, 
                             ldns_rr_clone(cur_rr));
		if (result == LDNS_STATUS_OK) {
		    result = status;
                }
            }
        }

        ldns_rr_list_free(failed_nsec3_rrsigs);
        ldns_rr_list_free(failed_nsec3s);
        RETVAL = result;
	OUTPUT:
	RETVAL

void
print(zone, fp)
	Net__LDNS__DNSSecZone zone;
	FILE* fp;
	CODE:
	ldns_dnssec_zone_print(fp, zone);

LDNS_Status
ldns_dnssec_zone_add_rr(zone, rr)
	Net__LDNS__DNSSecZone zone;
	Net__LDNS__RR	 rr;
	ALIAS:
	_add_rr = 1

LDNS_Status
ldns_dnssec_zone_add_empty_nonterminals(zone)
	Net__LDNS__DNSSecZone zone;
	ALIAS:
	_add_empty_nonterminals = 1

LDNS_Status
ldns_dnssec_zone_mark_glue(zone)
	Net__LDNS__DNSSecZone zone;
	ALIAS:
	_mark_glue = 1

Net__LDNS__DNSSecName
_soa(zone)
	Net__LDNS__DNSSecZone zone;
	CODE:
	RETVAL = zone->soa;
	OUTPUT:
	RETVAL

Net__LDNS__RBTree
_names(zone)
	Net__LDNS__DNSSecZone zone;
	CODE:
	RETVAL = zone->names;
	OUTPUT:
	RETVAL

Net__LDNS__DNSSecRRSets
ldns_dnssec_zone_find_rrset(zone, rdf, type)
	Net__LDNS__DNSSecZone zone;
	Net__LDNS__RData rdf;
	LDNS_RR_Type type;
	ALIAS:
	_find_rrset = 1

LDNS_Status
_sign(zone, key_list, policy, flags)
	Net__LDNS__DNSSecZone zone;
	Net__LDNS__KeyList key_list;
	uint16_t policy;
	int flags;
	PREINIT:
	    ldns_rr_list * new_rrs;
	CODE:
	new_rrs = ldns_rr_list_new();
	RETVAL = ldns_dnssec_zone_sign_flg(zone, new_rrs, key_list, 
	    sign_policy, (void*)&policy, flags);
	ldns_rr_list_free(new_rrs);
	OUTPUT:
	RETVAL

LDNS_Status
_sign_nsec3(zone, key_list, policy, algorithm, flags, iterations, salt, signflags)
	Net__LDNS__DNSSecZone zone;
	Net__LDNS__KeyList key_list;
	uint16_t policy;
	uint8_t algorithm;
	uint8_t flags;
	uint16_t iterations;
	char * salt;
	int signflags;
	PREINIT:
	     ldns_rr_list * new_rrs;
	CODE:
	new_rrs = ldns_rr_list_new();
	RETVAL = ldns_dnssec_zone_sign_nsec3_flg(zone, new_rrs, key_list, 
	    sign_policy, (void*)&policy, algorithm, flags, iterations, 
	    strlen(salt), (uint8_t*)salt, signflags);
	ldns_rr_list_free(new_rrs);
	OUTPUT:
	RETVAL

LDNS_Status
create_nsecs(zone)
	Net__LDNS__DNSSecZone zone;
	PREINIT:
	    ldns_rr_list * new_rrs;
	CODE:
	new_rrs = ldns_rr_list_new();
	RETVAL = ldns_dnssec_zone_create_nsecs(zone, new_rrs);
	ldns_rr_list_free(new_rrs);
	OUTPUT:
	RETVAL

LDNS_Status
create_nsec3s(zone, algorithm, flags, iterations, salt)
	Net__LDNS__DNSSecZone zone;
	uint8_t algorithm;
	uint8_t flags;
	uint8_t iterations;
	char * salt;
	PREINIT:
	    ldns_rr_list * new_rrs;
	CODE:
	new_rrs = ldns_rr_list_new();
	RETVAL = ldns_dnssec_zone_create_nsec3s(zone, new_rrs, algorithm,
	    flags, iterations, strlen(salt), (uint8_t*)salt);
	ldns_rr_list_free(new_rrs);
	OUTPUT:
	RETVAL

LDNS_Status
create_rrsigs(zone, key_list, policy, flags)
	Net__LDNS__DNSSecZone zone;
	Net__LDNS__KeyList key_list;
	uint16_t policy;
	int flags;
	PREINIT:
	     ldns_rr_list * new_rrs;
	CODE:
	new_rrs = ldns_rr_list_new();
	RETVAL = ldns_dnssec_zone_create_rrsigs_flg(zone, new_rrs, key_list, 
	    sign_policy, (void*)&policy, flags);
	ldns_rr_list_free(new_rrs);
	OUTPUT:
	RETVAL


MODULE = Net::LDNS		PACKAGE = Net::LDNS::DNSSecRRSets

Net__LDNS__DNSSecRRs
_rrs(rrsets)
	Net__LDNS__DNSSecRRSets rrsets;
	CODE:
	RETVAL = rrsets->rrs;
	OUTPUT:
	RETVAL

Net__LDNS__DNSSecRRs
_signatures(rrsets)
	Net__LDNS__DNSSecRRSets rrsets;
	CODE:
	RETVAL = rrsets->signatures;
	OUTPUT:
	RETVAL

bool
ldns_dnssec_rrsets_contains_type(rrsets, type)
	Net__LDNS__DNSSecRRSets rrsets;
	LDNS_RR_Type type;
	ALIAS:
	contains_type = 1

LDNS_RR_Type
ldns_dnssec_rrsets_type(rrsets)
	Net__LDNS__DNSSecRRSets rrsets;
	ALIAS:
	type = 1

LDNS_Status
ldns_dnssec_rrsets_set_type(rrsets, type)
	Net__LDNS__DNSSecRRSets rrsets;
	LDNS_RR_Type type;
	ALIAS:
	_set_type = 1

Net__LDNS__DNSSecRRSets
_next(rrsets)
	Net__LDNS__DNSSecRRSets rrsets;
	CODE:
	RETVAL = rrsets->next;
	OUTPUT:
	RETVAL

LDNS_Status
ldns_dnssec_rrsets_add_rr(rrsets, rr)
	Net__LDNS__DNSSecRRSets rrsets;
	Net__LDNS__RR rr;
	ALIAS:
	_add_rr = 1


MODULE = Net::LDNS		PACKAGE = Net::LDNS::DNSSecRRs

Net__LDNS__DNSSecRRs
ldns_dnssec_rrs_new()
	ALIAS:
	_new = 1

Net__LDNS__RR
_rr(rrs)
	Net__LDNS__DNSSecRRs rrs;
	CODE:
	RETVAL = rrs->rr;
	OUTPUT:
	RETVAL

Net__LDNS__DNSSecRRs
_next(rrs)
	Net__LDNS__DNSSecRRs rrs;
	CODE:
	RETVAL = rrs->next;
	OUTPUT:
	RETVAL

LDNS_Status
ldns_dnssec_rrs_add_rr(rrs, rr)
	Net__LDNS__DNSSecRRs rrs;
	Net__LDNS__RR rr;
	ALIAS:
	_add_rr = 1


MODULE = Net::LDNS		PACKAGE = Net::LDNS::DNSSecName

Net__LDNS__DNSSecName
ldns_dnssec_name_new()
	ALIAS:
	_new = 1

Net__LDNS__RData
ldns_dnssec_name_name(name)
	Net__LDNS__DNSSecName name;
	ALIAS:
	_name = 1

bool
ldns_dnssec_name_is_glue(name)
	Net__LDNS__DNSSecName name;
	ALIAS:
	is_glue = 1

Net__LDNS__DNSSecRRSets
_rrsets(name)
	Net__LDNS__DNSSecName name;
	CODE:
	RETVAL = name->rrsets;
	OUTPUT:
	RETVAL

Net__LDNS__RR
_nsec(name)
	Net__LDNS__DNSSecName name;
	CODE:
	RETVAL = name->nsec;
	OUTPUT:
	RETVAL

Net__LDNS__RData
_hashed_name(name)
	Net__LDNS__DNSSecName name;
	CODE:
	RETVAL = name->hashed_name;
	OUTPUT:
	RETVAL

Net__LDNS__DNSSecRRs
_nsec_signatures(name)
	Net__LDNS__DNSSecName name;
	CODE:
	RETVAL = name->nsec_signatures;
	OUTPUT:
	RETVAL

void
ldns_dnssec_name_set_name(name, dname)
	Net__LDNS__DNSSecName name;
	Net__LDNS__RData dname;
	ALIAS:
	_set_name = 1

void
ldns_dnssec_name_set_nsec(name, nsec)
	Net__LDNS__DNSSecName name;
	Net__LDNS__RR nsec;
	ALIAS:
	_set_nsec = 1

int
ldns_dnssec_name_cmp(a, b)
	Net__LDNS__DNSSecName a;
	Net__LDNS__DNSSecName b;
	ALIAS:
	compare = 1

LDNS_Status
ldns_dnssec_name_add_rr(name, rr)
	Net__LDNS__DNSSecName name;
	Net__LDNS__RR rr;
	ALIAS:
	_add_rr = 1


MODULE = Net::LDNS		PACKAGE = Net::LDNS::RBTree

Net__LDNS__RBNode
ldns_rbtree_first(tree)
	Net__LDNS__RBTree tree;
	ALIAS:
	_first = 1

Net__LDNS__RBNode
ldns_rbtree_last(tree)
	Net__LDNS__RBTree tree;
	ALIAS:
	_last = 1


MODULE = Net::LDNS		PACKAGE = Net::LDNS::RBNode

Net__LDNS__RBNode
ldns_rbtree_next(node)
	Net__LDNS__RBNode node;
	ALIAS:
	_next = 1

Net__LDNS__RBNode
ldns_rbtree_previous(node)
	Net__LDNS__RBNode node;
	ALIAS:
	_previous = 1

Net__LDNS__RBNode
ldns_dnssec_name_node_next_nonglue(node)
	Net__LDNS__RBNode node;
	ALIAS:
	_next_nonglue = 1

bool
is_null(node)
	Net__LDNS__RBNode node;
	CODE:
	RETVAL = (node == LDNS_RBTREE_NULL);
	OUTPUT:
	RETVAL

Net__LDNS__DNSSecName
_name(node)
	Net__LDNS__RBNode node;
	CODE:
	RETVAL = (ldns_dnssec_name*)node->data;
	OUTPUT:
	RETVAL


MODULE = Net::LDNS		PACKAGE = Net::LDNS::Resolver

Net__LDNS__Resolver
_new_from_file(fp, s)
	FILE* fp;
	LDNS_Status s;
        PREINIT:
            ldns_resolver *r;
	CODE:
	RETVAL = NULL;
	s = ldns_resolver_new_frm_fp(&r, fp);
	if (s == LDNS_STATUS_OK) {
	    RETVAL = r;
	}
	OUTPUT:
	RETVAL
	s

Net__LDNS__Resolver
ldns_resolver_new()
	ALIAS:
	_new = 1

bool
ldns_resolver_dnssec(resolver)
	Net__LDNS__Resolver resolver;
	ALIAS:
	dnssec = 1

void
ldns_resolver_set_dnssec(resolver, d)
	Net__LDNS__Resolver resolver;
	bool d;
	ALIAS:
	set_dnssec = 1

bool
ldns_resolver_dnssec_cd(resolver)
	Net__LDNS__Resolver resolver;
	ALIAS:
	dnssec_cd = 1

void
ldns_resolver_set_dnssec_cd(resolver, d)
	Net__LDNS__Resolver resolver;
	bool d;
	ALIAS:
	set_dnssec_cd = 1

uint16_t
ldns_resolver_port(resolver)
	Net__LDNS__Resolver resolver;
	ALIAS:
	port = 1

void
ldns_resolver_set_port(resolver, port)
	Net__LDNS__Resolver resolver;
	uint16_t port;
	ALIAS:
	set_port = 1

bool
ldns_resolver_recursive(resolver)
	Net__LDNS__Resolver resolver;
	ALIAS:
	recursive = 1

void
ldns_resolver_set_recursive(resolver, b)
	Net__LDNS__Resolver resolver;
	bool b;
	ALIAS:
	set_recursive = 1

bool
ldns_resolver_debug(resolver)
	Net__LDNS__Resolver resolver;
	ALIAS:
	debug = 1

void
ldns_resolver_set_debug(resolver, b)
	Net__LDNS__Resolver resolver;
	bool b;
	ALIAS:
	set_debug = 1

uint8_t
ldns_resolver_retry(resolver)
	Net__LDNS__Resolver resolver;
	ALIAS:
	retry = 1

void
ldns_resolver_set_retry(resolver, re)
	Net__LDNS__Resolver resolver;
	uint8_t re;
	ALIAS:
	set_retry = 1

uint8_t
ldns_resolver_retrans(resolver)
	Net__LDNS__Resolver resolver;
	ALIAS:
	retrans = 1

void
ldns_resolver_set_retrans(resolver, re)
	Net__LDNS__Resolver resolver;
	uint8_t re;
	ALIAS:
	set_retrans = 1

bool
ldns_resolver_fallback(resolver)
	Net__LDNS__Resolver resolver;
	ALIAS:
	fallback = 1

void
ldns_resolver_set_fallback(resolver, f)
	Net__LDNS__Resolver resolver;
	bool f;
	ALIAS:
	set_fallback = 1

uint8_t
ldns_resolver_ip6(resolver)
	Net__LDNS__Resolver resolver;
	ALIAS:
	ip6 = 1

void
ldns_resolver_set_ip6(resolver, i)
	Net__LDNS__Resolver resolver;
	uint8_t i;
	ALIAS:
	set_ip6 = 1

uint16_t
ldns_resolver_edns_udp_size(resolver)
	Net__LDNS__Resolver resolver;
	ALIAS:
	edns_udp_size = 1

void
ldns_resolver_set_edns_udp_size(resolver, s)
	Net__LDNS__Resolver resolver;
	uint16_t s;
	ALIAS:
	set_edns_udp_size = 1

bool
ldns_resolver_usevc(resolver)
	Net__LDNS__Resolver resolver;
	ALIAS:
	usevc = 1

void
ldns_resolver_set_usevc(resolver, b)
	Net__LDNS__Resolver resolver;
	bool b;
	ALIAS:
	set_usevc = 1

bool
ldns_resolver_fail(resolver)
	Net__LDNS__Resolver resolver;
	ALIAS:
	fail = 1

void
ldns_resolver_set_fail(resolver, b)
	Net__LDNS__Resolver resolver;
	bool b;
	ALIAS:
	set_fail = 1

bool
ldns_resolver_defnames(resolver)
	Net__LDNS__Resolver resolver;
	ALIAS:
	defnames = 1

void
ldns_resolver_set_defnames(resolver, b)
	Net__LDNS__Resolver resolver;
	bool b;
	ALIAS:
	set_defnames = 1

bool
ldns_resolver_dnsrch(resolver)
	Net__LDNS__Resolver resolver;
	ALIAS:
	dnsrch = 1

void
ldns_resolver_set_dnsrch(resolver, b)
	Net__LDNS__Resolver resolver;
	bool b;
	ALIAS:
	set_dnsrch = 1

bool
ldns_resolver_igntc(resolver)
	Net__LDNS__Resolver resolver;
	ALIAS:
	igntc = 1

void
ldns_resolver_set_igntc(resolver, b)
	Net__LDNS__Resolver resolver;
	bool b;
	ALIAS:
	set_igntc = 1

bool
ldns_resolver_random(resolver)
	Net__LDNS__Resolver resolver;
	ALIAS:
	random = 1

void
ldns_resolver_set_random(resolver, b)
	Net__LDNS__Resolver resolver;
	bool b;
	ALIAS:
	set_random = 1

bool
ldns_resolver_trusted_key(resolver, keys, trusted_key)
	Net__LDNS__Resolver resolver;
	Net__LDNS__RRList keys;
	Net__LDNS__RRList trusted_key;
	ALIAS:
	trusted_key = 1

Net__LDNS__RRList
ldns_resolver_dnssec_anchors(resolver)
	Net__LDNS__Resolver resolver;
	ALIAS:
	_dnssec_anchors = 1

void
ldns_resolver_set_dnssec_anchors(resolver, list)
	Net__LDNS__Resolver resolver;
	Net__LDNS__RRList list;
	ALIAS:
	_set_dnssec_anchors = 1

void
ldns_resolver_push_dnssec_anchor(resolver, rr)
	Net__LDNS__Resolver resolver;
	Net__LDNS__RR rr;
	ALIAS:
	_push_dnssec_anchor = 1

Net__LDNS__RData
ldns_resolver_domain(resolver)
	Net__LDNS__Resolver resolver;
	ALIAS:
	_domain = 1

void
ldns_resolver_set_domain(resolver, rd)
	Net__LDNS__Resolver resolver;
	Net__LDNS__RData rd;
	ALIAS:
	_set_domain = 1

AV *
_nameservers(resolver)
	Net__LDNS__Resolver resolver;
	PREINIT:
	    ldns_rdf** list;
	    AV * result;
	    int i;
	    SV * elem;
	CODE:
	result = (AV *)sv_2mortal((SV *)newAV());
	list = ldns_resolver_nameservers(resolver);

	/* FIXME: Make a typemap for this ? */	
	for (i = 0; i < ldns_resolver_nameserver_count(resolver); i++) {
	    elem = newSVpv(0, 0);
	    sv_setref_pv(elem, "LDNS::RData", list[i]);
	    av_push(result, elem);
	}
	RETVAL = result;
	OUTPUT:
	RETVAL

size_t
ldns_resolver_nameserver_count(resolver)
	Net__LDNS__Resolver resolver;
	ALIAS:
	nameserver_count = 1

LDNS_Status
ldns_resolver_push_nameserver(resolver, n)
	Net__LDNS__Resolver resolver;
	Net__LDNS__RData n;
	ALIAS:
	_push_nameserver = 1

Net__LDNS__RData
ldns_resolver_pop_nameserver(resolver)
	Net__LDNS__Resolver resolver;
	ALIAS:
	_pop_nameserver = 1

void
ldns_resolver_nameservers_randomize(resolver)
	Net__LDNS__Resolver resolver;
	ALIAS:
	nameservers_randomize = 1

char*
ldns_resolver_tsig_keyname(resolver)
	Net__LDNS__Resolver resolver;
	ALIAS:
	tsig_keyname = 1

void
ldns_resolver_set_tsig_keyname(resolver, tsig_keyname)
	Net__LDNS__Resolver resolver;
	char* tsig_keyname;
	ALIAS:
	set_tsig_keyname = 1

char*
ldns_resolver_tsig_algorithm(resolver)
	Net__LDNS__Resolver resolver;
	ALIAS:
	tsig_algorithm = 1

void
ldns_resolver_set_tsig_algorithm(resolver, tsig_algorithm)
	Net__LDNS__Resolver resolver;
	char* tsig_algorithm;
	ALIAS:
	set_tsig_algorithm = 1

char*
ldns_resolver_tsig_keydata(resolver)
	Net__LDNS__Resolver resolver;
	ALIAS:
	tsig_keydata = 1

void
ldns_resolver_set_tsig_keydata(resolver, tsig_keydata)
	Net__LDNS__Resolver resolver;
	char* tsig_keydata;
	ALIAS:
	set_tsig_keydata = 1

size_t
ldns_resolver_searchlist_count(resolver)
	Net__LDNS__Resolver resolver;
	ALIAS:
	searchlist_count = 1

void
ldns_resolver_push_searchlist(resolver, rd)
	Net__LDNS__Resolver resolver;
	Net__LDNS__RData rd;
	ALIAS:
	_push_searchlist = 1

AV *
_searchlist(resolver)
	Net__LDNS__Resolver resolver;
	PREINIT:
	    ldns_rdf** list;
	    AV * result;
	    int i;
	    SV * elem;
	CODE:
	result = (AV *)sv_2mortal((SV *)newAV());
	list = ldns_resolver_searchlist(resolver);

	/* FIXME: Make a typemap for this ? */	
	for (i = 0; i < ldns_resolver_searchlist_count(resolver); i++) {
	    elem = newSVpv(0, 0);
	    sv_setref_pv(elem, "LDNS::RData", list[i]);
	    av_push(result, elem);
	}
	RETVAL = result;
	OUTPUT:
	RETVAL

size_t
ldns_resolver_nameserver_rtt(resolver, pos)
	Net__LDNS__Resolver resolver;
	size_t pos;
	ALIAS:
	nameserver_rtt = 1

void
ldns_resolver_set_nameserver_rtt(resolver, pos, val)
	Net__LDNS__Resolver resolver;
	size_t pos;
	size_t val;
	ALIAS:
	set_nameserver_rtt = 1

AV *
_timeout(resolver)
	Net__LDNS__Resolver resolver;
	PREINIT:
	    struct timeval t;
	    AV * result;
	CODE:
	t = ldns_resolver_timeout(resolver);
	result = (AV *)sv_2mortal((SV *)newAV());
	av_push(result, newSVuv(t.tv_sec));
	av_push(result, newSVuv(t.tv_usec));
	RETVAL = result;
	OUTPUT:
	RETVAL

void
set_timeout(resolver, sec, usec)
	Net__LDNS__Resolver resolver;
	uint32_t sec;
	uint32_t usec;
	PREINIT:
	    struct timeval t;
	CODE:
	t.tv_sec = sec;
	t.tv_usec = usec;
	ldns_resolver_set_timeout(resolver, t);

void
_set_rtt(resolver, rtt)
	Net__LDNS__Resolver resolver;
	AV * rtt;
	PREINIT:
	    size_t *buff;
	    int i;
	    SV** elem;
	CODE:
	buff = malloc(sizeof(size_t)*av_len(rtt));
	for (i = 0; i <= av_len(rtt); i++) {
	    elem = av_fetch(rtt, i, 0);
	    buff[i] = SvUV(*elem);
	}
	ldns_resolver_set_rtt(resolver, buff);

AV *
_rtt(resolver)
	Net__LDNS__Resolver resolver;
	PREINIT:
	    int i;
	    size_t *rtt;
	    AV * result;
	CODE:
	result = (AV *)sv_2mortal((SV *)newAV());
	rtt = ldns_resolver_rtt(resolver);

	for (i = 0; i < ldns_resolver_nameserver_count(resolver); i++) {
	    av_push(result, newSVuv(rtt[i]));
	}
	RETVAL = result;
	OUTPUT:
	RETVAL

Net__LDNS__RRList
ldns_validate_domain_dnskey(resolver, domain, keys)
	Net__LDNS__Resolver resolver;
	Net__LDNS__RData domain;
	Net__LDNS__RRList keys;
	ALIAS:
	validate_domain_dnskey = 1

LDNS_Status
ldns_verify_trusted(resolver, rrset, rrsigs, validating_keys)
	Net__LDNS__Resolver resolver;
	Net__LDNS__RRList rrset;
	Net__LDNS__RRList rrsigs;
	Net__LDNS__RRList validating_keys;
	ALIAS:
	_verify_trusted = 1

Net__LDNS__RRList
_fetch_valid_domain_keys(resolver, domain, keys, s)
	Net__LDNS__Resolver resolver;
	Net__LDNS__RData domain;
	Net__LDNS__RRList keys;
	LDNS_Status s;
        PREINIT:
            Net__LDNS__RRList trusted;
	    Net__LDNS__RRList ret;
	    size_t i;
	CODE:
	RETVAL = NULL;
	trusted = ldns_fetch_valid_domain_keys(resolver, domain, keys, &s);
	if (s == LDNS_STATUS_OK) {
	    RETVAL = ldns_rr_list_clone(trusted);
	    ldns_rr_list_free(trusted);
	}
	OUTPUT:
	RETVAL
	s

Net__LDNS__Packet
ldns_resolver_query(resolver, name, type, class, flags)
	Net__LDNS__Resolver resolver;
	Net__LDNS__RData name;
	LDNS_RR_Type type;
	LDNS_RR_Class class;
	uint16_t flags;
	ALIAS:
	query = 1

Net__LDNS__Packet
ldns_resolver_search(resolver, name, type, class, flags)
	Net__LDNS__Resolver resolver;
	Net__LDNS__RData name;
	LDNS_RR_Type type;
	LDNS_RR_Class class;
	uint16_t flags;
	ALIAS:
	search = 1

Net__LDNS__DNSSecDataChain
build_data_chain(res, qflags, data_set, pkt, orig_rr)
	Net__LDNS__Resolver res;
	uint16_t qflags;
	Net__LDNS__RRList data_set;
	Net__LDNS__Packet pkt;
	Net__LDNS__RR__Opt orig_rr;
	CODE:
	RETVAL = ldns_dnssec_build_data_chain(res, qflags, data_set, pkt, orig_rr);
	OUTPUT:
	RETVAL

Net__LDNS__RRList
ldns_get_rr_list_addr_by_name(res, name, class, flags)
	Net__LDNS__Resolver res;
	Net__LDNS__RData name;
	LDNS_RR_Class class;
	uint16_t flags;
	ALIAS:
	get_rr_list_addr_by_name = 1

Net__LDNS__RRList
ldns_get_rr_list_name_by_addr(res, addr, class, flags)
	Net__LDNS__Resolver res;
	Net__LDNS__RData addr;
	LDNS_RR_Class class;
	uint16_t flags;
	ALIAS:
	get_rr_list_addr_by_addr = 1


MODULE = Net::LDNS		PACKAGE = Net::LDNS::Packet

Mortal_PV
ldns_pkt2str(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	to_string = 1

Net__LDNS__RRList
ldns_pkt_question(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	_question = 1

void
ldns_pkt_set_question(pkt, l)
	Net__LDNS__Packet pkt;
	Net__LDNS__RRList l;
	ALIAS:
	_set_question = 1

Net__LDNS__RRList
ldns_pkt_answer(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	_answer = 1

void
ldns_pkt_set_answer(pkt, l)
	Net__LDNS__Packet pkt;
	Net__LDNS__RRList l;
	ALIAS:
	_set_answer = 1

Net__LDNS__RRList
ldns_pkt_authority(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	_authority = 1

void
ldns_pkt_set_authority(pkt, l)
	Net__LDNS__Packet pkt;
	Net__LDNS__RRList l;
	ALIAS:
	_set_authority = 1

Net__LDNS__RRList
ldns_pkt_additional(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	_additional = 1

void
ldns_pkt_set_additional(pkt, l)
	Net__LDNS__Packet pkt;
	Net__LDNS__RRList l;
	ALIAS:
	_set_additional = 1

Net__LDNS__RRList
ldns_pkt_all(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	all = 1

Net__LDNS__RRList
ldns_pkt_all_noquestion(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	all_noquestion = 1

signed char
ldns_pkt_qr(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	qr = 1

void
ldns_pkt_set_qr(pkt, b)
	Net__LDNS__Packet pkt;
	signed char b;
	ALIAS:
	set_qr = 1

signed char
ldns_pkt_aa(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	aa = 1

void
ldns_pkt_set_aa(pkt, b)
	Net__LDNS__Packet pkt;
	signed char b;
	ALIAS:
	set_aa = 1

signed char
ldns_pkt_tc(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	tc = 1

void
ldns_pkt_set_tc(pkt, b)
	Net__LDNS__Packet pkt;
	signed char b;
	ALIAS:
	set_tc = 1

signed char
ldns_pkt_rd(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	rd = 1

void
ldns_pkt_set_rd(pkt, b)
	Net__LDNS__Packet pkt;
	signed char b;
	ALIAS:
	set_rd = 1

bool
ldns_pkt_cd(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	cd = 1

void
ldns_pkt_set_cd(pkt, b)
	Net__LDNS__Packet pkt;
	signed char b;
	ALIAS:
	set_cd = 1

signed char
ldns_pkt_ra(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	ra = 1

void
ldns_pkt_set_ra(pkt, b)
	Net__LDNS__Packet pkt;
	signed char b;
	ALIAS:
	set_ra = 1

signed char
ldns_pkt_ad(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	ad = 1

void
ldns_pkt_set_ad(pkt, b)
	Net__LDNS__Packet pkt;
	signed char b;
	ALIAS:
	set_ad = 1

uint16_t
ldns_pkt_id(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	id = 1

void
ldns_pkt_set_id(pkt, id)
	Net__LDNS__Packet pkt;
	uint16_t id;
	ALIAS:
	set_id = 1

void
ldns_pkt_set_random_id(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	set_random_id = 1

uint16_t
ldns_pkt_qdcount(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	qdcount = 1

uint16_t
ldns_pkt_ancount(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	ancount = 1

uint16_t
ldns_pkt_nscount(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	nscount = 1

uint16_t
ldns_pkt_arcount(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	arcount = 1

LDNS_Pkt_Opcode
ldns_pkt_get_opcode(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	opcode = 1

void
ldns_pkt_set_opcode(pkt, c)
	Net__LDNS__Packet pkt;
	LDNS_Pkt_Opcode c;
	ALIAS:
	set_opcode = 1

uint8_t
ldns_pkt_get_rcode(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	rcode = 1

void
ldns_pkt_set_rcode(pkt, r)
	Net__LDNS__Packet pkt;
	uint8_t r;
	ALIAS:
	set_rcode = 1

size_t
ldns_pkt_size(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	size = 1

uint32_t
ldns_pkt_querytime(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	querytime = 1

void
ldns_pkt_set_querytime(pkt, t)
	Net__LDNS__Packet pkt;
	uint32_t t;
	ALIAS:
	set_querytime = 1

Net__LDNS__RData
ldns_pkt_answerfrom(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	_answerfrom = 1

AV *
_timestamp(pkt)
	Net__LDNS__Packet pkt;
	PREINIT:
	    struct timeval t;
	    AV * result;
	CODE:
	t = ldns_pkt_timestamp(pkt);
	result = (AV *)sv_2mortal((SV *)newAV());
	av_push(result, newSVuv(t.tv_sec));
	av_push(result, newSVuv(t.tv_usec));
	RETVAL = result;
	OUTPUT:
	RETVAL

void
set_timestamp(pkt, sec, usec)
	Net__LDNS__Packet pkt;
	uint32_t sec;
	uint32_t usec;
	PREINIT:
	    struct timeval t;
	CODE:
	t.tv_sec = sec;
	t.tv_usec = usec;
	ldns_pkt_set_timestamp(pkt, t);

void
ldns_pkt_set_answerfrom(pkt, a)
	Net__LDNS__Packet pkt;
	Net__LDNS__RData a;
	ALIAS:
	_set_answerfrom = 1

bool
ldns_pkt_set_flags(pkt, f)
	Net__LDNS__Packet pkt;
	uint16_t f;
	ALIAS:
	set_flags = 1

Net__LDNS__RRList
ldns_pkt_rr_list_by_name(pkt, name, sec)
	Net__LDNS__Packet pkt;
	Net__LDNS__RData name;
	LDNS_Pkt_Section sec;
	ALIAS:
	rr_list_by_name = 1

Net__LDNS__RRList
ldns_pkt_rr_list_by_type(pkt, type, sec)
	Net__LDNS__Packet pkt;
	LDNS_RR_Type type;
	LDNS_Pkt_Section sec;
	ALIAS:
	rr_list_by_type = 1

Net__LDNS__RRList
ldns_pkt_rr_list_by_name_and_type(pkt, name, type, sec)
	Net__LDNS__Packet pkt;
	Net__LDNS__RData name;
	LDNS_RR_Type type;
	LDNS_Pkt_Section sec;
	ALIAS:
	rr_list_by_name_and_type = 1

bool
ldns_pkt_rr(pkt, sec, rr)
	Net__LDNS__Packet pkt;
	LDNS_Pkt_Section sec;
	Net__LDNS__RR rr;
	ALIAS:
	rr = 1

bool
ldns_pkt_push_rr(pkt, sec, rr)
	Net__LDNS__Packet pkt;
	LDNS_Pkt_Section sec;
	Net__LDNS__RR rr;
	ALIAS:
	_push_rr = 1

bool
ldns_pkt_safe_push_rr(pkt, sec, rr)
	Net__LDNS__Packet pkt;
	LDNS_Pkt_Section sec;
	Net__LDNS__RR rr;
	ALIAS:
	_safe_push_rr = 1

uint16_t
ldns_pkt_section_count(pkt, sec)
	Net__LDNS__Packet pkt;
	LDNS_Pkt_Section sec;
	ALIAS:
	section_count = 1

signed char
ldns_pkt_empty(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	empty = 1

Net__LDNS__RR
ldns_pkt_tsig(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	_tsig = 1

void
ldns_pkt_set_tsig(pkt, rr)
	Net__LDNS__Packet pkt;
	Net__LDNS__RR rr;
	ALIAS:
	_set_tsig = 1

Net__LDNS__Packet
ldns_pkt_clone(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	clone = 1

LDNS_Pkt_Type
ldns_pkt_reply_type(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	reply_type = 1

Net__LDNS__Packet
ldns_pkt_new()
	ALIAS:
	_new = 1

Net__LDNS__Packet
ldns_pkt_query_new(name, type, class, flags)
	Net__LDNS__RData name;
	LDNS_RR_Type type;
	LDNS_RR_Class class;
	uint16_t flags;
	ALIAS:
	_query_new = 1

Net__LDNS__RRList
ldns_dnssec_pkt_get_rrsigs_for_name_and_type(pkt, name, type)
	Net__LDNS__Packet pkt;
	Net__LDNS__RData name;
	LDNS_RR_Type type;
	ALIAS:
	get_rrsigs_for_name_and_type = 1

Net__LDNS__RRList
ldns_dnssec_pkt_get_rrsigs_for_type(pkt, type)
	Net__LDNS__Packet pkt;
	LDNS_RR_Type type;
	ALIAS:
	get_rrsigs_for_type = 1

uint16_t
ldns_pkt_edns_udp_size(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	edns_udp_size = 1

void
ldns_pkt_set_edns_udp_size(pkt, s)
	Net__LDNS__Packet pkt;
	uint16_t s;
	ALIAS:
	set_edns_udp_size = 1

uint8_t
ldns_pkt_edns_extended_rcode(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	edns_extended_rcode = 1

void
ldns_pkt_set_edns_extended_rcode(pkt, c)
	Net__LDNS__Packet pkt;
	uint8_t c;
	ALIAS:
	set_edns_extended_rcode = 1

uint8_t
ldns_pkt_edns_version(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	edns_version = 1

void
ldns_pkt_set_edns_version(pkt, v)
	Net__LDNS__Packet pkt;
	uint8_t v;
	ALIAS:
	set_edns_version = 1

uint16_t
ldns_pkt_edns_z(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	edns_z = 1

void
ldns_pkt_set_edns_z(pkt, z)
	Net__LDNS__Packet pkt;
	uint16_t z;
	ALIAS:
	set_edns_z = 1

signed char
ldns_pkt_edns_do(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	edns_do = 1

Net__LDNS__RData
ldns_pkt_edns_data(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	_edns_data = 1

void
ldns_pkt_set_edns_data(pkt, data)
	Net__LDNS__Packet pkt;
	Net__LDNS__RData data;
	ALIAS:
	_set_edns_data = 1

void
ldns_pkt_set_edns_do(pkt, val)
	Net__LDNS__Packet pkt;
	signed char val;
	ALIAS:
	set_edns_do = 1

bool
ldns_pkt_edns(pkt)
	Net__LDNS__Packet pkt;
	ALIAS:
	edns = 1


MODULE = Net::LDNS		PACKAGE = Net::LDNS::Key

Net__LDNS__Key
_new_from_file(fp, line_nr, s)
	FILE*         fp;
	int           line_nr = 0;
	LDNS_Status   s = LDNS_STATUS_OK;
        PREINIT:
            ldns_key *key;
        CODE:
	RETVAL = NULL;
	s = ldns_key_new_frm_fp_l(&key, fp, &line_nr);

	if (s == LDNS_STATUS_OK) {
	    RETVAL = key;
	}
        OUTPUT:
        RETVAL
	s
	line_nr

Net__LDNS__Key
ldns_key_new()
	ALIAS:
	_new = 1

void
print(key, fp)
	Net__LDNS__Key key;
	FILE* fp;
	CODE:
	ldns_key_print(fp, key);

Mortal_PV
ldns_key2str(key)
	Net__LDNS__Key key;
	ALIAS:
	to_string = 1

void
ldns_key_set_algorithm(key, algorithm)
	Net__LDNS__Key key;
	LDNS_Signing_Algorithm algorithm;
	ALIAS:
	set_algorithm = 1

LDNS_Signing_Algorithm
ldns_key_algorithm(key)
	Net__LDNS__Key key;
	ALIAS:
	algorithm = 1

void
ldns_key_set_flags(key, flags)
	Net__LDNS__Key key;
	uint16_t flags;
	ALIAS:
	set_flags = 1

uint16_t
ldns_key_flags(key)
	Net__LDNS__Key key;
	ALIAS:
	flags = 1

void
ldns_key_set_hmac_key(key, hmac)
	Net__LDNS__Key key;
	unsigned char* hmac;
	ALIAS:
	set_hmac_key = 1

unsigned char *
ldns_key_hmac_key(key)
	Net__LDNS__Key key;
	ALIAS:
	hmac_key = 1

void
ldns_key_set_hmac_size(key, size)
	Net__LDNS__Key key;
	size_t size;
	ALIAS:
	set_hmac_size = 1

size_t
ldns_key_hmac_size(key)
	Net__LDNS__Key key;
	ALIAS:
	hmac_size = 1

void
ldns_key_set_origttl(key, t)
	Net__LDNS__Key key;
	uint32_t t;
	ALIAS:
	set_origttl = 1

uint32_t
ldns_key_origttl(key)
	Net__LDNS__Key key;
	ALIAS:
	origttl = 1

void
ldns_key_set_inception(key, i)
	Net__LDNS__Key key;
	uint32_t i;
	ALIAS:
	set_inception = 1

uint32_t
ldns_key_inception(key)
	Net__LDNS__Key key;
	ALIAS:
	inception = 1

void
ldns_key_set_expiration(key, e)
	Net__LDNS__Key key;
	uint32_t e;
	ALIAS:
	set_expiration = 1

uint32_t
ldns_key_expiration(key)
	Net__LDNS__Key key;
	ALIAS:
	expiration = 1

void
ldns_key_set_pubkey_owner(key, r)
	Net__LDNS__Key key;
	Net__LDNS__RData r;
	ALIAS:
	_set_pubkey_owner = 1

Net__LDNS__RData
ldns_key_pubkey_owner(key)
	Net__LDNS__Key key;
	ALIAS:
	_pubkey_owner = 1

void
ldns_key_set_keytag(key, tag)
	Net__LDNS__Key key;
	uint16_t tag;
	ALIAS:
	set_keytag = 1

uint16_t
ldns_key_keytag(key)
	Net__LDNS__Key key;
	ALIAS:
	keytag = 1

void
ldns_key_set_use(key, v)
	Net__LDNS__Key key;
	signed char v;
	ALIAS:
	set_use = 1

signed char
ldns_key_use(key)
	Net__LDNS__Key key;
	ALIAS:
	use = 1

char *
ldns_key_get_file_base_name(key)
	Net__LDNS__Key key;
	ALIAS:
	get_file_base_name = 1

Net__LDNS__RR
ldns_key2rr(key)
	Net__LDNS__Key key;
	ALIAS:
	to_rr = 1


MODULE = Net::LDNS		PACKAGE = Net::LDNS::KeyList

Net__LDNS__KeyList
ldns_key_list_new()
	ALIAS:
	_new = 1

void
ldns_key_list_set_use(keys, v)
	Net__LDNS__KeyList keys;
	bool v;
	ALIAS:
	set_use = 1

Net__LDNS__Key
ldns_key_list_pop_key(keylist)
	Net__LDNS__KeyList keylist;
	ALIAS:
	pop = 1

void
ldns_key_list_push_key(keylist, key)
	Net__LDNS__KeyList keylist;
	Net__LDNS__Key key;
	ALIAS:
	_push = 1

size_t
ldns_key_list_key_count(keylist)
	Net__LDNS__KeyList keylist;
	ALIAS:
	count = 1

Net__LDNS__Key
ldns_key_list_key(keylist, nr)
	Net__LDNS__KeyList keylist;
	size_t nr;
	ALIAS:
	_key = 1


MODULE = Net::LDNS		PACKAGE = Net::LDNS::DNSSecDataChain

Net__LDNS__DNSSecDataChain
ldns_dnssec_data_chain_new()
	ALIAS:
	_new = 1

void
print(chain, fp)
	Net__LDNS__DNSSecDataChain chain;
	FILE* fp;
	CODE:
	ldns_dnssec_data_chain_print(fp, chain);

Net__LDNS__DNSSecTrustTree
ldns_dnssec_derive_trust_tree(chain, rr)
	Net__LDNS__DNSSecDataChain chain;
	Net__LDNS__RR rr;
	ALIAS:
	_derive_trust_tree = 1

Net__LDNS__RRList
_rrset(chain)
	Net__LDNS__DNSSecDataChain chain;
	CODE:
	RETVAL = chain->rrset;
	OUTPUT:
	RETVAL

Net__LDNS__RRList
_signatures(chain)
	Net__LDNS__DNSSecDataChain chain;
	CODE:
	RETVAL = chain->signatures;
	OUTPUT:
	RETVAL

LDNS_RR_Type
parent_type(chain)
	Net__LDNS__DNSSecDataChain chain;
	CODE:
	RETVAL = chain->parent_type;
	OUTPUT:
	RETVAL

Net__LDNS__DNSSecDataChain
_parent(chain)
	Net__LDNS__DNSSecDataChain chain;
	CODE:
	RETVAL = chain->parent;
	OUTPUT:
	RETVAL

LDNS_Pkt_Rcode
packet_rcode(chain)
	Net__LDNS__DNSSecDataChain chain;
	CODE:
	RETVAL = chain->packet_rcode;
	OUTPUT:
	RETVAL

LDNS_RR_Type
packet_qtype(chain)
	Net__LDNS__DNSSecDataChain chain;
	CODE:
	RETVAL = chain->packet_qtype;
	OUTPUT:
	RETVAL

signed char
packet_nodata(chain)
	Net__LDNS__DNSSecDataChain chain;
	CODE:
	RETVAL = chain->packet_nodata;
	OUTPUT:
	RETVAL


MODULE = Net::LDNS		PACKAGE = Net::LDNS::DNSSecTrustTree

Net__LDNS__DNSSecTrustTree
ldns_dnssec_trust_tree_new()
	ALIAS:
	_new = 1

void
print(tree, fp, tabs, extended)
	Net__LDNS__DNSSecTrustTree tree;
	FILE* fp;
	size_t tabs;
	bool extended;
	CODE:
	ldns_dnssec_trust_tree_print(fp, tree, tabs, extended);

size_t
ldns_dnssec_trust_tree_depth(tree)
	Net__LDNS__DNSSecTrustTree tree;
	ALIAS:
	depth = 1

LDNS_Status
ldns_dnssec_trust_tree_add_parent(tree, parent, signature, parent_status)
	Net__LDNS__DNSSecTrustTree tree;
	Net__LDNS__DNSSecTrustTree parent;
	Net__LDNS__RR signature;
	LDNS_Status parent_status;
	ALIAS:
	_add_parent = 1

LDNS_Status
ldns_dnssec_trust_tree_contains_keys(tree, trusted_keys)
	Net__LDNS__DNSSecTrustTree tree;
	Net__LDNS__RRList trusted_keys;
	ALIAS:
	_contains_keys = 1

Net__LDNS__RR
_rr(tree)
	Net__LDNS__DNSSecTrustTree tree;
	CODE:
	RETVAL = tree->rr;
	OUTPUT:
	RETVAL

Net__LDNS__RRList
_rrset(tree)
	Net__LDNS__DNSSecTrustTree tree;
	CODE:
	RETVAL = tree->rrset;
	OUTPUT:
	RETVAL

Net__LDNS__DNSSecTrustTree
_parent(tree, i)
	Net__LDNS__DNSSecTrustTree tree;
	size_t i;
	CODE:
	RETVAL = tree->parents[i];
	OUTPUT:
	RETVAL

LDNS_Status
_parent_status(tree, i)
	Net__LDNS__DNSSecTrustTree tree;
	size_t i;
	CODE:
	RETVAL = tree->parent_status[i];
	OUTPUT:
	RETVAL

Net__LDNS__RR
_parent_signature(tree, i)
	Net__LDNS__DNSSecTrustTree tree;
	size_t i;
	CODE:
	RETVAL = tree->parent_signature[i];
	OUTPUT:
	RETVAL

size_t
parent_count(tree)
	Net__LDNS__DNSSecTrustTree tree;
	CODE:
	RETVAL = tree->parent_count;
	OUTPUT:
	RETVAL
