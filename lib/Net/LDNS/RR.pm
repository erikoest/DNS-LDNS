package Net::LDNS::RR;

use 5.008008;
use strict;
use warnings;

use Net::LDNS ':all';
use Carp 'croak';

our $VERSION = '0.02';

sub new {
    my $class = shift;

    my $rr;
    my $status = &LDNS_STATUS_OK;

    if (scalar(@_) == 0) {
	$rr = _new;
    }
    elsif (scalar(@_) == 1) {
	$rr = _new_from_str($_[0], $Net::LDNS::DEFAULT_TTL, 
	    $Net::LDNS::DEFAULT_ORIGIN, $status);
    }
    else {
	my %args = @_;

	if ($args{str}) {
	    $rr = _new_from_str($args{str}, 
				$args{default_ttl} || $Net::LDNS::DEFAULT_TTL, 
				$args{origin} || $Net::LDNS::DEFAULT_ORIGIN, 
				$status);
	}
	elsif ($args{filename} or $args{file}) {
	    my $line_nr = 0;
	    my $file = $args{file};
	    if ($args{filename}) {
		unless (open FILE, $args{filename}) {
		    $Net::LDNS::last_status = &LDNS_STATUS_FILE_ERR;
		    $Net::LDNS::line_nr = 0;
		    return;
		}
		$file = \*FILE;
	    }

	    $rr = _new_from_file($file, 
				 $args{default_ttl} || $Net::LDNS::DEFAULT_TTL, 
				 $args{origin} || $Net::LDNS::DEFAULT_ORIGIN, 
				 $status, $line_nr);
	    if ($args{filename}) {
		close $file;
	    }

	    $Net::LDNS::line_nr = $line_nr;
	}
	elsif ($args{type}) {
	    $rr = _new_from_type($args{type});
	    if ($args{owner}) {
		$rr->set_owner(new Net::LDNS::RData(
		    &LDNS_RDF_TYPE_DNAME, $args{owner}));
	    }
	    $rr->set_ttl($args{ttl} || $Net::LDNS::DEFAULT_TTL);
	    $rr->set_class($args{class} || $Net::LDNS::DEFAULT_CLASS);

	    if ($args{rdata}) {
		if (!$rr->set_rdata(@{$args{rdata}})) {
		    $Net::LDNS::last_status = &LDNS_STATUS_SYNTAX_RDATA_ERR;
		    return;
		}
	    }
	    else {
		$rr->_set_rdata_by_type(%args);
	    }
	}
    }

    if (!defined $rr) {
	$Net::LDNS::last_status = $status;
	return;
    }
    return $rr;
}

sub _set_rdata_by_type {
    my ($rr, %args) = @_;

    my %args_by_rr_type = (
	&LDNS_RR_TYPE_A => [
	     { name => 'address', type => &LDNS_RDF_TYPE_A } ],
	&LDNS_RR_TYPE_AAAA => [
	     { name => 'address', type => &LDNS_RDF_TYPE_AAAA } ],
	&LDNS_RR_TYPE_CNAME => [
	     { name => 'cname', type => &LDNS_RDF_TYPE_DNAME } ],
	&LDNS_RR_TYPE_DNSKEY => [ 
	     { name => 'flags', type => &LDNS_RDF_TYPE_INT16 }, 
	     { name => 'protocol', type => &LDNS_RDF_TYPE_INT8 }, 
	     { name => 'algorithm', type => &LDNS_RDF_TYPE_ALG }, 
	     { name => 'key', type => &LDNS_RDF_TYPE_B64 } ],
	&LDNS_RR_TYPE_DS => [
	     { name => 'keytag', type => &LDNS_RDF_TYPE_INT16 }, 
	     { name => 'algorithm', type => &LDNS_RDF_TYPE_ALG }, 
	     { name => 'digtype', type => &LDNS_RDF_TYPE_INT8 }, 
	     { name => 'digest', type => &LDNS_RDF_TYPE_HEX } ],
	&LDNS_RR_TYPE_MX => [ 
	     { name => 'preference', type => &LDNS_RDF_TYPE_INT16 }, 
	     { name => 'exchange', type => &LDNS_RDF_TYPE_DNAME } ],
	&LDNS_RR_TYPE_NAPTR => [
	     { name => 'order', type => &LDNS_RDF_TYPE_INT16 },
	     { name => 'preference', type => &LDNS_RDF_TYPE_INT16 },
	     { name => 'flags', type => &LDNS_RDF_TYPE_STR },
	     { name => 'service', type => &LDNS_RDF_TYPE_STR },
	     { name => 'regexp', type => &LDNS_RDF_TYPE_STR },
	     { name => 'replacement', type => &LDNS_RDF_TYPE_DNAME } ],
	&LDNS_RR_TYPE_NS => [ 
	     { name => 'nsdname', type => &LDNS_RDF_TYPE_DNAME } ],
	&LDNS_RR_TYPE_NSEC => [ 
	     { name => 'nxtdname', type => &LDNS_RDF_TYPE_DNAME }, 
	     { name => 'typelist', type => &LDNS_RDF_TYPE_NSEC } ],
	&LDNS_RR_TYPE_NSEC3 => [ 
	     { name => 'hashalgo', type => &LDNS_RDF_TYPE_INT8 }, 
	     { name => 'flags', type => &LDNS_RDF_TYPE_INT8 }, 
	     { name => 'iterations', type => &LDNS_RDF_TYPE_INT16 }, 
	     { name => 'salt', type => &LDNS_RDF_TYPE_NSEC3_SALT }, 
	     { name => 'hnxtname', type => &LDNS_RDF_TYPE_NSEC3_NEXT_OWNER }, 
	     { name => 'typelist', type => &LDNS_RDF_TYPE_NSEC } ],
	&LDNS_RR_TYPE_NSEC3PARAM => [
	     { name => 'hashalgo', type => &LDNS_RDF_TYPE_INT8 }, 
	     { name => 'flags', type => &LDNS_RDF_TYPE_INT8 }, 
	     { name => 'iterations', type => &LDNS_RDF_TYPE_INT16 }, 
	     { name => 'salt', type => &LDNS_RDF_TYPE_NSEC3_SALT } ],
	&LDNS_RR_TYPE_RRSIG => [
	     { name => 'coveredtype', type =>&LDNS_RDF_TYPE_TYPE  }, 
	     { name => 'algorithm', type => &LDNS_RDF_TYPE_ALG }, 
	     { name => 'labels', type => &LDNS_RDF_TYPE_INT8 }, 
	     { name => 'orgttl', type => &LDNS_RDF_TYPE_INT32 }, 
	     { name => 'sigexpiration', type => &LDNS_RDF_TYPE_TIME }, 
	     { name => 'siginception', type => &LDNS_RDF_TYPE_TIME },
	     { name => 'keytag', type => &LDNS_RDF_TYPE_INT16 }, 
	     { name => 'signame', type => &LDNS_RDF_TYPE_DNAME }, 
	     { name => 'sig', type => &LDNS_RDF_TYPE_B64 } ],
	&LDNS_RR_TYPE_SOA => [
	     { name => 'mname', type => &LDNS_RDF_TYPE_DNAME }, 
	     { name => 'rname', type => &LDNS_RDF_TYPE_DNAME }, 
	     { name => 'serial', type => &LDNS_RDF_TYPE_INT32 }, 
	     { name => 'refresh', type => &LDNS_RDF_TYPE_PERIOD,
	       default => $Net::LDNS::DEFAULT_SOA_REFRESH }, 
	     { name => 'retry', type => &LDNS_RDF_TYPE_PERIOD,
	       default => $Net::LDNS::DEFAULT_SOA_RETRY },
	     { name => 'expire', type => &LDNS_RDF_TYPE_PERIOD,
	       default => $Net::LDNS::DEFAULT_SOA_EXPIRE },
	     { name => 'minimum', type => &LDNS_RDF_TYPE_PERIOD, 
	       default => $Net::LDNS::DEFAULT_SOA_MINIMUM } ],
	&LDNS_RR_TYPE_SRV => [ 
	     { name => 'priority', type => &LDNS_RDF_TYPE_INT16 }, 
	     { name => 'weight', type => &LDNS_RDF_TYPE_INT16 }, 
	     { name => 'port', type => &LDNS_RDF_TYPE_INT16 }, 
	     { name => 'target', type => &LDNS_RDF_TYPE_DNAME } ],
	&LDNS_RR_TYPE_TXT => [ 
	     { name => 'txtdata', type => &LDNS_RDF_TYPE_STR } ],
    );

    if (!exists $args_by_rr_type{$args{type}}) {
	croak "Missing parameter 'rdata'";
    }

    my @rdata;
    for my $p (@{$args_by_rr_type{$args{type}}}) {
	my $val = $args{$p->{name}};
	if (!defined $val and exists $p->{default}) {
	    $val = $p->{default};
	}
	if (!defined $val) {
	    croak "Missing parameter '".$p->{name}."'";
	}
	my $r = new Net::LDNS::RData($p->{type}, $val)
	    or croak "Bad parameter '".$p->{name}."'";
	push @rdata, $r;
    }
    $rr->set_rdata(@rdata);
}

sub owner {
    my $self = shift;
    return Net::LDNS::GC::own($self->_owner, $self);
}

sub set_owner {
    my ($self, $owner) = @_;
    Net::LDNS::GC::disown(my $old = $self->owner);
    $self->_set_owner($owner);
    return Net::LDNS::GC::own($owner, $self);
}

sub dname {
    return $_[0]->owner->to_string;
}

sub rdata {
    my ($self, $index) = @_;
    return Net::LDNS::GC::own($self->_rdata($index), $self);
}

# replace all existing rdata with new ones. Requires the
# input array to be exactly same length as rd_count
sub set_rdata {
    my ($self, @rdata) = @_;

    if (scalar @rdata != $self->rd_count) {
	# Hopefully this is a proper error to return here...
	$Net::LDNS::last_status = LDNS_STATUS_SYNTAX_RDATA_ERR;
	return;
    }
    my $i = 0;
    for (@rdata) {
	my $oldrd = _set_rdata($self, my $copy = $_->clone, $i);
	Net::LDNS::GC::disown(my $old = $oldrd);
	Net::LDNS::GC::own($copy, $self);
	$i++;
    }

    return 1;
}

sub push_rdata {
    my ($self, @rdata) = @_;

    for (@rdata) {
	# Push a copy in case the input rdata are already owned
	$self->_push_rdata(my $copy = $_->clone);
	Net::LDNS::GC::own($copy, $self);
    }
}

sub rrsig_typecovered {
    my $self = shift;
    return Net::LDNS::GC::own($self->_rrsig_typecovered, $self);
}

sub rrsig_set_typecovered {
    my ($self, $type) = shift;
    Net::LDNS::GC::disown(my $old = $self->rrsig_typecovered);
    my $result = $self->_rrsig_set_typecovered(my $copy = $type->clone);
    Net::LDNS::GC::own($copy, $self);
    return $result;
}

sub rrsig_algorithm {
    my $self = shift;
    return Net::LDNS::GC::own($self->_rrsig_algorithm, $self);
}

sub rrsig_set_algorithm {
    my ($self, $algo) = shift;
    Net::LDNS::GC::disown(my $old = $self->rrsig_algorithm);
    my $result = $self->_rrsig_set_algorithm(my $copy = $algo->clone);
    Net::LDNS::GC::own($copy, $self);
    return $result;
}

sub rrsig_expiration {
    my $self = shift;
    return Net::LDNS::GC::own($self->_rrsig_expiration, $self);
}

sub rrsig_set_expiration {
    my ($self, $date) = shift;
    Net::LDNS::GC::disown(my $old = $self->rrsig_expiration);
    my $result = $self->_rrsig_set_expiration(my $copy = $date->clone);
    Net::LDNS::GC::own($copy, $self);
    return $result;
}

sub rrsig_inception {
    my $self = shift;
    return Net::LDNS::GC::own($self->_rrsig_inception, $self);
}

sub rrsig_set_inception {
    my ($self, $date) = shift;
    Net::LDNS::GC::disown(my $old = $self->rrsig_inception);
    my $result = $self->_rrsig_set_inception(my $copy = $date->clone);
    Net::LDNS::GC::own($copy, $self);
    return $result;
}

sub rrsig_keytag {
    my $self = shift;
    return Net::LDNS::GC::own($self->_rrsig_keytag, $self);
}

sub rrsig_set_keytag {
    my ($self, $tag) = shift;
    Net::LDNS::GC::disown(my $old = $self->rrsig_keytag);
    my $result = $self->_rrsig_set_keytag(my $copy = $tag->clone);
    Net::LDNS::GC::own($copy, $self);
    return $result;
}

sub rrsig_sig {
    my $self = shift;
    return Net::LDNS::GC::own($self->_rrsig_sig, $self);
}

sub rrsig_set_sig {
    my ($self, $sig) = shift;
    Net::LDNS::GC::disown(my $old = $self->rrsig_sig);
    my $result = $self->_rrsig_set_sig(my $copy = $sig->clone);
    Net::LDNS::GC::own($copy, $self);
    return $result;
}

sub rrsig_labels {
    my $self = shift;
    return Net::LDNS::GC::own($self->_rrsig_labels, $self);
}

sub rrsig_set_labels {
    my ($self, $lab) = shift;
    Net::LDNS::GC::disown(my $old = $self->rrsig_labels);
    my $result = $self->_rrsig_set_labels(my $copy = $lab->clone);
    Net::LDNS::GC::own($copy, $self);
    return $result;
}

sub rrsig_origttl {
    my $self = shift;
    return Net::LDNS::GC::own($self->_rrsig_origttl, $self);
}

sub rrsig_set_origttl {
    my ($self, $ttl) = shift;
    Net::LDNS::GC::disown(my $old = $self->rrsig_origttl);
    my $result = $self->_rrsig_set_origttl(my $copy = $ttl->clone);
    Net::LDNS::GC::own($copy, $self);
    return $result;
}

sub rrsig_signame {
    my $self = shift;
    return Net::LDNS::GC::own($self->_rrsig_signame, $self);
}

sub rrsig_set_signame {
    my ($self, $name) = shift;
    Net::LDNS::GC::disown(my $old = $self->rrsig_signame);
    my $result = $self->_rrsig_set_signame(my $copy = $name->clone);
    Net::LDNS::GC::own($copy, $self);
    return $result;
}

sub dnskey_algorithm {
    my $self = shift;
    return Net::LDNS::GC::own($self->_dnskey_algorithm, $self);
}

sub dnskey_set_algorithm {
    my ($self, $algo) = shift;
    Net::LDNS::GC::disown(my $old = $self->dnskey_algorithm);
    my $result = $self->_dnskey_set_algorithm(my $copy = $algo->clone);
    Net::LDNS::GC::own($copy, $self);
    return $result;
}

sub dnskey_flags {
    my $self = shift;
    return Net::LDNS::GC::own($self->_dnskey_flags, $self);
}

sub dnskey_set_flags {
    my ($self, $flags) = shift;
    Net::LDNS::GC::disown(my $old = $self->flags);
    my $result = $self->_dnskey_set_flags(my $copy = $flags->clone);
    Net::LDNS::GC::own($copy, $self);
    return $result;
}

sub dnskey_protocol {
    my $self = shift;
    return Net::LDNS::GC::own($self->_dnskey_protocol, $self);
}

sub dnskey_set_protocol {
    my ($self, $proto) = shift;
    Net::LDNS::GC::disown(my $old = $self->dnskey_protocol);
    my $result = $self->_dnskey_set_protocol(my $copy = $proto->clone);
    Net::LDNS::GC::own($copy, $self);
    return $result;
}

sub dnskey_key {
    my $self = shift;
    return Net::LDNS::GC::own($self->_dnskey_key, $self);
}

sub dnskey_set_key {
    my ($self, $key) = shift;
    Net::LDNS::GC::disown(my $old = $self->dnskey_key);
    my $result = $self->_dnskey_set_key(my $copy = $key->clone);
    Net::LDNS::GC::own($copy, $self);
    return $result;
}

sub nsec3_next_owner {
    my $self = shift;
    return Net::LDNS::GC::own($self->_nsec3_next_owner, $self);
}

sub nsec3_bitmap {
    my $self = shift;
    return Net::LDNS::GC::own($self->_nsec3_bitmap, $self);
}

sub nsec3_salt {
    my $self = shift;
    return Net::LDNS::GC::own($self->_nsec3_salt, $self);
}

sub hash_name_from_nsec3 {
    my ($self, $name) = @_;
    my $hash = $self->_hash_name_from_nsec3($name);
    return Net::LDNS::GC::own($self->_hash_name_from_nsec3($name), $self);
}

sub verify_denial {
    my ($self, $nsecs, $rrsigs) = @_;
    my $s = _verify_denial($self, $nsecs, $rrsigs);
    $Net::LDNS::last_status = $s;
    return $s;
}

sub verify_denial_nsec3 {
    my ($self, $nsecs, $rrsigs, $packet_rcode, $packet_qtype, 
	$packet_nodata) = @_;
    my $s = _verify_denial_nsec3($self, $nsecs, $rrsigs, $packet_rcode, 
				 $packet_qtype, $packet_nodata);
    $Net::LDNS::last_status = $s;
    return $s;
}

sub verify_denial_nsec3_match {
    my ($self, $nsecs, $rrsigs, $packet_rcode, $packet_qtype, 
	$packet_nodata) = @_;

    my $status;
    my $match = _verify_denial_nsec3_match($self, $nsecs, $rrsigs, $packet_rcode, $packet_qtype, $packet_nodata, $status);
    $Net::LDNS::last_status = $status;
    if ($status != &LDNS_STATUS_OK) {
	return;
    }

    # $match is an RR owned by the $nsecs list.
    return Net::LDNS::GC::own($match, $nsecs);
}

sub DESTROY {
    Net::LDNS::GC::free($_[0]);
}

1;

=head1 NAME

Net::LDNS - Perl extension for the ldns library

=head1 SYNOPSIS

  use Net::LDNS ':all'

  my rr = new Net::LDNS::RR('mylabel 3600 IN A 168.10.10.10')
  my rr = new Net::LDNS::RR(
    str => 'mylabel 3600 IN A 168.10.10.10',
    default_ttl => 3600, # optional,
    origin => new Net::LDNS::RData(LDNS_RDF_TYPE_NAME, 'myzone.'), " # optional
  )
  my rr = new Net::LDNS::RR(
    filename => '/path/to/rr',
    origin => ...)
  my rr = new Net::LDNS::RR(
    file => \*FILE,
    origin => ...)
  my rr = new Net::LDNS::RR(
    type => LDNS_RR_TYPE_A,
    rdata => [new Net::LDNS::RData(...), new Net::LDNS::RData(...), ...],
    class => LDNS_RR_CLASS_IN, # optional
    ttl => 3600, # optional
    owner => new Net::LDNS::RData(LDNS_RDF_TYPE_NAME, 'mylabel'), # optional)
  my rr = new Net::LDNS::RR

  rr2 = rr->clone

  rr->print(\*FILE)
  rr->to_string

  ttl = rr->ttl
  rr->set_ttl(ttl)

  type = rr->type
  rr->set_type(type)

  class = rr->class
  rr->set_class(class)

  rdata = rr->owner
  rr->set_owner(rdata)
  str = rr->dname

  count = rr->rd_count
  rdata = rr->rdata(index)
  rr->set_rdata(rd1, rd2, rd3, ...)
  rr->push_rdata(rd1, rd2, rd3, ...)
  rdata = rr->pop_rdata

  rr->compare(rr2)
  rr->compare_dname(rr2)
  rr->compare_no_rdata(rr2)
  rr->compare_ds(rr2)

  hash = rr->hash_name_from_nsec3(dname)

  status = rr->verify_denial(nsecs, rrsigs)
  status = rr->verify_denial_nsec3(nsecs, rrsigs, packet_rcode, packet_qtype, packet_nodata)
  match = rr->verify_denial_nsec3_match(nsecs, rrsigs, packet_rcode, packet_qtype, packet_nodata)

  rr->nsec3_add_param_rdfs(algorithm, flags, iterations, salt)
  a = rr->nsec3_algorithm
  f = rr->nsec3_flags
  o = rr->nsec3_optout
  i = rr->nsec3_iterations
  rdata = rr->nsec3_next_owner
  rdata = rr->nsec3_bitmap
  rdata = rr->nsec3_salt

  rdata = rr->rrsig_keytag
  bool = rr->rrsig_set_keytag(rdata)
  rdata = rr->rrsig_signame
  bool = rr->rrsig_set_signame(rdata)
  rdata = rr->rrsig_sig
  bool = rr->rrsig_set_sig(rdata)
  rdata = rr->rrsig_algorithm
  bool = rr->rrsig_set_algorithm(rdata)
  rdata = rr->rrsig_inception
  bool = rr->rrsig_set_inception(rdata)
  rdata = rr->rrsig_expiration
  bool = rr->rrsig_set_expiration(rdata)
  rdata = rr->rrsig_labels
  bool = rr->rrsig_set_labels(rdata)
  rdata = rr->rrsig_origttl
  bool = rr->rrsig_set_origttl(rdata)
  key = rr->get_dnskey_for_rrsig(rrlist)

  rdata = rr->dnskey_algorithm
  bool = rr->dnskey_set_algorithm(rdata)
  rdata = rr->dnskey_flags
  bool = rr->dnskey_set_flags(rdata)
  rdata = rr->dnskey_protocol
  bool = rr->dnskey_set_protocol(rdata)
  rdata = rr->dnskey_key
  bool = rr->dnskey_set_key(rdata)
  bits = rr->dnskey_key_size
  tag = rr->calc_keytag
  ds = rr->key_to_ds(hash)

  rr->is_question

=head1 SEE ALSO

http://www.nlnetlabs.nl/projects/ldns

=head1 AUTHOR

Erik Pihl Ostlyngen, E<lt>erik.ostlyngen@uninett.noE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2013 by Erik Pihl Ostlyngen

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.14.2 or,
at your option, any later version of Perl 5 you may have available.

=cut
