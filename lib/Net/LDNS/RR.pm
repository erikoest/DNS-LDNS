package Net::LDNS::RR;

use 5.008008;
use strict;
use warnings;

use Net::LDNS ':all';

our $VERSION = '0.02';

require XSLoader;
XSLoader::load('Net::LDNS', $VERSION);

sub new {
    my ($class, %args) = @_;

    my $rr;
    my $status = &LDNS_STATUS_OK;

    if ($args{str}) {
	$rr = _new_from_str($args{str}, $args{default_ttl}, 
			    $args{origin}, $status);
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

	$rr = _new_from_file($file, $args{default_ttl}, $args{origin}, 
			     $status, $line_nr);
	if ($args{filename}) {
	    close $file;
	}

	$Net::LDNS::last_status = $status;
	$Net::LDNS::line_nr = $line_nr;
	if (!defined $rr) {
	    return;
	}
    }
    elsif ($args{type}) {
	$rr = _new_from_type($args{type});
	if ($args{owner}) {
	    $rr->set_owner($args{owner});
	}
	if ($args{ttl}) {
	    $rr->set_ttl($args{ttl});
	}
	if ($args{class}) {
	    $rr->set_class($args{class});
	}
	if ($args{rdata}) {
	    if (!$rr->set_rdata(@{$args{rdata}})) {
		return;
	    }
	}
    }
    else {
	$rr = _new();
    }

    if (!defined $rr) {
	$Net::LDNS::last_status = $status;
	return;
    }
    return $rr;
}

sub owner {
    my $self = shift;
    my $owner = _owner($self);
    Net::LDNS::GC::own($owner, $self) if (defined $owner);
    return $owner;
}

sub set_owner {
    my ($self, $owner) = @_;
    my $oldowner = $self->owner;
    Net::LDNS::GC::disown($oldowner) if (defined $oldowner);
    $self->_set_owner($owner);
    Net::LDNS::GC::own($owner, $self);
    return $owner;
}

sub dname {
    return $_[0]->owner->to_string;
}

sub rdata {
    my ($self, $index) = @_;

    my $rdata = _rdata($self, $index);
    Net::LDNS::GC::own($rdata, $self) if (defined $rdata);
    return $rdata;
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
	Net::LDNS::GC::disown($oldrd) if (defined $oldrd);
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
    my $type = _rrsig_typecovered($self);
    Net::LDNS::GC::own($type, $self) if (defined $type);
    return $type;
}

sub rrsig_set_typecovered {
    my ($self, $type) = shift;
    my $result = $self->_rrsig_set_typecovered(my $copy = $type->clone);
    Net::LDNS::GC::own($copy, $self);
    return $result;
}

sub rrsig_algorithm {
    my $self = shift;
    my $algo = _rrsig_algorithm($self);
    Net::LDNS::GC::own($algo, $self) if (defined $algo);
    return $algo;
}

sub rrsig_set_algorithm {
    my ($self, $algo) = shift;
    my $result = $self->_rrsig_set_algorithm(my $copy = $algo->clone);
    Net::LDNS::GC::own($copy, $self);
    return $result;
}

sub rrsig_expiration {
    my $self = shift;
    my $date = _rrsig_expiration($self);
    Net::LDNS::GC::own($date, $self) if (defined $date);
    return $date;
}

sub rrsig_set_expiration {
    my ($self, $date) = shift;
    my $result = $self->_rrsig_set_expiration(my $copy = $date->clone);
    Net::LDNS::GC::own($copy, $self);
    return $result;
}

sub rrsig_inception {
    my $self = shift;
    my $date = _rrsig_inception($self);
    Net::LDNS::GC::own($date, $self) if (defined $date);
    return $date;
}

sub rrsig_set_inception {
    my ($self, $date) = shift;
    my $result = $self->_rrsig_set_inception(my $copy = $date->clone);
    Net::LDNS::GC::own($copy, $self);
    return $result;
}

sub rrsig_keytag {
    my $self = shift;
    my $tag = _rrsig_keytag($self);
    Net::LDNS::GC::own($tag, $self) if (defined $tag);
    return $tag;
}

sub rrsig_set_keytag {
    my ($self, $tag) = shift;
    my $result = $self->_rrsig_set_keytag(my $copy = $tag->clone);
    Net::LDNS::GC::own($copy, $self);
    return $result;
}

sub rrsig_sig {
    my $self = shift;
    my $sig = _rrsig_sig($self);
    Net::LDNS::GC::own($sig, $self) if (defined $sig);
    return $sig;
}

sub rrsig_set_sig {
    my ($self, $sig) = shift;
    my $result = $self->_rrsig_set_sig(my $copy = $sig->clone);
    Net::LDNS::GC::own($copy, $self);
    return $result;
}

sub rrsig_labels {
    my $self = shift;
    my $lab = _rrsig_labels($self);
    Net::LDNS::GC::own($lab, $self) if (defined $lab);
    return $lab;
}

sub rrsig_set_labels {
    my ($self, $lab) = shift;
    my $result = $self->_rrsig_set_labels(my $copy = $lab->clone);
    Net::LDNS::GC::own($copy, $self);
    return $result;
}

sub rrsig_origttl {
    my $self = shift;
    my $ttl = _rrsig_origttl($self);
    Net::LDNS::GC::own($ttl, $self) if (defined $ttl);
    return $ttl;
}

sub rrsig_set_origttl {
    my ($self, $lab) = shift;
    my $result = $self->_rrsig_set_origttl(my $copy = $lab->clone);
    Net::LDNS::GC::own($copy, $self);
    return $result;
}

sub rrsig_signame {
    my $self = shift;
    my $name = _rrsig_signame($self);
    Net::LDNS::GC::own($name, $self) if (defined $name);
    return $name;
}

sub rrsig_set_signame {
    my ($self, $name) = shift;
    my $result = $self->_rrsig_set_signame(my $copy = $name->clone);
    Net::LDNS::GC::own($copy, $self);
    return $result;
}

sub dnskey_algorithm {
    my $self = shift;
    my $algo = _dnskey_algorithm($self);
    Net::LDNS::GC::own($algo, $self) if (defined $algo);
    return $algo;
}

sub dnskey_set_algorithm {
    my ($self, $algo) = shift;
    my $result = $self->_dnskey_set_algorithm(my $copy = $algo->clone);
    Net::LDNS::GC::own($copy, $self);
    return $result;
}

sub dnskey_flags {
    my $self = shift;
    my $flags = _dnskey_flags($self);
    Net::LDNS::GC::own($flags, $self) if (defined $flags);
    return $flags;
}

sub dnskey_set_flags {
    my ($self, $flags) = shift;
    my $result = $self->_dnskey_set_flags(my $copy = $flags->clone);
    Net::LDNS::GC::own($copy, $self);
    return $result;
}

sub dnskey_protocol {
    my $self = shift;
    my $proto = _dnskey_protocol($self);
    Net::LDNS::GC::own($proto, $self) if (defined $proto);
    return $proto;
}

sub dnskey_set_protocol {
    my ($self, $proto) = shift;
    my $result = $self->_dnskey_set_protocol(my $copy = $proto->clone);
    Net::LDNS::GC::own($copy, $self);
    return $result;
}

sub dnskey_key {
    my $self = shift;
    my $key = _dnskey_key($self);
    Net::LDNS::GC::own($key, $self) if (defined $key);
    return $key;
}

sub dnskey_set_key {
    my ($self, $key) = shift;
    my $result = $self->_dnskey_set_key(my $copy = $key->clone);
    Net::LDNS::GC::own($copy, $self);
    return $result;
}

sub nsec3_next_owner {
    my $self = shift;
    my $owner = _nsec3_next_owner($self);
    Net::LDNS::GC::own($owner, $self) if (defined $owner);
    return $owner;
}

sub nsec3_bitmap {
    my $self = shift;
    my $owner = _nsec3_bitmap($self);
    Net::LDNS::GC::own($owner, $self) if (defined $owner);
    return $owner;
}

sub nsec3_salt {
    my $self = shift;
    my $owner = _nsec3_salt($self);
    Net::LDNS::GC::own($owner, $self) if (defined $owner);
    return $owner;
}

sub hash_name_from_nsec3 {
    my ($self, $name) = @_;
    my $hash = _hash_name_from_nsec3($self, $name);
    Net::LDNS::GC::own($hash, $self) if (defined $hash);
    return $hash;
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
    Net::LDNS::GC::own($match, $nsecs);
    return $match;
}

sub DESTROY {
    Net::LDNS::GC::free($_[0]);
}

1;

=head1 NAME

Net::LDNS - Perl extension for the ldns library

=head1 SYNOPSIS

  use Net::LDNS ':all'

  my rr = new Net::LDNS::RR(
    str => 'mylabel 3600 IN A 168.10.10.10',
    default_ttl => 3600, # optional,
    origin => new Net::LDNS::RData(LDNS_RDF_TYPE_NAME, 'myzone.'), " optional
  )
  my rr = new Net::LDNS::RR(
    filename => '/path/to/rr',
    default_ttl => ..., origin => ...)
  my rr = new Net::LDNS::RR(
    file => \*FILE,
    default_ttl => ..., origin => ...)
  my rr = new Net::LDNS::RR(
    type => LDNS_RR_TYPE_A,
    rdata => [new RData(...), new RData(...), ...],
    class => LDNS_RR_CLASS_*, # optional
    ttl => 3600, # optional
    owner => new RData(LDNS_RDF_TYPE_NAME, 'mylabel'), # optional)
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
  ds = rr->key_to_ds

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
