package Net::LDNS::DNSSecZone;

use 5.008008;
use strict;
use warnings;

use Net::LDNS ':all';

our $VERSION = '0.02';

sub new {
    my ($class, %args) = @_;

    my $line_nr;
    my $status = &LDNS_STATUS_OK;
    my $zone;
    my $file;

    if ($args{filename}) {
	unless (open FILE, $args{filename}) {
	    $Net::LDNS::last_status = &LDNS_STATUS_FILE_ERR;
	    $Net::LDNS::line_nr = 0;
	    return;
	}

	$file = \*FILE;
    }
    elsif ($args{file}) {
	$file = $args{file};
    }

    if ($file) {
	$zone = _new_from_file($file, 
			       $args{origin} || $LDNS::DEFAULT_ORIGIN, 
			       $args{ttl} || $LDNS::DEFAULT_TTL, 
			       $args{class} || $LDNS::DEFAULT_CLASS, 
			       $status, $line_nr);
    }
    else {
	$zone = _new();
    }

    if ($args{filename}) {
	close $file;
    }

    $Net::LDNS::last_status = $status;
    $Net::LDNS::line_nr = $line_nr;
    if (!defined $zone) {
	return;
    }

    return $zone;
}

sub soa {
    my $self = shift;
    return Net::LDNS::GC::own($self->_soa, $self);
}

sub names {
    my $self = shift;
    return Net::LDNS::GC::own($self->_names, $self);
}

sub find_rrset {
    my ($self, $name, $type) = @_;
    return Net::LDNS::GC::own($self->_find_rrset($name, $type), $self);
}

sub add_rr {
    my ($self, $rr) = @_;

    # Set a copy of the rr in case it is already owned
    my $s = _add_rr($self, my $copy = $rr->clone);
    $Net::LDNS::last_status = $s;
    Net::LDNS::GC::own($copy, $self);
    return $s;
}

sub add_empty_nonterminals {
    my $self = shift;
    my $s = _add_empty_nonterminals($self);
    $Net::LDNS::last_status = $s;
    return $s;
}

sub mark_glue {
    my $self = shift;
    my $s = _mark_glue($self);
    $Net::LDNS::last_status = $s;
    return $s;
}

sub sign {
    my ($self, $keylist, $policy, $flags) = @_;
    my $s = _sign($self, $keylist, $policy, $flags);
    $Net::LDNS::last_status = $s;
    return $s;
}

sub sign_nsec3 {
    my ($self, $keylist, $policy, $algorithm, $flags, $iterations, $salt,
	$signflags) = @_;
    my $s = _sign_nsec3($self, $keylist, $policy, $algorithm, $flags, 
	$iterations, $salt, $signflags);
    $Net::LDNS::last_status = $s;
    return $s;
}

sub to_string {
    return "Net::LDNS::DNSSecZone::to_string is not yet implemented";
}

sub DESTROY {
    Net::LDNS::GC::free($_[0]);
}

1;
=head1 NAME

Net::LDNS - Perl extension for the ldns library

=head1 SYNOPSIS

  use Net::LDNS ':all'

  my z = new Net::LDNS::DNSSecZone(
    filename => '/path/to/myzone',
    origin => new Net::LDNS::RData(LDNS_RDF_TYPE_DNAME, 'myzone'), #optional
    ttl => 3600, #optional
    class => LDNS_RR_CLASS_, #optional
  )
  my z = new Net::LDNS::DNSSecZone(
    file => \*FILE,
    origin => ..., ttl => ..., class => ...
  )
  my z = new Net::LDNS::DNSSecZone

  rr = z->soa
  rbtree = z->names
  rrsets = z->find_rrset
  z->add_rr(rr)
  z->create_from_zone(zone)
  z->add_empty_nonterminals

  z->sign(keylist, policy)
  z->sign_nsec3(keylist, policy, algorithm, flags, iterations, salt)

  z->create_nsecs
  z->create_nsec3s(algorithm, flags, iterations, salt)
  z->create_rrsigs(key_list, policy, flags)

=head1 TODO

  z->to_string

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
