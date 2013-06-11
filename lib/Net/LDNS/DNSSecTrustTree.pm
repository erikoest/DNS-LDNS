package Net::LDNS::DNSSecTrustTree;

use 5.008008;
use strict;
use warnings;

our $VERSION = '0.02';

require XSLoader;
XSLoader::load('Net::LDNS', $VERSION);

sub add_parent {
    my ($self, $parent, $sig, $parent_status) = @_;

    if (Net::LDNS::GC::is_owned($parent)) {
	die "Cannot add to multiple trees.";
    }
    my $s = _add_parent($self, $parent, $sig, $parent_status);
    Net::LDNS::GC::own($parent, $self);
    $Net::LDNS::last_status = $s;
    return $s;
}

sub contains_keys {
    my ($self, $trusted_keys) = @_;

    my $s = _contains_keys($self, $trusted_keys);
    $Net::LDNS::last_status = $s;
    return $s;
}

sub rr {
    my $self = shift;
    return Net::LDNS::GC::own($self->_rr, $self);
}

sub rrset {
    my $self = shift;
    return Net::LDNS::GC::own($self->_rrset, $self);
}

sub parent {
    my ($self, $i) = @_;
    return Net::LDNS::GC::own($self->_parent($i), $self);
}

sub parent_status {
    my ($self, $i) = @_;
    my $s = _parent_status($self, $i);
    $Net::LDNS::last_status = $s;
    return $s;
}

sub parent_signature {
    my ($self, $i) = @_;
    return Net::LDNS::GC::own($self->_parent_signature($i), $self);
}

1;
=head1 NAME

Net::LDNS - Perl extension for the ldns library

=head1 SYNOPSIS

  use Net::LDNS ':all'

  tree = new Net::LDNS::DNSSecTrustTree
  tree->print(fp)
  d = tree->depth
  status = tree->add_parent(parent, sig, parent_status)
  status = tree->contains_keys(trusted_keys)

  # Node attributes
  rr = tree->rr;
  rrset = tree->rrset
  ptree = tree->parent(i)
  pstatus = tree->parent_status(i)
  rr = tree->parent_signature(i)
  count = tree->parent_count

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
