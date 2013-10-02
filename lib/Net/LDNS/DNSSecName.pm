package Net::LDNS::DNSSecName;

use 5.008008;
use strict;
use warnings;

use Net::LDNS ':all';

our $VERSION = '0.02';

sub new {
    my $class = shift;
    return _new;
}

sub name {
    my $self = shift;
    return Net::LDNS::GC::own($self->_name, $self);
}

sub set_name {
    my ($self, $name) = @_;

    Net::LDNS::GC::disown(my $old = $self->name);
    _set_name($self, my $copy = $name->clone);
    Net::LDNS::GC::own($copy, $self);
}

sub rrsets {
    my $self = shift;
    return Net::LDNS::GC::own($self->_rrsets, $self);
}

sub add_rr {
    my ($self, $rr) = @_;

    my $s = _add_rr($self, my $copy = $rr->clone);
    Net::LDNS::GC::own($copy, $self);
    $Net::LDNS::last_status = $s;
    return $s;
}

sub nsec {
    my $self = shift;
    return Net::LDNS::GC::own($self->_nsec, $self);
}

sub set_nsec {
    my ($self, $nsec) = @_;

    Net::LDNS::GC::disown(my $old = $self->nsec);
    _set_nsec($self, my $copy = $nsec->clone);
    Net::LDNS::GC::own($copy, $self);
}

sub hashed_name {
    my $self = shift;
    return Net::LDNS::GC::own($self->_hashed_name, $self);
}

sub nsec_signatures {
    my $self = shift;
    return Net::LDNS::GC::own($self->_nsec_signatures, $self);
}

sub DESTROY {
    Net::LDNS::GC::free($_[0]);
}

1;
=head1 NAME

Net::LDNS - Perl extension for the ldns library

=head1 SYNOPSIS

  use LDNS ':all'

  my name = new Net::LDNS::DNSSecName

  rdata = name->name
  name->set_name(rdata)
  bool = name->is_glue
  rrsets = name->rrsets
  name->add_rr(rr)

  rr = name->nsec
  name->set_nsec(rr)
  hash = name->hashed_name
  rrs = name->nsec_signatures

=head1 SEE ALSO

http://www.nlnetlabs.nl/projects/ldns

=head1 AUTHOR

Erik Pihl Ostlyngen, E<lt>erik.ostlyngen@uninett.noE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2013 by UNINETT Norid AS

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.14.2 or,
at your option, any later version of Perl 5 you may have available.

=cut
