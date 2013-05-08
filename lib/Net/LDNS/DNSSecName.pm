package Net::LDNS::DNSSecName;

use 5.008008;
use strict;
use warnings;

use Net::LDNS ':all';

our $VERSION = '0.02';

require XSLoader;
XSLoader::load('Net::LDNS', $VERSION);

sub new {
    my $class = shift;
    return _new;
}

sub name {
    my $self = shift;
    my $name = _name($self);
    Net::LDNS::GC::own($name, $self) if (defined $name);
    return $name;    
}

sub set_name {
    my ($self, $name) = @_;

    _set_name($self, my $copy = $name->clone);
    Net::LDNS::GC::own($copy, $self);
}

sub rrsets {
    my $self = shift;
    my $rrsets = _rrsets($self);
    Net::LDNS::GC::own($rrsets, $self) if (defined $rrsets);
    return $rrsets;
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
    my $nsec = _nsec($self);
    Net::LDNS::GC::own($nsec, $self) if (defined $nsec);
    return $nsec;
}

sub set_nsec {
    my ($self, $nsec) = @_;

    _set_nsec($self, my $copy = $nsec->clone);
    Net::LDNS::GC::own($copy, $self);
}

sub hashed_name {
    my $self = shift;
    my $hname = _hashed_name($self);
    Net::LDNS::GC::own($hname, $self) if (defined $hname);
    return $hname;
}

sub nsec_signatures {
    my $self = shift;
    my $sigs = _nsec_signatures($self);
    Net::LDNS::GC::own($sigs, $self) if (defined $sigs);
    return $sigs;
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

Copyright (C) 2013 by Erik Pihl Ostlyngen

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.14.2 or,
at your option, any later version of Perl 5 you may have available.

=cut
