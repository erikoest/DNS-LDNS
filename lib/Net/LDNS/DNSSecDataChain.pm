package Net::LDNS::DNSSecDataChain;

use 5.008008;
use strict;
use warnings;

our $VERSION = '0.02';

require XSLoader;
XSLoader::load('Net::LDNS', $VERSION);

sub rrset {
    my $self = shift;
    my $rrset = _rrset($self);
    Net::LDNS::GC::own($rrset, $self) if (defined $rrset);
    return $rrset;
}

sub signatures {
    my $self = shift;
    my $sig = _signatures($self);
    Net::LDNS::GC::own($sig, $self) if (defined $sig);
    return $sig;
}

sub parent {
    my $self = shift;
    my $p = _parent($self);
    Net::LDNS::GC::own($p, $self) if (defined $p);
    return $p;
}

sub derive_trust_tree {
    my ($self, $rr) = @_;

    if (!Net::LDNS::GC::is_owned($rr) or Net::LDNS::GC::owner($rr) ne $self) {
	die "The rr ($rr) must be in the data chain ($self)";
    }
    my $tree = _derive_trust_tree($self, $rr);    
    Net::LDNS::GC::own($tree, $self) if (defined $tree);
    return $tree;
}

1;
=head1 NAME

Net::LDNS - Perl extension for the ldns library

=head1 SYNOPSIS

  use Net::LDNS ':all'

  chain = new Net::LDNS::DNSSecDataChain
  chain->print(fp)
  chain->derive_trust_tree(rr)

  # Node attributes
  rrset = chain->rrset
  rrset = chain->signatures
  rrtype = chain->parent_type
  pchain = chain->parent
  rcode = chain->packet_rcode
  rrtype = chain->packet_qtype
  bool = chain->packet_nodata

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
