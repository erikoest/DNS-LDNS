package Net::LDNS::RBNode;

use 5.008008;
use strict;
use warnings;

our $VERSION = '0.02';

require XSLoader;
XSLoader::load('Net::LDNS', $VERSION);

# Note: This class does not have a constructor. Thus, it can not be created
# as an individual object. The data structure of the object will always be 
# owned and freed by its parent object.

sub next {
    my $self = shift;
    my $node = _next($self);
    Net::LDNS::GC::own($node, $self) if (defined $node);
    return $node;
}

sub previous {
    my $self = shift;
    my $node = _previous($self);
    Net::LDNS::GC::own($node, $self) if (defined $node);
    return $node;
}

sub next_nonglue {
    my $self = shift;
    my $node = _next_nonglue($self);
    Net::LDNS::GC::own($node, $self) if (defined $node);
    return $node;
}

sub name {
    my ($self) = @_;
    my $name = _name($self);
    Net::LDNS::GC::own($name, $self) if (defined $name);
    return $name;
}

sub DESTROY {
    Net::LDNS::GC::free($_[0]);
}

1;
=head1 NAME

Net::LDNS - Perl extension for the ldns library

=head1 SYNOPSIS

  use Net::LDNS ':all'

  node2 = node->next
  node2 = node->next_nonglue
  bool = node->is_null
  dnssec_name = node->name

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
