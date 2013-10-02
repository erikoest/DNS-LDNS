package Net::LDNS::RBTree;

use 5.008008;
use strict;
use warnings;

use Net::LDNS;

our $VERSION = '0.02';

# Note: Since this class does not have a constructor, we can let its child
# objects be owned by the parent. This reduces the recursion depth on
# DESTROY.

sub first {
    my $self = shift;
    return Net::LDNS::GC::own($self->_first, $self);
}

sub last {
    my $self = shift;
    return Net::LDNS::GC::own($self->_last, $self);
}

sub DESTROY {
    Net::LDNS::GC::free($_[0]);
}

1;
=head1 NAME

Net::LDNS - Perl extension for the ldns library

=head1 SYNOPSIS

  use Net::LDNS ':all'

  rbnode = rbtree->first
  rbnode = rbtree->last

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
