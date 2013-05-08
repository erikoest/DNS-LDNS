package Net::LDNS::KeyList;

use 5.008008;
use strict;
use warnings;

use Net::LDNS ':all';

our $VERSION = '0.02';

require XSLoader;
XSLoader::load('Net::LDNS', $VERSION);

sub new {
    my $class = shift;
    
    return _new();
}

sub push {
    my ($self, @keys) = @_;

    for my $k (@keys) {
	if (Net::LDNS::GC::is_owned($k)) {
	    die "Cannot push a key on multiple lists.";
	}
	$self->_push($k);
	Net::LDNS::GC::own($k, $self);
    }
}

sub key {
    my ($self, $index) = @_;

    my $key = _key($self, $index);
    Net::LDNS::GC::own($key, $self) if (defined $key);
    return $key;
}

sub DESTROY {
    Net::LDNS::GC::free($_[0]);
}

1;
=head1 NAME

Net::LDNS - Perl extension for the ldns library

=head1 SYNOPSIS

  use Net::LDNS ':all'

  my l = new Net::LDNS::KeyList
  l->set_use(bool)
  l->push(@keys)
  key = l->pop
  c = l->count
  key = l->key(index)

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
