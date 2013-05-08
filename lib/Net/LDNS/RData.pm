package Net::LDNS::RData;

use 5.008008;
use strict;
use warnings;

our $VERSION = '0.02';

require XSLoader;
XSLoader::load('Net::LDNS', $VERSION);

sub new {
    my ($class, $type, $str) = @_;
    return _new($type, $str);
}

sub cat {
    my ($self, $other) = @_;

    my $s = _cat($self, $other);
    $Net::LDNS::last_status = $s;
    return $s;
}

sub nsec3_hash_name {
    my ($self, $algorithm, $iterations, $salt) = @_;

    my $nsec3 = _nsec3_hash_name($self, $algorithm, $iterations, $salt);
    Net::LDNS::GC::own($nsec3, $self) if (defined $nsec3);
    return $nsec3;
}

sub DESTROY {
    Net::LDNS::GC::free($_[0]);
}

1;
=head1 NAME

Net::LDNS - Perl extension for the ldns library

=head1 SYNOPSIS

  use Net::LDNS ':all'

  my rd = new Net::LDNS::RData(rdf_type, str)
  rd2 = rd->clone

  rdf_type = rd->type
  rd->set_type(rdf_type)

  rd->print(\*FILE)
  str = rd->to_string

  count = rd->label_count
  rd2 = rd->label(pos)

  bool = rd->is_wildcard
  bool = rd->matches_wildcard(wildcard)
  bool = rd->is_subdomain(parent)

  rd2 = rd->left_chop

  status = rd->cat(rd2)
  rd->compare(rd2)
  rd2 = rd->address_reverse
  rd2 = rd->dname_reverse

  rd2 = rd->nsec3_hash_name(name, algorithm, iterations, salt)

  epoch = rd->to_unix_time;
( epoch = rd->2native_time_t;)

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
