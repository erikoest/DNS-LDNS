package Net::LDNS::Zone;

use 5.008008;
use strict;
use warnings;

use Net::LDNS ':all';

our $VERSION = '0.02';

require XSLoader;
XSLoader::load('Net::LDNS', $VERSION);

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

    if ($file) {
	$zone = _new_from_file($file, $args{origin}, $args{ttl}, $args{class}, 
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

sub to_string {
    my $self = shift;

    return join('', map { $self->$_ ? $self->$_->to_string : '' } qw/soa rrs/);
}

sub soa {
    my $self = shift;
    my $soa = _soa($self);
    Net::LDNS::GC::own($soa, $self) if (defined $soa);
    return $soa;
}

sub set_soa {
    my ($self, $soa) = @_;
    my $oldsoa = $self->soa;
    Net::LDNS::GC::disown($oldsoa) if (defined $oldsoa);
    # Set a copy of the soa in case it is already owned
    _set_soa($self, my $copy = $soa->clone);
    Net::LDNS::GC::own($copy, $self);
}

sub rrs {
    my $self = shift;
    my $list = _rrs($self);
    Net::LDNS::GC::own($list, $self) if (defined $list);
    return $list;
}

sub set_rrs {
    my ($self, $list) = @_;
    my $oldlist = $self->rrs;
    Net::LDNS::GC::disown($oldlist) if (defined $oldlist);
    _set_rrs($self, my $copy = $list->clone);
    Net::LDNS::GC::own($copy, $self);
}

sub DESTROY {
    Net::LDNS::GC::free($_[0]);
}

1;
__END__

=head1 NAME

Net::LDNS - Perl extension for the ldns library

=head1 SYNOPSIS

  use Net::LDNS ':all'

  my z = new Net::LDNS::Zone(
    filename => '/path/to/myzone',
    origin => new Net::LDNS::RData(LDNS_RDF_TYPE_DNAME, 'myzone'), #optional
    ttl => 3600, #optional
    class => LDNS_RR_CLASS_, #optional
  )
  my z = new Net::LDNS::Zone(
    file => \*FILE,
    origin => ..., ttl => ..., class => ...
  )
  my z = new Net::LDNS::Zone

  z->to_string
  z->print(\*FILE)
  z->canonicalize
  z->sort
  rr = z->soa
  z->set_soa(rr)
  rrlist = z->rrs
  z->set_rrs(rrlist)
  z->sign(keylist)
  z->sign_nsec3(keylist, algorithm, flags, iterations, salt)

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
