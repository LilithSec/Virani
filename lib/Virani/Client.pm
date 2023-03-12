package Virani::Client;

use 5.006;
use strict;
use warnings;
use LWP::UserAgent;
use HTTP::Request::Common;

=head1 NAME

Virani::Client - Client for remotely accessing Virani vis HTTP or HTTPS.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

Quick summary of what the module does.

Perhaps a little code snippet.

    use Virani::Client;

    my $virani_client = Virani::Client->new(apikey=>$apikey, url=>$url, SSL_verify_mode=>0, verify_hostname=>0, timeout=>30);


=head1 METHODS


=head2 new



=cut

sub new {
	my ( $blank, %opts ) = @_;

	if ( !defined( $opts{url} ) ) {
		die('No url defined');
	}

	my $self = {
		apikey => $opts{apikey},
		url    => $opts{url},
	};
	bless $self;

	return $self;
}

=head2 fetch

=cut

sub fetch{
	my ( $self, %opts ) = @_;

	if (!defined($opts{filter})) {
		$opts{filter}='';
	}

	if (!defined($opts{type})) {
		$opts{type}='tcpdump';
	}

	my $ua= LWP::UserAgent->new();
}

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-virani at rt.cpan.org>, or through
the web interface at L<https://rt.cpan.org/NoAuth/ReportBug.html?Queue=Virani>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Virani::Client


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<https://rt.cpan.org/NoAuth/Bugs.html?Dist=Virani>

=item * CPAN Ratings

L<https://cpanratings.perl.org/d/Virani>

=item * Search CPAN

L<https://metacpan.org/release/Virani>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2023 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The GNU Lesser General Public License, Version 2.1, February 1999


=cut

1;    # End of Virani::Client
