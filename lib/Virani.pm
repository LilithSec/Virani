package Virani;

use 5.006;
use strict;
use warnings;
use TOML;
use File::Slurp;
use Net::Subnet;

=head1 NAME

Virani - The great new Virani!

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

Quick summary of what the module does.

Perhaps a little code snippet.

    use Virani;

    my $foo = Virani->new();
    ...

=head1 METHODS

=head2 new_from_conf

Initiates the Virani object from the specified file.

    - conf :: The config TOML to use.
        - Default :: /usr/local/etc/virani.toml

=cut

sub new_from_conf {
	my ( $blank, %opts ) = @_;

	if ( !defined( $opts{conf} ) ) {
		$opts{conf} = '/usr/local/etc/virani.toml';
	}

	if ( !-f $opts{conf} ) {
		die( "'" . $opts{conf} . "' is not a file or does not exist" );
	}

	my $raw_toml;
	eval { $raw_toml = read_file( $opts{conf} ); };
	if ( $@ || !defined($raw_toml) ) {
		my $error = 'Failed to read config file, "' . $opts{conf} . '"';
		if ($@) {
			$error = $error . ' ' . $@;
		}
		die($error);
	}

	my $toml;
	eval { $toml = from_toml($raw_toml); };
	if ($@) {
		die($@);
	}

	return Virani->new( %{$toml} );
}

=head2 new



=cut

sub new {
	my ( $blank, %opts ) = @_;

	my $self = {
		allowed_subnets => [ '192.168.0.0/', '127.0.0.1/8', '::1/127', '172.16.0.0/12' ],
		apikey          => '',
		default_set     => 'default',
		sets            => {
			default => {
				path     => '/var/log/daemonlogger',
				regex    => '(?<timestamp>\\d\\d\\d\\d\\d\\d+)(\\.pcap|(?<subsec>\\.\\d+)\\.pcap)$',
				strptime => '%s'
			}
		},

	};
	bless $self;

	# make sure we have a API key
	if ( defined( $opts{apikey} ) ) {
		$self->{apikey} = $opts{apikey};
	}
	else {
		die("$opts{apikey} not set");
	}

	if ( defined( $opts{allowed_subnets} ) && ref( $opts{allowed_subnets}) eq 'ARRAY' ) {
		$self->{allowed_subnets} = $opts{allowed_subnets};
	}
	elsif ( defined( $opts{allowed_subnets} ) && ref( $opts{allowed_subnets}) ne 'ARRAY' ) {
		die("$opts{allowed_subnets} defined, but not a array");
	}

	if ( defined( $opts{default_set} ) ) {
		$self->{default_set} = $opts{default_set};
	}

	if ( defined( $opts{set} ) ) {
		$self->{sets} = $opts{set};
	}

	return $self;
}

=head1 check_remote_ip

Checks if the remote IP is allowed or not.

=cut

sub check_remote_ip{
	my $self=$_[0];
	my $ip=$_[1];

	if (!defined($ip)) {
		die("No IP specified");
	}

	if (!defined( $self->{allowed_subnets}[0]) ) {
		return 1;
	}

	my $allowed_subnets;
	eval{
		$allowed_subnets=subnet_matcher(@{ $self->{allowed_subnets} });
	};
	if ($@) {
		die('Failed it init subnet matcher... '.$@);
	}elsif (!defined($allowed_subnets)) {
		die('Failed it init subnet matcher... sub_matcher returned undef');
	}

	if ($allowed_subnets->($ip)) {
		return 1;
	}

	return 0;
}

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-virani at rt.cpan.org>, or through
the web interface at L<https://rt.cpan.org/NoAuth/ReportBug.html?Queue=Virani>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Virani


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

1;    # End of Virani
