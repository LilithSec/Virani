package Virani;

use 5.006;
use strict;
use warnings;
use TOML;
use File::Slurp;
use Net::Subnet;
use File::Find::IncludesTimeRange;
use File::Find::Rule;
use Digest::MD5 qw(md5_hex);
use File::Spec;
use IPC::Cmd qw(run);
use File::Copy "cp";

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

	# allow overriding the api key or setting a blank one
	if ( defined( $opts{apikey} ) ) {
		$toml->{apikey} = $opts{apikey};
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
		cache           => '/var/cache/virani',
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

	if ( defined( $opts{allowed_subnets} ) && ref( $opts{allowed_subnets} ) eq 'ARRAY' ) {
		$self->{allowed_subnets} = $opts{allowed_subnets};
	}
	elsif ( defined( $opts{allowed_subnets} ) && ref( $opts{allowed_subnets} ) ne 'ARRAY' ) {
		die("$opts{allowed_subnets} defined, but not a array");
	}

	if ( defined( $opts{default_set} ) ) {
		$self->{default_set} = $opts{default_set};
	}

	if ( defined( $opts{set} ) ) {
		$self->{sets} = $opts{set};
	}

	if ( defined( $opts{cache} ) ) {
		$self->{sets} = $opts{cache};
	}

	return $self;
}

=head1 check_remote_ip

Checks if the remote IP is allowed or not.

=cut

sub check_remote_ip {
	my $self = $_[0];
	my $ip   = $_[1];

	if ( !defined($ip) ) {
		die("No IP specified");
	}

	if ( !defined( $self->{allowed_subnets}[0] ) ) {
		return 1;
	}

	my $allowed_subnets;
	eval { $allowed_subnets = subnet_matcher( @{ $self->{allowed_subnets} } ); };
	if ($@) {
		die( 'Failed it init subnet matcher... ' . $@ );
	}
	elsif ( !defined($allowed_subnets) ) {
		die('Failed it init subnet matcher... sub_matcher returned undef');
	}

	if ( $allowed_subnets->($ip) ) {
		return 1;
	}

	return 0;
}

=head2 bpf_clean

Removes starting and trailing whitespace as well as collapsing
consecutive whitespace to a single space.

The purpose for this is to make sure that BPF filters passed
are consistent for cacheing, even if their white space differs.

A undef passed to it will return ''.

Will die if the BPF matches /^\w*\-/ as it starts with a '-', which
tcpdump will interpret as a switch.

    my $cleaned_bpf=$virani->bpf_clean($bpf);

=cut

sub bpf_clean {
	my $self   = $_[0];
	my $string = $_[1];

	if ( !defined($string) ) {
		return '';
	}

	if ( $string =~ /^\w*\-/ ) {
		die( 'The BPF, "' . $string . '", begins with a "-", which dieing for safety reasons' );
	}

	# remove white space at the start and end
	$string =~ s/^\s*//g;
	$string =~ s/\s+$//g;

	# replace all multiple white space characters with a single space
	$string =~ s/\s\s+/ /g;

	return $string;
}

=head2 get_pcap_local

Generates a PCAP locally and returns the path to it.

    - start :: A L<Time::Piece> object of when to start looking.
        - Default :: undef

    - end :: A L<Time::Piece> object of when to stop looking.
        - Default :: undef

    - padding :: Number of seconds to pad the start and end with.
        - Default :: 5

    - bpf :: The BPF filter to use.
        - Default :: ''

    - set :: The PCAP set to use.
        - Default :: default

    - file :: The file to output to. If undef it just returns the path to
              the cache file.
        - Default :: undef

    - no_cache :: Don't cache this entry, just use the the the cache dir or dir
                  as scratch space. If the cache dir is not writable, CWD will be
                  tried.
        - Default :: undef

    - auto_no_cache :: If the cache dir is being used and not writeable and a file
                       as been specified, don't die, but just CWD as the scrach dir.
        - Default :: 1

    - verbose :: Print out what it is doing.
        - Default :: 1

The return is a hash reference that includes the following keys.

    - pcaps :: A array of PCAPs used.

    - pcap_count :: A count of used PCAPs.

    - failed :: A hash of PCAPs that failed. PCAP path as key and value being the reason.

    - failed_count :: A count of failed PCAPs.

    - path :: The path to the results file. If undef, unable it was unable
              to process any of them.

    - success_found :: A count of successfully processed PCAPs.

    - bpf :: The used BPF.

=cut

sub get_pcap_local {
	my ( $self, %opts ) = @_;

	# basic sanity checking
	if ( !defined( $opts{start} ) ) {
		die('$opts{start} not defined');
	}
	elsif ( !defined( $opts{end} ) ) {
		die('$opts{start} not defined');
	}
	elsif ( ref( $opts{start} ) ne 'Time::Piece' ) {
		die('$opts{start} is not a Time::Piece object');
	}
	elsif ( ref( $opts{end} ) ne 'Time::Piece' ) {
		die('$opts{end} is not a Time::Piece object');
	}
	elsif ( defined( $opts{padding} ) && $opts{padding} !~ /^\d+/ ) {
		die('$opts{padding} is not numeric');
	}

	if ( !defined( $opts{padding} ) ) {
		$opts{padding} = 5;
	}

	if ( !defined( $opts{auto_no_cache} ) ) {
		$opts{auto_no_cache} = 1;
	}

	if ( !defined( $opts{set} ) ) {
		$opts{set} = 'default';
	}

	if ( !defined( $opts{verbose} ) ) {
		$opts{verbose} = 1;
	}

	# make sure the set exists
	if ( !defined( $self->{sets}->{ $opts{set} } ) ) {
		die( 'The set "' . $opts{set} . '" is not defined' );
	}
	elsif ( !defined( $self->{sets}->{ $opts{set} }{path} ) ) {
		die( 'The path for set "' . $opts{set} . '" is not defined' );
	}
	elsif ( !-d $self->{sets}->{ $opts{set} }{path} ) {
		die(      'The path for set "'
				. $opts{set} . '", "'
				. $self->{sets}->{ $opts{set} }{path}
				. '" is not exist or is not a directory' );
	}

	# clean the bpf
	$opts{bpf} = $self->bpf_clean( $opts{bpf} );

	# get the pcaps
	my @pcaps = File::Find::Rule->file()->name("*.pcap*")->in( $self->{sets}->{ $opts{set} }{path} );

	my $to_check = File::Find::IncludesTimeRange->find(
		items => \@pcaps,
		start => $opts{start},
		end   => $opts{end},
	);

	my $cache_file;
	if ( defined( $opts{file} ) ) {
		my ( $volume, $directories, $file ) = File::Spec->splitpath( $opts{file} );

		# make sure the directory the output file is using exists
		if ( $directories ne '' && !-d $directories ) {
			die(      '$opts{file} is set to "'
					. $opts{file}
					. '" but the directory part,"'
					. $directories
					. '", does not exist' );
		}

		# figure what what to use as the cache file
		if ( $opts{no_cache} ) {
			$cache_file = $opts{file};
		}
		elsif ( $opts{auto_no_cache} && ( !-d $self->{cache} || !-w $self->{cache} ) ) {
			$cache_file = $opts{file};
		}
		elsif ( !$opts{auto_no_cache} && ( !-d $self->{cache} || !-w $self->{cache} ) ) {
			die(      '$opts{auto_no_cache} is false and $opts{no_cache} is false, but the cache dir "'
					. $self->{dir}
					. '" does not exist, is not a dir, or is not writable' );
		}
	}
	else {
		# make sure the cache is usable
		if ( !-d $self->{cache} ) {
			die( 'Cache dir,"' . $self->{cache} . '", does not exist or is not a dir' );
		}
		elsif ( !-w $self->{cache} ) {
			die( 'Cache dir,"' . $self->{cache} . '", is not writable' );
		}

		$cache_file
			= $self->{cache} . '/' . $opts{start}->epoch . '-' . $opts{end}->epoch . "-" . lc( md5_hex( $opts{bpf} ) );
	}

	# The path to return.
	my $to_return = {
		pcaps         => $to_check,
		pcap_count    => 0,
		failed        => {},
		failed_count  => 0,
		success_count => 0,
		path          => $cache_file,
		bpf           => $opts{bpf},
	};

	if ( $opts{verbose} ) {
		print 'BPF: ' . $opts{bpf} . "\n";
	}

	# used for tracking the files to cleanup
	my @tmp_files;

	# the merge command
	my $to_merge = [ 'mergecap', '-w', $cache_file ];
	foreach my $pcap ( @{$to_check} ) {
		if ( $opts{verbose} ) {
			print 'Processing ' . $pcap . " ...\n";
		}

		my $tmp_file = $cache_file . '-' . $to_return->{pcap_count};

		my ( $success, $error_message, $full_buf, $stdout_buf, $stderr_buf ) = run(
			command => [ 'tcpdump', '-r', $pcap, '-w', $tmp_file, $opts{bpf} ],
			verbose => 0
		);
		if ($success) {
			push( @{$to_merge}, $tmp_file );
			$to_return->{success_count}++;
			push( @tmp_files, $tmp_file );
		}
		else {
			$to_return->{failed}{$pcap} = $error_message;
			$to_return->{failed_count}++;

			if ( $opts{verbose} ) {
				print 'Failed ' . $pcap . " ... " . $error_message . "\n";
			}

			unlink $tmp_file;
		}

		$to_return->{pcap_count}++;
	}

	# only try merging if we had more than one success
	if ( $to_return->{success_count} > 0 ) {
		if ( $opts{verbose} ) {
			print "Merging PCAPs...\n";
		}
		my ( $success, $error_message, $full_buf, $stdout_buf, $stderr_buf ) = run(
			command => $to_merge,
			verbose => 0
		);
		if ($success) {
			if ( $opts{verbose} ) {
				print "PCAPs merged into " . $cache_file . "\n";
			}
		}
		else {
			if ( $opts{verbose} ) {
				print "PCAPs merge failed " . $error_message . "\n";
			}
		}

		# remove each tmp file
		foreach my $tmp_file (@tmp_files) {
			unlink($tmp_file);
		}
	}else {
		if ( $opts{verbose} ) {
			print "No PCAPs to merge.\n";
		}
	}

	if ( $cache_file ne $opts{file} ) {
		cp( $cache_file, $opts{file} );
	}

	return $to_return;
}

=head2 timestamp_to_object

Takes a string and figures out the format to use to return a Time::Piece object.

The following formats are supported. Microseconds are removed as L<Time::Piece> does
not have 

    %s
    %s\.\d*
    %Y-%m-%d %H:%M%z
    %Y-%m-%d %H:%M:%S%z
    %Y-%m-%d %H:%M:%S\.\d*%z
    %Y-%m-%dT%H:%M%z
    %Y-%m-%dT%H:%M:%S%z
    %Y-%m-%dT%H:%M:%S\.\d*%z
    %Y-%m-%d/%H:%M%z
    %Y-%m-%d/%H:%M:%S%z
    %Y-%m-%d/%H:%M:%S\.\d*%z
    %Y-%m-%d %H:%M
    %Y-%m-%d %H:%M:%S
    %Y-%m-%d %H:%M:%S\.\d*
    %Y-%m-%dT%H:%M
    %Y-%m-%dT%H:%M:%S
    %Y-%m-%dT%H:%M:%S\.\d*
    %Y-%m-%d/%H:%M
    %Y-%m-%d/%H:%M:%S
    %Y-%m-%d/%H:%M:%S\.\d*
    %Y%m%d %H:%M%Z
    %Y%m%d %H:%M:%S%Z
    %Y%m%d %H:%M:%S\.\d*%Z
    %Y%m%dT%H:%M%Z
    %Y%m%dT%H:%M:%S%Z
    %Y%m%dT%H:%M:%S\.\d*%Z
    %Y%m%d/%H:%M%Z
    %Y%m%d/%H:%M:%S%Z
    %Y%m%d/%H:%M:%S\.\d*%Z
    %Y%m%d %H:%M
    %Y%m%d %H:%M:%S
    %Y%m%d %H:%M:%S\.\d*
    %Y%m%dT%H:%M
    %Y%m%dT%H:%M:%S
    %Y%m%dT%H:%M:%S\.\d*
    %Y%m%d/%H:%M
    %Y%m%d/%H:%M:%S
    %Y%m%d/%H:%M:%S\.\d*

=cut

sub timestamp_to_object {
	my ( $self, $string ) = @_;

	if ( !defined($string) ) {
		die('No string passed');
	}

	# remove micro seconds if they are present
	$string =~ s/\.\d+$//;
	$string =~ s/\.\d+([\-\+]\d+)$/$1/;

	my $format;
	if ( $string =~ /^\d+$/ ) {
		$format = '%s';
	}
	elsif ( $string =~ /\d\d\d\d\-\d\d-\d\d\ [0-2][0-9]\:[0-5][0-9][-+]\d+$/ ) {
		$format = '%Y-%m-%d %H:%M%z';
	}
	elsif ( $string =~ /\d\d\d\d\-\d\d-\d\d\ [0-2][0-9]\:[0-5][0-9]\:[0-5][0-9][-+]\d+$/ ) {
		$format = '%Y-%m-%d %H:%M:%S%z';
	}
	elsif ( $string =~ /\d\d\d\d\-\d\d-\d\dT[0-2][0-9]\:[0-5][0-9][-+]\d+$/ ) {
		$format = '%Y-%m-%dT%H:%M%z';
	}
	elsif ( $string =~ /\d\d\d\d\-\d\d-\d\dT[0-2][0-9]\:[0-5][0-9]\:[0-5][0-9][-+]\d+$/ ) {
		$format = '%Y-%m-%dT%H:%M:%S%z';
	}
	elsif ( $string =~ /\d\d\d\d\-\d\d-\d\d\/[0-2][0-9]\:[0-5][0-9][-+]\d+$/ ) {
		$format = '%Y-%m-%dT%H:%M%Z';
	}
	elsif ( $string =~ /\d\d\d\d\-\d\d-\d\d\/[0-2][0-9]\:[0-5][0-9]\:[0-5][0-9][-+]\d+$/ ) {
		$format = '%Y-%m-%d/%H:%M:%S%z';
	}
	elsif ( $string =~ /\d\d\d\d\d\d\d\d\ [0-2][0-9]\:[0-5][0-9][-+]\d+$/ ) {
		$format = '%Y%m%d %H:%M%z';
	}
	elsif ( $string =~ /\d\d\d\d\d\d\d\d\ [0-2][0-9]\:[0-5][0-9]\:[0-5][0-9][-+]\d+$/ ) {
		$format = '%Y%m%d %H:%M:%S%z';
	}
	elsif ( $string =~ /\d\d\d\d\d\d\d\dT[0-2][0-9]\:[0-5][0-9][-+]\d+$/ ) {
		$format = '%Y%m%dT%H:%M%z';
	}
	elsif ( $string =~ /\d\d\d\d\d\d\d\dT[0-2][0-9]\:[0-5][0-9]\:[0-5][0-9][-+]\d+$/ ) {
		$format = '%Y%m%dT%H:%M:%S%z';
	}
	elsif ( $string =~ /\d\d\d\d\d\d\d\d\/[0-2][0-9]\:[0-5][0-9][-+]\d+$/ ) {
		$format = '%Y%m%dT%H:%M%z';
	}
	elsif ( $string =~ /\d\d\d\d\d\d\d\d\/[0-2][0-9]\:[0-5][0-9]\:[0-5][0-9][-+]\d+$/ ) {
		$format = '%Y%m%d/%H:%M:%S%z';
	}
	elsif ( $string =~ /\d\d\d\d\-\d\d-\d\d\ [0-2][0-9]\:[0-5][0-9]$/ ) {
		$format = '%Y-%m-%d %H:%M';
	}
	elsif ( $string =~ /\d\d\d\d\-\d\d-\d\d\ [0-2][0-9]\:[0-5][0-9]\:[0-5][0-9]$/ ) {
		$format = '%Y-%m-%d %H:%M:%S';
	}
	elsif ( $string =~ /\d\d\d\d\-\d\d-\d\dT[0-2][0-9]\:[0-5][0-9]$/ ) {
		$format = '%Y-%m-%dT%H:%M';
	}
	elsif ( $string =~ /\d\d\d\d\-\d\d-\d\dT[0-2][0-9]\:[0-5][0-9]\:[0-5][0-9]$/ ) {
		$format = '%Y-%m-%dT%H:%M:%S';
	}
	elsif ( $string =~ /\d\d\d\d\-\d\d-\d\d\/[0-2][0-9]\:[0-5][0-9]$/ ) {
		$format = '%Y-%m-%dT%H:%M';
	}
	elsif ( $string =~ /\d\d\d\d\-\d\d-\d\d\/[0-2][0-9]\:[0-5][0-9]\:[0-5][0-9]$/ ) {
		$format = '%Y-%m-%d/%H:%M:%S';
	}
	elsif ( $string =~ /\d\d\d\d\d\d\d\d\ [0-2][0-9]\:[0-5][0-9]$/ ) {
		$format = '%Y%m%d %H:%M';
	}
	elsif ( $string =~ /\d\d\d\d\d\d\d\d\ [0-2][0-9]\:[0-5][0-9]\:[0-5][0-9]$/ ) {
		$format = '%Y%m%d %H:%M:%S';
	}
	elsif ( $string =~ /\d\d\d\d\d\d\d\dT[0-2][0-9]\:[0-5][0-9]$/ ) {
		$format = '%Y%m%dT%H:%M';
	}
	elsif ( $string =~ /\d\d\d\d\d\d\d\dT[0-2][0-9]\:[0-5][0-9]\:[0-5][0-9]$/ ) {
		$format = '%Y%m%dT%H:%M:%S';
	}
	elsif ( $string =~ /\d\d\d\d\d\d\d\d\/[0-2][0-9]\:[0-5][0-9]$/ ) {
		$format = '%Y%m%dT%H:%M';
	}
	elsif ( $string =~ /\d\d\d\d\d\d\d\d\/[0-2][0-9]\:[0-5][0-9]\:[0-5][0-9]$/ ) {
		$format = '%Y%m%d/%H:%M:%S';
	}

	my $t;
	eval { $t = Time::Piece->strptime( $string, $format ); };
	if ($@) {
		die( 'Failed to parse the string "' . $string . '" using "' . $format . '"' );
	}

	return $t;
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
