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
use Sys::Syslog;

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
		allowed_subnets   => [ '192.168.0.0/', '127.0.0.1/8', '::1/127', '172.16.0.0/12' ],
		apikey            => '',
		default_set       => 'default',
		cache             => '/var/cache/virani',
		default_regex     => '(?<timestamp>\\d\\d\\d\\d\\d\\d+)(\\.pcap|(?<subsec>\\.\\d+)\\.pcap)$',
		default_strptime  => '%s',
		default_max_time  => '3600',
		verbose_to_syslog => 0,
		verbose           => 1,
		sets              => {
			default => {
				path => '/var/log/daemonlogger',
			}
		},

	};
	bless $self;

	if ( defined( $opts{allowed_subnets} ) && ref( $opts{allowed_subnets} ) eq 'ARRAY' ) {
		$self->{allowed_subnets} = $opts{allowed_subnets};
	}
	elsif ( defined( $opts{allowed_subnets} ) && ref( $opts{allowed_subnets} ) ne 'ARRAY' ) {
		die("$opts{allowed_subnets} defined, but not a array");
	}

	if ( defined( $opts{sets} ) && ref( $opts{sets} ) eq 'HASH' ) {
		$self->{sets} = $opts{sets};
	}
	elsif ( defined( $opts{sets} ) && ref( $opts{allowed_subnets} ) ne 'HASH' ) {
		die("$opts{sets} defined, but not a hash");
	}

	# real in basic values
	my @real_in = ( 'apikey', 'default_set', 'cache', 'default_max_time', 'verbose_to_syslog', 'verbose' );
	for my $key (@real_in) {
		if ( defined( $opts{$key} ) ) {
			$self->{$key} = $opts{$key};
		}
	}

	return $self;
}

=head1 check_apikey

Checks the API key.

	my $apikey=$c->param('apikey');
	if (!$virani->check_apikey($apikey)) {
		$c->render( text => "Invalid API key\n", status=>403, );
		return;
	}

=cut

sub check_apikey {
	my $self   = $_[0];
	my $apikey = $_[1];

	if ( !defined($apikey) ) {
		return 0;
	}

	if ( !defined( $self->{apikey} ) || $self->{apikey} ne '' ) {
		return 0;
	}

	if ( $apikey ne $self->{apikey} ) {
		return 0;
	}

	return 1;
}

=head1 check_remote_ip

Checks if the remote IP is allowed or not.

    if ( ! $virani->check_remote_ip( $c->{tx}{original_remote_address} )){
		$c->render( text => "IP or subnet not allowed\n", status=>403, );
		return;
    }

=cut

sub check_remote_ip {
	my $self = $_[0];
	my $ip   = $_[1];

	if ( !defined($ip) ) {
		return 0;
	}

	if ( !defined( $self->{allowed_subnets}[0] ) ) {
		return 0;
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

=head2 get_default_set

Returns the deefault set to use.

    my $set=$virani->get_default_set;

=cut

sub get_default_set {
	my ($self) = @_;

	return $self->{default_set};
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

    - set :: The PCAP set to use. Will use what ever the default is set to if undef or blank.
        - Default :: $viarni->get_default_set

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

The return is a hash reference that includes the following keys.

    - pcaps :: A array of PCAPs used.

    - pcap_count :: A count of used PCAPs.

    - failed :: A hash of PCAPs that failed. PCAP path as key and value being the reason.

    - failed_count :: A count of failed PCAPs.

    - path :: The path to the results file. If undef, unable it was unable
              to process any of them.

    - success_found :: A count of successfully processed PCAPs.

    - bpf :: The used BPF.

    - total_size :: The size of all PCAP files checked.

    - failed_size :: The size of the PCAP files that failed.

    - success_size :: the size of the PCAP files that successfully processed

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

	if ( !defined( $opts{set} ) || $opts{set} eq '' ) {
		$opts{set} = $self->get_default_set;
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

	# apply the padding
	$opts{start} = $opts{start} - $opts{padding};
	$opts{end}   = $opts{end} + $opts{padding};

	# clean the bpf
	$opts{bpf} = $self->bpf_clean( $opts{bpf} );

	#
	my $set_path = $self->get_set_path( $opts{set} );
	if ( !defined($set_path) ) {
		die( 'The set "' . $opts{set} . '" does not either exist or the path value for it is undef' );
	}

	# get the pcaps
	my @pcaps = File::Find::Rule->file()->name("*.pcap*")->in($set_path);

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
			= $self->{cache} . '/'
			. $opts{set} . '-'
			. $opts{start}->epoch . '-'
			. $opts{end}->epoch . "-"
			. lc( md5_hex( $opts{bpf} ) );
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
		total_size    => 0,
		failed_size   => 0,
		success_size  => 0,
		tmp_size      => 0,
		final_size    => 0,
	};

	$self->verbose( 'info', 'BPF: ' . $opts{bpf} );

	# used for tracking the files to cleanup
	my @tmp_files;

	# the merge command
	my $to_merge = [ 'mergecap', '-w', $cache_file ];
	foreach my $pcap ( @{$to_check} ) {

		# get stat info for the file
		my ( $dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks )
			= stat($pcap);
		$to_return->{total_size} += $size;

		$self->verbose( 'info', 'Processing ' . $pcap . ", size=" . $size . " ..." );

		my $tmp_file = $cache_file . '-' . $to_return->{pcap_count};

		my ( $success, $error_message, $full_buf, $stdout_buf, $stderr_buf ) = run(
			command => [ 'tcpdump', '-r', $pcap, '-w', $tmp_file, $opts{bpf} ],
			verbose => 0
		);
		if ($success) {
			$to_return->{success_count}++;
			$to_return->{success_size} += $size;
			push( @{$to_merge}, $tmp_file );
			push( @tmp_files,   $tmp_file );

			# get stat info for the tmp file
			( $dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks )
				= stat($tmp_file);
			$to_return->{tmp_size} += $size;

		}
		else {
			$to_return->{failed}{$pcap} = $error_message;
			$to_return->{failed_count}++;
			$to_return->{failed_size} += $size;

			$self->verbose( 'warning', 'Failed ' . $pcap . " ... " . $error_message );

			unlink $tmp_file;
		}

		$to_return->{pcap_count}++;
	}

	# only try merging if we had more than one success
	if ( $to_return->{success_count} > 0 ) {

		$self->verbose( 'info', "Merging PCAPs... " . join( ' ', @{$to_merge} ) );

		my ( $success, $error_message, $full_buf, $stdout_buf, $stderr_buf ) = run(
			command => $to_merge,
			verbose => 0
		);
		if ($success) {
			$self->verbose( 'info', "PCAPs merged into " . $cache_file );
		}
		else {
			# if verbose print different messages if mergecap generated a ouput file or not when it fialed
			if ( -f $cache_file ) {
				$self->verbose( 'warning', "PCAPs partially(output file generated) failed " . $error_message );
			}
			else {
				$self->verbose( 'err', "PCAPs merge completely(output file not generated) failed " . $error_message );
			}
		}

		# remove each tmp file
		foreach my $tmp_file (@tmp_files) {
			unlink($tmp_file);
		}

		# don't bother checking size if the file was not generated
		if ( -f $cache_file ) {
			my ( $dev, $ino, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks )
				= stat($cache_file);
			$to_return->{final_size} = $size;
		}
	}
	else {
		$self->verbose( 'err', "No PCAPs to merge" );
	}

	$self->verbose( 'info',
			  "PCAP sizes... failed_size="
			. $to_return->{failed_size}
			. " success_size="
			. $to_return->{success_size}
			. " total_size="
			. $to_return->{total_size}
			. " tmp_size="
			. $to_return->{tmp_size}
			. " final_size="
			. $to_return->{final_size} );

	if ( $cache_file ne $opts{file} ) {
		cp( $cache_file, $opts{file} );
	}

	return $to_return;
}

=head2 get_set_path

Returns the path to a set.

If no set is given, the default is used.

Will return undef if the set does not exist or if the set does not have a path defined.

    my $path=$viarni->get_set_path($set);

=cut

sub get_set_path {
	my ( $self, $set ) = @_;

	if ( !defined($set) ) {
		$set = $self->get_default_set;
	}

	if ( !defined( $self->{sets}{$set} ) ) {
		return undef;
	}

	if ( !defined( $self->{sets}{$set}{path} ) ) {
		return undef;
	}

	return $self->{sets}{$set}{path};
}

=head2 set_verbose

Set if it should be verbose or not.

    # be verbose
    $virani->verbose(1);

    # do not be verbose
    $virani->verbose(0);

=cut

sub set_verbose {
	my ( $self, $verbose ) = @_;

	$self->{verbose} = $verbose;
}

=head2 set_verbose_to_syslog

Set if it should be verbose or not.

    # send verbose messages to syslog
    $viarni->set_verbose_to_syslog(1);

    # do not send verbose messages to syslog
    $viarni->set_verbose_to_syslog(0);

=cut

sub set_verbose_to_syslog {
	my ( $self, $to_syslog ) = @_;

	$self->{verbose_to_syslog} = $to_syslog;
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

=head2 verbose

Prints out error messages. This is inteded to be internal.

Only sends the string if verbose is enabled.

There is no need to add a "\n" as it will automatically if not sending to syslog.

Two variables are taken. The first is level the second is the message. Level is only used
for syslog. Default level is info.

    - Levels :: emerg, alert, crit, err, warning, notice, info, debug

    $self->verbose('info', 'some string');

=cut

sub verbose {
	my ( $self, $level, $string ) = @_;

	if ( !defined($string) || $string eq '' ) {
		return;
	}

	if ( !defined($level) ) {
		$level = 'info';
	}

	if ( $self->{verbose} ) {
		if ( $self->{verbose_to_syslog} ) {
			openlog( 'viarni', undef, 'daemon' );
			syslog( $level, $string );
			closelog();
		}
		else {
			print $string. "\n";
		}
	}

	return;
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
