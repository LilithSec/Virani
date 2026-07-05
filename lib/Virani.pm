package Virani;

use 5.010;
use strict;
use warnings;
use TOML;
use File::Slurp;
use Net::Subnet;
use File::Find::IncludesTimeRange;
use File::Find::Rule;
use Digest::MD5 qw(md5_hex);
use File::Spec;
use IPC::Cmd   qw(run can_run);
use File::Copy qw(cp move);
use Parallel::ForkManager;
use Sys::Syslog;
use JSON;
use Time::Piece;

=head1 NAME

Virani - PCAP retrieval for a FPC setup writing to PCAP files.

=head1 VERSION

Version 1.2.0

=cut

our $VERSION = '1.2.0';

=head1 SYNOPSIS

    use Virani;

    my $virani = Virani->new();
    ...

=head1 METHODS

=head2 new_from_conf

Initiates the Virani object from the specified file.

    - conf :: The config TOML to use.
        - Default :: /usr/local/etc/virani.toml

=cut

sub new_from_conf {
	my ( $class, %opts ) = @_;

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

	my ( $toml, $err ) = from_toml($raw_toml);
	if ( !defined($toml) ) {
		die( 'Failed to parse the config file, "' . $opts{conf} . '"... ' . ( $err // 'unknown error' ) );
	}

	return $class->new( %{$toml} );
} ## end sub new_from_conf

=head2 new

Initiates the object.

    - allowed_subnets :: The allowed subnets for fetching PCAPs for mojo-virani.
        Defaults :: [ '192.168.0.0/16', '127.0.0.1/8', '::1/127', '172.16.0.0/12' ]

    - apikey :: Optional API key for mojo-virani.
        Defaults :: undef

    - auth_by_IP_only :: Auth by IP only and don't use a API key.
        Default :: 1

    - default_set :: The default set to use.
        Default :: default

    - cache :: Cache directory to write to.
        Default :: /var/cache/virani

    - default_regex :: The regex to use for getting the timestamp. The regex to pass to
                       File::Find::IncludesTimeRange for finding PCAP files with timestamps
                       that include the range in question.
        Default :: (?<timestamp>\\d\\d\\d\\d\\d\\d+)(\\.pcap|(?<subsec>\\.\\d+)\\.pcap)$

    - verbose_to_syslog :: Send verbose items to syslog. This is used by mojo-virani.
        Default :: 0

    - pcap_glob :: The glob to use for matching files.
        Default :: *.pcap*

    - ts_is_unixtime :: The timestamp is unixtime and does not require additional processing.
        Default :: 1

    - verbose :: Print verbose info.
        Default :: 1

    - type :: Either tcpdump, tshark, or bpf2tshark, which to use for filtering PCAP files in the
              specified time slot. tcpdump is faster, but in general will not nicely handle
              some VLAN types. For that tshark is needed, but it is significantly slower. bpf2tshark
              is handled via Virani->bpf2tshark and that should be seen for more info on that.
        Default :: tcpdump

    - padding :: How many seconds to add to the start and end time stamps to ensure the specified
                 time slot is definitely included.
        Default :: 5

    - workers :: How many PCAPs to filter in parallel when generating. 0 disables
                 forking and processes them serially in the current process.
        Default :: 4

    - sets :: A hash of hashes of available sets.
        Default :: { default => { path => '/var/log/daemonlogger' } }

For sets, the following keys are usable, of which only path is required.

    - path :: The base path of which the PCAPs are located.

    - padding :: Padding value for this set.

    - regex :: The timestamp regex to use with this set.

    - type :: The default filter type to use with this set.

    - workers :: The worker count to use with this set.

    - ts_is_unixtime :: The timestamp is unixtime and does not require additional processing.

=cut

sub new {
	my ( $class, %opts ) = @_;

	my $self = {
		allowed_subnets   => [ '192.168.0.0/16', '127.0.0.1/8', '::1/127', '172.16.0.0/12' ],
		apikey            => undef,
		auth_by_IP_only   => 1,
		default_set       => 'default',
		cache             => '/var/cache/virani',
		default_regex     => '(?<timestamp>\\d\\d\\d\\d\\d\\d+)(\\.pcap|(?<subsec>\\.\\d+)\\.pcap)$',
		verbose_to_syslog => 0,
		verbose           => 1,
		type              => 'tcpdump',
		padding           => 5,
		workers           => 4,
		ts_is_unixtime    => 1,
		pcap_glob         => '*.pcap*',
		sets              => {
			default => {
				path => '/var/log/daemonlogger',
			}
		},

	};
	bless $self, $class;

	if ( defined( $opts{allowed_subnets} ) && ref( $opts{allowed_subnets} ) eq 'ARRAY' ) {
		$self->{allowed_subnets} = $opts{allowed_subnets};
	} elsif ( defined( $opts{allowed_subnets} ) && ref( $opts{allowed_subnets} ) ne 'ARRAY' ) {
		die("$opts{allowed_subnets} defined, but not a array");
	}

	if ( defined( $opts{sets} ) && ref( $opts{sets} ) eq 'HASH' ) {
		$self->{sets} = $opts{sets};
	} elsif ( defined( $opts{sets} ) && ref( $opts{sets} ) ne 'HASH' ) {
		die("$opts{sets} defined, but not a hash");
	}

	# real in basic values
	my @real_in = (
		'apikey',            'default_set', 'cache',           'padding',
		'verbose_to_syslog', 'verbose',     'auth_by_IP_only', 'type',
		'ts_is_unixtime',    'pcap_glob',   'default_regex',   'workers'
	);
	for my $key (@real_in) {
		if ( defined( $opts{$key} ) ) {
			$self->{$key} = $opts{$key};
		}
	}

	return $self;
} ## end sub new

=head2 bpf2tshark

Does a quick and dumb conversion of a BPF filter to tshark.

    my $tshark=$virani->bpf2tshark($bpf);



    ()  ->  ()
    not ()  ->  !()

    icmp -> icmp
    tcp -> tcp
    udp -> udp

    port $port -> ( tcp.port == $port or udp.port == $port )
    not port $port -> ( tcp.port != $port or udp.port != $port )

    dst port $port -> ( tcp.dstport == $port or udp.dstport == $port )
    not dst port $port -> ( tcp.dstport != $port or udp.dstport != $port )

    src port $port -> ( tcp.srcport == $port or udp.srcport == $port )
    not src port $port -> ( tcp.srcport != $port or udp.srcport != $port )

    host $host -> ip.addr == $host
    not host $host -> ip.addr != $host

    dst host $host -> ip.dst == $host
    not dst host $host -> ip.dst != $host

    src host $host -> ip.src == $host
    not src host $host -> ip.src != $host

    dst $host -> ip.dst == $host
    not dst $host -> ip.dst != $host

    src $host -> ip.src == $host
    not src $host -> ip.src != $host

=cut

sub bpf2tshark {
	my $self = $_[0];
	my $bpf  = $_[1];

	if ( !defined($bpf) ) {
		return '';
	}

	# make sure that () have spaces on either side
	$bpf =~ s/\(/\ \(\ /g;
	$bpf =~ s/\)/\ \)\ /g;

	my @bpf_split = split( /[\ \t]+/, $bpf );
	my @tshark_args;
	my @previous;
	my $not = 0;
	foreach my $item (@bpf_split) {

		# sets the equality operator based of if not is true or not
		my $equality = '==';
		if ($not) {
			$equality = '!=';
		}

		# tcp/udp/icmp
		if ( $item eq 'tcp' || $item eq 'udp' || $item eq 'icmp' ) {
			push( @tshark_args, $item );
			$not      = 0;
			@previous = ();
		}

		# handle negation
		elsif ( $item eq 'not' ) {
			$not = 1;
		}

		# handles closing )
		elsif ( $item eq ')' ) {
			$not = 0;
			push( @tshark_args, ')' );
			@previous = ();
		}

		# handles opening (
		elsif ( $item eq '(' ) {
			if ($not) {
				push( @tshark_args, '!(' );
			} else {
				push( @tshark_args, '(' );
			}
			$not      = 0;
			@previous = ();
		}

		# and/or
		elsif ( $item eq 'or' || $item eq 'and' ) {
			# make sure we do not add it twice or add it as the first item
			if ( @tshark_args && $tshark_args[-1] ne 'and' && $tshark_args[-1] ne 'or' ) {
				push( @tshark_args, $item );
			}
			$not      = 0;
			@previous = ();
		}

		# start of src/dst
		elsif ( !defined( $previous[0] ) && ( $item eq 'src' || $item eq 'dst' ) ) {
			push( @previous, $item );
		}

		# start of ether
		elsif ( !defined( $previous[0] ) && $item eq 'ether' ) {
			push( @previous, $item );
		}

		# adding src/dst/host to ether
		elsif ( defined( $previous[0] )
			&& $previous[0] eq 'ether'
			&& ( $item eq 'src' || $item eq 'dst' || $item eq 'host' ) )
		{
			push( @previous, $item );
		}

		# generic host/port
		elsif ( !defined( $previous[0] ) && ( $item eq 'port' || $item eq 'host' ) ) {
			push( @previous, $item );
		}

		# adding host/port to src/dst
		elsif ( defined( $previous[0] )
			&& ( $previous[0] eq 'src' || $previous[0] eq 'dst' )
			&& ( $item eq 'host' || $item eq 'port' ) )
		{
			push( @previous, $item );
		}

		# add ether src $ether
		elsif (defined( $previous[0] )
			&& defined( $previous[1] )
			&& $previous[0] eq 'ether'
			&& $previous[1] eq 'src' )
		{
			push( @tshark_args, 'eth.src', $equality, $item );
			$not      = 0;
			@previous = ();
		}

		# add ether dst $ether
		elsif (defined( $previous[0] )
			&& defined( $previous[1] )
			&& $previous[0] eq 'ether'
			&& $previous[1] eq 'dst' )
		{
			push( @tshark_args, 'eth.dst', $equality, $item );
			$not      = 0;
			@previous = ();
		}

		# add ether host $ether
		elsif (defined( $previous[0] )
			&& defined( $previous[1] )
			&& $previous[0] eq 'ether'
			&& $previous[1] eq 'host' )
		{
			push( @tshark_args, 'eth.addr', $equality, $item );
			$not      = 0;
			@previous = ();
		}

		# add src port $port
		elsif (defined( $previous[0] )
			&& defined( $previous[1] )
			&& $previous[0] eq 'src'
			&& $previous[1] eq 'port' )
		{
			push( @tshark_args, '(', 'tcp.srcport', $equality, $item, 'or', 'udp.srcport', $equality, $item, ')' );
			$not      = 0;
			@previous = ();
		}

		# add dst port $port
		elsif (defined( $previous[0] )
			&& defined( $previous[1] )
			&& $previous[0] eq 'dst'
			&& $previous[1] eq 'port' )
		{
			push( @tshark_args, '(', 'tcp.dstport', $equality, $item, 'or', 'udp.dstport', $equality, $item, ')' );
			$not      = 0;
			@previous = ();
		}

		# add src host $host
		elsif (defined( $previous[0] )
			&& defined( $previous[1] )
			&& $previous[0] eq 'src'
			&& $previous[1] eq 'host' )
		{
			push( @tshark_args, 'ip.src', $equality, $item );
			$not      = 0;
			@previous = ();
		}

		# add dst host $host
		elsif (defined( $previous[0] )
			&& defined( $previous[1] )
			&& $previous[0] eq 'dst'
			&& $previous[1] eq 'host' )
		{
			push( @tshark_args, 'ip.dst', $equality, $item );
			$not      = 0;
			@previous = ();
		}

		# add port $port
		elsif ( defined( $previous[0] ) && !defined( $previous[1] ) && $previous[0] eq 'port' ) {
			push( @tshark_args, '(', 'tcp.port', $equality, $item, 'or', 'udp.port', $equality, $item, ')' );
			$not      = 0;
			@previous = ();
		}

		# add host $host
		elsif ( defined( $previous[0] ) && !defined( $previous[1] ) && $previous[0] eq 'host' ) {
			push( @tshark_args, 'ip.addr', $equality, $item );
			$not      = 0;
			@previous = ();
		}

		# add src $host
		elsif ( defined( $previous[0] ) && !defined( $previous[1] ) && $previous[0] eq 'src' ) {
			push( @tshark_args, 'ip.src', $equality, $item );
			$not      = 0;
			@previous = ();
		}

		# add dst $host
		elsif ( defined( $previous[0] ) && !defined( $previous[1] ) && $previous[0] eq 'dst' ) {
			push( @tshark_args, 'ip.dst', $equality, $item );
			$not      = 0;
			@previous = ();
		}

		# if anything else is found, skip it
		else {
			$not      = 0;
			@previous = ();
		}
	} ## end foreach my $item (@bpf_split)

	return join( ' ', @tshark_args );
} ## end sub bpf2tshark

=head2 filter_clean

Removes starting and trailing whitespace as well as collapsing
consecutive whitespace to a single space.

The purpose for this is to make sure that tshark/BPF filters passed
are consistent for cacheing, even if their white space differs.

A undef passed to it will return ''.

Will die if the cleaned filter starts with a '-', which
tcpdump will interpret as a switch.

    my $cleaned_bpf=$virani->filter_clean($bpf);

=cut

sub filter_clean {
	my $self   = $_[0];
	my $string = $_[1];

	if ( !defined($string) ) {
		return '';
	}

	# remove white space at the start and end
	$string =~ s/^\s*//g;
	$string =~ s/\s+$//g;

	# replace all multiple white space characters with a single space
	$string =~ s/\s\s+/ /g;

	if ( $string =~ /^-/ ) {
		die( 'The filter, "' . $string . '", begins with a "-", so dying for safety reasons' );
	}

	return $string;
} ## end sub filter_clean

=head2 check_apikey

Checks the API key.

If auth_by_IP_only is 1, this will always return true.

	my $apikey=$c->param('apikey');
	if (!$virani->check_apikey($apikey)) {
		$c->render( text => "Invalid API key\n", status=>403, );
		return;
	}

=cut

sub check_apikey {
	my $self   = $_[0];
	my $apikey = $_[1];

	if ( $self->{auth_by_IP_only} ) {
		return 1;
	}

	if ( !defined($apikey) ) {
		return 0;
	}

	if ( !defined( $self->{apikey} ) || $self->{apikey} eq '' ) {
		return 0;
	}

	if ( $apikey ne $self->{apikey} ) {
		return 0;
	}

	return 1;
} ## end sub check_apikey

=head2 check_remote_ip

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

	# allowed_subnets is only set at construction, so the matcher only needs built once
	if ( !defined( $self->{allowed_subnets_matcher} ) ) {
		eval { $self->{allowed_subnets_matcher} = subnet_matcher( @{ $self->{allowed_subnets} } ); };
		if ($@) {
			die( 'Failed to init subnet matcher... ' . $@ );
		} elsif ( !defined( $self->{allowed_subnets_matcher} ) ) {
			die('Failed to init subnet matcher... subnet_matcher returned undef');
		}
	}

	if ( $self->{allowed_subnets_matcher}->($ip) ) {
		return 1;
	}

	return 0;
} ## end sub check_remote_ip

=head2 check_type

Verify if the type is valid or not.

Returns 0/1 based on if it a known type or not.

    if ( ! $virani->check_type( $type )){
        print $type." is not known\n";
    }

=cut

sub check_type {
	my $self = $_[0];
	my $type = $_[1];

	if ( !defined($type) ) {
		return 0;
	}

	if ( $type ne 'tshark' && $type ne 'tcpdump' && $type ne 'bpf2tshark' ) {
		return 0;
	}

	return 1;
} ## end sub check_type

=head2 get_default_set

Returns the default set to use.

    my $set=$virani->get_default_set;

=cut

sub get_default_set {
	my ($self) = @_;

	return $self->{default_set};
}

=head2 get_sets

Returns a hash ref of the configured sets. The keys are the set
names and the values are hash refs of the non-path settings for
that set, any of type, padding, regex, ts_is_unixtime, or pcap_glob.

    my $sets=$virani->get_sets;

=cut

sub get_sets {
	my ($self) = @_;

	my $sets = {};
	foreach my $set_name ( keys( %{ $self->{sets} } ) ) {
		$sets->{$set_name} = {};
		foreach my $key ( 'type', 'padding', 'regex', 'ts_is_unixtime', 'pcap_glob' ) {
			if ( defined( $self->{sets}{$set_name}{$key} ) ) {
				$sets->{$set_name}{$key} = $self->{sets}{$set_name}{$key};
			}
		}
	}

	return $sets;
} ## end sub get_sets

# Internal helper that resolves and sanity checks the common options taken by
# get_cache_file and get_pcap_local. Takes a hash ref of the options and fills
# in set, type, padding, filter, auto_no_cache, and no_cache. Dies on anything
# not sane.
sub _resolve_opts {
	my ( $self, $opts ) = @_;

	# if set is undef or blank, use the default
	if ( !defined( $opts->{set} ) || $opts->{set} eq '' ) {
		$opts->{set} = $self->get_default_set;
	}

	# make sure the set exists
	if ( !defined( $self->{sets}->{ $opts->{set} } ) ) {
		die( 'The set "' . $opts->{set} . '" is not defined' );
	} elsif ( !defined( $self->{sets}->{ $opts->{set} }{path} ) ) {
		die( 'The path for set "' . $opts->{set} . '" is not defined' );
	} elsif ( !-d $self->{sets}->{ $opts->{set} }{path} ) {
		die(      'The path for set "'
				. $opts->{set} . '", "'
				. $self->{sets}->{ $opts->{set} }{path}
				. '" does not exist or is not a directory' );
	}

	# make sure we have something for type and check to make sure it is sane
	if ( !defined( $opts->{type} ) ) {
		$opts->{type} = $self->{type};
		if ( defined( $self->{sets}{ $opts->{set} }{type} ) ) {
			$opts->{type} = $self->{sets}{ $opts->{set} }{type};
		}
	}

	# check it here incase the config includes something off
	if ( !$self->check_type( $opts->{type} ) ) {
		die( 'type "' . $opts->{type} . '" is not a supported type, tcpdump, tshark, or bpf2tshark' );
	}

	# basic sanity checking
	if ( !defined( $opts->{start} ) ) {
		die('$opts{start} not defined');
	} elsif ( !defined( $opts->{end} ) ) {
		die('$opts{end} not defined');
	} elsif ( ref( $opts->{start} ) ne 'Time::Piece' ) {
		die('$opts{start} is not a Time::Piece object');
	} elsif ( ref( $opts->{end} ) ne 'Time::Piece' ) {
		die('$opts{end} is not a Time::Piece object');
	}

	if ( !defined( $opts->{auto_no_cache} ) ) {
		$opts->{auto_no_cache} = 1;
	}

	if ( !defined( $opts->{no_cache} ) ) {
		$opts->{no_cache} = 0;
	}

	# get the padding and make sure it is sane
	if ( !defined( $opts->{padding} ) ) {
		$opts->{padding} = $self->{padding};
		if ( defined( $self->{sets}{ $opts->{set} }{padding} ) ) {
			$opts->{padding} = $self->{sets}{ $opts->{set} }{padding};
		}
	}
	if ( $opts->{padding} !~ /^\d+$/ ) {
		die( '"' . $opts->{padding} . '" is not a numeric padding value' );
	}

	# get the workers count and make sure it is sane
	if ( !defined( $opts->{workers} ) ) {
		$opts->{workers} = $self->{workers};
		if ( defined( $self->{sets}{ $opts->{set} }{workers} ) ) {
			$opts->{workers} = $self->{sets}{ $opts->{set} }{workers};
		}
	}
	if ( $opts->{workers} !~ /^\d+$/ ) {
		die( '"' . $opts->{workers} . '" is not a numeric workers value' );
	}

	# clean the filter
	$opts->{filter} = $self->filter_clean( $opts->{filter} );

	return;
} ## end sub _resolve_opts

=head2 get_cache_file

Takes the same args as get_pcap_local.

Returns the path to the file.

    my $cache_file=$virani->get_cache_file(%opts);
    if (! -f $cache_file.'.json'){
        print "Cache file metadata does not exist, so either get_pcap_local died or it has not been ran\n";
    }

=cut

sub get_cache_file {
	my ( $self, %opts ) = @_;

	$self->_resolve_opts( \%opts );

	my $cache_file_base
		= $self->{cache} . '/'
		. $opts{set} . '-'
		. $opts{type} . '-'
		. $opts{start}->epoch . '-'
		. $opts{end}->epoch . '-'
		. lc( md5_hex( $opts{filter} ) );

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

		# figure out what to use as the cache file
		if ( $opts{no_cache} ) {
			$cache_file = $opts{file};
		} elsif ( -d $self->{cache} && -w $self->{cache} ) {
			$cache_file = $cache_file_base;
		} elsif ( $opts{auto_no_cache} ) {
			$cache_file = $opts{file};
		} else {
			die(      '$opts{auto_no_cache} is false and $opts{no_cache} is false, but the cache dir "'
					. $self->{cache}
					. '" does not exist, is not a dir, or is not writable' );
		}
	} else {
		# make sure the cache is usable
		if ( !-d $self->{cache} ) {
			die( 'Cache dir,"' . $self->{cache} . '", does not exist or is not a dir' );
		} elsif ( !-w $self->{cache} ) {
			die( 'Cache dir,"' . $self->{cache} . '", is not writable' );
		}

		$cache_file = $cache_file_base;
	} ## end else [ if ( defined( $opts{file} ) ) ]

	return $cache_file;
} ## end sub get_cache_file

# Internal helper that runs each PCAP in @$to_check through tcpdump/tshark
# with the filter, writing the results to tmp files, $opts->{workers} at a
# time. The stats in $to_return are updated and failures recorded in failed.
# Returns an array ref of the tmp files to merge.
sub _filter_pcaps {
	my ( $self, $opts, $to_check, $cache_file, $tshark_filter, $to_return ) = @_;

	my $pm = Parallel::ForkManager->new( $opts->{workers} );
	my %filter_results;
	$pm->run_on_finish(
		sub {
			my ( $pid, $exit_code, $ident, $exit_signal, $core_dump, $data ) = @_;
			if ( defined($data) ) {
				$filter_results{$ident} = $data;
			} else {
				$filter_results{$ident} = { success => 0, error => 'child died without returning results' };
			}
		}
	);

	my $pcap_int = 0;
	foreach my $pcap ( @{$to_check} ) {
		my $size = ( -s $pcap ) // 0;
		$to_return->{total_size} += $size;
		$to_return->{pcap_count}++;
		$self->verbose( 'info', 'Processing ' . $pcap . ", size=" . $size . " ..." );

		my $tmp_file = $cache_file . '-' . $pcap_int;
		my $ident    = $pcap_int;
		$pcap_int++;

		if ( $pm->start($ident) ) {
			next;
		}
		my ( $success, $error_message, $full_buf, $stdout_buf, $stderr_buf );
		if ( $opts->{type} eq 'tcpdump' ) {
			( $success, $error_message, $full_buf, $stdout_buf, $stderr_buf ) = run(
				command => [ 'tcpdump', '-r', $pcap, '-w', $tmp_file, $opts->{filter} ],
				verbose => 0
			);
		} else {
			( $success, $error_message, $full_buf, $stdout_buf, $stderr_buf ) = run(
				command => [ 'tshark', '-r', $pcap, '-w', $tmp_file, $tshark_filter ],
				verbose => 0
			);
		}
		$pm->finish(
			0,
			{
				success  => $success ? 1     : 0,
				error    => $success ? undef : $error_message,
				size     => $size,
				tmp_size => ( -s $tmp_file ) // 0,
			}
		);
	} ## end foreach my $pcap ( @{$to_check} )
	$pm->wait_all_children;

	# gather the results, in the same order the PCAPs were dispatched
	my @filtered;
	$pcap_int = 0;
	foreach my $pcap ( @{$to_check} ) {
		my $result   = $filter_results{$pcap_int};
		my $tmp_file = $cache_file . '-' . $pcap_int;
		$pcap_int++;
		if ( $result->{success} ) {
			$to_return->{success_count}++;
			$to_return->{success_size} += $result->{size};
			$to_return->{tmp_size}     += $result->{tmp_size};
			push( @filtered, $tmp_file );
		} else {
			$to_return->{failed}{$pcap} = $result->{error};
			$to_return->{failed_count}++;
			$to_return->{failed_size} += $result->{size};

			$self->verbose( 'warning', 'Failed ' . $pcap . " ... " . ( $result->{error} // '' ) );

			unlink $tmp_file;
		}
	} ## end foreach my $pcap ( @{$to_check} )

	return \@filtered;
} ## end sub _filter_pcaps

# Internal helper that merges the passed PCAPs into $cache_file via mergecap,
# setting merge_error in $to_return if it fails. A single PCAP skips mergecap
# and is just moved or copied into place. If $inputs_are_tmp is true the
# inputs are tmp files and are removed afterwards.
sub _merge_pcaps {
	my ( $self, $to_return, $cache_file, $merge_inputs, $inputs_are_tmp ) = @_;

	if ( scalar( @{$merge_inputs} ) == 1 && $inputs_are_tmp ) {
		# a single tmp file does not need merged as tcpdump/tshark already
		# validated it... originals still go through mergecap so unvalidated
		# PCAPs, such as one still being written to, are never used directly
		$self->verbose( 'info', 'Only one PCAP, moving "' . $merge_inputs->[0] . '" to "' . $cache_file . '"' );
		if ( !move( $merge_inputs->[0], $cache_file ) ) {
			$to_return->{merge_error} = 'Failed to move "' . $merge_inputs->[0] . '" in place... ' . $!;
			$self->verbose( 'err', $to_return->{merge_error} );
		}
	} else {
		my $to_merge = [ 'mergecap', '-w', $cache_file, @{$merge_inputs} ];

		$self->verbose( 'info', "Merging PCAPs... " . join( ' ', @{$to_merge} ) );

		my ( $success, $error_message, $full_buf, $stdout_buf, $stderr_buf ) = run(
			command => $to_merge,
			verbose => 0
		);
		if ($success) {
			$self->verbose( 'info', "PCAPs merged into " . $cache_file );
		} else {
			$to_return->{merge_error} = $error_message;

			# if verbose print different messages if mergecap generated a output file or not when it failed
			if ( -f $cache_file ) {
				$self->verbose( 'warning', "PCAPs partially(output file generated) failed " . $error_message );
			} else {
				$self->verbose( 'err', "PCAPs merge completely(output file not generated) failed " . $error_message );
			}
		} ## end else [ if ($success) ]
	} ## end else [ if ( scalar( @{$merge_inputs} ) == 1 && $inputs_are_tmp)]

	# remove each tmp file
	if ($inputs_are_tmp) {
		foreach my $tmp_file ( @{$merge_inputs} ) {
			if ( -f $tmp_file ) {
				unlink($tmp_file);
			}
		}
	}

	return;
} ## end sub _merge_pcaps

=head2 get_pcap_local

Generates a PCAP locally and returns the path to it.

    - start :: A L<Time::Piece> object of when to start looking.
        - Default :: undef

    - end :: A L<Time::Piece> object of when to stop looking.
        - Default :: undef

    - padding :: Number of seconds to pad the start and end with.
        - Default :: 5

    - filter :: The BPF or tshark filter to use. If empty, the matching PCAPs
                are merged directly, skipping per PCAP filtering. Should that
                fail, such as one of the PCAPs still being written to, it
                falls back to per PCAP filtering.
        - Default :: ''

    - set :: The PCAP set to use. Will use what ever the default is set to if undef or blank.
        - Default :: $virani->get_default_set

    - file :: The file to output to. If undef it just returns the path to
              the cache file.
        - Default :: undef

    - no_cache :: If cached, don't return that, but regen and if applicable re-cache.
        - Default :: 0

    - auto_no_cache :: If the cache dir is being used and not writeable and a file
                       has been specified, don't die, but use the output file name
                       as the basis of for the tmp file.
        - Default :: 1

    - type :: 'tcpdump' or 'tshark', depending on what one wants the filter todo.
        - Default :: tcpdump

    - workers :: How many PCAPs to filter in parallel. 0 disables forking and
                 processes them serially in the current process.
        - Default :: 4

The return is a hash reference that includes the following keys.

    - pcaps :: A array of PCAPs used.

    - pcap_count :: A count of used PCAPs.

    - pcap_glob :: The value of pcap_glob used.

    - ts_is_unixtime :: The value of ts_is_unixtime used.

    - failed :: A hash of PCAPs that failed. PCAP path as key and value being the reason.

    - failed_count :: A count of failed PCAPs.

    - path :: The path to the results file. If undef, unable it was unable
              to process any of them.

    - merge_error :: The error message from mergecap if merging failed.
                     undef if merging worked or was never attempted.

    - success_count :: A count of successfully processed PCAPs.

    - filter :: The used filter.

    - total_size :: The size of all PCAP files checked.

    - failed_size :: The size of the PCAP files that failed.

    - success_size :: the size of the PCAP files that successfully processed

    - type :: The value of $opts{type}

    - padding :: The value of padding.

    - start_s :: Start time in seconds since epoch, not including padding.

    - start :: Start time in the format '%Y-%m-%dT%H:%M:%S%z'.

    - end_s :: End time in seconds since epoch, not including padding.

    - end :: End time in the format '%Y-%m-%dT%H:%M:%S%z'.

    - using_cache :: If the cache was used or not.

    - req_start :: Timestamp of when the request started. In the format
                   %Y-%m-%dT%H:%M:%S%z

    - req_start_s :: Same as req_start, but unixtime.

    - req_end :: Timestamp of when the request finished. In the format
                 %Y-%m-%dT%H:%M:%S%z

    - req_end_s :: Same as req_end, but unixtime.

    - req_time :: Number of seconds it took.

=cut

sub get_pcap_local {
	my ( $self, %opts ) = @_;

	# start of the request
	my $req_start = localtime;

	# resolve and sanity check set, type, padding, filter, and the cache options
	$self->_resolve_opts( \%opts );
	$self->verbose( 'info', 'Set: ' . $opts{set} );
	$self->verbose( 'info', 'Type: ' . $opts{type} );
	$self->verbose( 'info', 'Start: ' . $opts{start}->strftime('%Y-%m-%dT%H:%M:%S%z') . ', ' . $opts{start}->epoch );
	$self->verbose( 'info', 'End: ' . $opts{end}->strftime('%Y-%m-%dT%H:%M:%S%z') . ', ' . $opts{end}->epoch );
	$self->verbose( 'info', 'auto_no_cache: ' . $opts{auto_no_cache} );
	$self->verbose( 'info', 'no_cache: ' . $opts{no_cache} );
	$self->verbose( 'info', 'Filter: ' . $opts{filter} );

	# figure out what to use for $ts_is_unixtime
	my $ts_is_unixtime;
	if ( defined( $self->{sets}{ $opts{set} }{ts_is_unixtime} ) ) {
		$ts_is_unixtime = $self->{sets}{ $opts{set} }{ts_is_unixtime};
	} else {
		$ts_is_unixtime = $self->{ts_is_unixtime};
	}

	# figure out what to use for $pcap_glob
	my $pcap_glob;
	if ( defined( $self->{sets}{ $opts{set} }{pcap_glob} ) ) {
		$pcap_glob = $self->{sets}{ $opts{set} }{pcap_glob};
	} else {
		$pcap_glob = $self->{pcap_glob};
	}
	$self->verbose( 'info', 'PCAP Glob: ' . $pcap_glob );

	# get the cache file to use
	my $cache_file;
	eval { $cache_file = $self->get_cache_file(%opts); };
	if ($@) {
		die( '$self->get_cache_file(%opts) failed... ' . $@ );
	}

	# if applicable return the cache file
	my $return_cache = 0;
	if (   defined( $opts{file} )
		&& $opts{file} ne $cache_file
		&& !$opts{no_cache}
		&& -f $cache_file
		&& -f $cache_file . '.json' )
	{
		$return_cache = 1;
	} elsif ( !defined( $opts{file} ) && !$opts{no_cache} && -f $cache_file && -f $cache_file . '.json' ) {
		$return_cache = 1;
	}
	if ($return_cache) {
		my $cache_message = 'Already cached... "' . $cache_file . '"';
		if ( defined( $opts{file} ) && $opts{file} ne $cache_file ) {
			$cache_message = $cache_message . ' -> "' . $opts{file} . '"';
		}
		$self->verbose( 'info', $cache_message );
		if ( defined( $opts{file} ) && $opts{file} ne $cache_file ) {
			# try hardlinking as they will often be on the same filesystem, otherwise copy it
			if ( !link( $cache_file, $opts{file} ) ) {
				cp( $cache_file, $opts{file} );
			}
		}
		my $to_return;
		eval {
			my $cache_meta_raw = read_file( $cache_file . '.json' );
			$to_return = decode_json($cache_meta_raw);
		};
		if ($@) {
			die( 'Failed to read cache metadata JSON, "' . $cache_file . '.json"' );
		}
		$to_return->{using_cache} = 1;
		return $to_return;
	} ## end if ($return_cache)

	# not cached, so PCAPs will need generated... make sure the required binaries
	# are present before starting so it can fail with a clear error
	my $filter_bin = $opts{type} eq 'tcpdump' ? 'tcpdump' : 'tshark';
	foreach my $bin ( $filter_bin, 'mergecap' ) {
		if ( !can_run($bin) ) {
			die( 'The command "' . $bin . '" is required for PCAP generation, but was not found in the path' );
		}
	}

	# set the padding
	my $start = $opts{start} - $opts{padding};
	my $end   = $opts{end} + $opts{padding};
	$self->verbose( 'info', 'Padded Start: ' . $start->strftime('%Y-%m-%dT%H:%M:%S%z') . ', ' . $start->epoch );
	$self->verbose( 'info', 'Padded End: ' . $end->strftime('%Y-%m-%dT%H:%M:%S%z') . ', ' . $end->epoch );

	# get the set
	my $set_path = $self->get_set_path( $opts{set} );
	if ( !defined($set_path) ) {
		die( 'The set "' . $opts{set} . '" does not either exist or the path value for it is undef' );
	}

	# get the pcaps
	my @pcaps = File::Find::Rule->file()->name($pcap_glob)->in($set_path);

	# get the ts_regexp to use
	my $ts_regexp;
	if ( defined( $self->{sets}{ $opts{set} }{regex} ) ) {
		$ts_regexp = $self->{sets}{ $opts{set} }{regex};
	} else {
		$ts_regexp = $self->{default_regex};
	}
	$self->verbose( 'info', 'Timestamp Regexp: ' . $ts_regexp );

	my $to_check = File::Find::IncludesTimeRange->find(
		items          => \@pcaps,
		start          => $start,
		end            => $end,
		regex          => $ts_regexp,
		ts_is_unixtime => $ts_is_unixtime,
	);

	# The return hash and what will be used for the cache JSON
	# req_end stuff set later
	my $to_return = {
		pcaps          => $to_check,
		pcap_glob      => $pcap_glob,
		pcap_count     => 0,
		failed         => {},
		failed_count   => 0,
		success_count  => 0,
		path           => $cache_file,
		filter         => $opts{filter},
		merge_error    => undef,
		total_size     => 0,
		failed_size    => 0,
		success_size   => 0,
		tmp_size       => 0,
		final_size     => 0,
		type           => $opts{type},
		padding        => $opts{padding},
		start_s        => $opts{start}->epoch,
		start          => $opts{start}->strftime('%Y-%m-%dT%H:%M:%S%z'),
		end_s          => $opts{end}->epoch,
		end            => $opts{end}->strftime('%Y-%m-%dT%H:%M:%S%z'),
		req_start      => $req_start->strftime('%Y-%m-%dT%H:%M:%S%z'),
		req_start_s    => $req_start->epoch,
		ts_is_unixtime => $ts_is_unixtime,
	};

	# puts together the tshark filter if needed
	my $tshark_filter = $opts{filter};
	if ( $opts{type} eq 'bpf2tshark' ) {
		$tshark_filter = $self->bpf2tshark( $opts{filter} );
		$to_return->{filter_translated} = $tshark_filter;
		$self->verbose( 'info', 'Translated Filter ' . $tshark_filter );
	}

	# generate the filtered PCAPs and merge them
	if ( $opts{filter} eq '' ) {
		# a empty filter matches everything, so try merging the PCAPs
		# directly, skipping the per PCAP filtering
		$self->verbose( 'info', 'Empty filter... attempting to merge the PCAPs directly' );
		my @merge_inputs;
		foreach my $pcap ( @{$to_check} ) {
			my $size = ( -s $pcap ) // 0;
			$to_return->{total_size}   += $size;
			$to_return->{success_size} += $size;
			$to_return->{success_count}++;
			$to_return->{pcap_count}++;
			push( @merge_inputs, $pcap );
		}
		if ( $to_return->{success_count} > 0 ) {
			$self->_merge_pcaps( $to_return, $cache_file, \@merge_inputs, 0 );

			# if the direct merge failed, such as one of the PCAPs still being
			# written to, redo it via per PCAP filtering, which handles
			# failures of single PCAPs gracefully
			if ( defined( $to_return->{merge_error} ) ) {
				$self->verbose( 'warning', 'Direct merge failed... falling back to per PCAP filtering' );
				if ( -f $cache_file ) {
					unlink($cache_file);
				}
				foreach my $key (qw(pcap_count success_count failed_count total_size success_size failed_size tmp_size))
				{
					$to_return->{$key} = 0;
				}
				$to_return->{failed}      = {};
				$to_return->{merge_error} = undef;
				my $filtered = $self->_filter_pcaps( \%opts, $to_check, $cache_file, $tshark_filter, $to_return );
				if ( $to_return->{success_count} > 0 ) {
					$self->_merge_pcaps( $to_return, $cache_file, $filtered, 1 );
				}
			} ## end if ( defined( $to_return->{merge_error} ) )
		} ## end if ( $to_return->{success_count} > 0 )
	} else {
		my $filtered = $self->_filter_pcaps( \%opts, $to_check, $cache_file, $tshark_filter, $to_return );
		if ( $to_return->{success_count} > 0 ) {
			$self->_merge_pcaps( $to_return, $cache_file, $filtered, 1 );
		}
	}

	if ( $to_return->{success_count} < 1 ) {
		$self->verbose( 'err', "No PCAPs to merge" );
	}

	# don't bother checking size if the file was not generated
	if ( -f $cache_file ) {
		$to_return->{final_size} = ( -s $cache_file ) // 0;
	}

	# if the output file was never generated, note that via setting path to undef
	if ( !-f $cache_file ) {
		$to_return->{path} = undef;
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

	# finalize info on how long the request took
	my $req_end = localtime;
	$to_return->{req_end}   = $req_end->strftime('%Y-%m-%dT%H:%M:%S%z');
	$to_return->{req_end_s} = $req_end->epoch;
	$to_return->{req_time}  = $req_end->epoch - $req_start->epoch;

	$self->verbose( 'info', 'Creating metadata JSON at "' . $cache_file . '.json" ' );
	my $json     = JSON->new->allow_nonref->pretty->canonical(1);
	my $raw_json = $json->encode($to_return);
	write_file( $cache_file . '.json', $raw_json );

	# if the file and cache file are the same, then the cache dir is not being used, so no need to copy it
	if ( defined( $to_return->{path} ) && defined( $opts{file} ) && $cache_file ne $opts{file} ) {
		$self->verbose( 'info', 'Copying "' . $cache_file . '" to "' . $opts{file} . '"' );
		# try hardlinking as they will often be on the same filesystem, otherwise copy it
		if ( !link( $cache_file, $opts{file} ) ) {
			cp( $cache_file, $opts{file} );
		}
	}

	$to_return->{using_cache} = 0;

	return $to_return;
} ## end sub get_pcap_local

=head2 get_set_path

Returns the path to a set.

If no set is given, the default is used.

Will return undef if the set does not exist or if the set does not have a path defined.

    my $path=$virani->get_set_path($set);

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
} ## end sub get_set_path

=head2 set_verbose

Set if it should be verbose or not.

    # be verbose
    $virani->set_verbose(1);

    # do not be verbose
    $virani->set_verbose(0);

=cut

sub set_verbose {
	my ( $self, $verbose ) = @_;

	$self->{verbose} = $verbose;
}

=head2 set_verbose_to_syslog

Set if verbose messages should be sent to syslog or not.

    # send verbose messages to syslog
    $virani->set_verbose_to_syslog(1);

    # do not send verbose messages to syslog
    $virani->set_verbose_to_syslog(0);

=cut

sub set_verbose_to_syslog {
	my ( $self, $to_syslog ) = @_;

	$self->{verbose_to_syslog} = $to_syslog;
}

=head2 verbose

Prints out verbose messages. This is intended to be internal.

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
			openlog( 'virani', undef, 'daemon' );
			syslog( $level, $string );
			closelog();
		} else {
			print $string. "\n";
		}
	}

	return;
} ## end sub verbose

=head2 CONFIG

The config format used toml, processed via L<TOML>.

'new_from_conf' will initiate virani by reading it in and feeding it to 'new'.

=head2 DAEMONLOGGER ON FREEBSD

With daemonlogger setup along the lines of like below...

    daemonlogger_enable="YES"
    daemonlogger_flags="-f /usr/local/etc/daemonlogger.bpf -d -l /var/log/daemonlogger -t 120"

The following can be made available via mojo-virani or locally via virani with the set name of
default as below.

    allowed_subnets=["192.168.14.0/23", "127.0.0.1/8"]
    [sets.default]
    path='/var/log/daemonlogger'

If you want to use 'init/freebsd' to start mojo-virani, you just need to copy
it to '/usr/local/etc/rc.d/virani' and add the following or the like to '/etc/rc.conf'.

    virani_enable="YES"
    virani_flags="daemon -m production -l http://127.0.0.1:8080 -l http://192.168.14.1:8080"

See the script for information on the various possible config args for it.

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

=item * Search CPAN

L<https://metacpan.org/release/Virani>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2024 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The GNU Lesser General Public License, Version 2.1, February 1999


=cut

1;    # End of Virani
