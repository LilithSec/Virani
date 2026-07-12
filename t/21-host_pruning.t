#!perl
use 5.010;
use strict;
use warnings;
use Test::More;
use File::Temp  qw(tempdir);
use File::Slurp qw(write_file);
use File::Path  qw(make_path);
use Time::Piece;

use Virani;

my $cache    = tempdir( CLEANUP => 1 );
my $set_path = tempdir( CLEANUP => 1 );
my $virani   = Virani->new(
	cache   => $cache,
	verbose => 0,
	sets    => {
		default => { path => $set_path },
	},
);

###
### _bpf_required_hosts
###

# filters that require one or more IP hosts, returned as OR-of-AND-groups
is_deeply( $virani->_bpf_required_hosts('host 1.2.3.4'),     [ ['1.2.3.4'] ], 'host X' );
is_deeply( $virani->_bpf_required_hosts('src host 1.2.3.4'), [ ['1.2.3.4'] ], 'src host X' );
is_deeply( $virani->_bpf_required_hosts('dst host 1.2.3.4'), [ ['1.2.3.4'] ], 'dst host X' );
is_deeply( $virani->_bpf_required_hosts('src 1.2.3.4'),      [ ['1.2.3.4'] ], 'src X' );
is_deeply( $virani->_bpf_required_hosts('dst 1.2.3.4'),      [ ['1.2.3.4'] ], 'dst X' );
is_deeply( $virani->_bpf_required_hosts('host fe80::1'),     [ ['fe80::1'] ], 'IPv6 host' );
is_deeply(
	$virani->_bpf_required_hosts('host 1.2.3.4 or host 5.6.7.8'),
	[ ['1.2.3.4'], ['5.6.7.8'] ],
	'host X or host Y -> two single host groups'
);
is_deeply(
	$virani->_bpf_required_hosts('host 1.2.3.4 and host 5.6.7.8'),
	[ [ '1.2.3.4', '5.6.7.8' ] ],
	'host X and host Y -> one two host group'
);
is_deeply(
	$virani->_bpf_required_hosts('host 1.2.3.4 or host 5.6.7.8 and host 9.10.11.12'),
	[ ['1.2.3.4'], [ '5.6.7.8', '9.10.11.12' ] ],
	'and binds tighter than or'
);
is_deeply(
	$virani->_bpf_required_hosts('host 1.2.3.4 and host 5.6.7.8 or host 9.10.11.12'),
	[ [ '1.2.3.4', '5.6.7.8' ], ['9.10.11.12'] ],
	'a leading and-group then an or-group'
);
is_deeply( $virani->_bpf_required_hosts('host 1.2.3.4 and host 1.2.3.4'),
	[ ['1.2.3.4'] ], 'hosts are deduped within a group' );
is_deeply( $virani->_bpf_required_hosts('  host 1.2.3.4  '), [ ['1.2.3.4'] ], 'surrounding whitespace is tolerated' );

# filters that can not be safely pruned on -> undef
is( $virani->_bpf_required_hosts('not host 1.2.3.4'),      undef, 'negation bails' );
is( $virani->_bpf_required_hosts('host 1.2.3.4 or port 443'), undef, 'an OR branch without a host bails' );
is( $virani->_bpf_required_hosts('( host 1.2.3.4 )'),      undef, 'grouping bails' );
is( $virani->_bpf_required_hosts('port 443'),             undef, 'a bare port bails' );
is( $virani->_bpf_required_hosts('tcp'),                  undef, 'a bare proto bails' );
is( $virani->_bpf_required_hosts('ether host aa:bb:cc:dd:ee:ff'), undef, 'ether host bails (not an IP endpoint)' );
is( $virani->_bpf_required_hosts('host example.com'),     undef, 'a hostname bails' );
is( $virani->_bpf_required_hosts(''),                     undef, 'a empty filter bails' );
is( $virani->_bpf_required_hosts(undef),                  undef, 'undef bails' );

###
### _tshark_required_hosts
###

# native display filters that require one or more IP hosts
is_deeply( $virani->_tshark_required_hosts('ip.addr == 1.2.3.4'), [ ['1.2.3.4'] ], 'ip.addr == X' );
is_deeply( $virani->_tshark_required_hosts('ip.src == 1.2.3.4'),  [ ['1.2.3.4'] ], 'ip.src == X' );
is_deeply( $virani->_tshark_required_hosts('ip.dst == 1.2.3.4'),  [ ['1.2.3.4'] ], 'ip.dst == X' );
is_deeply( $virani->_tshark_required_hosts('ip.addr==1.2.3.4'),   [ ['1.2.3.4'] ], 'no spaces around ==' );
is_deeply( $virani->_tshark_required_hosts('ip.addr eq 1.2.3.4'), [ ['1.2.3.4'] ], 'the eq operator' );
is_deeply( $virani->_tshark_required_hosts('ipv6.addr == fe80::1'), [ ['fe80::1'] ], 'ipv6.addr == X' );
is_deeply(
	$virani->_tshark_required_hosts('ip.addr == 1.2.3.4 || ip.addr == 5.6.7.8'),
	[ ['1.2.3.4'], ['5.6.7.8'] ],
	'|| -> two single host groups'
);
is_deeply(
	$virani->_tshark_required_hosts('ip.src == 1.2.3.4 && ip.dst == 5.6.7.8'),
	[ [ '1.2.3.4', '5.6.7.8' ] ],
	'&& -> one two host group'
);
is_deeply(
	$virani->_tshark_required_hosts('ip.addr == 1.2.3.4 or ip.addr == 5.6.7.8 and ip.addr == 9.10.11.12'),
	[ ['1.2.3.4'], [ '5.6.7.8', '9.10.11.12' ] ],
	'and binds tighter than or, word operators'
);

# native display filters that can not be safely pruned on -> undef
is( $virani->_tshark_required_hosts('ip.addr != 1.2.3.4'),  undef, 'the != operator bails' );
is( $virani->_tshark_required_hosts('! ip.addr == 1.2.3.4'), undef, 'negation bails' );
is( $virani->_tshark_required_hosts('not ip.addr == 1.2.3.4'), undef, 'the not operator bails' );
is( $virani->_tshark_required_hosts('( ip.addr == 1.2.3.4 )'), undef, 'grouping bails' );
is( $virani->_tshark_required_hosts('ip.addr == 1.2.3.4 || tcp.port == 443'),
	undef, 'an OR branch without a host field bails' );
is( $virani->_tshark_required_hosts('tcp.port == 443'), undef, 'a non host field bails' );
is( $virani->_tshark_required_hosts('eth.addr == aa:bb:cc:dd:ee:ff'), undef, 'eth.addr bails (not an IP endpoint)' );
is( $virani->_tshark_required_hosts('ip.addr == 192.168.0.0/24'), undef, 'a CIDR value bails' );
is( $virani->_tshark_required_hosts('ip.addr == example.com'),    undef, 'a hostname value bails' );
is( $virani->_tshark_required_hosts('ip.addr =='),  undef, 'a term missing its value bails' );
is( $virani->_tshark_required_hosts('ip'),          undef, 'a bare protocol bails' );
is( $virani->_tshark_required_hosts('frame.len >= 100'), undef, 'a relational term bails' );
is( $virani->_tshark_required_hosts(''),            undef, 'a empty filter bails' );
is( $virani->_tshark_required_hosts(undef),         undef, 'undef bails' );

###
### config plumbing
###
is( Virani->new( verbose => 0 )->{host_pruning}, 0, 'host_pruning defaults to off' );
is( Virani->new( verbose => 0, host_pruning => 1 )->{host_pruning}, 1, 'host_pruning is read in from opts' );

###
### pruning in get_pcap_local
###
# the index is what pruning trusts, so drive the selection purely off of
# hand written index entries rather than needing real PCAP contents

# builds a minimal single packet PCAP so the filtering step has something real
# to run against, and names it after $ts so it lands in the time window
sub mk_pcap {
	my ( $file, $ts ) = @_;
	my $udp = pack( 'nnnn', 1111, 2222, 12, 0 ) . 'test';
	my $ip  = pack( 'CCnnnCCn', 0x45, 0, 20 + length($udp), 0, 0, 64, 17, 0 )
		. pack( 'C4', 10, 0, 0, 1 )
		. pack( 'C4', 10, 0, 0, 2 );
	my $eth    = pack( 'H12H12n', '001122334455', '66778899aabb', 0x0800 );
	my $pkt    = $eth . $ip . $udp;
	my $header = pack( 'VvvVVVV', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1 );
	my $rec    = pack( 'VVVV',    $ts,        0, length($pkt), length($pkt) ) . $pkt;
	write_file( $file, { binmode => ':raw' }, $header . $rec );
} ## end sub mk_pcap

use IPC::Cmd qw(can_run);
SKIP: {
	if ( !can_run('tcpdump') || !can_run('mergecap') ) {
		skip 'tcpdump and mergecap are required for the pruning integration test', 9;
	}

	my $hosts_dir = $cache . '/pcap_hosts/default';
	make_path($hosts_dir);

	my $now = time;
	foreach my $ts ( 1000000, 1000100, 1000200 ) {
		mk_pcap( $set_path . '/' . $ts . '.pcap', $ts );
		utime( $now - 600, $now - 600, $set_path . '/' . $ts . '.pcap' );
	}

	# index says 1000000.pcap has the anchor, 1000100.pcap does not...
	# 1000200.pcap is left unindexed and so must be kept
	write_file( $hosts_dir . '/1000000.pcap', "10.0.0.1\n10.0.0.2\n" );
	write_file( $hosts_dir . '/1000100.pcap', "192.0.2.9\n" );
	utime( $now, $now, $hosts_dir . '/1000000.pcap' );
	utime( $now, $now, $hosts_dir . '/1000100.pcap' );

	my $start = localtime(999999);
	my $end   = localtime(1000300);

	my $res = $virani->get_pcap_local(
		set          => 'default',
		type         => 'tcpdump',
		filter       => 'host 10.0.0.1',
		start        => $start,
		end          => $end,
		no_cache     => 1,
		host_pruning => undef,
		file         => $cache . '/out.pcap',
	);

	# host_pruning is set per set, so enable it and rerun
	$virani->{host_pruning} = 1;
	$res = $virani->get_pcap_local(
		set      => 'default',
		type     => 'tcpdump',
		filter   => 'host 10.0.0.1',
		start    => $start,
		end      => $end,
		no_cache => 1,
		file     => $cache . '/out.pcap',
	);

	ok( defined( $res->{host_pruning} ), 'host_pruning stats are present when enabled' )
		|| diag( explain($res) );
	is_deeply( $res->{host_pruning}{groups}, [ ['10.0.0.1'] ], 'the derived host group is recorded' );
	# >= 3 rather than == 3 to tolerate the known File::Find::IncludesTimeRange
	# duplicate-entry bug, which can list a time matched PCAP more than once
	cmp_ok( $res->{host_pruning}{candidates}, '>=', 3, 'all three time matched PCAPs were candidates' );
	is( $res->{host_pruning}{kept},
		$res->{host_pruning}{candidates} - $res->{host_pruning}{pruned},
		'kept + pruned accounts for every candidate' );
	is( $res->{host_pruning}{pruned},         1, '1000100.pcap is pruned as its index lacks the host' );
	is( $res->{host_pruning}{unindexed_kept}, 1, '1000200.pcap is kept as it is unindexed' );

	# strong AND... 1000000.pcap indexes 10.0.0.1 but not 203.0.113.5, so the
	# whole group is unsatisfiable and it must be pruned even though one of the
	# two hosts is present. weak OR handling would have kept it.
	$res = $virani->get_pcap_local(
		set      => 'default',
		type     => 'tcpdump',
		filter   => 'host 10.0.0.1 and host 203.0.113.5',
		start    => $start,
		end      => $end,
		no_cache => 1,
		file     => $cache . '/out.pcap',
	);
	is_deeply(
		$res->{host_pruning}{groups},
		[ [ '10.0.0.1', '203.0.113.5' ] ],
		'the AND filter is one two host group'
	);
	is( $res->{host_pruning}{unindexed_kept}, 1, 'only the unindexed PCAP survives the AND filter' );
	is( $res->{host_pruning}{kept},
		$res->{host_pruning}{unindexed_kept},
		'every indexed PCAP is pruned as no group is fully present' );

	# the tshark type derives its host requirements from the native display
	# filter, so pruning works the same way there
	SKIP: {
		if ( !can_run('tshark') ) {
			skip 'tshark is required for the tshark type pruning test', 3;
		}

		$res = $virani->get_pcap_local(
			set      => 'default',
			type     => 'tshark',
			filter   => 'ip.addr == 10.0.0.1',
			start    => $start,
			end      => $end,
			no_cache => 1,
			file     => $cache . '/out.pcap',
		);
		is_deeply( $res->{host_pruning}{groups}, [ ['10.0.0.1'] ], 'the tshark filter host group is recorded' )
			|| diag( explain($res) );
		is( $res->{host_pruning}{pruned},         1, '1000100.pcap is pruned for the tshark filter' );
		is( $res->{host_pruning}{unindexed_kept}, 1, '1000200.pcap is kept as it is unindexed' );
	} ## end SKIP:
} ## end SKIP:

done_testing;
