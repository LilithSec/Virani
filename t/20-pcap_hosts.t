#!perl
use 5.010;
use strict;
use warnings;
use Test::More;
use File::Temp  qw(tempdir);
use File::Slurp qw(write_file read_file);
use File::Path  qw(make_path);
use IPC::Cmd    qw(can_run);

use Virani;

my $cache    = tempdir( CLEANUP => 1 );
my $set_path = tempdir( CLEANUP => 1 );
my $upd_path = tempdir( CLEANUP => 1 );
my $virani   = Virani->new(
	cache   => $cache,
	verbose => 0,
	sets    => {
		default => { path => $set_path },
		upd     => { path => $upd_path },
	},
);

my $hosts_dir = $cache . '/pcap_hosts/default';

###
### _parse_tshark_endpoints
###
my $tshark_output = '================================================================================
IPv4 Endpoints
Filter:<No Filter>
                       |  Packets  | |  Bytes  | | Tx Packets | | Tx Bytes | | Rx Packets | | Rx Bytes |
192.168.1.1                  22          17454         11           9317          11            8137
10.0.0.2                      5            555          3            333           2             222
================================================================================
IPv6 Endpoints
Filter:<No Filter>
                       |  Packets  | |  Bytes  | | Tx Packets | | Tx Bytes | | Rx Packets | | Rx Bytes |
fe80::1                       2            120          1             60           1              60
::ffff:10.0.0.2               1             60          1             60           0               0
================================================================================
';

my $hosts = $virani->_parse_tshark_endpoints($tshark_output);
is( ref($hosts), 'ARRAY', '_parse_tshark_endpoints returns a array ref' );
is_deeply(
	[ sort( @{$hosts} ) ],
	[ sort( '192.168.1.1', '10.0.0.2', 'fe80::1', '::ffff:10.0.0.2' ) ],
	'all hosts parsed from both sections'
);

is_deeply( $virani->_parse_tshark_endpoints(undef), [], 'undef parses to a empty list' );
is_deeply( $virani->_parse_tshark_endpoints(''),    [], 'a empty string parses to a empty list' );
is_deeply( $virani->_parse_tshark_endpoints("stuff outside a section\n10.9.9.9    1    2\n"),
	[], 'lines outside a endpoints section are ignored' );

###
### read_pcap_hosts
###
my $now = time;

write_file( $set_path . '/foo.pcap', 'x' );
make_path($hosts_dir);
write_file( $hosts_dir . '/foo.pcap', "10.0.0.1\n10.0.0.2\n" );
utime( $now - 100, $now - 100, $set_path . '/foo.pcap' );
utime( $now,       $now,       $hosts_dir . '/foo.pcap' );

is_deeply(
	$virani->read_pcap_hosts( pcap => $set_path . '/foo.pcap' ),
	[ '10.0.0.1', '10.0.0.2' ],
	'read via a absolute path'
);
is_deeply( $virani->read_pcap_hosts( pcap => 'foo.pcap' ), [ '10.0.0.1', '10.0.0.2' ], 'read via a relative path' );

# stale... the PCAP is newer than the entry
utime( $now + 100, $now + 100, $set_path . '/foo.pcap' );
is( $virani->read_pcap_hosts( pcap => 'foo.pcap' ), undef, 'undef for a stale entry' );
utime( $now - 100, $now - 100, $set_path . '/foo.pcap' );

# no entry
write_file( $set_path . '/nocache.pcap', 'x' );
is( $virani->read_pcap_hosts( pcap => 'nocache.pcap' ), undef, 'undef when there is no entry' );

# entry present but the PCAP is gone
write_file( $hosts_dir . '/gone.pcap', "10.0.0.3\n" );
is( $virani->read_pcap_hosts( pcap => 'gone.pcap' ), undef, 'undef when the PCAP is gone' );

# PCAPs in subdirs of the set path
make_path( $set_path . '/sub' );
write_file( $set_path . '/sub/bar.pcap', 'x' );
make_path( $hosts_dir . '/sub' );
write_file( $hosts_dir . '/sub/bar.pcap', "192.0.2.1\n" );
utime( $now - 100, $now - 100, $set_path . '/sub/bar.pcap' );
utime( $now,       $now,       $hosts_dir . '/sub/bar.pcap' );
is_deeply( $virani->read_pcap_hosts( pcap => 'sub/bar.pcap' ), ['192.0.2.1'], 'read for a PCAP in a subdir' );

# invalid usage
eval { $virani->read_pcap_hosts };
ok( $@, 'dies on undef pcap' );
eval { $virani->read_pcap_hosts( pcap => 'foo.pcap', set => 'nonexistent' ) };
ok( $@, 'dies on a nonexistent set' );
eval { $virani->read_pcap_hosts( pcap => '../../etc/passwd' ) };
ok( $@, 'dies when the relative path escapes the set path' );
eval { $virani->read_pcap_hosts( pcap => '/etc/passwd' ) };
ok( $@, 'dies when the absolute path is not under the set path' );

###
### update_pcap_hosts
###

# computes a IP header checksum
sub ip_checksum {
	my ($data) = @_;
	my $sum = 0;
	foreach my $word ( unpack( 'n*', $data ) ) {
		$sum += $word;
	}
	while ( $sum >> 16 ) {
		$sum = ( $sum & 0xffff ) + ( $sum >> 16 );    ## no critic (BitwiseOperators)
	}
	return ~$sum & 0xffff;                            ## no critic (BitwiseOperators)
} ## end sub ip_checksum

# writes a minimal valid PCAP containing a single UDP packet
# between 10.0.0.1 and 10.0.0.2
sub mk_pcap {
	my ($file) = @_;
	my $udp = pack( 'nnnn', 1111, 2222, 12, 0 ) . 'test';
	my $ip_no_sum
		= pack( 'CCnnnCCn', 0x45, 0, 20 + length($udp), 0, 0, 64, 17, 0 )
		. pack( 'C4',       10,   0, 0, 1 )
		. pack( 'C4',       10,   0, 0, 2 );
	my $ip
		= pack( 'CCnnnCCn', 0x45, 0, 20 + length($udp), 0, 0, 64, 17, ip_checksum($ip_no_sum) )
		. pack( 'C4',       10,   0, 0, 1 )
		. pack( 'C4',       10,   0, 0, 2 );
	my $eth    = pack( 'H12H12n', '001122334455', '66778899aabb', 0x0800 );
	my $pkt    = $eth . $ip . $udp;
	my $header = pack( 'VvvVVVV', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1 );
	my $rec    = pack( 'VVVV',    1000000,    0, length($pkt), length($pkt) ) . $pkt;
	write_file( $file, { binmode => ':raw' }, $header . $rec );
} ## end sub mk_pcap

eval { $virani->update_pcap_hosts( set => 'nonexistent' ) };
ok( $@, 'update_pcap_hosts dies on a nonexistent set' );

SKIP: {
	if ( !can_run('tshark') ) {
		skip 'tshark not found in the path', 18;
	}

	mk_pcap( $upd_path . '/a.pcap' );

	# too new to index
	my $stats = $virani->update_pcap_hosts( set => 'upd', workers => 0, min_age => 120 );
	is( $stats->{pcap_count}, 1, 'one PCAP found' );
	is( $stats->{too_new},    1, 'a recently modified PCAP is skipped as too new' );
	is( $stats->{indexed},    0, 'nothing indexed while too new' );
	is( $virani->read_pcap_hosts( set => 'upd', pcap => 'a.pcap' ), undef, 'no entry while too new' );

	# age it and it indexes
	utime( $now - 600, $now - 600, $upd_path . '/a.pcap' );
	$stats = $virani->update_pcap_hosts( set => 'upd', workers => 0, min_age => 120 );
	is( $stats->{indexed},      1, 'a aged PCAP is indexed' );
	is( $stats->{failed_count}, 0, 'no failures indexing a valid PCAP' )
		|| diag( explain($stats) );
	is_deeply(
		$virani->read_pcap_hosts( set => 'upd', pcap => 'a.pcap' ),
		[ '10.0.0.1', '10.0.0.2' ],
		'indexed hosts read back'
	);

	# a second run leaves it alone
	$stats = $virani->update_pcap_hosts( set => 'upd', workers => 0, min_age => 120 );
	is( $stats->{fresh},   1, 'a current entry is seen as fresh' );
	is( $stats->{indexed}, 0, 'a current entry is not reindexed' );

	# modifying the PCAP reindexes it... the entry is backdated to older
	# than the PCAP, as happens when a PCAP changes after being indexed
	utime( $now - 500, $now - 500, $upd_path . '/a.pcap' );
	utime( $now - 600, $now - 600, $cache . '/pcap_hosts/upd/a.pcap' );
	$stats = $virani->update_pcap_hosts( set => 'upd', workers => 0, min_age => 120 );
	is( $stats->{indexed}, 1, 'a modified PCAP is reindexed' );

	# failure handling for a bogus PCAP
	write_file( $upd_path . '/bad.pcap', 'not really a pcap' );
	utime( $now - 600, $now - 600, $upd_path . '/bad.pcap' );
	$stats = $virani->update_pcap_hosts( set => 'upd', workers => 0, min_age => 120 );
	is( $stats->{failed_count}, 1, 'a bogus PCAP fails' );
	ok( defined( $stats->{failed}{ $upd_path . '/bad.pcap' } ), 'the failure reason is recorded' );
	is( $stats->{fresh},                                              1,     'the valid PCAP is still fresh' );
	is( $virani->read_pcap_hosts( set => 'upd', pcap => 'bad.pcap' ), undef, 'no entry for a failed PCAP' );
	unlink( $upd_path . '/bad.pcap' );

	# pruning of entries who's PCAP is gone
	write_file( $cache . '/pcap_hosts/upd/removed.pcap', "10.9.9.9\n" );
	$stats = $virani->update_pcap_hosts( set => 'upd', workers => 0, min_age => 120 );
	is( $stats->{pruned}, 1, 'a entry for a removed PCAP is pruned' );
	ok( !-f $cache . '/pcap_hosts/upd/removed.pcap', 'the pruned entry is gone' );

	# forking still works
	$stats = $virani->update_pcap_hosts( set => 'upd', workers => 2, min_age => 120 );
	is( $stats->{fresh}, 1, 'update with forking works' );

	# a PCAP in a subdir of the set path
	make_path( $upd_path . '/sub' );
	mk_pcap( $upd_path . '/sub/b.pcap' );
	utime( $now - 600, $now - 600, $upd_path . '/sub/b.pcap' );
	$stats = $virani->update_pcap_hosts( set => 'upd', workers => 0, min_age => 120 );
	is_deeply(
		$virani->read_pcap_hosts( set => 'upd', pcap => 'sub/b.pcap' ),
		[ '10.0.0.1', '10.0.0.2' ],
		'a PCAP in a subdir indexes and reads back'
	);
} ## end SKIP:

done_testing;
