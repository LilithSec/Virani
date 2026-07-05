#!perl
use 5.010;
use strict;
use warnings;
use Test::More;
use File::Temp  qw(tempdir);
use File::Slurp qw(write_file);
use JSON;

use Virani;

my $cache  = tempdir( CLEANUP => 1 );
my $virani = Virani->new( cache => $cache, verbose => 0 );

# creates a fake cache entry, optionally without the PCAP,
# as will happen for failed generation
sub mk_entry {
	my ( $id, $with_pcap, $meta ) = @_;
	if ( !defined($meta) ) {
		$meta = { filter => 'port 22', final_size => 42, req_time => 1 };
	}
	write_file( $cache . '/' . $id . '.json', encode_json($meta) );
	if ($with_pcap) {
		write_file( $cache . '/' . $id, 'fakepcap' );
	}
} ## end sub mk_entry

my $id_a = 'default-tcpdump-100-200-' . ( 'a' x 32 );
my $id_b = 'my-set-tshark-300-400-' . ( 'b' x 32 );
my $id_c = 'default-bpf2tshark-500-600-' . ( 'c' x 32 );

mk_entry( $id_a, 1 );
mk_entry( $id_b, 1, { filter => 'host 10.0.0.1', final_size => 5, req_time => 2 } );
mk_entry( $id_c, 0 );

# these should all be ignored by list_cached
write_file( $cache . '/' . $id_a . '-0', 'tmpfile' );
write_file( $cache . '/random.json',     '{}' );
write_file( $cache . '/random.pcap',     'x' );
write_file( $cache . '/nodashes.json',   '{}' );

###
### list_cached
###
my $cached = $virani->list_cached;
is( ref($cached),         'ARRAY', 'list_cached returns a array ref' );
is( scalar( @{$cached} ), 3,       'three cached searches listed' );
is_deeply( [ map { $_->{id} } @{$cached} ], [ $id_a, $id_b, $id_c ], 'sorted by start time' );

my ($item_a) = grep { $_->{id} eq $id_a } @{$cached};
is( $item_a->{set},        'default', 'set parsed from ID' );
is( $item_a->{type},       'tcpdump', 'type parsed from ID' );
is( $item_a->{start_s},    100,       'start_s parsed from ID' );
is( $item_a->{end_s},      200,       'end_s parsed from ID' );
is( $item_a->{has_pcap},   1,         'has_pcap true when the PCAP exists' );
is( $item_a->{filter},     'port 22', 'filter read from the metadata JSON' );
is( $item_a->{final_size}, 42,        'final_size read from the metadata JSON' );
ok( defined( $item_a->{generated_s} ), 'generated_s is set' );

my ($item_b) = grep { $_->{id} eq $id_b } @{$cached};
is( $item_b->{set},  'my-set', 'set names with dashes parse' );
is( $item_b->{type}, 'tshark', 'type parses with a dashed set name' );

my ($item_c) = grep { $_->{id} eq $id_c } @{$cached};
is( $item_c->{has_pcap}, 0, 'has_pcap false when generation failed' );

# set limiting
$cached = $virani->list_cached( set => 'default' );
is( scalar( @{$cached} ), 2, 'set limiting to default' );
$cached = $virani->list_cached( set => 'my-set' );
is( scalar( @{$cached} ), 1, 'set limiting to my-set' );
$cached = $virani->list_cached( set => 'nonexistent' );
is( scalar( @{$cached} ), 0, 'set limiting to a set with no cached searches' );

###
### get_cached
###
is( $virani->get_cached( id => $id_a ), $cache . '/' . $id_a, 'get_cached returns the PCAP path' );
ok( -f $virani->get_cached( id => $id_a ), 'returned PCAP path exists' );
is(
	$virani->get_cached( id => $id_a, what => 'json' ),
	$cache . '/' . $id_a . '.json',
	'get_cached returns the JSON path'
);

# failed generation... JSON fetchable, PCAP not
ok( -f $virani->get_cached( id => $id_c, what => 'json' ), 'JSON fetchable for a failed generation' );
eval { $virani->get_cached( id => $id_c ) };
ok( $@, 'PCAP fetch dies for a failed generation' );

# invalid what
eval { $virani->get_cached( id => $id_a, what => 'exe' ) };
ok( $@, 'dies on a invalid what' );

# undef ID
eval { $virani->get_cached };
ok( $@, 'dies on undef ID' );

# invalid or unsafe IDs
my @bad_ids = (
	'../../../etc/passwd',
	'foo',
	$id_a . '-0',
	'../x-tcpdump-100-200-' . ( 'a' x 32 ),
	'a/b-tcpdump-100-200-' . ( 'a' x 32 ),
	'a\\b-tcpdump-100-200-' . ( 'a' x 32 ),
	'default-nmap-100-200-' . ( 'a' x 32 ),
	'default-tcpdump-100-200-' . ( 'a' x 31 ) . 'Z',
	'default-tcpdump-100-200-' . ( 'a' x 32 ) . "\n",
);
foreach my $bad_id (@bad_ids) {
	eval { $virani->get_cached( id => $bad_id ) };
	my $printable = $bad_id;
	$printable =~ s/\n/\\n/g;
	ok( $@, 'dies on the invalid ID "' . $printable . '"' );
	if ( defined($@) ) {
		like( $@, qr/not a valid cache ID/, 'invalid ID error mentions the ID being invalid' );
	}
}

# existent entry, but non-existent cache file removed under it
unlink( $cache . '/' . $id_b );
eval { $virani->get_cached( id => $id_b ) };
ok( $@, 'dies when the PCAP has been removed' );

done_testing;
