#!perl
use 5.010;
use strict;
use warnings;
use Test::More;

use Virani::Client;

my $client = Virani::Client->new( url => 'https://example.com/' );

###
### _build_query
###

# a plain value is passed through, unreserved characters untouched
is( $client->_build_query( set => 'default' ), '?set=default', 'a plain value' );

# spaces become %20, matching the old behavior for space only filters
is( $client->_build_query( bpf => 'host 1.2.3.4' ), '?bpf=host%201.2.3.4', 'spaces are encoded' );

# reserved characters that used to corrupt/inject the query are encoded
is(
	$client->_build_query( bpf => 'host 1.2.3.4 && tcp.port==80' ),
	'?bpf=host%201.2.3.4%20%26%26%20tcp.port%3D%3D80',
	'&& and == are encoded rather than injected'
);

# a would-be parameter injection is neutralized
is(
	$client->_build_query( bpf => 'x&apikey=sekret&get_meta=1' ),
	'?bpf=x%26apikey%3Dsekret%26get_meta%3D1',
	'an embedded &apikey= can not inject a parameter'
);

# IPv6 colons are encoded and round trip through a decoder
is( $client->_build_query( bpf => 'host fe80::1' ), '?bpf=host%20fe80%3A%3A1', 'IPv6 colons are encoded' );

# undef values are skipped, just like the old "only append if defined" logic
is(
	$client->_build_query( list_cached => 1, set => undef, apikey => undef ),
	'?list_cached=1',
	'undef pairs are skipped'
);

# ordering is preserved and multiple pairs join with &
is(
	$client->_build_query( start => 100, end => 200, bpf => 'tcp' ),
	'?start=100&end=200&bpf=tcp',
	'multiple pairs join with & in order'
);

# numeric values are unaffected
is( $client->_build_query( start => 1000000 ), '?start=1000000', 'numeric values pass through' );

done_testing;
