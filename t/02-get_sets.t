#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

use Virani;

my $virani = Virani->new(
	default_set => 'foo',
	sets        => {
		foo => {
			path => '/var/log/daemonlogger/foo',
			type => 'tshark',
		},
		bar => {
			path    => '/var/log/daemonlogger/bar',
			padding => 10,
		},
	},
);

my $sets = $virani->get_sets;

is( ref($sets), 'HASH', 'get_sets returns a hash ref' );
is( scalar( keys( %{$sets} ) ), 2, 'both sets returned' );
ok( defined( $sets->{foo} ), 'set foo present' );
ok( defined( $sets->{bar} ), 'set bar present' );
is( $sets->{foo}{type},    'tshark', 'type for set foo returned' );
is( $sets->{bar}{padding}, 10,       'padding for set bar returned' );
ok( !defined( $sets->{foo}{path} ), 'path not included for set foo' );
ok( !defined( $sets->{bar}{path} ), 'path not included for set bar' );
is( $virani->get_default_set, 'foo', 'get_default_set returns the default set' );

done_testing;
