use v6;

use Auth::SASL;
use Test;

my $sasl = Auth::SASL.new;

ok $sasl, 'constructed';
isa-ok $sasl, Auth::SASL;

$sasl.start-session(
    data => %(
        user     => 'zostay',
        pass     => 'oofoof',
        authname => 'cheese',
    ),
);

my @mechs = $sasl.attempt-mechanisms('PLAIN');
is @mechs.elems, 1, 'got only one mechanism';

is @mechs[0].mechanism, 'PLAIN', 'sasl mech is PLAIN';
is @mechs[0].is-complete, False, 'mechanism has work to do';
is @mechs[0].step, "cheese\0zostay\0oofoof", 'step does the thing';
is @mechs[0].is-complete, True, 'mechanism is finished';

done-testing;
