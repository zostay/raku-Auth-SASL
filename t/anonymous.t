use v6;

use Test;

use Auth::SASL;

my $sasl = Auth::SASL.new;

ok $sasl, 'got an object';
isa-ok $sasl, Auth::SASL;

$sasl.start-session(
    data => %(
        user     => 'zostay',
        pass     => 'oofoof',
        authname => 'cheese',
    ),
);

my @mechs = $sasl.attempt-mechanisms('ANONYMOUS');
is @mechs.elems, 1, 'got one mechanism';

is @mechs[0].mechanism, 'ANONYMOUS', 'mechanism is ANONYMOUS';
is @mechs[0].is-complete, False, 'mechanism has work to do';
is @mechs[0].step, 'cheese', 'step works';
is @mechs[0].is-complete, True, 'mechnism is done';

done-testing;
