use v6;

use Test;

use Auth::SASL;

my $sasl = Auth::SASL.new(
    mechanism => 'ANONYMOUS',
    callback  => %(
        user     => 'zostay',
        pass     => 'oofoof',
        authname => 'cheese',
    ),
);

ok $sasl, 'got an object';
isa-ok $sasl, Auth::SASL;

is $sasl.mechanism, 'ANONYMOUS', 'mechanism is ANONYMOUS';

my $conn = $sasl.prepare-client(:service<ldap>, :host<localhost>);
is $conn.mechanism, 'ANONYMOUS', 'connection mechanism is ANONYMOUS';

my $initial = $conn.start-client;
is $initial, 'cheese', 'start-client works';

my $step = $conn.step-client('xyz');
is $step, 'cheese', 'step-client works too';

done-testing;
