use v6;

use Auth::SASL;
use Test;

my $sasl = Auth::SASL.new(
    mechanism => 'PLAIN',
    callback  => %(
        user     => 'zostay',
        pass     => &cb-pass,
        authname => &cb-authname.assuming(1),
    ),
);

ok $sasl, 'constructed';
isa-ok $sasl, Auth::SASL;

is $sasl.mechanism, 'PLAIN', 'sasl mech is PLAIN';

my $conn = $sasl.prepare-client(:service<ldap>, :host<localhost>);
is $conn.mechanism, 'PLAIN', 'conn mech is PLAIN';

is $conn.start-client, "cheese\0zostay\0oofoof", 'client-start does the thing';
is $conn.step-client('xyz'), Nil, 'client-step does the thing';

sub cb-pass() {
    pass('regular callback works');
    'oofoof';
}

sub cb-authname($v) {
    is $v, 1, 'assuming callback also works';
    'cheese';
}

done-testing;
