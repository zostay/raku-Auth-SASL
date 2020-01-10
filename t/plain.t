use v6;

use Auth::SASL;
use Test;

my $sasl = Auth::SASL.new(
    mechanism => 'PLAIN',
    callback  => %(
        user     => 'zostay',
        pass     => 'oofoof',
        authname => 'cheese',
    ),
);
ok $sasl, 'constructed';
isa-ok $sasl, Auth::SASL;

is $sasl.mechanism, 'PLAIN', 'sasl mech is PLAIN';

my $conn = $sasl.prepare-client(:service<ldap>, :host<localhost>);

is $conn.mechanism, 'PLAIN', 'conn mech is PLAIN';

is $conn.start-client, "cheese\0zostay\0oofoof", 'start-client does the thing';
is $conn.step-client('xyz'), Nil, 'step-client does the thing';

done-testing;
