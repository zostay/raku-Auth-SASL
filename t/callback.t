use v6;

use Auth::SASL;
use Test;

my $sasl = Auth::SASL.new;

multi my-callback('pass', *%_) {
    pass('pass callback works');
    'oofoof';
}

multi my-callback('authname', :$service, :$host) {
    if $service eq 'ldap' && $host eq 'localhost' {
        pass('authname with service/host check works');
        'cheese';
    }
    else {
        flunk('authname with service/host check fails');
        'tofu';
    }
}

$sasl.start-session(
    data => %(
        user => 'zostay',
    ),
    callback => &my-callback,
);

ok $sasl, 'constructed';
isa-ok $sasl, Auth::SASL;

my @mechs = $sasl.attempt-mechanisms('PLAIN', :service<ldap>, :host<localhost>);
is @mechs.elems, 1, 'got one mechanism';

is @mechs[0].mechanism, 'PLAIN', 'sasl mech is PLAIN';
is @mechs[0].is-complete, False, 'mechanism has work to do';
is @mechs[0].step, "cheese\0zostay\0oofoof", 'step does the thing';
is @mechs[0].is-complete, True, 'mechanism is finished';

done-testing;
