use v6;

use Test;

use Auth::SASL;

my $sasl = Auth::SASL.new;

ok $sasl, 'got an object';
isa-ok $sasl, Auth::SASL;

ok $sasl.supports-client-mechanisms('PLAIN'), 'supports PLAIN';
ok $sasl.supports-client-mechanisms('ANONYMOUS'), 'supports ANONYMOUS';
ok $sasl.supports-client-mechanisms('PLAIN ANONYMOUS'), 'supports PLAIN ANONYMOUS';
ok $sasl.supports-client-mechanisms('PLAIN WEIRD'), 'supports PLAIN WEIRD';
nok $sasl.supports-client-mechanisms('SUPER WEIRD'), 'does not supoprt SUPER WEIRD';

ok $sasl.supports-client-mechanisms(<PLAIN>.Mix), 'supports PLAIN';
ok $sasl.supports-client-mechanisms(<ANONYMOUS>.Mix), 'supports ANONYMOUS';
ok $sasl.supports-client-mechanisms(<PLAIN ANONYMOUS>.Mix), 'supports PLAIN ANONYMOUS';
ok $sasl.supports-client-mechanisms(<PLAIN WEIRD>.Mix), 'supports PLAIN WEIRD';
nok $sasl.supports-client-mechanisms(<SUPER WEIRD>.Mix), 'does not supoprt SUPER WEIRD';

done-testing;
