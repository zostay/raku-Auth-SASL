use v6;

use Auth::SASL::Raku::Mechanism;
use Auth::SASL::Mechanism;

unit class Auth::SASL::Raku::ANONYMOUS does Auth::SASL::Raku::Mechanism does Auth::SASL::Mechanism::Client;

constant $SECURITY-FLAGS = <nonplaintext>.Set;

method mechanism(::?CLASS: --> Str:D) { 'ANONYMOUS' }

method mechanism-security-flags(::?CLASS: --> Set:D) {
    $SECURITY-FLAGS
}

method start-client(::?CLASS:D:) { self.call('authname') }
method step-client(::?CLASS:D: $) { self.call('authname') }
