use v6;

use Auth::SASL::Mechanism;
use Auth::SASL::Raku::Mechanism;

unit class Auth::SASL::Raku::PLAIN does Auth::SASL::Raku::Mechanism does Auth::SASL::Mechanism::Client;

constant $SECURITY-FLAGS = <noanonymous>.Set;
constant @TOKENS = <authname user pass>;

method order(::?CLASS: --> Int:D) { 1 }
method mechanism(::?CLASS: --> Str:D) { 'PLAIN' }

method mechanism-security-flags(::?CLASS: --> Set:D) {
    $SECURITY-FLAGS
}

method start-client(::?CLASS:D:) {
    @TOKENS.map({ self.call($_) // '' }).join("\0")
}
