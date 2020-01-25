use v6;

use Auth::SASL::Mechanism;
use Auth::SASL::Session;
use Auth::SASL::Raku::Mechanism;

unit class Auth::SASL::Raku::Plain does Auth::SASL::Mechanism::Client;

method mechanism(::?CLASS: --> Str:D) { 'PLAIN' }

method status-client(::?CLASS:D:
    Auth::SASL::Session::State:D $session,
    --> Auth::SASL::Status
) {
    $session.state('step', :default(0)) > 0 ?? Auth::SASL::Okay !! Auth::SASL::MoreSteps
}

method step-client(::?CLASS:D:
    Auth::SASL::Session::State:D $session,
    Str:D $challenge,
    --> Str:D
) {
    $session.state('step', :default(0)) = 1;
    join "\0",
        $session.get-property(<authname user>),
        $session.get-property('user'),
        $session.get-property('pass'),
        ;
}
