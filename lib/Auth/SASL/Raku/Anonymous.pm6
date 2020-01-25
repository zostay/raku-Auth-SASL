use v6;

use Auth::SASL::Raku::Mechanism;
use Auth::SASL::Mechanism;

unit class Auth::SASL::Raku::Anonymous does Auth::SASL::Mechanism::Client;

method mechanism(::?CLASS: --> Str:D) { 'ANONYMOUS' }

method status-client(::?CLASS:D:
    Auth::SASL::Session::State:D $session,
    --> Auth::SASL::Status
) {
    $session.state('step', :default(0)) > 0 ?? Auth::SASL::Okay !! Auth::SASL::MoreSteps
}

method step-client(::?CLASS:D:
    Auth::SASL::Session::State:D $session,
    Str:D $
    --> Str:D
) {
    $session.state('step', :default(0)) = 1;
    $session.get-property('authname');
}
