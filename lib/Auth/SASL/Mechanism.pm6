use v6;

unit package Auth::SASL;

role Mechanism {
    method mechanism(::?CLASS: --> Str:D) { ... }
}

enum Status <Failure Okay MoreSteps>;

role Mechanism::Client does Mechanism {
    method status-client(::?CLASS:D:
        Auth::SASL::Session::State:D $session,
        --> Status:D
    ) { Okay }

    method start-client(::?CLASS:D:
        Auth::SASL::Session::State:D $session,
        Str:D $challenge,
        --> Str:D
    ) { $session.clear }

    method step-client(::?CLASS:D:
        Auth::SASL::Session::State:D $session,
        Str:D $challenge,
        --> Str:D
    ) { }
}

role Mechanism::Server does Mechanism {
    method status-server(::?CLASS:D: --> Status:D) { ... }
    method step-server(::CLASS:D: --> Str:D) { }
}
