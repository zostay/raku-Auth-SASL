use v6;

unit package Auth::SASL;

use Auth::SASL::Session;

role Mechanism {
    method mechanism(::?CLASS: --> Str:D) { ... }
}

enum Status <Failed Okay MoreSteps>;

role Mechanism::Client does Mechanism {
    method status-client(::?CLASS:D:
        Auth::SASL::Session::State:D $session,
        --> Status:D
    ) { Okay }

    method begin-client(::?CLASS:D:
        Auth::SASL::Session::State:D $session,
    ) { $session.clear }

    method step-client(::?CLASS:D:
        Auth::SASL::Session::State:D $session,
        Str:D $challenge,
        --> Str:D
    ) { }
}

class Mechanism::WorkingClient {
    has Auth::SASL::Session::State $.session;
    has Mechanism::Client $.mechanism;

    method mechanism(::?CLASS:D: --> Str:D) {
        $!mechanism.mechanism;
    }

    method status(::?CLASS:D: --> Status:D) {
        $!mechanism.status-client($!session);
    }

    method is-complete(::?CLASS:D: --> Bool:D) {
        $.status == Okay
    }

    method is-ongoing(::?CLASS:D: --> Bool:D) {
        $.status == MoreSteps
    }

    method is-failed(::?CLASS:D: --> Bool:D) {
        $.status == Failed;
    }

    method begin(::?CLASS:D:) {
        $!mechanism.begin-client($!session);
    }

    method step(::?CLASS:D:
        Str:D $challenge = '',
        --> Str:D
    ) {
        $!mechanism.step-client($!session, $challenge);
    }
}

role Mechanism::Server does Mechanism {
    method status-server(::?CLASS:D: --> Status:D) { ... }
    method step-server(::CLASS:D: --> Str:D) { }
}

=begin pod

=head1 NAME

Auth::SASL::Mechanism - role all SASL mechanisms implement

=head1 DESCRIPTION

This is a very abstact class that all SASL mechanism handlers must implement.

See L<Auth::SASL::Mechanism::Client> for a full description on implementing a SASL client mechanism.

=end pod
