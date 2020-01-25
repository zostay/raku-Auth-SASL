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

=begin pod

=head1 NAME

Auth::SASL::Raku::Plain - pure-Raku implementation of PLAIN authentication

=head1 DESCRIPTION

Provides PLAIN SASL authentication. This mechanism sends three claims to verify the user's identity. The name the user is claiming, the user id, and the password.

B<WARNING:> For security reasons, you should never use this mechanism without first ensure secure transport for the underlaying protocol, usually by using SSL to secure the communication channel. In any case, this mechanism makes no special effort to conceal the user and password secrets from any party who could read the communication channel.

=head1 PROPERTIES

=item C<authname>: This is the name the user is claiming. If C<authname> is not provided, this will fallback to the C<user> property.

=item C<user>: This is the user ID the user is claiming.

=item C<pass>: This is the secret the user provides to verify their identity.

=end pod
