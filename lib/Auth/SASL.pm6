use v6;

unit class Auth::SASL:ver<0.0.1>:auth<github:zostay>;

use Auth::SASL::Factory;
use Auth::SASL::Mechanism;
use Auth::SASL::Raku;
use Auth::SASL::Session;

has Auth::SASL::Session $.session;
has Auth::SASL::Factory $.factory = Auth::SASL::Raku.new;

our sub split-mechanisms(Str:D $mechanisms --> Mix:D) {
    $mechanisms.comb(/ <[- \w]>+ /).Mix;
}

multi method begin-session(::?CLASS:D:
    Auth::SASL::Session $session,
) {
    $!session = $session;
}

multi method begin-session(::?CLASS:D: :%data, :&callback) {
    $!session = Auth::SASL::Session::Standard.new(:%data, :&callback);
}

method end-session(::?CLASS:D:) {
    $!session = Nil;
}

multi method attempt-mechanisms(::?CLASS:D:
    Str:D $mechanisms,
    Str:D :$service = '',
    Str:D :$host = '',
    --> Seq:D
) {
    self.attempt-mechanisms(
        split-mechanisms($mechanisms),
        :$service,
        :$host,
    );
}

multi method attempt-mechanisms(::?CLASS:D:
    Mixy:D $mechanisms,
    Str:D :$service = '',
    Str:D :$host = '',
    --> Seq:D
) {
    gather {
        my $open-mechs = $mechanisms.MixHash;
        while $open-mechs {

            # Ask the factory for the best mechanism handler
            my $mechanism = $!factory.new-client($open-mechs);

            # build a working mechanism, which binds the session
            my $working-mech = Auth::SASL::Mechanism::WorkingClient.new(
                mechanism => $mechanism,
                session   => $!session.mechanism-state(
                    $mechanism.mechanism,
                    :$service,
                    :$host,
                ),
            );

            # Start it
            $working-mech.begin;

            # Take it
            take $working-mech;

            # Remove the last picked mech so we do not try it again
            $open-mechs{ $mechanism.mechanism }:delete;
        }
    }
}

=begin pod

=head1 NAME

Auth::SASL - Simple Authentication Security Layer

=head1 SYNOPSIS

    use Auth::SASL;
    use Base64;

    # naïve ESMTP handler...
    my $smtp = IO::Socket::INET.new(:host<localhost>, :port(25));
    $smtp.print("EHLO localhost\n");
    my ($more, %properties);
    repeat {
        if $smtp.get ~~ /^ (\d\d\d)(<[-\ ]>)(.*) $/ {
            my ($code, $more, $props) = ("$0", $1 eq "-", "$2");
            if $props ~~ /(<[-\w]>+) >> <[=\ \t]>* (<-[\n]>*)/ {
                %properties{ "$0" } = "$1";
            }
        }
        else {
            die "error occurred while initiating SMTP connection";
        }
    } while $more;

    my $mechanisms = %properties<AUTH>;

    my $sasl = Auth::SASL.new;
    $sasl.begin-session(
        data => %(
            user     => 'zostay',
            pass     => 'secret',
            authname => 'zostay',
        ),
    );

    my ($response-code, $challenge);
    MECHANISM: for $sasl.attempt-mechanisms($mechanisms, :service<smtp>, :host<localhost>) {
        $challenge = '';
        repeat {
            $smtp.print(encode-base64(.step($challenge), :str) ~ "\n");
            ($response-code, $challenge) = $smtp.get.split(' ', 2);
            next MECHANISM unless $response-code ~~ /^ 2 | 3 /;
        } until .is-complete;

        last MECHANISM if $response-code eq '235';

        CATCH {
            when X::Auth::SASL {
                $smtp.print("*\n");
            }
        }
    }

    die "unable to authenticate" unless $response-code eq '235';

    # Send email...
    ...

=head1 DESCRIPTION

SASL stands for Simple Authentication and Security Layer. It is really just a means of exchanging authentication strings with a service. This library implements the client-side interaction for SASL. SASL itself is complicated only in the fact that it provides a means of exchanging authentication strings, but without specifying the protocol-specific details. Therefore, to use this module for a given protocol, any encoding, error handling, or other details must be implemented by the application developer.

=head1 METHODS

=head2 method new

    method new(Auth::SASL:U:
        Auth::SASL::Session :$session,
        Auth::SASL::Factory :$factory = Auth::SASL::Raku.new,
        --> Auth::SASL:D
    )

Constructs an C<Auth::SASL> front-end. Both arguments are optional. The C<$factory> defaults to L<Auth::SASL::Raku>, which provides a pure Raku implementation of some SASL mechanisms. Without setting C<$session>, you will be required to call L<.begin-session|#method begin-session> to initiate a session.

=head2 method begin-session

    multi method begin-session(Auth::SASL:D: Auth::SASL::Session $session)
    multi method begin-session(Auth::SASL:D: :%data, :&callback)

Est

=end pod
