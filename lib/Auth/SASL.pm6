use v6;

unit class Auth::SASL:ver<0.0.1>:auth<github:zostay>;

use Auth::SASL::Factory;
use Auth::SASL::Mechanism;
use Auth::SASL::Raku;
use Auth::SASL::Session;
use X::Auth::SASL;

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
        my $first = True;
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

            # Only rethrow the exception if this occurs on the first attempt
            CATCH {
                when X::Auth::SASL::NotFound {
                    if $first {
                        .rethrow;
                    }
                    else {
                        last;
                    }
                }
            }

            # Start it
            $working-mech.begin;

            # Take it
            take $working-mech;
            $first--;

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

This API is designed to work in a very modular way. This class, C<Auth::SASL>, is designed to operate as the front-end. As long as you are just making use of this module distribution to implement a SASL protocol for a client service, such as SMTP, IMAP, or LDAP, this class will provide most of what you need.

The factory objects are used to find and build mechanism objects. Mechanism objects provide handling to implement each kind of SASL authentication mechanism. The session objects provide the information about the identity that is being authenticated.

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

Starts a new session. The session provides information about the identity being authenticated.

For simple cases, you can provide C<%data> directly. These will be simple key/value pairs that provide the authentication details. The keys required will vary by the mechanisms involved.

For more complex cases you can provide a C<&callback>, this will be a L<Callable> routine that will be called each time a mechanism object requires a property. The callback must provide a signature compatible with:

    sub (Str:D $property-name, Str:D :$service, Str:D :$host --> Str)

It should always return defined string. If it does not and the authentication method depends on that value,  authentication mechansim will fail with an L<X::Auth::SASL::Property> exception.

Finally, you can provide an object implementing L<Auth::SASL::Session>.

=head2 method end-session

    method end-session(Auth::SASL:D:)

Clears the session. The front-end will not work until a new session is started by calling L<.begin-session|#method begin-session>.

=head2 method attempt-mechanisms

    multi method attempt-mechanisms(Auth::SASL:D: Str:D $mechanisms, Str:D :$service = '', Str:D :$host = '' --> Seq:D)
    multi method attempt-mechanisms(Auth::SASL:D: Mixy:D $mechanisms, Str:D :$service = '', Str:D :$host = '' --> Seq:D)

Once a session has been established, this method may be called to itereate over potential authentication mechanisms. The C<$mechanisms> should be set to the list of mechanisms the server has reported as supporting. The factory will then use this and the list of mechanisms it supports to select the mechanisms to attempt. The L<Seq> returned will allow you to iterate through 1 or more L<Auth::SASL::Mechanism::WorkingClient> objects to use for authentication. If no compatible mechanism is found, the L<X::Auth::SASL::NotFound|X::Auth::SASL#class X::Auth::SASL::NotFound> exception will be thrown.

If C<$mechanisms> is passed as a string, it may either be a single mechanism name, e.g., C<PLAIN>, or it it can be a space separated list of mechanism names, e.g., C<PLAIN ANONYMOUS>. The factory object will determine which mechanisms are most preferable in this case.

If C<$mechanisms> is passed as a L<Mixy> object, such as a L<Mix> or L<MixHash>, the factory can use the score assigned to each key in the L<Mixy> object to reorder the mechanisms and go in a different order.

The C<$service> and C<$host> parameters are optional and are used to allow a single session to connect to multiple services safely and even concurrently, so long as only a particular mechanism is permitted to make its attempt on a given C<$service> and C<$host> concurrently. The C<$service> and C<$host> parameters can also be used to allow a session to have multiple configurations for a given identity for different service/host combinations.

=end pod
