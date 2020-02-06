NAME
====

Auth::SASL - Simple Authentication Security Layer

SYNOPSIS
========

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
        $smtp.print("AUTH $_.mechanism\n");
        ($response-code, $challenge) = $smtp.get.split(' ', 2);
        next MECHANISM unless $response-code eq '334';

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

DESCRIPTION
===========

SASL stands for Simple Authentication and Security Layer. It is really just a means of exchanging authentication strings with a service. This library implements the client-side interaction for SASL. SASL itself is complicated only in the fact that it provides a means of exchanging authentication strings, but without specifying the protocol-specific details. Therefore, to use this module for a given protocol, any encoding, error handling, or other details must be implemented by the application developer.

This API is designed to work in a very modular way. This class, `Auth::SASL`, is designed to operate as the front-end. As long as you are just making use of this module distribution to implement a SASL protocol for a client service, such as SMTP, IMAP, or LDAP, this class will provide most of what you need.

The factory objects are used to find and build mechanism objects. Mechanism objects provide handling to implement each kind of SASL authentication mechanism. The session objects provide the information about the identity that is being authenticated.

METHODS
=======

method new
----------

    method new(Auth::SASL:U:
        Auth::SASL::Session :$session,
        Auth::SASL::Factory :$factory = Auth::SASL::Raku.new,
        --> Auth::SASL:D
    )

Constructs an `Auth::SASL` front-end. Both arguments are optional. The `$factory` defaults to [Auth::SASL::Raku](Auth::SASL::Raku), which provides a pure Raku implementation of some SASL mechanisms. Without setting `$session`, you will be required to call [.begin-session](#method begin-session) to initiate a session.

method begin-session
--------------------

    multi method begin-session(Auth::SASL:D: Auth::SASL::Session $session)
    multi method begin-session(Auth::SASL:D: :%data, :&callback)

Starts a new session. The session provides information about the identity being authenticated.

For simple cases, you can provide `%data` directly. These will be simple key/value pairs that provide the authentication details. The keys required will vary by the mechanisms involved.

For more complex cases you can provide a `&callback`, this will be a [Callable](Callable) routine that will be called each time a mechanism object requires a property. The callback must provide a signature compatible with:

    sub (Str:D $property-name, Str:D :$service, Str:D :$host --> Str)

It should always return defined string. If it does not and the authentication method depends on that value, authentication mechansim will fail with an [X::Auth::SASL::Property](X::Auth::SASL::Property) exception.

Finally, you can provide an object implementing [Auth::SASL::Session](Auth::SASL::Session).

method end-session
------------------

    method end-session(Auth::SASL:D:)

Clears the session. The front-end will not work until a new session is started by calling [.begin-session](#method begin-session).

method supports-client-mechanisms
---------------------------------

    multi method supports-client-mechanisms(Auth::SASL:D: Str:D $mechanisms --> Bool:D)
    multi method supports-client-mechanisms(Auth::SASL:D: Mixy:D $mechanisms --> Bool:D)

Returns a `True` value if at least one of the mechanisms listed in `$mechanisms` is supported by the current, `False` otherwise.

method attempt-mechanisms
-------------------------

    multi method attempt-mechanisms(Auth::SASL:D: Str:D $mechanisms, Str:D :$service = '', Str:D :$host = '' --> Seq:D)
    multi method attempt-mechanisms(Auth::SASL:D: Mixy:D $mechanisms, Str:D :$service = '', Str:D :$host = '' --> Seq:D)

Once a session has been established, this method may be called to itereate over potential authentication mechanisms. The `$mechanisms` should be set to the list of mechanisms the server has reported as supporting. The factory will then use this and the list of mechanisms it supports to select the mechanisms to attempt. The [Seq](Seq) returned will allow you to iterate through 1 or more [Auth::SASL::Mechanism::WorkingClient](Auth::SASL::Mechanism::WorkingClient) objects to use for authentication. If no compatible mechanism is found, the [X::Auth::SASL::NotFound](X::Auth::SASL#class X::Auth::SASL::NotFound) exception will be thrown.

If `$mechanisms` is passed as a string, it may either be a single mechanism name, e.g., `PLAIN`, or it it can be a space separated list of mechanism names, e.g., `PLAIN ANONYMOUS`. The factory object will determine which mechanisms are most preferable in this case.

If `$mechanisms` is passed as a [Mixy](Mixy) object, such as a [Mix](Mix) or [MixHash](MixHash), the factory can use the score assigned to each key in the [Mixy](Mixy) object to reorder the mechanisms and go in a different order.

The `$service` and `$host` parameters are optional and are used to allow a single session to connect to multiple services safely and even concurrently, so long as only a particular mechanism is permitted to make its attempt on a given `$service` and `$host` concurrently. The `$service` and `$host` parameters can also be used to allow a session to have multiple configurations for a given identity for different service/host combinations.

