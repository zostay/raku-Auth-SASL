use v6;

use X::Auth::SASL;

class Auth::SASL::Session::State { ... }

role Auth::SASL::Session {
    has %!mechanism-state;

    method mechanism-state(
        Str:D $mechanism,
        Str:D :$service = '',
        Str:D :$host = '',
        --> Auth::SASL::Session::State:D
    ) {
        %!mechanism-state{ $service }{ $host }{ $mechanism } //=
            Auth::SASL::Session::State.new(
                parent => self,
                :$service,
                :$host,
            );
    }

    method session-property(
        Str:D $,
        Str:D :$service,
        Str:D :$host,
        --> Str
    ) { ... }

    multi method get-property(
        Str:D $name,
        Str:D :$service = '',
        Str:D :$host = '',
        --> Str:D
    ) {
        with self.session-property($name, :$service, :$host) {
            return $_;
        }
        else {
            fail X::Auth::SASL::Property.new(:property($name), :$service, :$host);
        }
    }

    multi method get-property(
        @names,
        Str:D :$service = '',
        Str:D :$host = '',
        --> Str:D
    ) {
        for @names -> $name {
            return $_ with self.session-property($name, :$service, :$host);
        }

        fail X::Auth::SASL::Property.new(:property(@names[0]), :$service, :$host);
    }
}

class Auth::SASL::Session::State {
    has Str $.service;
    has Str $.host;
    has Auth::SASL::Session $.parent;
    has %!state;

    method state(Str:D $var, :$default) is rw {
        %!state{ $var } //= $default with $default;
        return-rw %!state{ $var };
    }

    method clear() {
        %!state = ();
    }

    multi method get-property(Str:D $name --> Str:D) {
        $!parent.get-property($name, :$!service, :$!host);
    }

    multi method get-property(@names --> Str:D) {
        $!parent.get-property(@names, :$!service, :$!host);
    }
}

class Auth::SASL::Session::Standard does Auth::SASL::Session {
    has %.data;
    has &.callback;

    method session-property(Str:D $name, Str:D :$service, Str:D :$host --> Str) {
        if %.data.{ $name }:exists {
            %.data.{ $name };
        }
        orwith &.callback {
            .( $name, :$service, :$host );
        }
        else {
            Nil;
        }
    }

    method set-property(Str:D $name, Str:D $value) {
        %.data.{ $name } = $value;
    }

}

=begin pod

=head1 NAME

Auth::SASL::Session - provide properties for a SASL authetication session

=head1 SYNOPSIS

    use Auth::SASL::Session;

    class MySession does Auth::SASL::Session {
        method session-property(
            Str $name, Str :$service, Str :$host,
            --> Str
        ) {
            prompt("$name? ");
        }
    }

=head1 DESCRIPTION

The SASL authentication system needs a way to get information like username and password, authentication keys, tokens, and what-not to pass through to the SASL mechanism handlers. Any object wishing to do that must implement this role.

=head1 REQUIRED METHODS

These methods must be defined for any implementation of this role.

=head2 method session-property

    method session-property(
        Str:D $name,
        Str:D :$service,
        Str:D :$host,
        --> Str
    )

This method provides the property to the SASL mechanism handler. The name of the property being requested will be set as C<$name>. The C<$service> and C<$host> values will also be passed, though, they may be set to the empty string. These latter two are used to give context in case that matters for the value returned.

For example, you might implement a configuration system that allows the user to provide different credentials for the "ldap" service from the "smtp" service or different credentials for different hosts.

If no property is defined for the given name, return an undefined L<Str> type object. This may cause an L<X::Auth::SASL::Property failure|X::Auth::SASL#class X::Auth::SASL::Property>.

=head1 PROVIDED METHODS

These methods are provided by this role. These should not be overridden.

=head2 method get-property

    multi method get-property(
        Str:D $name,
        Str:D :$service = '',,
        Str:D :$host = '',
        --> Str:D
    )
    multi method get-property(
        @names,
        Str:D :$service = '',
        Str:D :$host = '',
        --> Str:D
    )

This is the method that is called by mechanisms to retrieve their properties. These methods will return a defined value for the string or a L<X::Auth::SASL::Property failure|X::Auth::SASL#class X::Auth::SASL::Property>.

If the version taking a single C<$name> is called, that single property must exist.

If the version taking an array of C<@names> is called, the names are tried in order to find a property value and the first found will be returned (or the failure if none are defined).

=head2 method mechanism-state

    method mechanism-state(
        Str:D $mechanism,
        Str:D :$service = '',
        Str:D :$host = '',
        --> Auth::SASL::Session::State:D
    )

You will probably never need to call this method. It is used internally by the L<.attempt-mechanisms method|Auth::SASL#method attempt-mechanisms> to build a state object for this session for use with L<Auth::SASL::Mechanism::WorkingClient>.

=end pod
