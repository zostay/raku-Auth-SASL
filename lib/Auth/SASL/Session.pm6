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
            die X::Auth::SASL::Property.new(:property($name), :$service, :$host);
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

        die X::Auth::SASL::Property.new(:property(@names[0], :$service, :$host));
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
