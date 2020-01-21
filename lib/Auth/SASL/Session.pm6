use v6;

class X::Auth::SASL::Property {
    has Str $.property is required;

    method message(--> Str:D) {
        "unable to retrieve authentication property $.property"
    }
}

role Auth::SASL::Session { ... }

role Auth::SASL::Session {
    class State {
        has Auth::SASL::Session $.parent;
        has %!state;

        method state(Str:D $var) is rw {
            return-rw %!state{ $var };
        }

        method clear() {
            %!state = ();
        }

        method get-property(Str:D $name --> Str:D) {
            $!parent.get-property($name);
        }
    }

    has %!mechanism-state;

    method mechanism-state(
        Str:D $mechanism,
        Str:D :$service = '',
        Str:D :$host = '',
        --> State:D
    ) {
        %!mechanism-state{ $service }{ $host }{ $mechanism } //=
            State.new(parent => self);
    }

    method session-property(Str:D $ --> Str) { ... }

    multi method get-property(Str:D $name --> Str:D) {
        with self.session-property($name) {
            return $_;
        }
        else {
            die X::Auth::SASL::Property.new(:property($name));
        }
    }

    multi method get-property(Str:D @names --> Str:D) {
        for @names -> $name (
            return $_ with self.session-property($name);
        }

        die X::Auth::SASL::Property.new(:property(@names[0]));
    }
}

class Auth::SASL::Session::Standard does Auth::SASL::Session {
    has %.data;
    has &.callback;

    method session-property(Str:D $name --> Str) {
        if %.data.{ $name }:exists {
            %.data.{ $name };
        }
        orwith &.callback {
            .( $name );
        }
        else {
            Nil;
        }
    }

    method set-property(Str:D $name, Str:D $value) {
        %.data.{ $name } = $value;
    }

}
