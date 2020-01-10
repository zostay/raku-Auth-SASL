use v6;

use Auth::SASL::API;

unit package Auth::SASL;

role Mechanism {
    has Auth::SASL::API $.parent is required;
    has Str $.service = '';
    has Str $.host = '';
    has Set $.security-flags .= new;
    has %!answer;

    method mechanism(::?CLASS: --> Str:D) { ... }

    method callback(::?CLASS:D: --> Hash[Callable]) { $.parent.callback }
    method debug(::?CLASS:D: --> Bool:D) { $.parent.debug }

    method answer(::?CLASS:D: Str:D $name --> Any) { %!answer{ $name } }

    method call(::?CLASS:D:
        Str $name, |c
    ) {
        my &callback = %.callback{ $name };

        return Nil without &callback;

        my $value = callback(|c);

        # cache responses, except password
        %!answer{ $name } = $value unless $name eq 'pass';

        $value
    }
}

role Mechanism::Client does Mechanism {
    method start-client(::?CLASS:D: --> Str:D) { ... }
    method step-client(::?CLASS:D: --> Str:D) { }
}

role Mechanism::Server does Mechanism {
    method start-server(::CLASS:D: --> Str:D) { ... }
    method step-server(::CLASS:D: --> Str:D) { }
}
