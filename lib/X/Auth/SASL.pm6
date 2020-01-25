use v6;

class X::Auth::SASL is Exception {
    method message(--> Str:D) { "Unknown SASL error" }
}

class X::Auth::SASL::NotFound is X::Auth::SASL {
    has Mix $.mechanism is required;

    method message(--> Str:D) {
        "Unable to perform authentication for any of these SASL mechanisms: $!mechanism.keys.sort.join(', ')"
    }
}

=begin pod

=head1 NAME

X::Auth::SASL - SASL authentication exceptions

=head1 DESCRIPTION

All L<Auth::SASL>-specific exceptions are sub-classed from C<X::Auth::SASL>.

=head1 EXCEPTIONS

=head2 class X::Auth::SASL

This is the parent class of all the others. It should never be thrown directly.

=head2 class X::Auth::SASL::NotFound

    class X::Auth::SASL::NotFound is X::Auth::SASL {
        has Mix $.mechanism is required;
        ...
    }

This should be thrown by L<Auth::SASL::Factory> objects if no SASL mechanism can be found matching the requests SASL mechanisms.

=end pod
