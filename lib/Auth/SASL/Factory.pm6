use v6;

use Auth::SASL::Mechanism;

class X::Auth::SASL::NotFound is Exception {
    has Mix $.mechanism is required;

    method message(--> Str:D) {
        "Unable to perform authentication for any of these SASL mechanisms: $!mechanism.keys.sort.join(', ')"
    }
}

role Auth::SASL::Factory {

    method new-client(
        Mixy:D $mechanism,
        --> Auth::SASL::Mechanism:D
    ) {
        ...
    }

    method list-mechanisms(::CLASS:D: --> Seq:D) {
        ...
    }
}
