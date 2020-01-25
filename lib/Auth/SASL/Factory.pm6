use v6;

use Auth::SASL::Mechanism;

unit role Auth::SASL::Factory;

method new-client(
    Mixy:D $mechanism,
    --> Auth::SASL::Mechanism:D
) {
    ...
}

method list-mechanisms(::CLASS:D: --> Seq:D) {
    ...
}
