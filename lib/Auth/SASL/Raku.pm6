use v6

use Auth::SASL::Factory;

unit class Auth::SASL::Raku does Auth::SASL::Factory;

use Auth::SASL::Mechanism;

sub DEFAULT-MECHANISMS {
    require Auth::SASL::Raku::Plain;
    require Auth::SASL::Raku::Anonymous;

    (
        Auth::SASL::Raku::Plain.new,
        Auth::SASL::Raku::Anonymous.new,
    )
}

has Auth::SASL::Mechanism @.supported-mechanisms = DEFAULT-MECHANISMS();

method new-client(::?CLASS:D:
    Mixy:D $mechanism,
    --> Auth::SASL::Mechanism:D
) {
    my $last-err;

    for @!supported-mechanisms.sort({ $mechanism{ $_ } }) -> $mech {
        next unless $mech.mechanism ∈ $mechanism;
        return $mech;
    }

    die X::Auth::SASL::NotFound.new(:$mechanism);
}

method list-mechanisms(::?CLASS:D: --> Seq:D) {
    @!supported-mechanisms».mechanism;
}
