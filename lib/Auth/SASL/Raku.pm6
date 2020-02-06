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

method client-mechanisms(::?CLASS:D: --> Seq:D) {
    @!supported-mechanisms.map(*.mechanism);
}

=begin pod

=head1 NAME

Auth::SASL::Raku - factory for pure-Raku mechanisms

=head1 SYNOPSIS

    use Auth::SASL;
    use Auth::SASL::Raku;
    use Auth::SASL::Raku::Plain;

    # Customize Auth::SASL::Raku to only support PLAIN
    my Auth::SASL::Raku $factory .= new(
        supported-mechanisms = (Auth::SASL::Raku:Plain.new,),
    );

    my Auth::SASL $sasl .= new(:$factory);

=head1 DESCRIPTION

This is a SASL mechanism factory for pure-Raku implemented SASL mechanisms included with L<Auth::SASL>.

=head1 METHODS

=head2 method new

    method new(Auth::SASL::Raku:U: :@supported-mechanisms --> Auth::SASL::Raku:D)

As of this writing, this factory provides support for the following mechanisms in this order:

    PLAIN
    ANONYMOUS

You can modify the order or the list of supported mechanisms by passing C<$supported-mechansims> during construction. These must be implementations of L<Auth::SASL::Mechanism>. This could be useful as well if you want to add your own custom mechanism.

=end pod
