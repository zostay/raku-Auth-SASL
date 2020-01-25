use v6;

use Auth::SASL::Mechanism;

unit role Auth::SASL::Factory;

method new-client(
    Mixy:D $mechanism,
    --> Auth::SASL::Mechanism:D
) {
    ...
}

method client-mechanisms(::CLASS:D: --> Seq:D) {
    ...
}

=begin pod

=head1 NAME

Auth::SASL::Factory - interface for mechanism factories

=head1 DESCRIPTION

This is the role theat defines the interface for building a factory that organizes and constructs SASL mechanisms. A factory determines which mechanisms to return and in what order to attempt them.

=head1 REQUIRED METHODS

The following methods must be implemented by any class implementing this role.

=head2 method new-client

    method new-client(Mixy:D $mechanism --> Auth::SASL::Mechanism:D)

Given a mixed set of mechanisms, this should return the first most appropriate mechanism handler this factory is able to provide. If no sucn mechanism exists, then it must throw an L<X::Auth::SASL::NotFound|X::Auth::SASL|#class X::Auth::SASL::NotFound> exception.

The factory should use the weights associated with keys in the L<Mixy> C<$mechanism> or assert whatever the factory's natural ordering is if the weights are the same.

=head2 method client-mechanisms

    method client-mechanisms(--> Seq:D)

This returns a L<Seq> listing the names of the mechanisms this factory supports. Each mechanism is returned as a L<Str>, e.g., "PLAIN".

=end pod
