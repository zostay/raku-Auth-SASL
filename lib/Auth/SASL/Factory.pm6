use v6;

unit role Auth::SASL::Factory;

use Auth::SASL::API;
use Auth::SASL::Mechanism;

multi method new-client(
    Auth::SASL::API:D $parent,
    Str :$service,
    Str :$host,
    Set :$security-flags,
    --> Auth::SASL::Mechanism:D
) {
    # FIXME BUG RT#127303 - required multi does not work
    # ...
}

multi method new-client(
    Auth::SASL::API:D $parent,
    Str :$service,
    Str :$host,
    Str :$security-flags!,
    --> Auth::SASL::Mechanism:D
) {
    my $flags = $security-flags.lc.comb(/\w+/);

    self.new-client($parent, :$service, :$host,
        security-flags => $flags,
    );
}
