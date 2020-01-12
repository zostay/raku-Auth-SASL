use v6;

unit role Auth::SASL::Factory;

use Auth::SASL::API;
use Auth::SASL::Mechanism;

method new-client(
    Auth::SASL::API:D $parent,
    Str :$service,
    Str :$host,
    Set :$security-flags,
    --> Auth::SASL::Mechanism:D
) {
    ...
}
