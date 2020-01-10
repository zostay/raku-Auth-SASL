use v6

use Auth::SASL::Factory;

unit class Auth::SASL::Raku does Auth::SASL::Factory;

use Auth::SASL::API;
use Auth::SASL::Mechanism;
use Auth::SASL::Raku::Mechanism;

constant $SECURITY-FLAGS = <noplaintext noanonymous nodictionary>.Set;

proto method new-client(|) { * }

multi method new-client(
    Auth::SASL::API:D $parent,
    Str :$service = '',
    Str :$host = '',
    Set :$security-flags = Set.new,
    --> Auth::SASL::Mechanism:D
) {
    my $last-err;

    my $mech-pkgs = gather for $parent.mechanism.keys -> $mech {
        my $mech-pkg = $?PACKAGE.^name ~ "::$mech";

        try require ::($mech-pkg);
        if ::($mech-pkg) ~~ Failure {
            $last-err = ::($mech-pkg);
            next;
        }

        (::($mech-pkg) ~~ Auth::SASL::Mechanism::Client) or next;
        (::($mech-pkg) ~~ Auth::SASL::Raku::Mechanism) or next;
        (::($mech-pkg).HOW ~~ Metamodel::ClassHOW) or next;
        if $security-flags {
            ::($mech-pkg).matching-security-flags($security-flags);
        }

        take ::($mech-pkg);
    }

    die "No working SASL authentication mechanisms found:\n$last-err.gist.indent(4)"
        unless $mech-pkgs;

    $mech-pkgs.first.new(:$parent, :$service, :$host, :need-step);
}

