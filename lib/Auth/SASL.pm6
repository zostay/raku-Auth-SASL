use v6;

use Auth::SASL::API;

unit class Auth::SASL:ver<0.0.1>:auth<github:zostay> does Auth::SASL::API;

use Auth::SASL::Factory;
use Auth::SASL::Mechanism;
use Auth::SASL::Raku;

has Mix $.mechanism is required;
has Callable %.callback;
has Bool $.debug = False;
has Auth::SASL::Factory $!factory = Auth::SASL::Raku;

our sub split-mechanisms(Str:D $mechanisms --> Mix:D) {
    $mechanisms.comb(/ <[- \w]>+ /).Mix;
}

our sub split-security-flags(Str:D $security-flags --> Set:D) {
    $security-flags.lc.comb(/\w+/).Set;
}

multi method new(::?CLASS:U:
    Mix :$mechanism!,
    :callback(%cb),
    :$debug = False,
    --> Auth::SASL:D
) {
    my %callback = %cb.map: {
        my $value = do given .value {
            when Callable { $_ }
            default { -> { $_ } }
        }

        .key => $value
    }

    self.bless: :$mechanism, :%callback, :$debug;
}

multi method new(::?CLASS:U:
    Str :mechanism($mech-str)!,
    :%callback,
    :$debug = False,
    --> ::?CLASS:D
) {
    my $mechanism = split-mechanisms($mech-str);
    self.new: :$mechanism, :%callback, :$debug;
}

multi method prepare-client(
    Str :$service,
    Str :$host,
    Str :$security-flags!,
    --> Auth::SASL::Mechanism:D
) {
    $!factory.new-client(self, :$service, :$host,
        security-flags => split-security-flags($security-flags),
    );
}

multi method prepare-client(::?CLASS:D:
    Str :$service = '',
    Str :$host = '',
    Set :$security-flags = Set.new,
    --> Auth::SASL::Mechanism:D
) {
    $!factory.new-client(self, :$service, :$host, :$security-flags);
}

method prepare-server(::?CLASS:D: |c) {
    $!factory.new-server(self, |c);
}
