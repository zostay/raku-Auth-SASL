use v6;

use Auth::SASL::API;

unit class Auth::SASL does Auth::SASL::API;

use Auth::SASL::Factory;
use Auth::SASL::Mechanism;
use Auth::SASL::Raku;

has Set $.mechanism is required;
has Callable %.callback;
has Bool $.debug = False;
has Auth::SASL::Factory $!factory = Auth::SASL::Raku;
has Auth::SASL::Mechanism $!conn;

multi method new(::?CLASS:U:
    Set :$mechanism!,
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
    my $mechanism = $mech-str.comb(/ <[- \w]>+ /).Set;
    self.new: :$mechanism, :%callback, :$debug;
}

method prepare-client(::?CLASS:D: |c) {
    $!conn = Auth::SASL::Raku.new-client(self, |c);
}

method prepare-server(::?CLASS:D: |c) {
    $!conn = Auth::SASL::Raku.new-server(self, |c);
}

method initial(::?CLASS:D:) { self.prepare-client.client-start }
method challenge(::?CLASS:D: Str $challenge?) { $!conn.client-step($challenge) }
