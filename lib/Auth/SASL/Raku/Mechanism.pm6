use v6;

unit role Auth::SASL::Raku::Mechanism;

method mechanism-security-flags(::?CLASS:U: --> Set:D) { Set.new }

method matching-security-flags(::?CLASS:U: Set:D $flags --> Bool:D) {
    ?(self.mechanism-security-flags ∩ $flags)
}

