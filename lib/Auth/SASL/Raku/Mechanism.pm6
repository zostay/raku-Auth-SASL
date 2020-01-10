use v6;

unit role Auth::SASL::Raku::Mechanism;

method mechanism-security-flags(::?CLASS:U: --> Set:D) { Set.new }

method matching-security-flags(::?CLASS:U: Set:D $flags --> Bool:D) {
    dd self.mechanism-security-flags;
    dd $flags;
    dd self.mechanism-security-flags ∩ $flags;
    dd ?(self.mechanism-security-flags ∩ $flags);

    ?(self.mechanism-security-flags ∩ $flags)
}

