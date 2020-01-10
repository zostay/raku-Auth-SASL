use v6;

unit role Auth::SASL::API;

method debug(::?CLASS:D: --> Bool:D) { ... }
method callback(::?CLASS:D: --> Hash[Callable]) { ... }

