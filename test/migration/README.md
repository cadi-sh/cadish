# Migration fixtures

End-to-end migration targets: real-world configs translated to cadish, with a
golden behavior spec asserting the translation is semantics-true to the original.
Today this holds **storefront** (`storefront/`), a fictional e-commerce site used
as the v1 parity goal — the `Cadishfile` (+ imported `nocache.cadish`) is a
production-complete form-A translation of a legacy `storefront.vcl` using only
directives the pipeline implements, and `golden_cases.md` is the request→decision
table that the end-to-end test asserts. The config is kept passing
`go run ./cmd/cadish check -config test/migration/storefront/Cadishfile` with
zero errors; behaviors the VCL had that cadish v1 cannot yet express are marked
`# TODO(v2):` in the config with the closest v1 approximation.
