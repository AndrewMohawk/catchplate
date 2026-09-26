//! Fixed offline ingress-evidence CLI. The shared owner retains and rechecks
//! the exact expectations and trust-root originals before any result output.
//! Its four required flags and local-only trust boundary are unchanged; the
//! ingress verifier additionally checks this bounded input's JSON-line form.

pub(super) fn run() -> Result<(), String> {
    super::cli::run_with_input_limit(65_536, super::verify_ingress)
}
