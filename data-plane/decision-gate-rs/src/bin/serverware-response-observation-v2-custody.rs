use serverware_decision_gate::
    run_response_observation_v2_provider_from_env as run_custody_multicall;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    run_custody_multicall().map_err(Into::into)
}
