# Federated-Directly-Follows-Graph-Discovery
ICPM 2025 Submission Repository

## Structure
- [data](data): contains the event logs split into an organization A and organization B part
- [src](src): Contains the rust code to be run
- [output](output): The directory to output PNG files of the discovered DFGs - Initially, they contain the DFGs of the event logs that were run sucessfully in the paper.

## How to run
- You can adapt the event log to be processed by changing the event `event_log_name` variable in [src/main.rs](src/main.rs).
- By setting the `let debug = true` variable, you can test the protocol using a fast trivial encryption of the TFHE library that does not guarantee privacy.
- Otherwise, set the value `let debug = false` resulting in a higher run time but the privacy guarantees to hold.
- To run the code, call `cargo run --release`.
