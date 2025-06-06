# Federated-Directly-Follows-Graph-Discovery
ICPM 2025 Submission Repository

## Structure
- [data](data): contains the event logs split into an organization A and organization B part
- [src](src): Contains the rust code to be run
- [output](output): The directory to output PNG files of the discovered DFGs - Initially, they contain the DFGs of the event logs that were run sucessfully in the paper.

## How to run
- To run the code, call `cargo run --release -- ./data/org_A_split_by_random/BPI_Challenge_2013_incidents.xes.gz ./data/org_B_split_by_random/BPI_Challenge_2013_incidents.xes.gz ./output/BPI_Challenge_2013_incidents.dfg true false`.
- If you want to use a different event log, change the given name in all paths
- The params are as follows
  1. The partial event log from organization A
  2. The partial event log from organization B
  3. The output path of the DFG
  4. Whether the so-called debug mode should be used: This uses a trivial encryption, following the given protocol but without usage of computationally expensive cryptographic operations. For the experiments this was set to `false`.
  5. Whether private set intersection should be used.

__Hint: if you face problems with link.exe when running the program above, consider renaming the directory's path to contain dashes or underscores__ 

## Where to find the brute force approach? How was the number of operations measured?[main.rs](../../Users/rennert/Downloads/directory/directory/src/main.rs)
 - There are two further branches that implement the trace-based and brute-force protocol without any (trivial) encryption
 - The protocol is semantically followed, however, they can only be used for counting the number of operations without any cryptographic usage.
 - They can be called identically to this main implementation.