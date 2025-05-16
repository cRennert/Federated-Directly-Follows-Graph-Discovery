use process_mining::dfg::image_export::export_dfg_image_png;
use process_mining::dfg::DirectlyFollowsGraph;
use process_mining::{import_xes_file, XESImportOptions};
use std::env;
use std::ops::Add;
use std::time::Instant;
use tfhe::set_server_key;
use Federated_Discovery::federated::organization_communication;
use Federated_Discovery::federated::organization_struct::{
    PrivateKeyOrganization, PublicKeyOrganization,
};

fn main() {
    // set name of event log to be imported
    let event_log_name = "BPI_Challenge_2013_open_problems".to_string();
    let input_file = event_log_name.clone().add(".xes.gz");
    let output_file = event_log_name.clone().add(".png");

    // read args
    let mut args: Vec<String> = env::args().collect();
    args.remove(0);
    let path1 = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("org_A_split_by_random")
        .join(input_file.clone());
    let path2 = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("org_B_split_by_random")
        .join(input_file);
    let output_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("output")
        .join(output_file);

    // read logs
    let mut options = XESImportOptions::default();
    options.sort_events_with_timestamp_key = Some("time:timestamp".to_string());
    let mut log1 = import_xes_file(path1, options.clone()).unwrap();
    let mut log2 = import_xes_file(path2, options).unwrap();

    // Filter empty traces
    log1.traces.retain(|trace| !trace.events.is_empty());
    log2.traces.retain(|trace| !trace.events.is_empty());

    // set debug flag
    let debug = false;

    println!(
        "Start directly-follows graph discovery for  {}",
        event_log_name
    );
    let time_start = Instant::now();

    //setup keys
    let mut org_a = PrivateKeyOrganization::new(log1, debug);
    set_server_key(org_a.get_server_key());
    let true_val = org_a.encrypt_true();

    let mut org_b = PublicKeyOrganization::new(log2, true_val);

    let result: DirectlyFollowsGraph =
        organization_communication::communicate(&mut org_a, &mut org_b, 100);
    let time_elapsed = time_start.elapsed().as_millis();
    println!("Time elapsed is {}ms", time_elapsed);

    export_dfg_image_png(&result, &output_path).unwrap();
}
