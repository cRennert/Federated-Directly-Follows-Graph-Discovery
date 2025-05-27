use process_mining::dfg::image_export::export_dfg_image_png;
use process_mining::dfg::DirectlyFollowsGraph;
use process_mining::{import_xes_file, XESImportOptions};
use std::env;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::ops::Add;
use std::time::Instant;
use tfhe::set_server_key;
use Federated_Discovery::federated::organization_communication;
use Federated_Discovery::federated::organization_struct::{
    PrivateKeyOrganization, PublicKeyOrganization,
};

fn main() -> std::io::Result<()> {
    //read args
    let mut args: Vec<String> = env::args().collect();
    args.remove(0);
    let path1 = args.remove(0);
    let path2 = args.remove(0);
    let output_file = args.remove(0);
    let debug = args.remove(0).parse::<bool>().unwrap();
    let use_psi = args.remove(0).parse::<bool>().unwrap();

    // read args
    let mut options = XESImportOptions::default();
    options.sort_events_with_timestamp_key = Some("time:timestamp".to_string());
    let mut log1 = import_xes_file(path1, options.clone()).unwrap();
    let mut log2 = import_xes_file(path2, options).unwrap();

    // Filter empty traces
    log1.traces.retain(|trace| !trace.events.is_empty());
    log2.traces.retain(|trace| !trace.events.is_empty());

    println!(
        "Start directly-follows graph discovery to be output to {}",
        output_file
    );
    let time_start = Instant::now();

    //setup keys
    let mut org_a = PrivateKeyOrganization::new(log1, debug);
    set_server_key(org_a.get_server_key());
    let true_val = org_a.encrypt_true();

    let mut org_b = PublicKeyOrganization::new(log2, true_val);

    let result: DirectlyFollowsGraph =
        organization_communication::communicate(&mut org_a, &mut org_b, 100, use_psi);
    let time_elapsed = time_start.elapsed().as_millis();
    println!("Time elapsed is {}ms", time_elapsed);

    // export_dfg_image_png(&result, &output_file.clone().add(".png")).unwrap();
    let file = File::create(output_file)?;
    let mut writer = BufWriter::new(file);
    writeln!(writer, "{}", result.to_json())?;
    writer.flush()?;
    Ok(())
}
