use crate::federated::organization_struct::{PrivateKeyOrganization, PublicKeyOrganization};
use crate::federated::utils;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use process_mining::dfg::DirectlyFollowsGraph;
use std::collections::{HashMap, HashSet};
use std::time::Instant;
use tfhe::{FheBool, FheUint16, FheUint32, FheUint64, ServerKey};

/// The protocol for the federated computation of a directly-follows graph between two organizations
///
/// # Arguments
///
/// * `org_a`: A private key-owning organization
/// * `org_b`: A public key-owning organization.
/// * `window_size`: A window size to reduce the number of traces to be computed in B.
///
/// Returns: DirectlyFollowsGraph The directly-follows graph of the federate computation.
///
pub fn communicate<'a>(
    org_a: &'a mut PrivateKeyOrganization,
    org_b: &'a mut PublicKeyOrganization,
    window_size: usize,
) -> DirectlyFollowsGraph<'a> {
    // Introduce variables to keep track of homomorphic operations
    let mut case_id_hom_comparisons: u64 = 0;
    let mut timestamp_hom_comparisons: u64 = 0;
    let mut selection_hom_comparisons: u64 = 0;

    println!("Start communication");

    println!("Exchange keys");
    let server_key: ServerKey = org_a.get_server_key();
    org_b.set_server_key(server_key);


    println!("Agree on activity encoding");
    let time_start_enconding_agreement = Instant::now();
    let activities_b: HashSet<String> = org_b.find_activities();
    let agreed_activity_to_pos: HashMap<String, usize> =
        org_a.update_with_foreign_activities(activities_b);
    let mut sample_encryptions: HashMap<u16, u16> = org_a.provide_sample_encryptions();
    org_b.sanitize_sample_encryptions(&mut sample_encryptions);

    org_b.set_activity_to_pos(agreed_activity_to_pos, &sample_encryptions);
    let time_elapsed_encoding_agreement = time_start_enconding_agreement.elapsed().as_millis();
    println!(
        "Encoding agreement - Time elapsed is {}ms",
        time_elapsed_encoding_agreement
    );

    println!("Encrypt & encode data for organization A");
    let time_start_encrypt_org_a = Instant::now();
    let org_a_encrypted_data: Vec<(u64, u16, u64)> =
        org_a.encrypt_all_data();
    org_b.set_foreign_case_to_trace(org_a_encrypted_data);
    let time_elapsed_encrypt_org_a = time_start_encrypt_org_a.elapsed().as_millis();
    println!(
        "Encrypting Organization A data - Time elapsed is {}ms",
        time_elapsed_encrypt_org_a
    );

    println!("Encrypt & encode data for organization B");
    let time_start_encypt_org_b = Instant::now();
    org_b.encrypt_all_data(&sample_encryptions);
    let time_elapsed_encrypt_org_b = time_start_encypt_org_b.elapsed().as_millis();
    println!(
        "Encrypting Organization B data - Time elapsed is {}ms",
        time_elapsed_encrypt_org_b
    );

    let max_size: usize = 1;
    let multi_bar = MultiProgress::new();
    let progress_cases = multi_bar.add(ProgressBar::new(max_size as u64));
    progress_cases.set_style(
        ProgressStyle::with_template(
            "[{elapsed_precise}/{eta_precise} - {per_sec}] {wide_bar} {pos}/{len}",
        )
        .unwrap(),
    );
    progress_cases.tick();

    let progress_decryption = multi_bar.add(ProgressBar::new(1 as u64));
    progress_decryption.set_style(
        ProgressStyle::with_template(
            "[{elapsed_precise}/{eta_precise} - {per_sec}] {wide_bar} {pos}/{len}",
        )
        .unwrap(),
    );
    progress_decryption.tick();

    progress_cases.println("(Find all encrypted edges / Decrypt edges)");
    let time_start_edge_finding = Instant::now();


    let org_b_secrets: Vec<(u16, u16)> = org_b.find_all_secrets(
        &progress_cases,
        &mut case_id_hom_comparisons,
        &mut timestamp_hom_comparisons,
        &mut selection_hom_comparisons,
    );
    let decrypted_edges = org_a.decrypt_edges(org_b_secrets, &progress_decryption);

    progress_cases.finish();
    progress_decryption.finish();
    let time_elapsed_edge_finding = time_start_edge_finding.elapsed().as_millis();
    println!(
        "Edge finding/computation/decryption - Time elapsed is {}ms",
        time_elapsed_edge_finding
    );

    println!("Transform the computed and decrypted edges to a directly-follows graph");
    let time_start_computing_dfg = Instant::now();
    let mut graph: DirectlyFollowsGraph = org_a.evaluate_decrypted_edges_to_dfg(decrypted_edges);

    utils::recalculate_activity_counts(&mut graph);

    graph.directly_follows_relations = graph
        .directly_follows_relations
        .iter()
        .filter_map(|((from, to), freq)| {
            if from.eq("start") {
                graph.start_activities.insert(to.to_string());
                None
            } else if to.eq("end") {
                graph.end_activities.insert(from.to_string());
                None
            } else {
                Some(((from.clone(), to.clone()), *freq))
            }
        })
        .collect::<HashMap<_, _>>();
    graph.activities.remove("start");
    graph.activities.remove("end");

    let time_elapsed_computing_dfg = time_start_computing_dfg.elapsed().as_millis();
    println!(
        "DFG from decrypted edges - Time elapsed is {}ms",
        time_elapsed_computing_dfg
    );

    println!(
        "Number of homomorphic case ID comparisons: {}",
        case_id_hom_comparisons
    );
    println!(
        "Number of homomorphic timestamp comparions: {}",
        timestamp_hom_comparisons
    );
    println!(
        "Number of homomorphic if then else statements: {}",
        selection_hom_comparisons
    );

    graph
}
