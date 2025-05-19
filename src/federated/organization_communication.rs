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
    println!("Start communication");

    println!("Exchange keys");
    let server_key: ServerKey = org_a.get_server_key();
    org_b.set_server_key(server_key);

    println!("Apply private set intersection");
    let time_start_psi = Instant::now();
    let (org_a_case_ids, encrypted_case_ids): (Vec<String>, Vec<FheUint64>) = org_a.encrypt_all_case_ids();
    let shared_case_id_result: Vec<(usize, FheBool)> = org_b.find_shared_case_ids(&encrypted_case_ids);
    let shared_case_ids: HashSet<String> = org_a.decrypt_and_identify_shared_case_ids(&org_a_case_ids, &shared_case_id_result);
    let time_elapsed_psi = time_start_psi.elapsed().as_millis();
    println!("PSI - Time elapsed is {}ms", time_elapsed_psi);
    
    println!("Agree on activity encoding");
    let time_start_enconding_agreement = Instant::now();
    let activities_b: HashSet<String> = org_b.find_activities();
    let agreed_activity_to_pos: HashMap<String, usize> = org_a.update_with_foreign_activities(activities_b);
    let mut sample_encryptions: HashMap<u16, FheUint16> = org_a.provide_sample_encryptions();
    org_b.sanitize_sample_encryptions(&mut sample_encryptions);

    org_b.set_activity_to_pos(agreed_activity_to_pos, &sample_encryptions);
    let time_elapsed_encoding_agreement = time_start_enconding_agreement.elapsed().as_millis();
    println!("Encoding agreement - Time elapsed is {}ms", time_elapsed_encoding_agreement);

    println!("Encrypt & encode data for organization A");
    let time_start_encrypt_org_a = Instant::now();
    let org_a_encrypted_data: HashMap<String, (Vec<FheUint16>, Vec<FheUint32>)> =
        org_a.encrypt_all_data(&shared_case_ids);
    org_b.set_foreign_case_to_trace(org_a_encrypted_data);
    org_b.compute_all_case_names();
    let time_elapsed_encrypt_org_a = time_start_encrypt_org_a.elapsed().as_millis();
    println!("Encrypting Organization A data - Time elapsed is {}ms", time_elapsed_encrypt_org_a);

    println!("Encrypt & encode data for organization B");
    let time_start_encypt_org_b = Instant::now();
    org_b.encrypt_all_data(&sample_encryptions);
    let time_elapsed_encrypt_org_b = time_start_encypt_org_b.elapsed().as_millis();
    println!("Encrypting Organization B data - Time elapsed is {}ms", time_elapsed_encrypt_org_b);

    let max_size: usize = org_b.get_cases_len();
    let multi_bar = MultiProgress::new();
    let progress_cases = multi_bar.add(ProgressBar::new(max_size as u64));
    progress_cases.set_style(
        ProgressStyle::with_template(
            "[{elapsed_precise}/{eta_precise} - {per_sec}] {wide_bar} {pos}/{len}",
        )
        .unwrap(),
    );
    progress_cases.tick();

    let progress_decryption = multi_bar.add(ProgressBar::new(org_b.get_secret_edges_len() as u64));
    progress_decryption.set_style(
        ProgressStyle::with_template(
            "[{elapsed_precise}/{eta_precise} - {per_sec}] {wide_bar} {pos}/{len}",
        )
        .unwrap(),
    );
    progress_decryption.tick();

    progress_cases.println("(Find all encrypted edges / Decrypt edges)");
    let time_start_edge_finding = Instant::now();

    let decrypted_edges: Vec<(u16, u16)> = (0..max_size)
        .step_by(window_size)
        .collect::<Vec<_>>()
        .into_iter()
        .flat_map(|step| {
            let upper_bound;
            if step + window_size > max_size {
                return Vec::new();
            } else if step + 2 * window_size > max_size {
                upper_bound = max_size;
            } else {
                upper_bound = step + window_size;
            }

            let org_b_secrets: Vec<(FheUint16, FheUint16)> =
                org_b.find_all_secrets(step, upper_bound, &progress_cases);
            org_a.decrypt_edges(org_b_secrets, &progress_decryption)
        })
        .collect::<Vec<(u16, u16)>>();

    progress_cases.finish();
    progress_decryption.finish();
    let time_elapsed_edge_finding = time_start_edge_finding.elapsed().as_millis();
    println!("Edge finding/computation/decryption - Time elapsed is {}ms", time_elapsed_edge_finding);

    println!("Transform the computed and decrypted edges to a directly-follows graph");
    let time_start_computing_dfg = Instant::now();
    let mut graph: DirectlyFollowsGraph = org_a.evaluate_decrypted_edges_to_dfg(decrypted_edges);
    org_a.update_graph_with_private_cases(&mut graph, &org_a_case_ids, &shared_case_ids);
    
    utils::recalculate_activity_counts(&mut graph);
    graph.start_activities.insert("start".to_string());
    graph.end_activities.insert("end".to_string());
    let time_elapsed_computing_dfg= time_start_computing_dfg.elapsed().as_millis();
    println!("DFG from decrypted edges - Time elapsed is {}ms", time_elapsed_computing_dfg);
    
    graph
}
