use crate::federated::utils;
use indicatif::ProgressIterator;
use indicatif::{ParallelProgressIterator, ProgressBar, ProgressFinish, ProgressStyle};
use process_mining::dfg::DirectlyFollowsGraph;
use process_mining::event_log::event_log_struct::EventLogClassifier;
use process_mining::event_log::{Event, Trace, XESEditableAttribute};
use process_mining::EventLog;
use rand::rng;
use rand::seq::SliceRandom;
use rayon::prelude::*;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::ops::Not;
use tfhe::prelude::*;
use tfhe::{
    generate_keys, set_server_key, ClearString, ClientKey, Config, ConfigBuilder, FheAsciiString,
    FheBool, FheUint16, FheUint32, ServerKey,
};

/// Computes the activities present in an event log.
///
/// # Arguments
///
/// * `event_log`: An event log.
///
/// Returns: HashSet<String, RandomState> The set of activities of the event log
///
pub fn find_activities(event_log: &EventLog) -> HashSet<String> {
    let mut result = HashSet::new();
    let classifier = EventLogClassifier::default();

    event_log.traces.iter().for_each(|trace| {
        trace.events.iter().for_each(|event| {
            result.insert(classifier.get_class_identity(event));
        })
    });

    result
}

/// Obtains the timestamp of an event in the right format, i.e., a `u32`.
///
/// # Arguments
///
/// * `event`: An event.
///
/// Returns: u32 The timestamp of the event.
///
pub fn get_timestamp(event: &Event) -> u32 {
    event
        .attributes
        .get_by_key("time:timestamp")
        .and_then(|t| t.value.try_as_date())
        .unwrap()
        .timestamp() as u32
}

///
/// The organization with the private key.
///
pub struct PrivateKeyOrganization {
    private_key: ClientKey,
    server_key: ServerKey,
    event_log: EventLog,
    activity_to_pos: HashMap<String, usize>,
    pos_to_activity: HashMap<usize, String>,
    debug: bool,
}

impl PrivateKeyOrganization {
    ///
    /// Initializing function
    ///
    pub fn new(event_log: EventLog, debug: bool) -> Self {
        let config: Config = ConfigBuilder::default().build();
        let (private_key, server_key): (ClientKey, ServerKey) = generate_keys(config);
        Self {
            private_key,
            server_key,
            event_log,
            activity_to_pos: HashMap::new(),
            pos_to_activity: HashMap::new(),
            debug,
        }
    }

    ///
    /// Computes a directly-follows graph from decrypted edges.
    ///
    pub fn edges_to_dfg(&self, edges: Vec<(String, String)>) -> DirectlyFollowsGraph<'_> {
        let mut result = DirectlyFollowsGraph::default();
        self.activity_to_pos.keys().for_each(|act| {
            result.add_activity(act.clone(), 0);
        });

        edges.into_iter().for_each(|(from, to)| {
            result.add_df_relation(Cow::from(from), Cow::from(to), 1);
        });

        utils::recalculate_activity_counts(&mut result);

        result
    }

    ///
    /// Encrypts a timestamp using the private key
    ///
    pub fn encrypt_timestamp(&self, value: u32, private_key: &ClientKey) -> FheUint32 {
        if self.debug {
            FheUint32::encrypt_trivial(value)
        } else {
            FheUint32::encrypt(value, private_key)
        }
    }

    ///
    /// Encrypts an encoded activity using the private key.
    ///
    pub fn encrypt_activity(&self, value: u16, private_key: &ClientKey) -> FheUint16 {
        if self.debug {
            FheUint16::encrypt_trivial(value)
        } else {
            FheUint16::encrypt(value, private_key)
        }
    }

    pub fn encrypt_true(&self) -> FheBool {
        if self.debug {
            FheBool::encrypt_trivial(true)
        } else {
            FheBool::encrypt(true, &self.private_key)
        }
    }

    ///
    /// Decrypts an encrypted activity using the private key.
    ///
    fn decrypt_activity(&self, val: FheUint16) -> u16 {
        val.decrypt(&self.private_key)
    }

    ///
    /// Encrypts all its timestamps and activities of a trace.
    ///
    pub fn encrypt_all_data(
        &self,
        shared_case_ids: &HashSet<String>,
    ) -> HashMap<String, (Vec<FheUint16>, Vec<FheUint32>)> {
        self.compute_case_to_trace_with_encryption(
            &self.activity_to_pos,
            &self.private_key,
            &self.event_log,
            shared_case_ids,
        )
    }

    pub fn encrypt_all_case_ids(&self) -> (Vec<String>, Vec<FheAsciiString>) {
        let case_ids = self
            .event_log
            .traces
            .iter()
            .map(|trace| {
                self.event_log
                    .get_trace_attribute(trace, "concept:name")
                    .unwrap()
                    .value
                    .try_as_string()
                    .unwrap()
                    .to_string()
            })
            .collect::<Vec<_>>();

        println!("Encrypt case IDs for organization A");
        let bar = ProgressBar::new(self.event_log.traces.len() as u64);
        bar.set_style(
            ProgressStyle::with_template(
                "[{elapsed_precise}/{eta_precise} - {per_sec}] {wide_bar} {pos}/{len}",
            )
            .unwrap(),
        );

        let encrypted_case_ids = case_ids
            .par_iter()
            .progress_with(bar)
            .with_finish(ProgressFinish::AndLeave)
            .map(|case_id| {
                if !self.debug {
                    FheAsciiString::encrypt(case_id, &self.private_key)
                } else {
                    FheAsciiString::try_encrypt_trivial(case_id).unwrap()
                }
            })
            .collect();

        (case_ids, encrypted_case_ids)
    }

    pub fn decrypt_and_identify_shared_case_ids(
        &self,
        own_case_ids: &Vec<String>,
        case_id_check_result: &Vec<(usize, FheBool)>,
    ) -> HashSet<String> {
        case_id_check_result
            .par_iter()
            .filter_map(|(id, enc_bool)| {
                if FheBool::decrypt(enc_bool, &self.private_key) {
                    Some(own_case_ids.get(*id).unwrap().to_string())
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn update_graph_with_private_cases(
        &self,
        dfg: &mut DirectlyFollowsGraph,
        own_case_ids: &Vec<String>,
        shared_case_ids: &HashSet<String>,
    ) {
        let classifier = EventLogClassifier::default();

        let own_case_id_set = own_case_ids
            .iter()
            .map(|x| x.to_string())
            .collect::<HashSet<_>>();

        let non_shared_case_id: HashSet<&String> = own_case_id_set
            .difference(shared_case_ids)
            .collect::<HashSet<_>>();
        self.event_log.traces.iter().for_each(|trace| {
            if non_shared_case_id.contains(
                &self
                    .event_log
                    .get_trace_attribute(trace, "concept:name")
                    .unwrap()
                    .value
                    .try_as_string()
                    .unwrap(),
            ) && !trace.events.is_empty()
            {
                let mut last_activity = "start".to_string();

                trace.events.iter().for_each(|event| {
                    let next_activity = classifier.get_class_identity(event);

                    dfg.add_df_relation(
                        Cow::from(last_activity.clone()),
                        Cow::from(next_activity.clone()),
                        1,
                    );

                    last_activity = next_activity;
                });

                dfg.add_df_relation(
                    Cow::from(last_activity.clone()),
                    Cow::from("end".to_string()),
                    1,
                );
            }
        })
    }

    ///
    /// Encodes and encrypts a trace's activities and timestamps.
    ///
    pub fn preprocess_trace_private_with_encryption(
        &self,
        activity_to_pos: &HashMap<String, usize>,
        private_key: &ClientKey,
        trace: &Trace,
    ) -> (Vec<FheUint16>, Vec<FheUint32>) {
        let mut activities: Vec<FheUint16> = Vec::with_capacity(trace.events.len());
        let mut timestamps: Vec<FheUint32> = Vec::with_capacity(trace.events.len());

        let classifier = EventLogClassifier::default();

        trace.events.iter().for_each(|event| {
            let activity: String = classifier.get_class_identity(event);
            let activity_pos: u16 =
                u16::try_from(activity_to_pos.get(&activity).unwrap().clone()).unwrap_or(0);
            activities.push(self.encrypt_activity(activity_pos, private_key));
            timestamps.push(self.encrypt_timestamp(get_timestamp(event), private_key));
        });

        (activities, timestamps)
    }

    ///
    /// Computes the encrypted sequences for each trace.
    ///
    pub fn compute_case_to_trace_with_encryption(
        &self,
        activity_to_pos: &HashMap<String, usize>,
        private_key: &ClientKey,
        event_log: &EventLog,
        shared_case_ids: &HashSet<String>,
    ) -> HashMap<String, (Vec<FheUint16>, Vec<FheUint32>)> {
        let name_to_trace: HashMap<&String, &Trace> = utils::find_name_trace_dictionary(event_log);
        let name_to_trace_vec: Vec<(&String, &Trace)> = name_to_trace
            .iter()
            .filter_map(|(&k, &v)| {
                if shared_case_ids.contains(&k.to_string()) {
                    Some((k, v))
                } else {
                    None
                }
            })
            .collect();

        let bar = ProgressBar::new(name_to_trace.len() as u64);
        bar.set_style(
            ProgressStyle::with_template(
                "[{elapsed_precise}/{eta_precise} - {per_sec}] {wide_bar} {pos}/{len}",
            )
            .unwrap(),
        );
        bar.println("Encrypt data organization A");
        let result: HashMap<String, (Vec<FheUint16>, Vec<FheUint32>)> = name_to_trace_vec
            .into_par_iter()
            .progress_with(bar)
            .with_finish(ProgressFinish::AndLeave)
            .map(|(name, trace)| {
                (
                    name.clone(),
                    self.preprocess_trace_private_with_encryption(
                        activity_to_pos,
                        private_key,
                        trace,
                    ),
                )
            })
            .collect::<HashMap<String, (Vec<FheUint16>, Vec<FheUint32>)>>();

        result
    }

    ///
    /// Sample encrypt all activities with their encoded positions.
    /// B can use the sample encryptions to reduce runtime in terms of encryption.
    ///
    pub fn provide_sample_encryptions(&self) -> HashMap<u16, FheUint16> {
        self.pos_to_activity
            .par_iter()
            .map(|(pos, _)| {
                let pos_u16 = u16::try_from(*pos).unwrap();
                (pos_u16, self.encrypt_activity(pos_u16, &self.private_key))
            })
            .collect::<HashMap<u16, FheUint16>>()
    }

    ///
    /// Provide the public key that can be used for homomorphic operations.
    ///
    pub fn get_server_key(&self) -> ServerKey {
        self.server_key.clone()
    }

    ///
    /// Creates the encoding using
    ///
    pub fn update_with_foreign_activities(
        &mut self,
        foreign_activities: HashSet<String>,
    ) -> HashMap<String, usize> {
        let mut activities: HashSet<String> = find_activities(&self.event_log);
        activities.extend(foreign_activities);

        self.activity_to_pos.insert("start".to_string(), 0);
        self.activity_to_pos.insert("end".to_string(), 1);

        activities.iter().enumerate().for_each(|(pos, act)| {
            self.activity_to_pos.insert(act.clone(), pos + 2);
        });

        self.activity_to_pos.iter().for_each(|(act, pos)| {
            self.pos_to_activity.insert(*pos, act.clone());
        });

        self.activity_to_pos.clone()
    }

    ///
    /// Decrypts encrypted edges computed by the protocol
    ///
    pub fn decrypt_edges(
        &self,
        secret_edges: Vec<(FheUint16, FheUint16)>,
        bar: &ProgressBar,
    ) -> Vec<(u16, u16)> {
        secret_edges
            .into_par_iter()
            .map(|(from, to)| {
                let from_pos = self.decrypt_activity(from);
                let to_pos = self.decrypt_activity(to);

                bar.inc(1);
                (from_pos, to_pos)
            })
            .collect::<Vec<(u16, u16)>>()
    }

    ///
    /// Creates a DFG from a list of decrypted edges.
    ///
    pub fn evaluate_decrypted_edges_to_dfg<'a>(
        &self,
        decrypted_edges: Vec<(u16, u16)>,
    ) -> DirectlyFollowsGraph<'a> {
        let mut result = DirectlyFollowsGraph::new();
        let mut found_edges_by_pos: HashMap<(u16, u16), u32> = HashMap::new();

        self.activity_to_pos.keys().for_each(|act| {
            result.add_activity(act.clone(), 0);
        });

        let mut pos_to_activity: HashMap<usize, String> = HashMap::new();
        self.activity_to_pos.iter().for_each(|(act, pos)| {
            pos_to_activity.insert(*pos, act.clone());
        });

        let bar = ProgressBar::new(decrypted_edges.len() as u64);
        bar.set_style(
            ProgressStyle::with_template(
                "[{elapsed_precise}/{eta_precise} - {per_sec}] {wide_bar} {pos}/{len}",
            )
            .unwrap(),
        );
        bar.println("Create directly-follows graph from decrypted edges");
        decrypted_edges
            .into_iter()
            .progress_with(bar)
            .with_finish(ProgressFinish::AndLeave)
            .for_each(|(from, to)| {
                if !pos_to_activity.get(&(from as usize)).unwrap().eq("end") {
                    if found_edges_by_pos.contains_key(&(from, to)) {
                        found_edges_by_pos
                            .insert((from, to), found_edges_by_pos.get(&(from, to)).unwrap() + 1);
                    } else {
                        found_edges_by_pos.insert((from, to), 1);
                    }
                }
            });

        for ((from_pos, to_pos), freq) in found_edges_by_pos {
            if pos_to_activity.contains_key(&(from_pos as usize))
                & pos_to_activity.contains_key(&(to_pos as usize))
            {
                result.add_df_relation(
                    pos_to_activity
                        .get(&(from_pos as usize))
                        .unwrap()
                        .clone()
                        .into(),
                    pos_to_activity
                        .get(&(to_pos as usize))
                        .unwrap()
                        .clone()
                        .into(),
                    freq,
                )
            }
        }

        result
    }
}

///
/// Organization B that holds the public key
///
pub struct PublicKeyOrganization {
    event_log: EventLog,
    activity_to_pos: HashMap<String, usize>,
    own_case_to_trace: HashMap<String, (Vec<FheUint16>, Vec<u32>)>,
    foreign_case_to_trace: HashMap<String, (Vec<FheUint16>, Vec<FheUint32>)>,
    start: Option<FheUint16>,
    end: Option<FheUint16>,
    all_case_names: Vec<String>,
    true_val: FheBool,
}

impl PublicKeyOrganization {
    ///
    /// Initialize function
    ///
    pub fn new(event_log: EventLog, true_val: FheBool) -> Self {
        Self {
            event_log,
            own_case_to_trace: HashMap::new(),
            foreign_case_to_trace: HashMap::new(),
            activity_to_pos: HashMap::new(),
            start: None,
            end: None,
            all_case_names: Vec::new(),
            true_val,
        }
    }

    ///
    /// Returns the number of traces
    ///
    pub fn get_cases_len(&self) -> usize {
        self.all_case_names.len()
    }

    ///
    /// Computes the number of encrypted edges to be returned
    ///
    pub fn get_secret_edges_len(&self) -> usize {
        let mut result = 0;
        self.all_case_names.iter().for_each(|case_name| {
            let (foreign_activities, _) = self
                .foreign_case_to_trace
                .get(case_name)
                .unwrap_or(&(Vec::new(), Vec::new()))
                .to_owned();

            let (own_activities, _): (Vec<FheUint16>, Vec<u32>) = self
                .own_case_to_trace
                .get(case_name)
                .unwrap_or(&(Vec::new(), Vec::new()))
                .to_owned();

            result += foreign_activities.len() + own_activities.len() + 1;
        });
        result
    }

    ///
    /// Sets the public key of the computation that is used for the homomorphic operations
    ///
    pub fn set_server_key(&mut self, server_key: ServerKey) {
        set_server_key(server_key.clone());
        rayon::broadcast(|_| set_server_key(server_key.clone()));
    }

    ///
    /// Computes all activities in the event log
    ///
    pub fn find_activities(&self) -> HashSet<String> {
        find_activities(&self.event_log)
    }

    ///
    /// Sets the dictionary for activity encoding
    ///
    pub fn set_activity_to_pos(
        &mut self,
        activity_to_pos: HashMap<String, usize>,
        sample_encryptions: &HashMap<u16, FheUint16>,
    ) {
        self.activity_to_pos = activity_to_pos;
        let activities_len = u16::try_from(self.activity_to_pos.len()).unwrap();
        self.start = Some(sample_encryptions.get(&(0)).unwrap().clone());
        self.end = Some(sample_encryptions.get(&(1)).unwrap().clone());
    }

    ///
    /// Compares two timestamps with a homomorphic operation
    ///
    fn comparison_fn(&self, val1: &FheUint32, val2: &u32) -> FheBool {
        val1.le(*val2)
    }

    ///
    /// Sanitizes the activities encoded and encrypted by A
    ///
    pub fn sanitize_sample_encryptions(&self, sample_encryptions: &mut HashMap<u16, FheUint16>) {
        sample_encryptions.iter().for_each(|(val, _)| {
            if *val >= u16::try_from(sample_encryptions.len()).unwrap_or(0) {
                panic!()
            }
        });

        let zero = sample_encryptions.get(&0).unwrap() - sample_encryptions.get(&0).unwrap();

        sample_encryptions
            .par_iter_mut()
            .for_each(|(val, encrypted_val)| {
                *encrypted_val = encrypted_val.eq(*val).select(encrypted_val, &zero);
            })
    }

    pub fn find_shared_case_ids(
        &self,
        foreign_case_ids: &Vec<FheAsciiString>,
    ) -> Vec<(usize, FheBool)> {
        let own_case_ids = self
            .event_log
            .traces
            .par_iter()
            .map(|trace| {
                self.event_log
                    .get_trace_attribute(trace, "concept:name")
                    .unwrap()
                    .value
                    .try_as_string()
                    .unwrap()
            })
            .collect::<Vec<_>>();

        println!("Compute case ID intersection at Organization B");
        let bar = ProgressBar::new(self.event_log.traces.len() as u64);
        bar.set_style(
            ProgressStyle::with_template(
                "[{elapsed_precise}/{eta_precise} - {per_sec}] {wide_bar} {pos}/{len}",
            )
            .unwrap(),
        );

        foreign_case_ids
            .par_iter()
            .enumerate()
            .progress_with(bar)
            .with_finish(ProgressFinish::AndLeave)
            .map(|(pos, case_id)| (pos, self.has_matching_case_id(case_id, &own_case_ids)))
            .collect::<Vec<_>>()
    }

    fn has_matching_case_id(
        &self,
        foreign_case_id: &FheAsciiString,
        own_case_ids: &Vec<&String>,
    ) -> FheBool {
        let mut result = FheBool::not(self.true_val.clone());

        own_case_ids.iter().for_each(|&case_id| {
            result = foreign_case_id
                .eq(&ClearString::new(case_id.to_string()))
                .select(&self.true_val, &result);
        });

        result
    }

    ///
    /// Stores and sanitizes the foreign-encrypted data for each case
    ///
    pub fn set_foreign_case_to_trace(
        &mut self,
        mut foreign_case_to_trace: HashMap<String, (Vec<FheUint16>, Vec<FheUint32>)>,
    ) {
        let max_activities: u16 = u16::try_from(self.activity_to_pos.len() - 3).unwrap_or(0);

        let len = foreign_case_to_trace.len() as u64;
        let bar = ProgressBar::new(len);
        bar.set_style(
            ProgressStyle::with_template(
                "[{elapsed_precise}/{eta_precise} - {per_sec}] {wide_bar} {pos}/{len}",
            )
            .unwrap(),
        );
        bar.println("Sanitize activities from A in B");

        foreign_case_to_trace
            .par_iter_mut()
            .progress_with(bar)
            .with_finish(ProgressFinish::AndLeave)
            .for_each(|(_, (foreign_activities, _))| {
                foreign_activities.iter_mut().for_each(|act| {
                    *act = act.max(max_activities);
                });
            });

        self.foreign_case_to_trace = foreign_case_to_trace;
    }

    ///
    /// Computes all case names present
    ///
    pub fn compute_all_case_names(&mut self) {
        let mut all_case_names = self
            .event_log
            .traces
            .iter()
            .map(|trace| {
                self.event_log
                    .get_trace_attribute(trace, "concept:name")
                    .unwrap()
                    .value
                    .try_as_string()
                    .unwrap()
                    .to_string()
            })
            .collect::<HashSet<_>>();
        all_case_names.extend(self.foreign_case_to_trace.keys().cloned());

        self.all_case_names = all_case_names.iter().cloned().collect();
        self.all_case_names.shuffle(&mut rand::rng());
    }

    ///
    /// Encrypts all data in organization B
    ///
    pub fn encrypt_all_data(&mut self, sample_encryptions: &HashMap<u16, FheUint16>) {
        self.own_case_to_trace = self.compute_case_to_trace_using_sample_encryption(
            &self.activity_to_pos,
            &self.event_log,
            sample_encryptions,
        );
    }

    ///
    /// Computes all encrypted DFG edges
    ///
    pub fn find_all_secrets(
        &self,
        start_case: usize,
        upper_bound: usize,
        bar: &ProgressBar,
    ) -> Vec<(FheUint16, FheUint16)> {
        let mut result: Vec<(FheUint16, FheUint16)> = self
            .all_case_names
            .get(start_case..upper_bound)
            .unwrap()
            .par_iter()
            .flat_map(|case_name| {
                let (foreign_activities, foreign_timestamps) = self
                    .foreign_case_to_trace
                    .get(case_name)
                    .unwrap_or(&(Vec::new(), Vec::new()))
                    .to_owned();

                let (own_activities, own_timestamps): (Vec<FheUint16>, Vec<u32>) = self
                    .own_case_to_trace
                    .get(case_name)
                    .unwrap_or(&(Vec::new(), Vec::new()))
                    .to_owned();

                let intermediate_result = self.find_secrets_for_case(
                    foreign_activities,
                    foreign_timestamps,
                    own_activities,
                    own_timestamps,
                );

                bar.inc(1);
                intermediate_result
            })
            .collect();

        result.shuffle(&mut rng());
        result
    }

    ///
    /// Computes encrypted DFG edges for a trace
    ///
    fn find_secrets_for_case(
        &self,
        foreign_activities: Vec<FheUint16>,
        foreign_timestamps: Vec<FheUint32>,
        own_activities: Vec<FheUint16>,
        own_timestamps: Vec<u32>,
    ) -> Vec<(FheUint16, FheUint16)> {
        let mut result: Vec<(FheUint16, FheUint16)> = Vec::new();

        if own_activities.is_empty() {
            self.add_full_trace(&foreign_activities, &mut result);
            return result;
        } else if foreign_activities.is_empty() {
            self.add_full_trace(&own_activities, &mut result);
            return result;
        }

        let mut comparison_foreign_to_own: HashMap<(usize, usize), FheBool> = HashMap::new();
        let mut comparison_own_to_foreign: HashMap<(usize, usize), FheBool> = HashMap::new();
        for (i, foreign_timestamp) in foreign_timestamps.iter().enumerate() {
            for (j, &own_timestamp) in own_timestamps.iter().enumerate() {
                let foreign_less_equal_own = self.comparison_fn(foreign_timestamp, &own_timestamp);
                let own_less_foreign = foreign_less_equal_own.clone().not();
                comparison_foreign_to_own.insert((i, j), foreign_less_equal_own);
                comparison_own_to_foreign.insert((j, i), own_less_foreign);
            }
        }

        // Find start
        result.push((
            self.start.as_ref().unwrap().clone(),
            comparison_foreign_to_own
                .get(&(0, 0))
                .unwrap()
                .select(&foreign_activities[0], &own_activities[0]),
        ));

        result.extend(
            (0..foreign_activities.len() - 1)
                .into_par_iter()
                .map(|i| {
                    (
                        foreign_activities.get(i).unwrap().clone(),
                        self.find_following_activity(
                            i,
                            foreign_activities.get(i + 1).unwrap(),
                            &own_activities,
                            &comparison_foreign_to_own,
                            &comparison_own_to_foreign,
                        ),
                    )
                })
                .collect::<Vec<(FheUint16, FheUint16)>>(),
        );

        result.extend(
            (0..own_activities.len() - 1)
                .into_par_iter()
                .map(|j| {
                    (
                        own_activities.get(j).unwrap().clone(),
                        self.find_following_activity(
                            j,
                            own_activities.get(j + 1).unwrap(),
                            &foreign_activities,
                            &comparison_own_to_foreign,
                            &comparison_foreign_to_own,
                        ),
                    )
                })
                .collect::<Vec<(FheUint16, FheUint16)>>(),
        );

        result.push((
            foreign_activities.last().unwrap().clone(),
            self.handle_last(
                foreign_activities.len() - 1,
                &own_activities,
                &comparison_foreign_to_own,
            ),
        ));

        result.push((
            own_activities.last().unwrap().clone(),
            self.handle_last(
                own_activities.len() - 1,
                &foreign_activities,
                &comparison_own_to_foreign,
            ),
        ));

        result
    }

    ///
    /// Adds a trace without homomorphic operations if the other trace is empty
    ///
    fn add_full_trace(
        &self,
        activities: &Vec<FheUint16>,
        result: &mut Vec<(FheUint16, FheUint16)>,
    ) {
        if !activities.is_empty() {
            result.push((
                self.start.as_ref().unwrap().clone(),
                activities.first().unwrap().clone(),
            ));
            result.push((
                activities.last().unwrap().clone(),
                self.end.as_ref().unwrap().clone(),
            ));
        }

        for i in 0..activities.len() - 1 {
            result.push((
                activities.get(i).unwrap().clone(),
                activities.get(i + 1).unwrap().clone(),
            ));
        }
    }

    ///
    /// Computes the following encrypted activity if the end of a trace is reached
    ///
    fn handle_last(
        &self,
        pos: usize,
        other_activities: &Vec<FheUint16>,
        comparison_this_to_other: &HashMap<(usize, usize), FheBool>,
    ) -> FheUint16 {
        let mut result: FheUint16 = self.end.as_ref().unwrap().clone();
        for i in (0..other_activities.len()).rev() {
            result = comparison_this_to_other
                .get(&(pos, i))
                .unwrap()
                .select(other_activities.get(i).unwrap(), &result);
        }
        result
    }

    ///
    /// Finds the encrypted activity following for a general case
    ///
    fn find_following_activity(
        &self,
        pos: usize,
        next_activity: &FheUint16,
        other_activities: &Vec<FheUint16>,
        comparison_this_to_other: &HashMap<(usize, usize), FheBool>,
        comparison_other_to_this: &HashMap<(usize, usize), FheBool>,
    ) -> FheUint16 {
        let mut result: FheUint16 = next_activity.clone();

        for i in (0..other_activities.len()).rev() {
            let intermediate_result = comparison_other_to_this
                .get(&(i, pos + 1))
                .unwrap()
                .select(other_activities.get(i).unwrap(), next_activity);
            result = comparison_this_to_other
                .get(&(pos, i))
                .unwrap()
                .select(&intermediate_result, &result);
        }

        result
    }

    ///
    /// Encodes the activities and encrypts them with the provided sample encryptions of A
    ///
    pub fn preprocess_trace_using_sample_encryption(
        &self,
        activity_to_pos: &HashMap<String, usize>,
        trace: &Trace,
        sample_encryptions: &HashMap<u16, FheUint16>, // debug: bool,
    ) -> (Vec<FheUint16>, Vec<u32>) {
        let classifier = EventLogClassifier::default();

        trace
            .events
            .par_iter()
            .map(|event| {
                let activity: String = classifier.get_class_identity(event);
                let activity_pos: u16 =
                    u16::try_from(activity_to_pos.get(&activity).unwrap().clone()).unwrap_or(0);
                (
                    sample_encryptions.get(&activity_pos).unwrap() + 0,
                    get_timestamp(event),
                )
            })
            .collect::<(Vec<FheUint16>, Vec<u32>)>()
    }

    ///
    /// For each case, it encodes and encrypts the activities
    ///
    pub fn compute_case_to_trace_using_sample_encryption(
        &self,
        activity_to_pos: &HashMap<String, usize>,
        event_log: &EventLog,
        sample_encryptions: &HashMap<u16, FheUint16>,
    ) -> HashMap<String, (Vec<FheUint16>, Vec<u32>)> {
        let name_to_trace: HashMap<&String, &Trace> = utils::find_name_trace_dictionary(event_log);
        let name_to_trace_vec: Vec<(&String, &Trace)> =
            name_to_trace.iter().map(|(&k, &v)| (k, v)).collect();

        let bar = ProgressBar::new(name_to_trace.len() as u64);
        bar.set_style(
            ProgressStyle::with_template(
                "[{elapsed_precise}/{eta_precise} - {per_sec}] {wide_bar} {pos}/{len}",
            )
            .unwrap(),
        );
        bar.println("Encrypt data organization B");

        name_to_trace_vec
            .into_par_iter()
            .progress_with(bar)
            .with_finish(ProgressFinish::AndLeave)
            .map(|(name, trace)| {
                (
                    name.clone(),
                    self.preprocess_trace_using_sample_encryption(
                        activity_to_pos,
                        trace,
                        sample_encryptions,
                    ),
                )
            })
            .collect::<HashMap<String, (Vec<FheUint16>, Vec<u32>)>>()
    }
}
