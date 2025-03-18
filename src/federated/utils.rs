use std::collections::HashMap;
use process_mining::dfg::dfg_struct::Activity;
use process_mining::dfg::DirectlyFollowsGraph;
use process_mining::event_log::Trace;
use process_mining::EventLog;

pub fn recalculate_activity_counts(dfg: &mut DirectlyFollowsGraph) {
    let mut updated_activities: HashMap<Activity, u32> = HashMap::with_capacity(dfg.activities.len());

    dfg.activities.iter().for_each(|(act, _)| {
        let mut new_count: u32;

        new_count = dfg
            .get_ingoing_df_relations(act)
            .iter()
            .map(|dfr| dfg.directly_follows_relations.get(dfr).unwrap())
            .sum();
        new_count = new_count.max(
            dfg.get_outgoing_df_relations(act)
                .iter()
                .map(|dfr| dfg.directly_follows_relations.get(dfr).unwrap())
                .sum(),
        );

        updated_activities.insert(act.clone(), new_count);
    });

    dfg.activities = updated_activities;
}

///
/// Computes a dictionary from a trace's name to the trace for all traces in the event log
///
pub fn find_name_trace_dictionary(event_log: &EventLog) -> HashMap<&String, &Trace> {
    let mut result: HashMap<&String, &Trace> = HashMap::new();

    event_log.traces.iter().for_each(|t| {
        result.insert(
            event_log.get_trace_attribute(t, "concept:name")
                .unwrap()
                .value
                .try_as_string()
                .unwrap(),
            t,
        );
    });

    result
}