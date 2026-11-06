//! Prints contract v1's JSON Schema (the request, with every op and parameter) from the Rust types: the one source
//! the client's TypeScript types are generated from (`bun run contract`). A review decision (`POST /api/review`) is
//! the one write beside the reads; its types go in the schema's definitions.
fn main() {
    let mut schema = serde_json::to_value(schemars::schema_for!(msp_console::contract::EvidenceRequest)).expect("schema");
    let review = serde_json::to_value(schemars::schema_for!(msp_console::contract::ReviewDecision)).expect("schema");
    let defs = schema["$defs"].as_object_mut().expect("definitions");
    for (k, v) in review["$defs"].as_object().into_iter().flatten() { defs.insert(k.clone(), v.clone()); }
    let mut me = review.clone();
    if let Some(o) = me.as_object_mut() { o.remove("$defs"); o.remove("$schema"); }
    defs.insert("ReviewDecision".into(), me);
    println!("{}", serde_json::to_string_pretty(&schema).expect("schema"));
}
