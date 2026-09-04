use sentrdel_review::business_logic::data::{
    DataCoverageGapReason, SUPABASE_DATA_EXECUTES_QUERIES, SUPABASE_DATA_PROVES_DATABASE_RESULT,
    SUPABASE_DATA_PROVES_HOSTED_STATE, SUPABASE_DATA_PROVES_RUNTIME_REACHABILITY,
    extract_supabase_data_operations,
};
use sentrdel_review::business_logic::model::{
    BusinessLogicLimits, DataOperationKind, FieldSetMode,
};
use sentrdel_review::business_logic::route::RouteAdapter;
use sentrdel_review::structural::StructuralLanguage;
use sentrdel_review::view::NormalizedRepoPath;

fn path(value: &str) -> NormalizedRepoPath {
    NormalizedRepoPath::parse(value, 4_096).expect("normalized fixture path")
}

#[test]
fn static_relation_read_and_filters_are_observed_without_provider_authority() {
    let source = br#"Deno.serve(async (request) => {
  const body = await request.json();
  return supabase
    .from("profiles")
    .select("id, display_name")
    .eq("user_id", body.user_id)
    .maybeSingle();
});
"#;
    let result = extract_supabase_data_operations(
        RouteAdapter::SupabaseEdge,
        StructuralLanguage::JavaScript,
        &path("supabase/functions/profile/index.ts"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("extract bounded data operation");

    assert_eq!(result.operations().len(), 1);
    let operation = &result.operations()[0];
    assert_eq!(operation.operation_kind(), DataOperationKind::Read);
    assert_eq!(operation.resource().resource_name(), "profiles");
    assert_eq!(operation.resource().provider(), None);
    assert_eq!(operation.filters().len(), 1);
    let fields = operation.read_fields().expect("static selected fields");
    assert_eq!(fields.mode(), FieldSetMode::Explicit);
    assert_eq!(
        fields.fields(),
        &["display_name".to_owned(), "id".to_owned()]
    );
}

#[test]
fn explicit_update_fields_and_request_value_links_remain_static_only() {
    let source = br#"Deno.serve(async (request) => {
  const body = await request.json();
  return supabase
    .from("profiles")
    .update({ display_name: body.display_name, timezone: body.timezone })
    .eq("user_id", body.user_id)
    .select("id, display_name, timezone");
});
"#;
    let result = extract_supabase_data_operations(
        RouteAdapter::SupabaseEdge,
        StructuralLanguage::JavaScript,
        &path("supabase/functions/profile/index.ts"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("extract update operation");

    assert_eq!(result.operations().len(), 1);
    let operation = &result.operations()[0];
    assert_eq!(operation.operation_kind(), DataOperationKind::Update);
    let mutation = operation.mutation_fields().expect("mutation fields");
    assert_eq!(mutation.mode(), FieldSetMode::Explicit);
    assert_eq!(
        mutation.fields(),
        &["display_name".to_owned(), "timezone".to_owned()]
    );
    assert!(!mutation.value_origins().is_empty());
    assert!(operation.read_fields().is_some());

    const { assert!(!SUPABASE_DATA_EXECUTES_QUERIES) };
    const { assert!(!SUPABASE_DATA_PROVES_HOSTED_STATE) };
    const { assert!(!SUPABASE_DATA_PROVES_RUNTIME_REACHABILITY) };
    const { assert!(!SUPABASE_DATA_PROVES_DATABASE_RESULT) };
}

#[test]
fn verified_request_body_can_be_observed_as_broad_mutation_without_runtime_claim() {
    let source = br#"Deno.serve(async (request) => {
  return supabase.from("profiles").update(await request.json()).eq("id", "fixture");
});
"#;
    let result = extract_supabase_data_operations(
        RouteAdapter::SupabaseEdge,
        StructuralLanguage::JavaScript,
        &path("supabase/functions/profile/index.ts"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("extract broad request mutation");

    assert_eq!(result.operations().len(), 1);
    assert_eq!(
        result.operations()[0]
            .mutation_fields()
            .expect("broad mutation")
            .mode(),
        FieldSetMode::BroadRequestObject
    );
}

#[test]
fn canonical_data_helper_parameter_qualifies_broad_request_object() {
    let source = br#"export async function updateProfile(elevatedClient, req, userId) {
  return elevatedClient
    .from("profiles")
    .update(req.body)
    .eq("user_id", userId);
}
"#;
    let result = extract_supabase_data_operations(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/profile.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("extract canonical broad request mutation");

    assert_eq!(result.operations().len(), 1);
    assert_eq!(
        result.operations()[0]
            .mutation_fields()
            .expect("broad mutation")
            .mode(),
        FieldSetMode::BroadRequestObject
    );
}

#[test]
fn free_lexical_request_name_never_qualifies_broad_request_object() {
    let source = br#"export function helper(client) {
  return client.from("profiles").update(request.body);
}
"#;
    let result = extract_supabase_data_operations(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/helper.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect free lexical request lookalike");

    assert_eq!(result.operations().len(), 1);
    assert_eq!(
        result.operations()[0]
            .mutation_fields()
            .expect("mutation field set")
            .mode(),
        FieldSetMode::Dynamic
    );
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == DataCoverageGapReason::UnqualifiedBroadRequestObject)
    );
}

#[test]
fn reassigned_request_parameter_never_qualifies_broad_request_object() {
    let source = br#"export function helper(client, req) {
  req = fakeRequest;
  return client.from("profiles").update(req.body);
}
"#;
    let result = extract_supabase_data_operations(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/reassigned.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect reassigned request parameter");

    assert_eq!(result.operations().len(), 1);
    assert_eq!(
        result.operations()[0]
            .mutation_fields()
            .expect("mutation field set")
            .mode(),
        FieldSetMode::Dynamic
    );
}

#[test]
fn transformed_request_body_never_becomes_broad_request_object() {
    let source = br#"export function helper(client, req) {
  return client.from("profiles").update(sanitize(req.body));
}
"#;
    let result = extract_supabase_data_operations(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/transformed.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect transformed request body");

    assert_eq!(result.operations().len(), 1);
    assert_eq!(
        result.operations()[0]
            .mutation_fields()
            .expect("mutation field set")
            .mode(),
        FieldSetMode::Dynamic
    );
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == DataCoverageGapReason::DynamicMutationFields)
    );
}

#[test]
fn block_shadowed_request_parameter_never_qualifies_broad_request_object() {
    let source = br#"export function helper(client, req) {
  {
    const req = fakeRequest;
    return client.from("profiles").update(req.body);
  }
}
"#;
    let result = extract_supabase_data_operations(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/shadowed.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect block-shadowed request parameter");

    assert_eq!(result.operations().len(), 1);
    assert_eq!(
        result.operations()[0]
            .mutation_fields()
            .expect("mutation field set")
            .mode(),
        FieldSetMode::Dynamic
    );
}

#[test]
fn overwritten_request_body_never_qualifies_broad_request_object() {
    let source = br#"export function helper(client, req) {
  req.body = fakeBody;
  return client.from("profiles").update(req.body);
}
"#;
    let result = extract_supabase_data_operations(
        RouteAdapter::Express,
        StructuralLanguage::JavaScript,
        &path("src/body-overwrite.js"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect overwritten request body");

    assert_eq!(result.operations().len(), 1);
    assert_eq!(
        result.operations()[0]
            .mutation_fields()
            .expect("mutation field set")
            .mode(),
        FieldSetMode::Dynamic
    );
}

#[test]
fn dynamic_resource_and_rpc_names_fail_visible_instead_of_guessing_identity() {
    let source = br#"Deno.serve(async () => {
  await supabase.from(tableName).delete();
  await supabase.rpc(functionName, { id: "fixture" });
});
"#;
    let result = extract_supabase_data_operations(
        RouteAdapter::SupabaseEdge,
        StructuralLanguage::JavaScript,
        &path("supabase/functions/dynamic/index.ts"),
        source,
        BusinessLogicLimits::default(),
    )
    .expect("inspect dynamic data identities");

    assert!(result.operations().is_empty());
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == DataCoverageGapReason::DynamicResource)
    );
    assert!(
        result
            .gaps()
            .iter()
            .any(|gap| gap.reason() == DataCoverageGapReason::DynamicRpcName)
    );
}
