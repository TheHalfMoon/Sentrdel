use sentrdel_review::project_detection::DetectionLimits;
use sentrdel_review::supabase::SUPABASE_R2_PACK_ID;
use sentrdel_review::supabase_detection::{SupabaseStaticPostureStatus, detect_supabase};
use sentrdel_schema::coverage::CoverageState;

const POSITIVE_CONFIG: &str =
    include_str!("../../../fixtures/repos/t062-supabase/positive/supabase/config.toml");
const NEGATIVE_CONFIG: &str =
    include_str!("../../../fixtures/repos/t062-supabase/negative/docs/supabase/config.toml");

#[test]
fn positive_and_negative_fixture_layouts_preserve_detection_only_semantics() {
    assert!(POSITIVE_CONFIG.contains("t062-positive-fixture"));
    assert!(NEGATIVE_CONFIG.contains("not-a-root-supabase-project"));

    let positive = detect_supabase(["supabase/config.toml"], DetectionLimits::default()).unwrap();
    assert!(positive.detected);
    assert!(!positive.has_security_verdict());
    let posture = positive
        .static_posture
        .expect("detected provider posture marker");
    assert_eq!(posture.status, SupabaseStaticPostureStatus::Available);
    assert_eq!(posture.coverage_state, CoverageState::Unavailable);
    assert_eq!(posture.pack_id, SUPABASE_R2_PACK_ID);
    assert!(
        posture
            .roadmap
            .contains("R2: Supabase P0 Static/Posture Pack")
    );

    let negative =
        detect_supabase(["docs/supabase/config.toml"], DetectionLimits::default()).unwrap();
    assert!(!negative.detected);
    assert!(negative.static_posture.is_none());
    assert!(!negative.has_security_verdict());
}
