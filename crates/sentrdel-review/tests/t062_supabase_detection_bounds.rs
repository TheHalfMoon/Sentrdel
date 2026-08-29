use sentrdel_review::project_detection::DetectionLimits;
use sentrdel_review::supabase_detection::{detect_supabase, SupabaseDetectionError};

#[test]
fn supabase_detection_fails_closed_on_path_budget_or_noncanonical_path() {
    assert!(matches!(
        detect_supabase(
            ["supabase/config.toml", "supabase/seed.sql"],
            DetectionLimits {
                max_paths: 1,
                max_path_bytes: 128,
            },
        ),
        Err(SupabaseDetectionError::TooManyPaths { max: 1 })
    ));

    assert!(matches!(
        detect_supabase(
            ["../supabase/config.toml"],
            DetectionLimits {
                max_paths: 8,
                max_path_bytes: 128,
            },
        ),
        Err(SupabaseDetectionError::InvalidPath { index: 0, .. })
    ));
}
