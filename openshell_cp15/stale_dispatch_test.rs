
    #[tokio::test]
    async fn cp15_new_writer_blocks_previously_committed_stale_dispatch() {
        let engine = OpaEngine::from_strings(POLICY, "network_policies: {}\n").unwrap();
        let guard = engine.generation_guard(engine.current_generation()).unwrap();
        let authority = Arc::new(DispatchAuthorityFence::default());
        authority.publish_session(Some("session-a".into()));
        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("permits.jsonl");
        let old = DurableEgressPermitGate::new("sandbox-a", Arc::clone(&authority), &journal).unwrap();
        let permit = old.commit_before_effect(&guard, test_input()).await.unwrap();
        let _new = DurableEgressPermitGate::new("sandbox-a", authority, &journal).unwrap();
        assert!(old.linearize_dispatch(&engine, &guard, &permit).is_err(),
            "CP15_STALE_DISPATCH: replaced writer must not admit an old committed permit");
    }
