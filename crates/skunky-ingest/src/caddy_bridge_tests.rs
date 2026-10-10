use super::*;
use std::io::Write;

    fn test_caddyfile_content() -> String {
        "git.primals.eco {\n\t# ~~FLEET_PRESSURE_START~~\n\t# ~~FLEET_PRESSURE_END~~\n\troot * /opt/ecoPrimals/gitea-data\n}\n".to_string()
    }

    fn test_config(caddyfile: PathBuf) -> CaddyBridgeConfig {
        let snippet_dir = caddyfile.parent().unwrap().join("fleet-imports");
        CaddyBridgeConfig {
            caddyfile_path: caddyfile,
            caddy_reload_cmd: "true".to_string(),
            ip_ttl_secs: 3600,
            start_marker: "~~FLEET_PRESSURE_START~~".to_string(),
            end_marker: "~~FLEET_PRESSURE_END~~".to_string(),
            snippet_dir,
        }
    }

    #[test]
    fn add_and_track_ips() {
        let config = CaddyBridgeConfig {
            caddyfile_path: PathBuf::from("/tmp/nonexistent"),
            caddy_reload_cmd: "echo reload".to_string(),
            ip_ttl_secs: 3600,
            ..Default::default()
        };
        let mut bridge = CaddyBridge::new(config, HashSet::new());

        bridge.add_fleet_ips(
            &["57.141.20.1".to_string(), "57.141.20.2".to_string()],
            DefensePosture::WarnRoute,
        );

        assert_eq!(bridge.tracked_count(), 2);
        let ips = bridge.active_ips();
        assert!(ips.contains(&"57.141.20.1".to_string()));
        assert!(ips.contains(&"57.141.20.2".to_string()));
    }

    #[test]
    fn posture_escalation_on_same_ip() {
        let mut bridge = CaddyBridge::new(CaddyBridgeConfig {
            caddyfile_path: PathBuf::from("/tmp/nonexistent"),
            caddy_reload_cmd: "true".to_string(),
            ..Default::default()
        }, HashSet::new());

        bridge.add_fleet_ips(&["1.2.3.4".to_string()], DefensePosture::WarnRoute);
        assert_eq!(bridge.tracked_ips["1.2.3.4"].posture, DefensePosture::WarnRoute);

        bridge.add_fleet_ips(&["1.2.3.4".to_string()], DefensePosture::Scatter);
        assert_eq!(bridge.tracked_ips["1.2.3.4"].posture, DefensePosture::Scatter);

        // Lower posture should NOT de-escalate
        bridge.add_fleet_ips(&["1.2.3.4".to_string()], DefensePosture::WarnRoute);
        assert_eq!(bridge.tracked_ips["1.2.3.4"].posture, DefensePosture::Scatter);
    }

    #[test]
    fn expire_stale_ips() {
        let config = CaddyBridgeConfig {
            caddyfile_path: PathBuf::from("/tmp/nonexistent"),
            caddy_reload_cmd: "echo reload".to_string(),
            ip_ttl_secs: 0,
            ..Default::default()
        };
        let mut bridge = CaddyBridge::new(config, HashSet::new());

        bridge.add_fleet_ips(&["1.2.3.4".to_string()], DefensePosture::WarnRoute);
        std::thread::sleep(Duration::from_millis(10));
        bridge.expire_stale_ips();

        assert_eq!(bridge.tracked_count(), 0);
    }

    #[test]
    fn write_warn_route_directive() {
        let dir = tempfile::tempdir().unwrap();
        let caddyfile = dir.path().join("Caddyfile");
        {
            let mut f = std::fs::File::create(&caddyfile).unwrap();
            f.write_all(test_caddyfile_content().as_bytes()).unwrap();
        }

        let mut bridge = CaddyBridge::new(test_config(caddyfile.clone()), HashSet::new());
        bridge.add_fleet_ips(
            &["57.141.20.1".to_string(), "57.141.20.2".to_string()],
            DefensePosture::WarnRoute,
        );
        bridge.write_caddyfile().unwrap();

        let snippet = std::fs::read_to_string(dir.path().join("fleet-imports/fleet.snippet")).unwrap();
        assert!(snippet.contains("@fleet_warn"));
        assert!(snippet.contains("57.141.20.1"));
        assert!(snippet.contains("respond 403"));
        // Caddyfile itself should NOT be modified
        let caddyfile_content = std::fs::read_to_string(&caddyfile).unwrap();
        assert_eq!(caddyfile_content, test_caddyfile_content());
    }

    #[test]
    fn write_tarpit_directive() {
        let dir = tempfile::tempdir().unwrap();
        let caddyfile = dir.path().join("Caddyfile");
        std::fs::write(&caddyfile, test_caddyfile_content()).unwrap();

        let mut bridge = CaddyBridge::new(test_config(caddyfile.clone()), HashSet::new());
        bridge.add_fleet_ips(&["10.0.0.1".to_string()], DefensePosture::SlowDegrade);
        bridge.write_caddyfile().unwrap();

        let snippet = std::fs::read_to_string(dir.path().join("fleet-imports/fleet.snippet")).unwrap();
        assert!(snippet.contains("@fleet_tarpit"));
        assert!(snippet.contains("/tarpit{uri}"));
        assert!(snippet.contains("reverse_proxy localhost:9753"));
    }

    #[test]
    fn write_scatter_directive() {
        let dir = tempfile::tempdir().unwrap();
        let caddyfile = dir.path().join("Caddyfile");
        std::fs::write(&caddyfile, test_caddyfile_content()).unwrap();

        let mut bridge = CaddyBridge::new(test_config(caddyfile.clone()), HashSet::new());
        bridge.add_fleet_ips(&["10.0.0.2".to_string()], DefensePosture::Scatter);
        bridge.write_caddyfile().unwrap();

        let snippet = std::fs::read_to_string(dir.path().join("fleet-imports/fleet.snippet")).unwrap();
        assert!(snippet.contains("@fleet_scatter"));
        assert!(snippet.contains("reverse_proxy localhost:9753"));
    }

    #[test]
    fn write_vanish_directive() {
        let dir = tempfile::tempdir().unwrap();
        let caddyfile = dir.path().join("Caddyfile");
        std::fs::write(&caddyfile, test_caddyfile_content()).unwrap();

        let mut bridge = CaddyBridge::new(test_config(caddyfile.clone()), HashSet::new());
        bridge.add_fleet_ips(&["10.0.0.3".to_string()], DefensePosture::Vanish);
        bridge.write_caddyfile().unwrap();

        let snippet = std::fs::read_to_string(dir.path().join("fleet-imports/fleet.snippet")).unwrap();
        assert!(snippet.contains("@fleet_vanish"));
        assert!(snippet.contains("abort"));
    }

    #[test]
    fn write_multi_posture_ordering() {
        let dir = tempfile::tempdir().unwrap();
        let caddyfile = dir.path().join("Caddyfile");
        std::fs::write(&caddyfile, test_caddyfile_content()).unwrap();

        let mut bridge = CaddyBridge::new(test_config(caddyfile.clone()), HashSet::new());
        bridge.add_fleet_ips(&["10.0.0.1".to_string()], DefensePosture::WarnRoute);
        bridge.add_fleet_ips(&["10.0.0.2".to_string()], DefensePosture::Vanish);
        bridge.add_fleet_ips(&["10.0.0.3".to_string()], DefensePosture::Scatter);
        bridge.write_caddyfile().unwrap();

        let snippet = std::fs::read_to_string(dir.path().join("fleet-imports/fleet.snippet")).unwrap();
        let vanish_pos = snippet.find("@fleet_vanish").unwrap();
        let scatter_pos = snippet.find("@fleet_scatter").unwrap();
        let warn_pos = snippet.find("@fleet_warn").unwrap();
        assert!(vanish_pos < scatter_pos, "vanish should come before scatter");
        assert!(scatter_pos < warn_pos, "scatter should come before warn");
    }

    #[test]
    fn observe_posture_produces_no_directives() {
        let dir = tempfile::tempdir().unwrap();
        let caddyfile = dir.path().join("Caddyfile");
        std::fs::write(&caddyfile, test_caddyfile_content()).unwrap();

        let mut bridge = CaddyBridge::new(test_config(caddyfile.clone()), HashSet::new());
        bridge.add_fleet_ips(&["10.0.0.1".to_string()], DefensePosture::Observe);
        bridge.write_caddyfile().unwrap();

        let snippet = std::fs::read_to_string(dir.path().join("fleet-imports/fleet.snippet")).unwrap();
        assert!(!snippet.contains("@fleet_"));
    }

    #[test]
    fn sync_no_change_returns_false() {
        let dir = tempfile::tempdir().unwrap();
        let caddyfile = dir.path().join("Caddyfile");
        std::fs::write(&caddyfile, test_caddyfile_content()).unwrap();

        let mut bridge = CaddyBridge::new(test_config(caddyfile), HashSet::new());
        let changed = bridge.sync().unwrap();
        assert!(!changed);
    }

    #[test]
    fn negative_selection_filters_self_ips() {
        let self_ips: HashSet<String> =
            ["10.13.37.1", "162.226.225.148"].iter().map(|s| s.to_string()).collect();
        let mut bridge = CaddyBridge::new(
            CaddyBridgeConfig {
                caddyfile_path: PathBuf::from("/tmp/nonexistent"),
                caddy_reload_cmd: "true".to_string(),
                ..Default::default()
            },
            self_ips,
        );

        bridge.add_fleet_ips(
            &[
                "57.141.20.1".to_string(),  // fleet — should be tracked
                "162.226.225.148".to_string(),  // self — should be filtered
                "10.13.37.1".to_string(),  // self — should be filtered
                "57.141.20.2".to_string(),  // fleet — should be tracked
            ],
            DefensePosture::Vanish,
        );

        assert_eq!(bridge.tracked_count(), 2);
        assert!(bridge.tracked_ips.contains_key("57.141.20.1"));
        assert!(bridge.tracked_ips.contains_key("57.141.20.2"));
        assert!(!bridge.tracked_ips.contains_key("162.226.225.148"));
        assert!(!bridge.tracked_ips.contains_key("10.13.37.1"));
    }

    #[test]
    fn negative_selection_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let self_file = dir.path().join("self-ips.txt");
        std::fs::write(
            &self_file,
            "# Known infrastructure\n\
             162.226.225.148  # sporeGate WAN\n\
             10.13.37.1       # golgiBody wg0\n\
             \n\
             # golgiBody\n\
             157.230.3.183    # this server\n",
        )
        .unwrap();

        let self_ips = load_self_ips(&self_file);
        assert_eq!(self_ips.len(), 3);
        assert!(self_ips.contains("162.226.225.148"));
        assert!(self_ips.contains("10.13.37.1"));
        assert!(self_ips.contains("157.230.3.183"));
    }

    #[test]
    fn sourdough_restores_from_snippet() {
        let dir = tempfile::tempdir().unwrap();
        let caddyfile = dir.path().join("Caddyfile");
        std::fs::write(&caddyfile, test_caddyfile_content()).unwrap();

        // Write a snippet file directly (simulates previous session)
        let snippet_dir = dir.path().join("fleet-imports");
        std::fs::create_dir_all(&snippet_dir).unwrap();
        std::fs::write(
            snippet_dir.join("fleet.snippet"),
            "\t@fleet_disperse remote_ip 57.141.20.1 57.141.20.2 57.141.20.3\n\
             \thandle @fleet_disperse {\n\t\trewrite * /disperse{uri}\n\t\treverse_proxy localhost:9753\n\t}\n\
             \t@fleet_warn remote_ip 10.0.0.1\n\
             \thandle @fleet_warn {\n\t\trespond 403\n\t}\n",
        )
        .unwrap();

        let bridge = CaddyBridge::new(test_config(caddyfile), HashSet::new());
        assert_eq!(bridge.tracked_count(), 4);
        assert!(bridge.tracked_ips.contains_key("57.141.20.1"));
        assert!(bridge.tracked_ips.contains_key("57.141.20.2"));
        assert!(bridge.tracked_ips.contains_key("57.141.20.3"));
        assert!(bridge.tracked_ips.contains_key("10.0.0.1"));
        assert_eq!(
            bridge.tracked_ips["57.141.20.1"].posture,
            DefensePosture::Disperse
        );
        assert_eq!(
            bridge.tracked_ips["10.0.0.1"].posture,
            DefensePosture::WarnRoute
        );
    }

    #[test]
    fn sourdough_legacy_migration_from_caddyfile() {
        let dir = tempfile::tempdir().unwrap();
        let caddyfile = dir.path().join("Caddyfile");
        // Legacy Caddyfile with fleet directives between markers (no snippet files)
        std::fs::write(
            &caddyfile,
            "git.primals.eco {\n\
             \t# ~~FLEET_PRESSURE_START~~\n\
             \t@fleet_disperse remote_ip 1.1.1.1 2.2.2.2\n\
             \thandle @fleet_disperse {\n\t\trewrite * /disperse{uri}\n\t\treverse_proxy localhost:9753\n\t}\n\
             \t@fleet_vanish remote_ip 3.3.3.3\n\
             \thandle @fleet_vanish {\n\t\tabort\n\t}\n\
             \t@fleet_scatter remote_ip 4.4.4.4\n\
             \thandle @fleet_scatter {\n\t\treverse_proxy localhost:9753\n\t}\n\
             \t@fleet_tarpit remote_ip 5.5.5.5 6.6.6.6\n\
             \thandle @fleet_tarpit {\n\t\trewrite * /tarpit{uri}\n\t\treverse_proxy localhost:9753\n\t}\n\
             \t# ~~FLEET_PRESSURE_END~~\n\
             }\n",
        )
        .unwrap();

        let bridge = CaddyBridge::new(test_config(caddyfile), HashSet::new());
        assert_eq!(bridge.tracked_count(), 6);
        assert_eq!(bridge.tracked_ips["1.1.1.1"].posture, DefensePosture::Disperse);
        assert_eq!(bridge.tracked_ips["3.3.3.3"].posture, DefensePosture::Vanish);
        assert_eq!(bridge.tracked_ips["4.4.4.4"].posture, DefensePosture::Scatter);
        assert_eq!(bridge.tracked_ips["5.5.5.5"].posture, DefensePosture::SlowDegrade);
    }

    #[test]
    fn sourdough_empty_restores_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let caddyfile = dir.path().join("Caddyfile");
        std::fs::write(&caddyfile, test_caddyfile_content()).unwrap();

        let bridge = CaddyBridge::new(test_config(caddyfile), HashSet::new());
        assert_eq!(bridge.tracked_count(), 0);
    }

    #[test]
    fn sourdough_survives_restart_cycle() {
        let dir = tempfile::tempdir().unwrap();
        let caddyfile = dir.path().join("Caddyfile");
        std::fs::write(&caddyfile, test_caddyfile_content()).unwrap();

        // Session 1: add IPs and write to snippets
        let mut bridge1 = CaddyBridge::new(test_config(caddyfile.clone()), HashSet::new());
        bridge1.add_fleet_ips(
            &["57.141.20.1".to_string(), "57.141.20.2".to_string()],
            DefensePosture::Disperse,
        );
        bridge1.write_caddyfile().unwrap();

        // Session 2: new bridge should restore from snippet file
        let bridge2 = CaddyBridge::new(test_config(caddyfile), HashSet::new());
        assert_eq!(bridge2.tracked_count(), 2);
        assert!(bridge2.tracked_ips.contains_key("57.141.20.1"));
        assert!(bridge2.tracked_ips.contains_key("57.141.20.2"));
        assert_eq!(
            bridge2.tracked_ips["57.141.20.1"].posture,
            DefensePosture::Disperse
        );
    }

    #[test]
    fn sync_with_new_ips_returns_true() {
        let dir = tempfile::tempdir().unwrap();
        let caddyfile = dir.path().join("Caddyfile");
        std::fs::write(&caddyfile, test_caddyfile_content()).unwrap();

        let mut bridge = CaddyBridge::new(test_config(caddyfile), HashSet::new());
        bridge.add_fleet_ips(&["57.141.20.1".to_string()], DefensePosture::WarnRoute);
        let changed = bridge.sync().unwrap();
        assert!(changed);
    }

    #[test]
    fn fleet_hash_header_in_scatter_directive() {
        let dir = tempfile::tempdir().unwrap();
        let caddyfile = dir.path().join("Caddyfile");
        std::fs::write(&caddyfile, test_caddyfile_content()).unwrap();

        let mut bridge = CaddyBridge::new(test_config(caddyfile.clone()), HashSet::new());
        bridge.add_fleet_ips_with_hash(
            &["57.141.20.1".to_string(), "57.141.20.2".to_string()],
            DefensePosture::Scatter,
            Some("abc123deadbeef"),
        );
        bridge.write_caddyfile().unwrap();

        let snippet = std::fs::read_to_string(dir.path().join("fleet-imports/fleet.snippet")).unwrap();
        assert!(snippet.contains("@fleet_scatter"), "should have scatter matcher");
        assert!(snippet.contains("X-Fleet-Hash"), "should have X-Fleet-Hash header");
        assert!(snippet.contains("abc123deadbeef"), "should have the behavioral hash value");
        assert!(snippet.contains("X-Real-IP"), "should still have X-Real-IP");
    }

    #[test]
    fn fleet_hash_survives_sourdough_restart() {
        let dir = tempfile::tempdir().unwrap();
        let caddyfile = dir.path().join("Caddyfile");
        std::fs::write(&caddyfile, test_caddyfile_content()).unwrap();

        // Session 1: add IPs with hash and write to snippet
        let mut bridge1 = CaddyBridge::new(test_config(caddyfile.clone()), HashSet::new());
        bridge1.add_fleet_ips_with_hash(
            &["57.141.20.1".to_string()],
            DefensePosture::Scatter,
            Some("deadbeef12345678"),
        );
        bridge1.write_caddyfile().unwrap();

        // Verify it was written to snippet
        let snippet = std::fs::read_to_string(dir.path().join("fleet-imports/fleet.snippet")).unwrap();
        assert!(snippet.contains("deadbeef12345678"), "hash should be in snippet");

        // Session 2: new bridge should restore hash from snippet
        let bridge2 = CaddyBridge::new(test_config(caddyfile), HashSet::new());
        assert_eq!(bridge2.tracked_count(), 1);
        assert!(bridge2.tracked_ips.contains_key("57.141.20.1"));
        assert_eq!(
            bridge2.tracked_ips["57.141.20.1"].behavioral_hash.as_deref(),
            Some("deadbeef12345678"),
            "behavioral hash should survive sourdough restart"
        );
    }

    #[test]
    fn no_fleet_hash_for_warn_route() {
        let dir = tempfile::tempdir().unwrap();
        let caddyfile = dir.path().join("Caddyfile");
        std::fs::write(&caddyfile, test_caddyfile_content()).unwrap();

        let mut bridge = CaddyBridge::new(test_config(caddyfile.clone()), HashSet::new());
        bridge.add_fleet_ips_with_hash(
            &["57.141.20.1".to_string()],
            DefensePosture::WarnRoute,
            Some("abc123"),
        );
        bridge.write_caddyfile().unwrap();

        let snippet = std::fs::read_to_string(dir.path().join("fleet-imports/fleet.snippet")).unwrap();
        assert!(snippet.contains("@fleet_warn"), "should have warn matcher");
        assert!(!snippet.contains("X-Fleet-Hash"), "warn route has no reverse_proxy, no hash header");
    }

    #[test]
    fn no_fleet_hash_for_vanish() {
        let dir = tempfile::tempdir().unwrap();
        let caddyfile = dir.path().join("Caddyfile");
        std::fs::write(&caddyfile, test_caddyfile_content()).unwrap();

        let mut bridge = CaddyBridge::new(test_config(caddyfile.clone()), HashSet::new());
        bridge.add_fleet_ips_with_hash(
            &["57.141.20.1".to_string()],
            DefensePosture::Vanish,
            Some("abc123"),
        );
        bridge.write_caddyfile().unwrap();

        let snippet = std::fs::read_to_string(dir.path().join("fleet-imports/fleet.snippet")).unwrap();
        assert!(snippet.contains("abort"), "vanish should abort");
        assert!(!snippet.contains("X-Fleet-Hash"), "vanish has no reverse_proxy, no hash header");
    }

    #[test]
    fn fleet_hash_in_disperse_and_tarpit() {
        let dir = tempfile::tempdir().unwrap();
        let caddyfile = dir.path().join("Caddyfile");
        std::fs::write(&caddyfile, test_caddyfile_content()).unwrap();

        let mut bridge = CaddyBridge::new(test_config(caddyfile.clone()), HashSet::new());
        bridge.add_fleet_ips_with_hash(
            &["10.0.0.1".to_string()],
            DefensePosture::Disperse,
            Some("disperse_hash_001"),
        );
        bridge.add_fleet_ips_with_hash(
            &["10.0.0.2".to_string()],
            DefensePosture::SlowDegrade,
            Some("tarpit_hash_002"),
        );
        bridge.write_caddyfile().unwrap();

        let snippet = std::fs::read_to_string(dir.path().join("fleet-imports/fleet.snippet")).unwrap();
        assert!(snippet.contains("disperse_hash_001"), "disperse should have its hash");
        assert!(snippet.contains("tarpit_hash_002"), "tarpit should have its hash");
    }

    #[test]
    fn honeycomb_snippet_created() {
        let dir = tempfile::tempdir().unwrap();
        let caddyfile = dir.path().join("Caddyfile");
        std::fs::write(&caddyfile, test_caddyfile_content()).unwrap();

        let mut bridge = CaddyBridge::new(test_config(caddyfile.clone()), HashSet::new());
        bridge.add_fleet_ips(&["10.0.0.1".to_string()], DefensePosture::Scatter);
        bridge.write_caddyfile().unwrap();

        let hc_snippet = std::fs::read_to_string(dir.path().join("fleet-imports/honeycomb.snippet")).unwrap();
        assert!(hc_snippet.contains("@hc_fleet"), "honeycomb snippet should have hc_fleet matcher");
        assert!(hc_snippet.contains("X-Honeycomb"), "honeycomb snippet should have X-Honeycomb header");
    }

    #[test]
    fn caddyfile_not_modified_by_write() {
        let dir = tempfile::tempdir().unwrap();
        let caddyfile = dir.path().join("Caddyfile");
        let original = test_caddyfile_content();
        std::fs::write(&caddyfile, &original).unwrap();

        let mut bridge = CaddyBridge::new(test_config(caddyfile.clone()), HashSet::new());
        bridge.add_fleet_ips(&["10.0.0.1".to_string()], DefensePosture::Disperse);
        bridge.write_caddyfile().unwrap();

        let after = std::fs::read_to_string(&caddyfile).unwrap();
        assert_eq!(after, original, "Caddyfile should not be modified by snippet-based write");
    }
