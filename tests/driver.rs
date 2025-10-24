use std::fs;
use std::path::PathBuf;
use worldline_registry::{Circuit, Driver, Plugin, RegistrySnapshot};

#[test]
fn export_generates_json() {
    let mut snapshot = RegistrySnapshot::default();
    snapshot
        .register_circuit(Circuit {
            id: "0x01".into(),
            description: "Square".into(),
            verifier: "0xdead".into(),
            abi_uri: "https://example.com/abi.json".parse().unwrap(),
        })
        .unwrap();
    snapshot
        .register_driver(Driver {
            id: "0x02".into(),
            version: "1.0.0".into(),
            endpoint: "https://example.com".parse().unwrap(),
        })
        .unwrap();
    snapshot
        .register_plugin(Plugin {
            id: "0x03".into(),
            version: "1.0.0".into(),
            implementation: "0xbeef".into(),
            circuit_id: "0x01".into(),
            deprecated: false,
        })
        .unwrap();

    let compat = worldline_compat::build_compat_snapshot(&snapshot).unwrap();
    let output = PathBuf::from("/tmp/worldline-compat.json");
    fs::write(&output, serde_json::to_vec_pretty(&compat).unwrap()).unwrap();
    let content = fs::read_to_string(output).unwrap();
    assert!(content.contains("0x03"));
}
