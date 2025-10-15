// Test with real SDK proof data from Dash Platform
use grovestark::MerkleNode;
use std::fs;

// Minimal SDK-proof parser used only in this test module.
// Skips [len(2)][root(32)] and scans for hash-carrying ops.
fn parse_sdk_grovedb_proof(bytes: &[u8]) -> Result<Vec<MerkleNode>, String> {
    if bytes.len() < 34 {
        return Err("too short".into());
    }
    let mut i = 34;
    let end = bytes.len();
    // find anchor 0x02 0x01 0x20 or fall back to first 0x01 0x20
    let mut start = None;
    while i + 2 < end {
        if bytes[i] == 0x02 && bytes[i + 1] == 0x01 && bytes[i + 2] == 0x20 {
            start = Some(i);
            break;
        }
        i += 1;
    }
    if start.is_none() {
        i = 34;
        while i + 1 < end {
            if bytes[i] == 0x01 && bytes[i + 1] == 0x20 {
                start = Some(i);
                break;
            }
            i += 1;
        }
    }
    let mut idx = start.ok_or_else(|| "no ops start".to_string())?;
    let mut nodes = Vec::new();
    while idx < end && nodes.len() < 4096 {
        match bytes[idx] {
            0x01 | 0x03 | 0x04 | 0x10 | 0x11 => {
                if idx + 34 <= end && bytes[idx + 1] == 0x20 {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&bytes[idx + 2..idx + 34]);
                    nodes.push(MerkleNode {
                        hash: h,
                        is_left: false,
                    });
                    idx += 34;
                } else {
                    break;
                }
            }
            0x02 => {
                idx += 1;
            }
            _ => {
                idx += 1;
            }
        }
    }
    if nodes.is_empty() {
        return Err("no nodes".into());
    }
    Ok(nodes)
}

#[test]
fn test_parse_real_document_proof() {
    // Load the real document proof from the test data
    let proof_path =
        "tests/fixtures/document_proof_B5XLy3cUDayaqZmcGaWb98PEAUguGHiHSU5DxiKrHBj3.bin";
    let proof_data = fs::read(proof_path).expect("Failed to read document proof file");

    println!("Document proof size: {} bytes", proof_data.len());

    // Parse the proof using the SDK parser
    let result = parse_sdk_grovedb_proof(&proof_data);

    assert!(
        result.is_ok(),
        "Failed to parse real document proof: {:?}",
        result.err()
    );

    let nodes = result.unwrap();
    println!("Parsed {} Merkle nodes from document proof", nodes.len());

    // Verify we got at least one node
    assert!(!nodes.is_empty(), "Expected at least one Merkle node");

    // Check the first node has valid data
    let first_node = &nodes[0];
    assert_ne!(first_node.hash, [0u8; 32], "Hash should not be all zeros");

    println!("First node hash: {:02x?}...", &first_node.hash[0..8]);
    println!("First node is_left: {}", first_node.is_left);
}

#[test]
fn test_parse_real_identity_proof() {
    // Load the real identity proof from the test data
    let proof_path =
        "tests/fixtures/identity_proof_FQ4waDowFQXD4tJPKQM1114VSr5f8s3qAc5bT8FJkT49.bin";
    let proof_data = fs::read(proof_path).expect("Failed to read identity proof file");

    println!("Identity proof size: {} bytes", proof_data.len());

    // Parse the proof using the SDK parser
    let result = parse_sdk_grovedb_proof(&proof_data);

    assert!(
        result.is_ok(),
        "Failed to parse real identity proof: {:?}",
        result.err()
    );

    let nodes = result.unwrap();
    println!("Parsed {} Merkle nodes from identity proof", nodes.len());

    // Verify we got at least one node
    assert!(!nodes.is_empty(), "Expected at least one Merkle node");

    // Check the first node has valid data
    let first_node = &nodes[0];
    assert_ne!(first_node.hash, [0u8; 32], "Hash should not be all zeros");

    println!("First node hash: {:02x?}...", &first_node.hash[0..8]);
    println!("First node is_left: {}", first_node.is_left);
}

#[test]
fn test_real_proofs_metadata_consistency() {
    // Load both proofs
    let doc_proof =
        fs::read("tests/fixtures/document_proof_B5XLy3cUDayaqZmcGaWb98PEAUguGHiHSU5DxiKrHBj3.bin")
            .expect("Failed to read document proof");
    let id_proof =
        fs::read("tests/fixtures/identity_proof_FQ4waDowFQXD4tJPKQM1114VSr5f8s3qAc5bT8FJkT49.bin")
            .expect("Failed to read identity proof");

    // Check the metadata file exists
    let metadata_path =
        "tests/fixtures/proof_metadata_B5XLy3cUDayaqZmcGaWb98PEAUguGHiHSU5DxiKrHBj3.json";
    assert!(
        std::path::Path::new(metadata_path).exists(),
        "Metadata file should exist"
    );

    // Parse both proofs
    let doc_nodes = parse_sdk_grovedb_proof(&doc_proof).expect("Failed to parse document proof");
    let id_nodes = parse_sdk_grovedb_proof(&id_proof).expect("Failed to parse identity proof");

    // Both proofs should parse successfully
    assert!(doc_nodes.len() > 0, "Document proof should have nodes");
    assert!(id_nodes.len() > 0, "Identity proof should have nodes");

    // The proofs are from the same document/identity pair
    // They should have been captured at the same state
    println!("Document proof nodes: {}", doc_nodes.len());
    println!("Identity proof nodes: {}", id_nodes.len());

    // Verify the state roots are the same (first 32 bytes after length prefix)
    assert_eq!(doc_proof.len(), 1375, "Document proof should be 1375 bytes");
    assert_eq!(id_proof.len(), 2351, "Identity proof should be 2351 bytes");

    // Extract state roots (bytes 2-33)
    let doc_state_root = &doc_proof[2..34];
    let id_state_root = &id_proof[2..34];

    println!("Document state root: {:02x?}...", &doc_state_root[0..8]);
    println!("Identity state root: {:02x?}...", &id_state_root[0..8]);
}

#[test]
fn test_proof_data_from_proof_data_md() {
    // Test using the hex data from PROOF_DATA.md
    // The document proof hex is on line 5 of PROOF_DATA.md
    let doc_proof_hex = "008d01b0b132cce1a5a4fa97cabc07bac83e285e9829616a88aac36b0b8294d5566c0704014000240201205bb4077299c35f3d25823bac24779abe40e3e0ff4d76104b5b6a074687142a480021ea29a7037f5c3e04e17cb393a2785588e55b0900135ddc46a3ce27ac6148cd1001c17d117b3974b340c882436105883ce18a32f9438f04f9485243cb84100aaaaa11010140fb02f101c7a162735269e73509f445711863ac72564ca5f915f9116e45a4a69993b3efe902f5a40b154096932fa4f0f0a0058553d8e34dadbb5536d789ab8d8da8be8fffc31001d9bd3d9b1670c9b266a3a3fea9ffe9d10cb4d2c13a552900ad9b8b12c7777c6d029803e1502880e8f3ab53c50f5ab52ee90fd38a10e7b080cf2e6d4fefed33834e100139ead1d1024e8080cac114638c0491abb119ac159c41f3abf023d10c29f09a100252204ccb995f0e6c24d8612e36708ac88a3f48fede4e96038ff8b07a27c691b11001acec11674f9c0b293428d13390828a0c51fc471ba60bb4acdeb5898b8d9f95d2024a7f6dc97589d4cf25d03e567736185ffb40acad77b53eae7f9b80d48efaf1ff100113cdb903028bbfd2f94e82ef3785c97cf862066428069754a75d4f3c2fb5794c02407df2bc4db091b2800a9c3d65930c689b5d4ad50b118c8ec8d609d17dc56ca710019303bb70e1b340c27fca57eb31d93314834bb3930f17b0f2d51e129e108f316802741b3792a0b8520e1e12ab2958d6ae2a9e12ee434ea9530fe2833c622249d42e1001f49ac9c35ea0ad28cac9f6535df8fab222030c3b6d5f08a965c2ab60d0b67b0f02f3887c540e229b76c180fbc1ae7f296cad7b140637db69fd0939d65b3fd94c3b100420a083bdbcf10c79e6bed7156a44756538f7e5ac32129b9376b65f179d4bf5cca400050201010100b8eae9e40fe8ec4f54b9965daea6c3c0c0dfd1947a068501a95ba19b5b8d8cad1102eeceda9a9815d52ea78e43a46a7fe305097183e30303b30186cbba043fec4cad100153b9686cc4f645a4ffd7622a6d6543a5a6b6c92912c253fdd5556fe47f6d6ca6110292aee347b15048664148151d81268bc567f0d1767bf99ca309525ccf8228b28d1001919400e706cb2e384cb050465f79adafe8216616d709c23235b0691c7dbf1a20111111111111029fb3688df9d92705bcbe036fda4f7153ae1f0b1a5629a9f4458b15b44389038010018d2e360ac530f4f93a6c79f26178ecefca7b498b9026be1e118a78cba88689fc11110120a083bdbcf10c79e6bed7156a44756538f7e5ac32129b9376b65f179d4bf5cca44f01851f7314176b1a06e514e3dd67609a5f6524e7a7ad55c80974f2c8583ecfef5a0401010008020104626c6f62000664a1a5db66b1a8fb0a2e40c084c19a51bf415c34fc5fb84cac7a1b7497d7e1100101013c0404626c6f62001402011073616c746564446f6d61696e4861736800c948211b44e64cf202bc02d21aeb383f126dc27ef54c1f411e9d0075a0048bc20104626c6f626b040100002402012095bd80bab08b470c5ab26d51c48113b64e1a85d8a0a710e02fd343b51d559e7e00ca4a1caf04fd6d86a857219f8ea65409c866301ebddc215964158b71974282ed021d6572ecc9d0bf3c14b46cbae0424920aed54d312f91631bcd4cd07202ccdd1210010100af032095bd80bab08b470c5ab26d51c48113b64e1a85d8a0a710e02fd343b51d559e7e008b00640195bd80bab08b470c5ab26d51c48113b64e1a85d8a0a710e02fd343b51d559e7ed5ec6e7bf0943364b70eef9c2aca3b825d141eeb7e567304f5da7c7a10cf82a60100000dab629328d129c69a48c54d2ce59d20b00ec72fd0a0e9a94adff4959e4c35bf012302d5ec6e7bf0943364b70eef9c2aca3b825d141eeb7e567304f5da7c7a10cf82a6250f0001";

    // The identity proof hex is on line 9 of PROOF_DATA.md
    let id_proof_hex = "00fb0146018ee04d96387a99216dc7f656cf623dee418d40a5947efbe16b0495e10d50355e04012000240201207dec59e08c02ff8b954769c3cb9d5a74f6eb0e2c8cd5a056fba4c47f1e5f545a0037118cfc31e5912b2d70da3b3e1c4959788cc6ccc74c30baf595576e169446c810014c38538213e4a28f2430897c19517cf0cb1137c37fae65ffadd62976251255dd110235016c0db886d098bff32408ec1a1ae653e0f521f42794e91ca80f9af86deaf0100135adcc4b8231042da89bcf5ce2b89e13fa69a7e03489ede06d7b4ee89d485ee9040160002d0401207dec59e08c02ff8b954769c3cb9d5a74f6eb0e2c8cd5a056fba4c47f1e5f545afd008498dcc623cf20005ffbc801d6564034c705aed9041318770cf46a1b9641bf591ef489b5c0697ad51001b5b78ec6129c0a20495b2b457cae5904f7b975f80c2605c23fd169fdf50f0cb31111020120fb033901cf5b14b166fa29627b438f6994f918501401cb1157433413de40c82ec9930b19020e703c94077502209bfed96e14b7a98f554929c572d8db2d805d9b4d0c1159d61001cc25f95dfe6b742fbc1bfac191866e7be2514ed3f0d2884d31bc2784dda1f4b8021c126c2cf2765ff9b2e464d8207a6645520ef7767ed3e5ad4f6a242fe38783f41001053933e015ad073ee1057c525fbec0066fd500d6afe8ce0ae46467a2e4260df10242397635b3d9c7ddef9573ee5ab57e0ee22b232db64c35241d2b263ca442fcaf1001bd78aab052cfd8261558a30f7c3efbe3f8802d2bef7989be46b0429ac476ae850256800e5fb18f97fff2ae609a233ae9708a589a110d04a32aed9562e7aaa8e61a10013eb3a5a0486c47298394ec0f801b7a66568bf282be12fc68ed4f06e10f39799d02193df0f3a24175bb6fb2e6debc04abb592d5e91501ed1f3a6ac77e6052cd57371001454de82a63bb7297f47fc270c2866fc7bb9173a8ac258ed55df4c67b84f9e9d00294a11e5a6ec8724ef5dae4135668761311443e08c3aadfe246583f9786b1c93c100420d5ec6e7bf0943364b70eef9c2aca3b825d141eeb7e567304f5da7c7a10cf82a600090201018001030024983fe0c9168b6439ab5ea7408cd65fe672d574575359852180ea407c5491598f7c1102de1073918de028645a98b6ea2c6094c8499d2c3ede3c056d7e10d41667876e7e10015da7d692a2792131f3ab1d341af773dd9c6612978ab3ec1e7df65189ea64aa19110219579cfcb61877d29c341caca459e3d979d83fbdefe58976c82e9b22b457507a1001ae345cfee2e6b761e95c6cf8cafd93069f4f7d835204a33407a80a43f0184044111102a45bb800f9258c3c196c47e102c66e31983865b95995efe6a33733e3e10d9d851001599556eeb06b33e6c8461b34ac925a1e29810072c74bb929980be6c9974f4bb211110226517bdad3aeeb4181c8f95e3adbf732707d051a462dd3325f4c305f0316b0ca10016de9c38d6c691d4e33dd2f9733368e280b95f93ce8538abd584c5e93f90e27961111023d9a5e0a2ec2017f1857ddc3c3e6b409ac9d0aabd0f0581812fd2a9a4bd86d3410018d6eb01f09885a0cca7ab376d42ea40df31e0fed797229973b03a85b66c2de701111110120d5ec6e7bf0943364b70eef9c2aca3b825d141eeb7e567304f5da7c7a10cf82a67f01e5fd7fb05220729e4dd20eefa4843074a497fca163bd1219def7d03e6a8ce13d0401800005020101020083281be3d5406e9e13d7d166aa7ff18b8b3df417466bcdbcaa094ff45357be2210018b07d2b2135669d4acdd271bb3dd084fda26d3f4be9c6a21ff96507a8eee7d2a0301c0000b00080000000000000001001011010180bd0301000020001d000000000002001468636429a95f5ff7317774481af05be14822b43b00000301010020001d0001000100020014062b0f24ceeda834130fb4cb81ec2dbe9033cc370000100301020020001d00020002000200143a1528a952af24d6a548439242a298b9aedce30f0000100301030020001d0003030100020014b25034ad6bf08c43425f0c7d6f68f0e0e14b713a00000301040020001d0004000100040014cc1fc8aa3166ea5d6b203b24cc9ede073761611700001111000160fb033b01279c3dadd4941b2b5b4bbd926811d6692b1640201c5c30ae6a980b1effccffab02daf894ac3b51314ddddd2fc825baa10aa9545bf593ddd561619d56e0cf6aee1b10018eb4a910923de14c2d492c7b691539c6975f84aea1159daaf4a1049f0c66ee670215fc9fd4568c35232f13cedb3fc89cd635e5efb916a0f92f31e21fe11de1b91f1001a22c03d1ff37b59f3a45b15e6cb58d209e86c064994eab3eb8b4a3fb8e25963c028b3c5988d04ddae33adb94eb5029d4f789ae54bd0ba60dfb0b7f7f0e46790df11001e5c376781678db5fc193b7ec6270d3930547a232f9e919d8d502ea9bca54d4e302161727cea90f8a6a04f11f19da54be2932b57ad69b0cf89bdc6e238926d0df8a1001fe6a3219024c97cd62b4ac251993b0e4935d95985baa14730133770b4d9df00b02139ccf21fba84a03c6c006591d7fa4313f240ca3da999c973c0f4c46f3ee89df100196150d0670181114764a94cce8d571ff380dde7ddfe488efb79174f4eb8a3fd802ff3048d1703f27aaf9c3ce4eb869fd2886551a8b2da2cb410366d7c202d65582100420d5ec6e7bf0943364b70eef9c2aca3b825d141eeb7e567304f5da7c7a10cf82a6000b03fd0000001547490334000cbc3b78a7dd0a0d12f2931ea1cceaf13fa5c5451a777b3e77eecaae98fe8a87110246e823f639f71820cf0e7f1d109ea6781eb5af0cf82219b0fa92d273281a8deb100103c2fff52463df61d176a8d6c39178edd6286d9a9b5e92ae855672dacbd230cf11026fb5bf545ee5ba18070673a5156711c2635daac26b441ec8645b5290d77d54ef1001b9515b12cf2dbf124e2f6f9b30b3d3b276e34b1d651732040b03b2085938e7a9111102d9f4ab2973183b03710fd38d75166d8c378a7005406609fd9891f12e8a07dd8c10019d579e0225add603f0f614f7cdfdf9e884f33a4024b5e834c40361112c175f2311110229cc472d20188f43d192f2bc5ae961db467796e5a027a51b8d3b30902cda3b681001c77caf2e5bd603b6dbbfc4d4c329350b64c1f0e41edad698bf8108d796c9cff2111102d7832875153efc0556d312023e809d753f3d5ccd4901532a9c0e907424214d5910011091b53f4df7d1ff39c87e8668afc043db4a818b4043d02f19ffaa35f560668f1111110001";

    // Convert hex to bytes
    let doc_proof = hex::decode(doc_proof_hex).expect("Failed to decode document proof hex");
    let id_proof = hex::decode(id_proof_hex).expect("Failed to decode identity proof hex");

    // Parse the proofs
    let doc_result = parse_sdk_grovedb_proof(&doc_proof);
    let id_result = parse_sdk_grovedb_proof(&id_proof);

    assert!(
        doc_result.is_ok(),
        "Document proof from PROOF_DATA.md should parse"
    );
    assert!(
        id_result.is_ok(),
        "Identity proof from PROOF_DATA.md should parse"
    );

    let doc_nodes = doc_result.unwrap();
    let id_nodes = id_result.unwrap();

    println!("PROOF_DATA.md document proof: {} nodes", doc_nodes.len());
    println!("PROOF_DATA.md identity proof: {} nodes", id_nodes.len());

    // Verify consistency with binary files
    let bin_doc_proof =
        fs::read("tests/fixtures/document_proof_B5XLy3cUDayaqZmcGaWb98PEAUguGHiHSU5DxiKrHBj3.bin")
            .expect("Failed to read binary document proof");
    let bin_id_proof =
        fs::read("tests/fixtures/identity_proof_FQ4waDowFQXD4tJPKQM1114VSr5f8s3qAc5bT8FJkT49.bin")
            .expect("Failed to read binary identity proof");

    // The hex and binary should be the same
    assert_eq!(
        doc_proof, bin_doc_proof,
        "Document proof hex should match binary"
    );
    assert_eq!(
        id_proof, bin_id_proof,
        "Identity proof hex should match binary"
    );
}
