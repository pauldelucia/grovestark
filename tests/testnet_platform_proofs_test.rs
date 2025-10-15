//! Test the platform proofs implementation with real testnet data

use grovestark::create_witness_from_platform_proofs;

#[test]
fn test_with_real_testnet_data() {
    // Real testnet data from REQUESTED_DATA.md

    // 1. Real document JSON
    let document_json = r#"{
        "$version": "0",
        "$id": "B5XLy3cUDayaqZmcGaWb98PEAUguGHiHSU5DxiKrHBj3",
        "$ownerId": "FQ4waDowFQXD4tJPKQM1114VSr5f8s3qAc5bT8FJkT49",
        "saltedDomainHash": "DatikyjRKcaaSMVNLOWdILAOxy/QoOmpSt/0lZ5MNb8=",
        "$revision": 1,
        "$createdAt": null,
        "$updatedAt": null,
        "$transferredAt": null,
        "$createdAtBlockHeight": null,
        "$updatedAtBlockHeight": null,
        "$transferredAtBlockHeight": null,
        "$createdAtCoreBlockHeight": null,
        "$updatedAtCoreBlockHeight": null,
        "$transferredAtCoreBlockHeight": null
    }"#
    .as_bytes()
    .to_vec();

    // 2. Document proof (hex to bytes)
    let document_proof_hex = "008d01dcf2f33ef7072d1ac4a46d8e8acc5e622fc79a1277c155e402f50db5c327ebe604014000240201205bb4077299c35f3d25823bac24779abe40e3e0ff4d76104b5b6a074687142a48005d12647e814c7ed634ef7f7847198b281c8925de13c5214cdf616a37472ce2251001e4f41522d0b50cd9e7ae9f953dfef625ca9e0e274cd1d446462ed0e59253eed411010140fb02f101cc619123cf0e3c8ae376b3844b2c961e943102c4998a3f2b436d0ed9d69be69602f5a40b154096932fa4f0f0a0058553d8e34dadbb5536d789ab8d8da8be8fffc31001d9bd3d9b1670c9b266a3a3fea9ffe9d10cb4d2c13a552900ad9b8b12c7777c6d029803e1502880e8f3ab53c50f5ab52ee90fd38a10e7b080cf2e6d4fefed33834e100139ead1d1024e8080cac114638c0491abb119ac159c41f3abf023d10c29f09a100252204ccb995f0e6c24d8612e36708ac88a3f48fede4e96038ff8b07a27c691b11001acec11674f9c0b293428d13390828a0c51fc471ba60bb4acdeb5898b8d9f95d2024a7f6dc97589d4cf25d03e567736185ffb40acad77b53eae7f9b80d48efaf1ff100113cdb903028bbfd2f94e82ef3785c97cf862066428069754a75d4f3c2fb5794c02407df2bc4db091b2800a9c3d65930c689b5d4ad50b118c8ec8d609d17dc56ca710019303bb70e1b340c27fca57eb31d93314834bb3930f17b0f2d51e129e108f316802741b3792a0b8520e1e12ab2958d6ae2a9e12ee434ea9530fe2833c622249d42e1001f49ac9c35ea0ad28cac9f6535df8fab222030c3b6d5f08a965c2ab60d0b67b0f02f3887c540e229b76c180fbc1ae7f296cad7b140637db69fd0939d65b3fd94c3b100420a083bdbcf10c79e6bed7156a44756538f7e5ac32129b9376b65f179d4bf5cca400050201010100b8eae9e40fe8ec4f54b9965daea6c3c0c0dfd1947a068501a95ba19b5b8d8cad1102eeceda9a9815d52ea78e43a46a7fe305097183e30303b30186cbba043fec4cad100153b9686cc4f645a4ffd7622a6d6543a5a6b6c92912c253fdd5556fe47f6d6ca6110292aee347b15048664148151d81268bc567f0d1767bf99ca309525ccf8228b28d1001919400e706cb2e384cb050465f79adafe8216616d709c23235b0691c7dbf1a20111111111111029fb3688df9d92705bcbe036fda4f7153ae1f0b1a5629a9f4458b15b44389038010018d2e360ac530f4f93a6c79f26178ecefca7b498b9026be1e118a78cba88689fc11110120a083bdbcf10c79e6bed7156a44756538f7e5ac32129b9376b65f179d4bf5cca44f01851f7314176b1a06e514e3dd67609a5f6524e7a7ad55c80974f2c8583ecfef5a0401010008020104626c6f62000664a1a5db66b1a8fb0a2e40c084c19a51bf415c34fc5fb84cac7a1b7497d7e1100101013c0404626c6f62001402011073616c746564446f6d61696e4861736800c948211b44e64cf202bc02d21aeb383f126dc27ef54c1f411e9d0075a0048bc20104626c6f626b040100002402012095bd80bab08b470c5ab26d51c48113b64e1a85d8a0a710e02fd343b51d559e7e00ca4a1caf04fd6d86a857219f8ea65409c866301ebddc215964158b71974282ed021d6572ecc9d0bf3c14b46cbae0424920aed54d312f91631bcd4cd07202ccdd1210010100af032095bd80bab08b470c5ab26d51c48113b64e1a85d8a0a710e02fd343b51d559e7e008b00640195bd80bab08b470c5ab26d51c48113b64e1a85d8a0a710e02fd343b51d559e7ed5ec6e7bf0943364b70eef9c2aca3b825d141eeb7e567304f5da7c7a10cf82a60100000dab629328d129c69a48c54d2ce59d20b00ec72fd0a0e9a94adff4959e4c35bf012302d5ec6e7bf0943364b70eef9c2aca3b825d141eeb7e567304f5da7c7a10cf82a6250f0001";
    let document_proof = hex::decode(document_proof_hex).expect("Invalid document proof hex");

    // 3. Key proof (hex to bytes)
    let key_proof_hex = "00d1014ece8c422e514a0066481e09418787fc3ebdddbad302e46c5613fa5bdc3d864604012000240201207dec59e08c02ff8b954769c3cb9d5a74f6eb0e2c8cd5a056fba4c47f1e5f545a00e0a3585c9acebdc745fc44776ffcf7d5721c19f4860215aa6b986a5e54950f98100100568778d2201d74bae20dee2268f516590b4ce5080667e5bb46bede39d6b04a11025e11937dd54672cebf0de7a16b20308d969bd9cf311e1f982cc82e6b72222a121001e4f41522d0b50cd9e7ae9f953dfef625ca9e0e274cd1d446462ed0e59253eed411010120fb03390143e398f02aa1303a4f3cf2f6b5c0966f9f1c7d1da22e8a356d5881a31a4a3c13020e703c94077502209bfed96e14b7a98f554929c572d8db2d805d9b4d0c1159d610016bf1057f90f8f032dc1f08f10624c137d98760da1045ba190cbf56b365e6bb36021c126c2cf2765ff9b2e464d8207a6645520ef7767ed3e5ad4f6a242fe38783f41001053933e015ad073ee1057c525fbec0066fd500d6afe8ce0ae46467a2e4260df10242397635b3d9c7ddef9573ee5ab57e0ee22b232db64c35241d2b263ca442fcaf1001bd78aab052cfd8261558a30f7c3efbe3f8802d2bef7989be46b0429ac476ae850256800e5fb18f97fff2ae609a233ae9708a589a110d04a32aed9562e7aaa8e61a10013eb3a5a0486c47298394ec0f801b7a66568bf282be12fc68ed4f06e10f39799d02193df0f3a24175bb6fb2e6debc04abb592d5e91501ed1f3a6ac77e6052cd57371001454de82a63bb7297f47fc270c2866fc7bb9173a8ac258ed55df4c67b84f9e9d00294a11e5a6ec8724ef5dae4135668761311443e08c3aadfe246583f9786b1c93c100420d5ec6e7bf0943364b70eef9c2aca3b825d141eeb7e567304f5da7c7a10cf82a60009020101800103002498c39bf5a0c64efa93d2302524debccfdbc10b8d4f06eb597327c7f13c4d81175f1102de1073918de028645a98b6ea2c6094c8499d2c3ede3c056d7e10d41667876e7e10015da7d692a2792131f3ab1d341af773dd9c6612978ab3ec1e7df65189ea64aa19110219579cfcb61877d29c341caca459e3d979d83fbdefe58976c82e9b22b457507a1001ae345cfee2e6b761e95c6cf8cafd93069f4f7d835204a33407a80a43f0184044111102a45bb800f9258c3c196c47e102c66e31983865b95995efe6a33733e3e10d9d851001599556eeb06b33e6c8461b34ac925a1e29810072c74bb929980be6c9974f4bb211110226517bdad3aeeb4181c8f95e3adbf732707d051a462dd3325f4c305f0316b0ca10016de9c38d6c691d4e33dd2f9733368e280b95f93ce8538abd584c5e93f90e27961111023d9a5e0a2ec2017f1857ddc3c3e6b409ac9d0aabd0f0581812fd2a9a4bd86d3410018d6eb01f09885a0cca7ab376d42ea40df31e0fed797229973b03a85b66c2de701111110120d5ec6e7bf0943364b70eef9c2aca3b825d141eeb7e567304f5da7c7a10cf82a66e0192ce14e75e0dcc6165ce82ad0037707b236d985b062681b163f4327d72744ced0401800005020101020083281be3d5406e9e13d7d166aa7ff18b8b3df417466bcdbcaa094ff45357be221001326ca291e394c522834208422432f3690ae5843e619c95ee432dc27dcd3a2109110101808b0180f291d1a36c82228ce18bfac612f67369b5abb07ae624eec11521bf2060744002f0a15509af452034de1e5d8fc5a3ca387235ffd6116ab39ac7dc13993f8afef11002be1e393bc062f7b668d4b11ad797d4d5da4a212107b940666e9aac975dfe7a600301040020001d0004000100040014cc1fc8aa3166ea5d6b203b24cc9ede0737616117000011110001";
    let key_proof = hex::decode(key_proof_hex).expect("Invalid key proof hex");

    // 4. EdDSA signature components
    let signature_r_hex = "dbb76975d7a20eead1884b434bf699a729cd35815c2c84a48fea66e12b2ab323";
    let signature_s_hex = "d99553f7a4bdb47c8161691a767eb511bed436e99a690331e8a384d96ecb7d08";
    let public_key_hex = "13f54fc83ab3112dc6e47a46822d0a6cdb0ec8bd496333d4d03527c198680928";
    let message_hex = "d43e625b43a2ceeae3bb3fc7119946fef628501b092ee2379aef649f55416e82";
    let private_key_hex = "6e6f24b6f7a51203e1cbee0c30066a18901b1d5e13f7ffc69017d28228c78f3f";

    let signature_r_bytes = hex::decode(signature_r_hex).expect("Invalid signature R hex");
    let signature_s_bytes = hex::decode(signature_s_hex).expect("Invalid signature S hex");
    let public_key_bytes = hex::decode(public_key_hex).expect("Invalid public key hex");
    let message_bytes = hex::decode(message_hex).expect("Invalid message hex");
    let private_key_bytes = hex::decode(private_key_hex).expect("Invalid private key hex");

    let mut signature_r = [0u8; 32];
    let mut signature_s = [0u8; 32];
    let mut public_key = [0u8; 32];
    let mut private_key = [0u8; 32];

    signature_r.copy_from_slice(&signature_r_bytes);
    signature_s.copy_from_slice(&signature_s_bytes);
    public_key.copy_from_slice(&public_key_bytes);
    private_key.copy_from_slice(&private_key_bytes);

    // 5. Expected values
    let expected_owner_id_hex = "d5ec6e7bf0943364b70eef9c2aca3b825d141eeb7e567304f5da7c7a10cf82a6";
    let expected_identity_id_hex =
        "d5ec6e7bf0943364b70eef9c2aca3b825d141eeb7e567304f5da7c7a10cf82a6";

    // Create witness using the platform proofs function
    let result = create_witness_from_platform_proofs(
        &document_proof,
        &key_proof,
        document_json,
        &public_key,
        &signature_r,
        &signature_s,
        &message_bytes,
        &private_key,
    );

    match result {
        Ok(witness) => {
            // Verify owner_id matches expected
            let owner_id_hex = hex::encode(&witness.owner_id);
            assert_eq!(
                owner_id_hex, expected_owner_id_hex,
                "Owner ID mismatch: got {}, expected {}",
                owner_id_hex, expected_owner_id_hex
            );

            // Verify identity_id matches expected
            let identity_id_hex = hex::encode(&witness.identity_id);
            assert_eq!(
                identity_id_hex, expected_identity_id_hex,
                "Identity ID mismatch: got {}, expected {}",
                identity_id_hex, expected_identity_id_hex
            );

            // Verify owner_id == identity_id (critical security check)
            assert_eq!(
                witness.owner_id, witness.identity_id,
                "Owner ID must match Identity ID for valid proof"
            );

            println!("✅ Real testnet data test passed!");
            println!("  Owner ID: {}", owner_id_hex);
            println!("  Identity ID: {}", identity_id_hex);
            println!(
                "  Document paths: {} + {} nodes",
                witness.owner_id_leaf_to_doc_path.len(),
                witness.docroot_to_state_path.len()
            );
            println!(
                "  Key paths: {} + {} nodes",
                witness.key_leaf_to_keysroot_path.len(),
                witness.identity_leaf_to_state_path.len()
            );
        }
        Err(e) => {
            panic!("Failed to create witness from real testnet data: {}", e);
        }
    }
}
