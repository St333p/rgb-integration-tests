pub mod utils;

use utils::*;

type TT = TransferType;
type DT = DescriptorType;
type AS = AssetSchema;

#[rstest]
// blinded: nia - nia
#[case(TT::Blinded, DT::Wpkh, DT::Wpkh, AS::Nia, AS::Nia)]
#[case(TT::Blinded, DT::Wpkh, DT::Tr, AS::Nia, AS::Nia)]
#[case(TT::Blinded, DT::Tr, DT::Wpkh, AS::Nia, AS::Nia)]
#[case(TT::Blinded, DT::Tr, DT::Tr, AS::Nia, AS::Nia)]
// blinded: nia - cfa
#[case(TT::Blinded, DT::Wpkh, DT::Wpkh, AS::Nia, AS::Cfa)]
#[case(TT::Blinded, DT::Wpkh, DT::Tr, AS::Nia, AS::Cfa)]
#[case(TT::Blinded, DT::Tr, DT::Wpkh, AS::Nia, AS::Cfa)]
#[case(TT::Blinded, DT::Tr, DT::Tr, AS::Nia, AS::Cfa)]
// blinded: nia - uda
#[case(TT::Blinded, DT::Wpkh, DT::Wpkh, AS::Nia, AS::Uda)]
#[case(TT::Blinded, DT::Wpkh, DT::Tr, AS::Nia, AS::Uda)]
#[case(TT::Blinded, DT::Tr, DT::Wpkh, AS::Nia, AS::Uda)]
#[case(TT::Blinded, DT::Tr, DT::Tr, AS::Nia, AS::Uda)]
// blinded: cfa - cfa
#[case(TT::Blinded, DT::Wpkh, DT::Wpkh, AS::Cfa, AS::Cfa)]
#[case(TT::Blinded, DT::Wpkh, DT::Tr, AS::Cfa, AS::Cfa)]
#[case(TT::Blinded, DT::Tr, DT::Wpkh, AS::Cfa, AS::Cfa)]
#[case(TT::Blinded, DT::Tr, DT::Tr, AS::Cfa, AS::Cfa)]
// blinded: cfa - nia
#[case(TT::Blinded, DT::Wpkh, DT::Wpkh, AS::Cfa, AS::Nia)]
#[case(TT::Blinded, DT::Wpkh, DT::Tr, AS::Cfa, AS::Nia)]
#[case(TT::Blinded, DT::Tr, DT::Wpkh, AS::Cfa, AS::Nia)]
#[case(TT::Blinded, DT::Tr, DT::Tr, AS::Cfa, AS::Nia)]
// blinded: cfa - uda
#[case(TT::Blinded, DT::Wpkh, DT::Wpkh, AS::Cfa, AS::Uda)]
#[case(TT::Blinded, DT::Wpkh, DT::Tr, AS::Cfa, AS::Uda)]
#[case(TT::Blinded, DT::Tr, DT::Wpkh, AS::Cfa, AS::Uda)]
#[case(TT::Blinded, DT::Tr, DT::Tr, AS::Cfa, AS::Uda)]
// blinded: uda - uda
#[case(TT::Blinded, DT::Wpkh, DT::Wpkh, AS::Uda, AS::Uda)]
#[case(TT::Blinded, DT::Wpkh, DT::Tr, AS::Uda, AS::Uda)]
#[case(TT::Blinded, DT::Tr, DT::Wpkh, AS::Uda, AS::Uda)]
#[case(TT::Blinded, DT::Tr, DT::Tr, AS::Uda, AS::Uda)]
// blinded: uda - nia
#[case(TT::Blinded, DT::Wpkh, DT::Wpkh, AS::Uda, AS::Nia)]
#[case(TT::Blinded, DT::Wpkh, DT::Tr, AS::Uda, AS::Nia)]
#[case(TT::Blinded, DT::Tr, DT::Wpkh, AS::Uda, AS::Nia)]
#[case(TT::Blinded, DT::Tr, DT::Tr, AS::Uda, AS::Nia)]
// blinded: uda - cfa
#[case(TT::Blinded, DT::Wpkh, DT::Wpkh, AS::Uda, AS::Cfa)]
#[case(TT::Blinded, DT::Wpkh, DT::Tr, AS::Uda, AS::Cfa)]
#[case(TT::Blinded, DT::Tr, DT::Wpkh, AS::Uda, AS::Cfa)]
#[case(TT::Blinded, DT::Tr, DT::Tr, AS::Uda, AS::Cfa)]
// witness: nia - nia
#[case(TT::Witness, DT::Wpkh, DT::Wpkh, AS::Nia, AS::Nia)]
#[case(TT::Witness, DT::Wpkh, DT::Tr, AS::Nia, AS::Nia)]
#[case(TT::Witness, DT::Tr, DT::Wpkh, AS::Nia, AS::Nia)]
#[case(TT::Witness, DT::Tr, DT::Tr, AS::Nia, AS::Nia)]
// witness: nia - cfa
#[case(TT::Witness, DT::Wpkh, DT::Wpkh, AS::Nia, AS::Cfa)]
#[case(TT::Witness, DT::Wpkh, DT::Tr, AS::Nia, AS::Cfa)]
#[case(TT::Witness, DT::Tr, DT::Wpkh, AS::Nia, AS::Cfa)]
#[case(TT::Witness, DT::Tr, DT::Tr, AS::Nia, AS::Cfa)]
// witness: nia - uda
#[case(TT::Witness, DT::Wpkh, DT::Wpkh, AS::Nia, AS::Uda)]
#[case(TT::Witness, DT::Wpkh, DT::Tr, AS::Nia, AS::Uda)]
#[case(TT::Witness, DT::Tr, DT::Wpkh, AS::Nia, AS::Uda)]
#[case(TT::Witness, DT::Tr, DT::Tr, AS::Nia, AS::Uda)]
// witness: cfa - cfa
#[case(TT::Witness, DT::Wpkh, DT::Wpkh, AS::Cfa, AS::Cfa)]
#[case(TT::Witness, DT::Wpkh, DT::Tr, AS::Cfa, AS::Cfa)]
#[case(TT::Witness, DT::Tr, DT::Wpkh, AS::Cfa, AS::Cfa)]
#[case(TT::Witness, DT::Tr, DT::Tr, AS::Cfa, AS::Cfa)]
// witness: cfa - nia
#[case(TT::Witness, DT::Wpkh, DT::Wpkh, AS::Cfa, AS::Nia)]
#[case(TT::Witness, DT::Wpkh, DT::Tr, AS::Cfa, AS::Nia)]
#[case(TT::Witness, DT::Tr, DT::Wpkh, AS::Cfa, AS::Nia)]
#[case(TT::Witness, DT::Tr, DT::Tr, AS::Cfa, AS::Nia)]
// witness: cfa - uda
#[case(TT::Witness, DT::Wpkh, DT::Wpkh, AS::Cfa, AS::Uda)]
#[case(TT::Witness, DT::Wpkh, DT::Tr, AS::Cfa, AS::Uda)]
#[case(TT::Witness, DT::Tr, DT::Wpkh, AS::Cfa, AS::Uda)]
#[case(TT::Witness, DT::Tr, DT::Tr, AS::Cfa, AS::Uda)]
// witness: uda - uda
#[case(TT::Witness, DT::Wpkh, DT::Wpkh, AS::Uda, AS::Uda)]
#[case(TT::Witness, DT::Wpkh, DT::Tr, AS::Uda, AS::Uda)]
#[case(TT::Witness, DT::Tr, DT::Wpkh, AS::Uda, AS::Uda)]
#[case(TT::Witness, DT::Tr, DT::Tr, AS::Uda, AS::Uda)]
// witness: uda - nia
#[case(TT::Witness, DT::Wpkh, DT::Wpkh, AS::Uda, AS::Nia)]
#[case(TT::Witness, DT::Wpkh, DT::Tr, AS::Uda, AS::Nia)]
#[case(TT::Witness, DT::Tr, DT::Wpkh, AS::Uda, AS::Nia)]
#[case(TT::Witness, DT::Tr, DT::Tr, AS::Uda, AS::Nia)]
// witness: uda - cfa
#[case(TT::Witness, DT::Wpkh, DT::Wpkh, AS::Uda, AS::Cfa)]
#[case(TT::Witness, DT::Wpkh, DT::Tr, AS::Uda, AS::Cfa)]
#[case(TT::Witness, DT::Tr, DT::Wpkh, AS::Uda, AS::Cfa)]
#[case(TT::Witness, DT::Tr, DT::Tr, AS::Uda, AS::Cfa)]
fn transfer_loop(
    #[case] transfer_type: TransferType,
    #[case] wlt_1_desc: DescriptorType,
    #[case] wlt_2_desc: DescriptorType,
    #[case] asset_schema_1: AssetSchema,
    #[case] asset_schema_2: AssetSchema,
) {
    println!(
        "transfer_type {transfer_type:?} wlt_1_desc {wlt_1_desc:?} wlt_2_desc {wlt_2_desc:?} \
        asset_schema_1 {asset_schema_1:?} asset_schema_2 {asset_schema_2:?}"
    );

    initialize();

    let mut wlt_1 = get_wallet(&wlt_1_desc);
    let mut wlt_2 = get_wallet(&wlt_2_desc);

    let issued_supply_1 = 999;
    let issued_supply_2 = 666;

    let mut sats = 9000;

    // wlt_1 issues 2 assets on the same UTXO
    let utxo = wlt_1.get_utxo(None);
    let (contract_id_1, iface_type_name_1) = match asset_schema_1 {
        AssetSchema::Nia => wlt_1.issue_nia(issued_supply_1, wlt_1.close_method(), Some(&utxo)),
        AssetSchema::Uda => wlt_1.issue_uda(wlt_1.close_method(), Some(&utxo)),
        AssetSchema::Cfa => wlt_1.issue_cfa(issued_supply_1, wlt_1.close_method(), Some(&utxo)),
    };
    let (contract_id_2, iface_type_name_2) = match asset_schema_2 {
        AssetSchema::Nia => wlt_1.issue_nia(issued_supply_2, wlt_1.close_method(), Some(&utxo)),
        AssetSchema::Uda => wlt_1.issue_uda(wlt_1.close_method(), Some(&utxo)),
        AssetSchema::Cfa => wlt_1.issue_cfa(issued_supply_2, wlt_1.close_method(), Some(&utxo)),
    };
    wlt_1.check_allocations(
        contract_id_1,
        &iface_type_name_1,
        asset_schema_1,
        vec![issued_supply_1],
        true,
    );
    wlt_1.check_allocations(
        contract_id_2,
        &iface_type_name_2,
        asset_schema_2,
        vec![issued_supply_2],
        true,
    );

    // wlt_1 spends asset 1, moving the other with a blank transition
    let amount_1 = if asset_schema_1 == AssetSchema::Uda {
        1
    } else {
        99
    };
    wlt_1.send(
        &mut wlt_2,
        transfer_type,
        contract_id_1,
        &iface_type_name_1,
        amount_1,
        sats,
    );
    wlt_1.check_allocations(
        contract_id_1,
        &iface_type_name_1,
        asset_schema_1,
        vec![issued_supply_1 - amount_1],
        false,
    );
    wlt_1.check_allocations(
        contract_id_2,
        &iface_type_name_2,
        asset_schema_2,
        vec![issued_supply_2],
        true,
    );
    wlt_2.check_allocations(
        contract_id_1,
        &iface_type_name_1,
        asset_schema_1,
        vec![amount_1],
        true,
    );

    // wlt_1 spends asset 1 change (only if possible)
    let amount_2 = 33;
    if asset_schema_1 != AssetSchema::Uda {
        wlt_1.send(
            &mut wlt_2,
            transfer_type,
            contract_id_1,
            &iface_type_name_1,
            amount_2,
            sats,
        );
        wlt_1.check_allocations(
            contract_id_1,
            &iface_type_name_1,
            asset_schema_1,
            vec![issued_supply_1 - amount_1 - amount_2],
            false,
        );
        wlt_1.check_allocations(
            contract_id_2,
            &iface_type_name_2,
            asset_schema_2,
            vec![issued_supply_2],
            true,
        );
        wlt_2.check_allocations(
            contract_id_1,
            &iface_type_name_1,
            asset_schema_1,
            vec![amount_1, amount_2],
            true,
        );
    }

    // wlt_1 spends asset 2
    let amount_3 = if asset_schema_2 == AssetSchema::Uda {
        1
    } else {
        22
    };
    wlt_1.send(
        &mut wlt_2,
        transfer_type,
        contract_id_2,
        &iface_type_name_2,
        amount_3,
        sats,
    );
    wlt_1.check_allocations(
        contract_id_1,
        &iface_type_name_1,
        asset_schema_1,
        vec![issued_supply_1 - amount_1 - amount_2],
        false,
    );
    wlt_1.check_allocations(
        contract_id_2,
        &iface_type_name_2,
        asset_schema_2,
        vec![issued_supply_2 - amount_3],
        false,
    );
    wlt_2.check_allocations(
        contract_id_1,
        &iface_type_name_1,
        asset_schema_1,
        vec![amount_1, amount_2],
        true,
    );
    wlt_2.check_allocations(
        contract_id_2,
        &iface_type_name_2,
        asset_schema_2,
        vec![amount_3],
        true,
    );

    // wlt_2 spends received allocation(s) of asset 1
    let amount_4 = if asset_schema_1 == AssetSchema::Uda {
        1
    } else {
        111
    };
    sats -= 1000;
    wlt_2.send(
        &mut wlt_1,
        transfer_type,
        contract_id_1,
        &iface_type_name_1,
        amount_4,
        sats,
    );
    wlt_1.check_allocations(
        contract_id_1,
        &iface_type_name_1,
        asset_schema_1,
        vec![issued_supply_1 - amount_1 - amount_2, amount_4],
        true,
    );
    wlt_1.check_allocations(
        contract_id_2,
        &iface_type_name_2,
        asset_schema_2,
        vec![issued_supply_2 - amount_3],
        false,
    );
    wlt_2.check_allocations(
        contract_id_1,
        &iface_type_name_1,
        asset_schema_1,
        vec![amount_1 + amount_2 - amount_4],
        false,
    );
    wlt_2.check_allocations(
        contract_id_2,
        &iface_type_name_2,
        asset_schema_2,
        vec![amount_3],
        true,
    );

    // wlt_2 spends asset 2
    let amount_5 = if asset_schema_2 == AssetSchema::Uda {
        1
    } else {
        11
    };
    sats -= 1000;
    wlt_2.send(
        &mut wlt_1,
        transfer_type,
        contract_id_2,
        &iface_type_name_2,
        amount_5,
        sats,
    );
    wlt_1.check_allocations(
        contract_id_1,
        &iface_type_name_1,
        asset_schema_1,
        vec![issued_supply_1 - amount_1 - amount_2, amount_4],
        true,
    );
    wlt_1.check_allocations(
        contract_id_2,
        &iface_type_name_2,
        asset_schema_2,
        vec![issued_supply_2 - amount_3, amount_5],
        true,
    );
    wlt_2.check_allocations(
        contract_id_1,
        &iface_type_name_1,
        asset_schema_1,
        vec![amount_1 + amount_2 - amount_4],
        false,
    );
    wlt_2.check_allocations(
        contract_id_2,
        &iface_type_name_2,
        asset_schema_2,
        vec![amount_3 - amount_5],
        false,
    );

    // wlt_1 spends asset 1, received back
    let amount_6 = if asset_schema_1 == AssetSchema::Uda {
        1
    } else {
        issued_supply_1 - amount_1 - amount_2 + amount_4
    };
    sats -= 1000;
    wlt_1.send(
        &mut wlt_2,
        transfer_type,
        contract_id_1,
        &iface_type_name_1,
        amount_6,
        sats,
    );
    wlt_1.check_allocations(
        contract_id_1,
        &iface_type_name_1,
        asset_schema_1,
        vec![],
        false,
    );
    wlt_1.check_allocations(
        contract_id_2,
        &iface_type_name_2,
        asset_schema_2,
        vec![issued_supply_2 - amount_3, amount_5],
        true,
    );
    wlt_2.check_allocations(
        contract_id_1,
        &iface_type_name_1,
        asset_schema_1,
        vec![amount_1 + amount_2 - amount_4, amount_6],
        true,
    );
    wlt_2.check_allocations(
        contract_id_2,
        &iface_type_name_2,
        asset_schema_2,
        vec![amount_3 - amount_5],
        false,
    );

    // wlt_1 spends asset 2, received back
    let amount_7 = if asset_schema_2 == AssetSchema::Uda {
        1
    } else {
        issued_supply_2 - amount_3 + amount_5
    };
    sats -= 1000;
    wlt_1.send(
        &mut wlt_2,
        transfer_type,
        contract_id_2,
        &iface_type_name_2,
        amount_7,
        sats,
    );
    wlt_1.check_allocations(
        contract_id_1,
        &iface_type_name_1,
        asset_schema_1,
        vec![],
        false,
    );
    wlt_1.check_allocations(
        contract_id_2,
        &iface_type_name_2,
        asset_schema_2,
        vec![],
        false,
    );
    wlt_2.check_allocations(
        contract_id_1,
        &iface_type_name_1,
        asset_schema_1,
        vec![amount_1 + amount_2 - amount_4, amount_6],
        true,
    );
    wlt_2.check_allocations(
        contract_id_2,
        &iface_type_name_2,
        asset_schema_2,
        vec![amount_3 - amount_5, amount_7],
        true,
    );
}

#[test]
fn same_transfer_twice() {
    initialize();

    let mut wlt_1 = get_wallet(&DescriptorType::Wpkh);
    let mut wlt_2 = get_wallet(&DescriptorType::Wpkh);

    let amount = 600;

    let (contract_id, iface_type_name) = wlt_1.issue_nia(amount, wlt_1.close_method(), None);

    stop_mining();
    let initial_height = get_height();

    let invoice = wlt_2.invoice(
        contract_id,
        &iface_type_name,
        amount,
        wlt_2.close_method(),
        InvoiceType::Witness,
    );
    let _ = wlt_1.transfer(invoice.clone(), None, Some(500));

    // retry with higher fees, TX hasn't been mined
    let mid_height = get_height();
    assert_eq!(initial_height, mid_height);

    let _ = wlt_1.transfer(invoice, None, Some(1000));

    let final_height = get_height();
    assert_eq!(initial_height, final_height);
    resume_mining();
}

#[test]
fn ln_htlc_transfer() {
    initialize();

    let mut wlt_1 = get_wallet(&DescriptorType::Wpkh);
    let mut wlt_2 = get_wallet(&DescriptorType::Wpkh);

    let utxo = wlt_1.get_utxo(Some(10_000));
    let (contract_id, iface_type_name) = wlt_1.issue_nia(600, wlt_1.close_method(), Some(&utxo));

    let htlc_vout = 2;
    let htlc_rgb_amt = 200;
    let htlc_btc_amt = 4000;
    let htlc_derived_addr = wlt_1.get_derived_address();

    println!("constructing fake commitment TX");
    let beneficiaries = vec![
        (wlt_2.get_address(), Some(2000)),
        (wlt_1.get_address(), None),
        (htlc_derived_addr.addr, Some(htlc_btc_amt)),
    ];
    let (mut psbt, _meta) = wlt_1.construct_psbt(vec![utxo], beneficiaries, None);

    println!("coloring fake commitment TX");
    let coloring_info = ColoringInfo {
        asset_info_map: HashMap::from([(
            contract_id,
            AssetColoringInfo {
                iface: iface_type_name.clone(),
                input_outpoints: vec![utxo],
                output_map: HashMap::from([(0, 100), (1, 300), (htlc_vout, htlc_rgb_amt)]),
                static_blinding: Some(666),
            },
        )]),
        static_blinding: Some(666),
    };
    let (fascia, _asset_beneficiaries) = wlt_1.color_psbt(&mut psbt, coloring_info);

    println!("constructing fake HTLC TX");
    let witness_id = fascia.witness_id();
    let txid = witness_id.as_reduced_unsafe();
    let input_outpoint = Outpoint::new(*txid, htlc_vout);
    let beneficiaries = vec![(wlt_1.get_address(), None)];
    let (mut psbt, _meta) = wlt_1.construct_psbt_offchain(
        vec![(input_outpoint, htlc_btc_amt, htlc_derived_addr.terminal)],
        beneficiaries,
        None,
    );

    println!("coloring fake HTLC TX");
    let coloring_info = ColoringInfo {
        asset_info_map: HashMap::from([(
            contract_id,
            AssetColoringInfo {
                iface: iface_type_name,
                input_outpoints: vec![input_outpoint],
                output_map: HashMap::from([(0, htlc_rgb_amt)]),
                static_blinding: Some(666),
            },
        )]),
        static_blinding: Some(666),
    };
    // this fails
    let (_fascia, _asset_beneficiaries) = wlt_1.color_psbt(&mut psbt, coloring_info);
}
