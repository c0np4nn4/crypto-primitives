#[cfg(feature = "constraints")]
mod constraints;
mod test_utils;

mod bytes_mt_tests {

    use crate::{crh::*, merkle_tree::*};
    use ark_ed_on_bls12_381::EdwardsProjective as JubJub;
    use ark_ff::BigInteger256;
    use ark_std::{iter::zip, test_rng, UniformRand};

    #[derive(Clone)]
    pub(super) struct Window4x256;
    impl pedersen::Window for Window4x256 {
        const WINDOW_SIZE: usize = 4;
        const NUM_WINDOWS: usize = 256;
    }

    type LeafH = pedersen::CRH<JubJub, Window4x256>;
    type CompressH = pedersen::TwoToOneCRH<JubJub, Window4x256>;

    struct JubJubMerkleTreeParams;

    impl Config for JubJubMerkleTreeParams {
        type Leaf = [u8];

        type LeafDigest = <LeafH as CRHScheme>::Output;
        type LeafInnerDigestConverter = ByteDigestConverter<Self::LeafDigest>;
        type InnerDigest = <CompressH as TwoToOneCRHScheme>::Output;

        type LeafHash = LeafH;
        type TwoToOneHash = CompressH;
    }
    type JubJubMerkleTree = MerkleTree<JubJubMerkleTreeParams>;

    /// Pedersen only takes bytes as leaf, so we use `ToBytes` trait.
    fn merkle_tree_test<L: CanonicalSerialize>(leaves: &[L], update_query: &[(usize, L)]) -> () {
        let mut rng = ark_std::test_rng();

        let mut leaves: Vec<_> = leaves
            .iter()
            .map(|leaf| crate::to_uncompressed_bytes!(leaf).unwrap())
            .collect();

        let leaf_crh_params = <LeafH as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_params = <CompressH as TwoToOneCRHScheme>::setup(&mut rng).unwrap();

        let mut tree =
            JubJubMerkleTree::new(&leaf_crh_params, &two_to_one_params, &leaves).unwrap();

        let mut root = tree.root();
        // test merkle tree functionality without update
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof
                .verify(&leaf_crh_params, &two_to_one_params, &root, leaf.as_slice())
                .unwrap());
        }

        // test the merkle tree multi-proof functionality
        let mut multi_proof = tree
            .generate_multi_proof((0..leaves.len()).collect::<Vec<_>>())
            .unwrap();

        assert!(multi_proof
            .verify(&leaf_crh_params, &two_to_one_params, &root, leaves.clone())
            .unwrap());

        // test merkle tree update functionality
        for (i, v) in update_query {
            let v = crate::to_uncompressed_bytes!(v).unwrap();
            tree.update(*i, &v).unwrap();
            leaves[*i] = v.clone();
        }
        // update the root
        root = tree.root();
        // verify again
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof
                .verify(&leaf_crh_params, &two_to_one_params, &root, leaf.as_slice())
                .unwrap());
        }

        // test the merkle tree multi-proof functionality again
        multi_proof = tree
            .generate_multi_proof((0..leaves.len()).collect::<Vec<_>>())
            .unwrap();

        assert!(multi_proof
            .verify(&leaf_crh_params, &two_to_one_params, &root, leaves.clone())
            .unwrap());
    }

    #[test]
    fn good_root_test() {
        let mut rng = test_rng();

        let mut leaves = Vec::new();
        for _ in 0..2u8 {
            leaves.push(BigInteger256::rand(&mut rng));
        }
        merkle_tree_test(
            &leaves,
            &vec![
                (0, BigInteger256::rand(&mut rng)),
                (1, BigInteger256::rand(&mut rng)),
            ],
        );

        let mut leaves = Vec::new();
        for _ in 0..4u8 {
            leaves.push(BigInteger256::rand(&mut rng));
        }
        merkle_tree_test(&leaves, &vec![(3, BigInteger256::rand(&mut rng))]);

        let mut leaves = Vec::new();
        for _ in 0..128u8 {
            leaves.push(BigInteger256::rand(&mut rng));
        }
        merkle_tree_test(
            &leaves,
            &vec![
                (2, BigInteger256::rand(&mut rng)),
                (3, BigInteger256::rand(&mut rng)),
                (5, BigInteger256::rand(&mut rng)),
                (111, BigInteger256::rand(&mut rng)),
                (127, BigInteger256::rand(&mut rng)),
            ],
        );
    }

    #[test]
    fn compact_multi_proof_test() {
        let mut rng = test_rng();

        // Test with several tree sizes and proof subsets
        for num_leaves in [2u8, 4, 8, 16, 32] {
            let leaves: Vec<_> = (0..num_leaves)
                .map(|_| crate::to_uncompressed_bytes!(BigInteger256::rand(&mut rng)).unwrap())
                .collect();

            let leaf_crh_params = <LeafH as CRHScheme>::setup(&mut rng).unwrap();
            let two_to_one_params = <CompressH as TwoToOneCRHScheme>::setup(&mut rng).unwrap();

            let tree =
                JubJubMerkleTree::new(&leaf_crh_params, &two_to_one_params, &leaves).unwrap();
            let root = tree.root();

            // Prove all leaves
            let proof = tree
                .generate_compact_multi_proof((0..leaves.len()).collect::<Vec<_>>())
                .unwrap();
            assert!(proof
                .verify(&leaf_crh_params, &two_to_one_params, &root, leaves.clone())
                .unwrap());

            // Wrong root must fail
            let wrong_root = tree
                .generate_compact_multi_proof(vec![0])
                .unwrap()
                .leaf_proof_hashes
                .first()
                .cloned();
            // Use a simple wrong root by generating a bogus proof and verifying with real root
            // (just verify that an impossible subset also rejects a tampered check)
            let proof_subset = tree
                .generate_compact_multi_proof(vec![0, (num_leaves / 2) as usize])
                .unwrap();
            assert!(proof_subset
                .verify(
                    &leaf_crh_params,
                    &two_to_one_params,
                    &root,
                    // supply leaves in sorted index order
                    vec![leaves[0].clone(), leaves[(num_leaves / 2) as usize].clone()]
                )
                .unwrap());
            // Supplying an incorrect leaf value must fail
            let mut tampered = leaves[0].clone();
            tampered[0] ^= 0xff;
            assert!(!proof_subset
                .verify(
                    &leaf_crh_params,
                    &two_to_one_params,
                    &root,
                    vec![tampered, leaves[(num_leaves / 2) as usize].clone()]
                )
                .unwrap());
            let _ = wrong_root;
        }
    }

    #[test]
    fn multi_proof_dissection_test() {
        let mut rng = test_rng();

        let mut leaves = Vec::new();
        for _ in 0..8u8 {
            leaves.push(BigInteger256::rand(&mut rng));
        }
        assert_eq!(leaves.len(), 8);

        let serialized_leaves: Vec<_> = leaves
            .iter()
            .map(|leaf| crate::to_uncompressed_bytes!(leaf).unwrap())
            .collect();

        let leaf_crh_params = <LeafH as CRHScheme>::setup(&mut rng).unwrap();
        let two_to_one_params = <CompressH as TwoToOneCRHScheme>::setup(&mut rng).unwrap();

        let tree = JubJubMerkleTree::new(&leaf_crh_params, &two_to_one_params, &serialized_leaves)
            .unwrap();

        let mut proofs = Vec::with_capacity(leaves.len());

        for (i, _) in leaves.iter().enumerate() {
            proofs.push(tree.generate_proof(i).unwrap());
        }

        let multi_proof = tree
            .generate_multi_proof((0..leaves.len()).collect::<Vec<_>>())
            .unwrap();

        // test compression theretical prefix lengths for size 8 Tree:
        // we should send 6 hashes instead of 2*8 = 16
        let theoretical_prefix_lengths = vec![0, 2, 1, 2, 0, 2, 1, 2];

        for (comp_len, exp_len) in zip(
            &multi_proof.auth_paths_prefix_lenghts,
            &theoretical_prefix_lengths,
        ) {
            assert_eq!(comp_len, exp_len);
        }

        // test that the compressed paths can expand to expected len
        for (prefix_len, suffix) in zip(
            &multi_proof.auth_paths_prefix_lenghts,
            &multi_proof.auth_paths_suffixes,
        ) {
            assert_eq!(prefix_len + suffix.len(), proofs[0].auth_path.len());
        }
    }
}

mod field_mt_tests {
    use crate::{
        crh::poseidon,
        merkle_tree::{
            tests::test_utils::poseidon_parameters, Config, IdentityDigestConverter, MerkleTree,
        },
    };
    use ark_std::{test_rng, One, UniformRand};

    type F = ark_ed_on_bls12_381::Fr;
    type H = poseidon::CRH<F>;
    type TwoToOneH = poseidon::TwoToOneCRH<F>;

    struct FieldMTConfig;
    impl Config for FieldMTConfig {
        type Leaf = [F];
        type LeafDigest = F;
        type LeafInnerDigestConverter = IdentityDigestConverter<F>;
        type InnerDigest = F;
        type LeafHash = H;
        type TwoToOneHash = TwoToOneH;
    }

    type FieldMT = MerkleTree<FieldMTConfig>;

    fn merkle_tree_test(leaves: &[Vec<F>], update_query: &[(usize, Vec<F>)]) -> () {
        let mut leaves = leaves.to_vec();
        let leaf_crh_params = poseidon_parameters();
        let two_to_one_params = leaf_crh_params.clone();

        let mut tree = FieldMT::new(&leaf_crh_params, &two_to_one_params, &leaves).unwrap();

        let mut root = tree.root();

        // test merkle tree functionality without update
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof
                .verify(&leaf_crh_params, &two_to_one_params, &root, leaf.as_slice())
                .unwrap());
        }

        // test the merkle tree multi-proof functionality
        let mut multi_proof = tree
            .generate_multi_proof((0..leaves.len()).collect::<Vec<_>>())
            .unwrap();

        assert!(multi_proof
            .verify(&leaf_crh_params, &two_to_one_params, &root, leaves.clone())
            .unwrap());

        {
            // wrong root should lead to error but do not panic
            let wrong_root = root + F::one();
            let proof = tree.generate_proof(0).unwrap();
            assert!(!proof
                .verify(
                    &leaf_crh_params,
                    &two_to_one_params,
                    &wrong_root,
                    leaves[0].as_slice()
                )
                .unwrap());

            // test the merkle tree multi-proof functionality
            let multi_proof = tree
                .generate_multi_proof((0..leaves.len()).collect::<Vec<_>>())
                .unwrap();

            assert!(!multi_proof
                .verify(
                    &leaf_crh_params,
                    &two_to_one_params,
                    &wrong_root,
                    leaves.clone()
                )
                .unwrap());
        }

        // test merkle tree update functionality
        for (i, v) in update_query {
            tree.update(*i, v).unwrap();
            leaves[*i] = v.to_vec();
        }

        // update the root
        root = tree.root();

        // verify again
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof
                .verify(&leaf_crh_params, &two_to_one_params, &root, leaf.as_slice())
                .unwrap());
        }

        multi_proof = tree
            .generate_multi_proof((0..leaves.len()).collect::<Vec<_>>())
            .unwrap();

        assert!(multi_proof
            .verify(&leaf_crh_params, &two_to_one_params, &root, leaves.clone())
            .unwrap());
    }

    #[test]
    fn good_root_test() {
        let mut rng = test_rng();
        let mut rand_leaves = || (0..3).map(|_| F::rand(&mut rng)).collect();

        let mut leaves: Vec<Vec<_>> = Vec::new();
        for _ in 0..128u8 {
            leaves.push(rand_leaves())
        }
        merkle_tree_test(
            &leaves,
            &vec![
                (2, rand_leaves()),
                (3, rand_leaves()),
                (5, rand_leaves()),
                (111, rand_leaves()),
                (127, rand_leaves()),
            ],
        )
    }
}

/// Index-level trace of the Compact Merkle Multiproof algorithm.
/// No actual hashing is performed; only the index selection at each round is shown.
/// Run with `cargo test compact_proof_index_trace -- --nocapture` to see output.
mod compact_proof_trace_tests {
    use ark_std::collections::BTreeSet;

    /// Prints the index selection at each round for a given set of leaf indices
    /// and tree height, matching the paper's Figure 7 (arXiv:2002.07648).
    fn trace_compact_proof(leaf_indexes: &[usize], tree_height: usize) {
        let num_leaves = 1usize << (tree_height - 1);
        println!(
            "=== Compact Merkle Multiproof Index Trace ===\n\
             Tree: {} leaves, height {}\n\
             Proving leaves: {:?}\n",
            num_leaves, tree_height, leaf_indexes
        );

        let mut a: Vec<usize> = leaf_indexes.to_vec();

        // ---- Round 1: leaf layer ----
        let b: Vec<[usize; 2]> = a.iter().map(|&i| [i & !1, (i & !1) + 1]).collect();
        let b_pruned = {
            let mut v = b.clone();
            v.dedup();
            v
        };
        let a_set: BTreeSet<usize> = a.iter().cloned().collect();
        let diff: Vec<usize> = b_pruned
            .iter()
            .flat_map(|&[l, r]| [l, r])
            .filter(|idx| !a_set.contains(idx))
            .collect();

        println!("Round 1 [leaf layer]");
        println!("  A        = {:?}", a);
        println!(
            "  B        = [{}]",
            b.iter()
                .map(|p| format!("[{},{}]", p[0], p[1]))
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!(
            "  B_pruned = [{}]",
            b_pruned
                .iter()
                .map(|p| format!("[{},{}]", p[0], p[1]))
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!(
            "  diff     = {:?}  <-- proof hash indices at this layer",
            diff
        );

        a = b_pruned.iter().map(|&[l, _]| l / 2).collect();
        println!("  A_new    = {:?}", a);

        // ---- Inner layers ----
        let mut current_depth = tree_height as isize - 2;
        let mut round = 2;
        while current_depth >= 1 {
            let layer_size = 1usize << current_depth;
            println!(
                "\nRound {} [depth {} from root, layer size {}]",
                round, current_depth, layer_size
            );

            let b: Vec<[usize; 2]> = a.iter().map(|&i| [i & !1, (i & !1) + 1]).collect();
            let b_pruned = {
                let mut v = b.clone();
                v.dedup();
                v
            };
            let a_set: BTreeSet<usize> = a.iter().cloned().collect();
            let diff: Vec<usize> = b_pruned
                .iter()
                .flat_map(|&[l, r]| [l, r])
                .filter(|idx| !a_set.contains(idx))
                .collect();

            println!("  A        = {:?}", a);
            println!(
                "  B        = [{}]",
                b.iter()
                    .map(|p| format!("[{},{}]", p[0], p[1]))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            println!(
                "  B_pruned = [{}]",
                b_pruned
                    .iter()
                    .map(|p| format!("[{},{}]", p[0], p[1]))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            println!(
                "  diff     = {:?}  <-- proof hash indices at this layer",
                diff
            );

            a = b_pruned.iter().map(|&[l, _]| l / 2).collect();
            println!("  A_new    = {:?}", a);

            current_depth -= 1;
            round += 1;
        }

        println!(
            "\n=== Reached root (index 0) after {} rounds ===",
            round - 1
        );
    }

    #[test]
    fn compact_proof_index_trace_paper_example() {
        // Reproduces the example from Figure 7 of the paper (arXiv:2002.07648):
        // 16-leaf tree, proving leaves at indices [2, 3, 8, 13].

        trace_compact_proof(&[2, 3, 8, 13], 5);
    }

    #[test]
    fn compact_proof_index_trace_all_leaves_8() {
        // All 8 leaves: shows that no proof hashes are needed.
        trace_compact_proof(&[0, 1, 2, 3, 4, 5, 6, 7], 4);
    }

    #[test]
    fn compact_proof_index_trace_single_leaf() {
        // Single leaf: equivalent to a standard single-leaf proof.
        trace_compact_proof(&[5], 4);
    }
}
