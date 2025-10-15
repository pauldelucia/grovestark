#![cfg(feature = "must_fail_test")]
/// Minimal reproducer for Winterfell 41-constraint bug
/// Per GUIDANCE.md Section Test B: 41 zero constraints fail verification
///
/// NOTE: This is a DOCUMENTATION TEST - not meant to be run directly
/// The simplified API here demonstrates the bug conceptually
///
/// Expected: Both 40 and 41 constraint tests pass
/// Actual (winterfell 0.13.1): 40 passes, 41 fails with InconsistentOodConstraintEvaluations
// This entire file is disabled to avoid compilation issues
// It serves as documentation of the winterfell bug
use winterfell::{
    math::{fields::f64::BaseElement, FieldElement, StarkField},
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, Prover, Trace, TraceInfo,
    TraceTable, TransitionConstraintDegree,
};

/// AIR with N degree-2 constraints that all evaluate to zero
struct ZeroConstraintAir {
    context: AirContext<BaseElement>,
    num_constraints: usize,
}

impl Air for ZeroConstraintAir {
    type BaseField = BaseElement;
    type PublicInputs = usize; // num constraints for debugging

    fn new(trace_info: TraceInfo, num_constraints: usize, options: ProofOptions) -> Self {
        // Create N identical degree-2 constraints
        let degrees = vec![TransitionConstraintDegree::new(2); num_constraints];

        let context = AirContext::new(
            trace_info, degrees, 1, // one assertion
            options,
        );

        Self {
            context,
            num_constraints,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        _frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        // All constraints evaluate to zero
        for i in 0..self.num_constraints {
            result[i] = E::ZERO;
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        vec![Assertion::single(0, 0, BaseElement::ZERO)]
    }
}

/// Prover for zero constraint AIR
struct ZeroConstraintProver {
    options: ProofOptions,
    num_constraints: usize,
}

impl Prover for ZeroConstraintProver {
    type BaseField = BaseElement;
    type Air = ZeroConstraintAir;
    type Trace = TraceTable<BaseElement>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> usize {
        self.num_constraints
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }
}

fn test_n_constraints(n: usize) -> Result<(), String> {
    println!("[TEST] Testing with {} zero constraints...", n);

    // Build minimal trace: 256 rows, 4 columns (more realistic than 1x8)
    let trace = vec![vec![BaseElement::ZERO; 256]; 4];
    let trace_table = TraceTable::init(trace);

    // Create prover with standard options
    let options = ProofOptions::new(
        20, // 20 queries (for security)
        8,  // 8x blowup
        16, // 16 bits grinding
        winterfell::FieldExtension::None,
        4,  // 4x folding
        31, // max remainder degree
    );

    let prover = ZeroConstraintProver {
        options: options.clone(),
        num_constraints: n,
    };

    println!("  Generating proof...");
    let proof = prover
        .prove(trace_table)
        .map_err(|e| format!("Proof generation failed: {:?}", e))?;

    let proof_bytes = proof.to_bytes();
    println!("  Proof size: {} bytes", proof_bytes.len());

    // Verify the proof
    println!("  Verifying proof...");
    let proof = winterfell::StarkProof::from_bytes(&proof_bytes)
        .map_err(|e| format!("Proof deserialization failed: {:?}", e))?;

    match winterfell::verify::<ZeroConstraintAir>(proof, n) {
        Ok(_) => {
            println!("  ✓ Verification succeeded!");
            Ok(())
        }
        Err(e) => {
            println!("  ✗ Verification failed: {:?}", e);
            Err(format!("Verification failed: {:?}", e))
        }
    }
}

#[test]
fn test_40_constraints_pass() {
    // This should pass
    test_n_constraints(40).expect("40 constraints should work");
}

#[test]
fn test_41_constraints_fail() {
    // This fails with InconsistentOodConstraintEvaluations
    match test_n_constraints(41) {
        Ok(_) => panic!("41 constraints unexpectedly passed - bug may be fixed!"),
        Err(e) => {
            println!(
                "[EXPECTED FAILURE] 41 constraints failed as expected: {}",
                e
            );
            assert!(
                e.contains("InconsistentOodConstraintEvaluations")
                    || e.contains("Ood")
                    || e.contains("verification"),
                "Unexpected error type: {}",
                e
            );
        }
    }
}

#[test]
fn test_constraint_threshold() {
    println!("\n[TEST] Finding exact constraint count threshold...\n");

    let mut last_working = 0;
    let mut first_failing = 100;

    // Binary search for the threshold
    for n in 38..=45 {
        println!("Testing {} constraints...", n);
        match test_n_constraints(n) {
            Ok(_) => {
                println!("  {} ✓ PASSED", n);
                last_working = n;
            }
            Err(e) => {
                println!("  {} ✗ FAILED: {}", n, e);
                if first_failing == 100 {
                    first_failing = n;
                }
            }
        }
    }

    println!("\n[RESULTS]");
    println!("  Last working: {} constraints", last_working);
    println!("  First failing: {} constraints", first_failing);
    println!("  Threshold: constraints > {} cause failure", last_working);

    assert_eq!(last_working, 40, "Expected 40 to be the last working count");
    assert_eq!(
        first_failing, 41,
        "Expected 41 to be the first failing count"
    );
}

#[test]
fn test_distribution_sensitivity() {
    println!("\n[TEST] Testing distribution sensitivity at 40 constraints...\n");

    // Test different distributions of 40 constraints between "phases"
    // This simulates how real AIRs might distribute constraints

    struct DistributedAir {
        context: AirContext<BaseElement>,
        phase1_count: usize,
        phase2_count: usize,
    }

    impl Air for DistributedAir {
        type BaseField = BaseElement;
        type PublicInputs = (usize, usize);

        fn new(trace_info: TraceInfo, pub_inputs: (usize, usize), options: ProofOptions) -> Self {
            let (phase1_count, phase2_count) = pub_inputs;
            let total = phase1_count + phase2_count;

            let degrees = vec![TransitionConstraintDegree::new(2); total];

            let context = AirContext::new(trace_info, degrees, 1, options);

            Self {
                context,
                phase1_count,
                phase2_count,
            }
        }

        fn context(&self) -> &AirContext<Self::BaseField> {
            &self.context
        }

        fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
            &self,
            _frame: &EvaluationFrame<E>,
            _periodic_values: &[E],
            result: &mut [E],
        ) {
            // Write phase 1 constraints
            for i in 0..self.phase1_count {
                result[i] = E::ZERO;
            }
            // Write phase 2 constraints
            for i in self.phase1_count..(self.phase1_count + self.phase2_count) {
                result[i] = E::ZERO;
            }
        }

        fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
            vec![Assertion::single(0, 0, BaseElement::ZERO)]
        }
    }

    let distributions = [
        (20, 20, "20/20 even split"),
        (19, 21, "19/21 slight imbalance"),
        (15, 25, "15/25 moderate imbalance"),
        (10, 30, "10/30 heavy imbalance"),
        (5, 35, "5/35 extreme imbalance"),
        (1, 39, "1/39 almost all in phase 2"),
    ];

    for (phase1, phase2, desc) in distributions.iter() {
        println!("Testing {}: {} + {} = 40", desc, phase1, phase2);

        let trace = vec![vec![BaseElement::ZERO; 256]; 4];
        let trace_table = TraceTable::init(trace);

        let options = ProofOptions::new(20, 8, 16, winterfell::FieldExtension::None, 4, 31);

        struct DistributedProver {
            options: ProofOptions,
            phase1_count: usize,
            phase2_count: usize,
        }

        impl Prover for DistributedProver {
            type BaseField = BaseElement;
            type Air = DistributedAir;
            type Trace = TraceTable<BaseElement>;

            fn get_pub_inputs(&self, _trace: &Self::Trace) -> (usize, usize) {
                (self.phase1_count, self.phase2_count)
            }

            fn options(&self) -> &ProofOptions {
                &self.options
            }
        }

        let prover = DistributedProver {
            options: options.clone(),
            phase1_count: *phase1,
            phase2_count: *phase2,
        };

        match prover.prove(trace_table.clone()) {
            Ok(proof) => {
                let proof_bytes = proof.to_bytes();
                let proof = winterfell::StarkProof::from_bytes(&proof_bytes).unwrap();

                match winterfell::verify::<DistributedAir>(proof, (*phase1, *phase2)) {
                    Ok(_) => println!("  ✓ {} PASSED", desc),
                    Err(e) => println!("  ✗ {} FAILED: {:?}", desc, e),
                }
            }
            Err(e) => println!("  ✗ {} FAILED (prove): {:?}", desc, e),
        }
    }
}
