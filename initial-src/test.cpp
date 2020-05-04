#include <stdlib.h>
#include <iostream>

#include "libff/algebra/fields/field_utils.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libsnark/gadgetlib1/pb_variable.hpp"

#include "util.hpp"

using namespace libsnark;
using namespace std;

int main()
{
  typedef libff::Fr<default_r1cs_ppzksnark_pp> FieldT;

  // Initialize the curve parameters

  default_r1cs_ppzksnark_pp::init_public_params();
  
  // Create protoboard

  protoboard<FieldT> pb;

  // Define variables

  pb_variable<FieldT> a1, a0, b1, b0;
  pb_variable<FieldT> a1gtb1, a0gtb0;
  pb_variable<FieldT> not_a1gtb1_and_a0gtb0;
  pb_variable<FieldT> agtb;
  pb_variable<FieldT> out;

  // Allocate variables to protoboard
  // The strings (like "x") are only for debugging purposes
  
  out.allocate(pb, "out");

  a1.allocate(pb, "a1");
  a0.allocate(pb, "a2");
  b1.allocate(pb, "b1");
  b0.allocate(pb, "b0");
  a1gtb1.allocate(pb, "a1gtb1");
  a0gtb0.allocate(pb, "a0gtb0");
  not_a1gtb1_and_a0gtb0.allocate(pb, "not_a1gtb1_and_a0gtb0");
  agtb.allocate(pb, "agtb");

  // This sets up the protoboard variables
  // so that the first one (out) represents the public
  // input and the rest is private input
  pb.set_input_sizes(1);

  // Add R1CS constraints to protoboard

  // a1gtb1 = (1 - b1)a1
  pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1 - b1, a1, a1gtb1));

  // a0gtb0 = (1 - b0)a0
  pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1 - b0, a0, a0gtb0));

  // not_a1gtb1_and_a0gtb0 = (1 - a1gtb1)a0gtb0
  pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1 - a1gtb1, a0gtb0, not_a1gtb1_and_a0gtb0));

  // agtb = (a1gtb1 + not_a1gtb1_and_a0gtb0)1
  pb.add_r1cs_constraint(r1cs_constraint<FieldT>(a1gtb1 + not_a1gtb1_and_a0gtb0, 1, agtb));

  // out = (agtb)1
  pb.add_r1cs_constraint(r1cs_constraint<FieldT>(agtb, 1, out));
  
  // Add witness values

  // inputs:
  pb.val(a1) = 1;
  pb.val(a0) = 0;

  pb.val(b1) = 0;
  pb.val(b0) = 1;

  // intermediate variables:
  pb.val(a1gtb1) = 1;
  pb.val(a0gtb0) = 0;
  pb.val(not_a1gtb1_and_a0gtb0) = 0;
  pb.val(agtb) = 1;

  // output:
  pb.val(out) = 1;

  const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

  const r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> keypair = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(constraint_system);

  const r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof = r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());

  bool verified = r1cs_ppzksnark_verifier_strong_IC<default_r1cs_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof);

  cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
  cout << "Primary (public) input: " << pb.primary_input() << endl;
  cout << "Auxiliary (private) input: " << pb.auxiliary_input() << endl;
  cout << "Verification status: " << verified << endl;

  const r1cs_ppzksnark_verification_key<default_r1cs_ppzksnark_pp> vk = keypair.vk;

  print_vk_to_file<default_r1cs_ppzksnark_pp>(vk, "../build/vk_data");
  print_proof_to_file<default_r1cs_ppzksnark_pp>(proof, "../build/proof_data");

  return 0;
}
