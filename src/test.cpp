#include <stdlib.h>
#include <iostream>

#include "libff/algebra/fields/field_utils.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libsnark/gadgetlib1/pb_variable.hpp"

#include "util.hpp"

using namespace libsnark;
using namespace std;

typedef libff::Fr<default_r1cs_ppzksnark_pp> FieldT;
typedef r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> KeyPair;
typedef r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> Proof;

struct ZKSystem {
    protoboard<FieldT> pb;
    std::vector<FieldElem> elems;

    ZKSystem() {
      default_r1cs_ppzksnark_pp::init_public_params();
    }
  
    const KeyPair make_keypair() {
      const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
      return r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(constraint_system);
    }

    const Proof make_proof(KeyPair keypair) {
        return r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());
    }

    bool verify_proof(KeyPair keypair, Proof proof) {
        return r1cs_ppzksnark_verifier_strong_IC<default_r1cs_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof);
    }

    FieldElem & def(std::string name) {
        return register_elem(LeafFieldElem(name, this));
    }

    FieldElem & register_elem(FieldElem elem) {
        int i = elems.size();
        elems.push_back(elem);
        return elems.at(i);
    }

    void allocate() {
        int n_pub = 0;
        for (FieldElem &elem : elems) {
            if (elem.pub) {
                n_pub += 1;
                elem.pb_var.allocate(pb, elem.name);
            }
        }

        for (FieldElem &elem : elems) {
            if (!elem.pub) {
                elem.pb_var.allocate(pb, elem.name);
            }
        }

        pb.set_input_sizes(n_pub);
    }

}

struct FieldElem {
    ZKSystem &system;
    pb_variable<FieldT> pb_var;
    std::string name;
    bool pub = false;

    void make_public() {
        pub = true;
    }

    friend FieldElem & operator+(const FieldElem &elem1, const FieldElem &elem2);
    friend FieldElem & operator*(const FieldElem &elem1, const FieldElem &elem2);
}

struct LeafFieldElem : public FieldElem {
    LeafFieldElem(std::string _name, ZKSystem &_system) : name(_name), system(_system);

    int val;

    void set(int x) {
        val = x;
    }

    void eval() {
        return val;
        system.pb.val(pb_var) = val;
    }
};

struct SumFieldElem : public FieldElem {
    FieldElem &child_a, &child_b;

    SumFieldElem(const FieldElem &elem1, const FieldElem &elem2, ZKSystem &_system) : child_a(elem1), child_b(elem2), system(_system) {
        name = elem1.name + "+" + elem2.name;
    }

    int eval() {
        int val = child_a.eval() + child_b.eval();
        system.pb.val(pb_var) = val;
        return val;
    }
}

struct ProdFieldElem : public FieldElem {
    FieldElem &child_a, &child_b;

    ProdFieldElem(const FieldElem &elem1, const FieldElem &elem2, ZKSystem &_system) : child_a(elem1), child_b(elem2), system(_system) {
        name = elem1.name + "*" + elem2.name;
    }

    int eval() {
        int val = child_a.eval() * child_b.eval();
        system.pb.val(pb_var) = val;
        return val;
    }
}

friend FieldElem & operator+(const FieldElem &elem1, const FieldElem &elem2) {
    return elem1.system.register_elem(SumFieldElem(elem1, elem2, elem1.system));
}

friend FieldElem & operator*(const FieldElem &elem1, const FieldElem &elem2) {
    return elem1.system.register_elem(ProdFieldElem(elem1, elem2, elem1.system));
}

int main()
{

  // Initialize the curve parameters
  // Create zksystem
  ZKSystem system;

  FieldElem &a1 = system.def("a1");
  FieldElem &a0 = system.def("a0");
  FieldElem &b1 = system.def("b1");
  FieldElem &b0 = system.def("b0");

  FieldElem &a1gtb1 = (1 - b1) * a1;
  FieldElem &a0gtb0 = (1 - b0) * a0;
  FieldElem &out = a1gtb1 + (1 - a1gtb1) * a0gtb0;

  out.make_public();
  system.allocate();

  // Add witness values
  a1.val(1);
  a0.val(0);
  b1.val(0);
  b0.val(1);

  out.eval();

  auto keypair = system.make_keypair();
  auto proof = system.make_proof(keypair);
  bool verified = system.verify_proof(keypair, proof);

  cout << "Primary (public) input: " << system.pb.primary_input() << endl;
  cout << "Auxiliary (private) input: " << system.pb.auxiliary_input() << endl;
  cout << "Verification status: " << verified << endl;

  return 0;
}
