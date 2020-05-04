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

struct ZKSystem;

struct FieldElem {
    ZKSystem &system;
    pb_variable<FieldT> pb_var;
    std::string name;
    bool pub = false;

    FieldElem(std::string _name, ZKSystem _system);

    void set(int x) {
        std::cout << "Can't set the value of a non-leaf element" << std::endl;
        throw 1;
    }
    void make_public() {
        pub = true;
    }

    virtual int eval() const;

    friend FieldElem & operator+(const FieldElem &elem1, const FieldElem &elem2);
    friend FieldElem & operator-(const FieldElem &elem1, const FieldElem &elem2);
    friend FieldElem & operator*(const FieldElem &elem1, const FieldElem &elem2);

    friend FieldElem & operator-(const int x, const FieldElem &elem);
};

struct LeafFieldElem : public FieldElem {
    LeafFieldElem(std::string _name, ZKSystem &_system);

    int val = 0;

    void set(int x) {
        val = x;
    }

    int eval() const;
};

struct SumFieldElem : public FieldElem {
    const FieldElem &child_a, &child_b;

    SumFieldElem(const FieldElem &elem1, const FieldElem &elem2, ZKSystem &_system);

    int eval() const;
};

struct DiffFieldElem : public FieldElem {
    const FieldElem &child_a, &child_b;

    DiffFieldElem(const FieldElem &elem1, const FieldElem &elem2, ZKSystem &_system);

    int eval() const;
};

struct ProdFieldElem : public FieldElem {
    const FieldElem &child_a, &child_b;

    ProdFieldElem(const FieldElem &elem1, const FieldElem &elem2, ZKSystem &_system);

    int eval() const;
};

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
        return register_elem(FieldElem(name, *this));
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

};

FieldElem::FieldElem(std::string _name, ZKSystem _system) : name(_name), system(_system) {};

FieldElem & operator+(const FieldElem &elem1, const FieldElem &elem2) {
    return elem1.system.register_elem(SumFieldElem(elem1, elem2, elem1.system));
}

FieldElem & operator-(const FieldElem &elem1, const FieldElem &elem2) {
    return elem1.system.register_elem(DiffFieldElem(elem1, elem2, elem1.system));
}

FieldElem & operator-(const int x, const FieldElem &elem) {
    auto constant = elem.system.def("const:" + std::to_string(x));
    return constant - elem;
}

FieldElem & operator*(const FieldElem &elem1, const FieldElem &elem2) {
    return elem1.system.register_elem(ProdFieldElem(elem1, elem2, elem1.system));
}

LeafFieldElem::LeafFieldElem(std::string _name, ZKSystem &_system) : FieldElem(_name, _system) {};

int LeafFieldElem::eval() const {
    system.pb.val(pb_var) = val;
    return val;
}

SumFieldElem::SumFieldElem(const FieldElem &elem1, const FieldElem &elem2, ZKSystem &_system) :
    child_a(elem1), child_b(elem2), FieldElem(elem1.name + "+" + elem2.name, _system) {};

int SumFieldElem::eval() const {
    int val = child_a.eval() + child_b.eval();
    system.pb.val(pb_var) = val;
    return val;
}

DiffFieldElem::DiffFieldElem(const FieldElem &elem1, const FieldElem &elem2, ZKSystem &_system) :
    child_a(elem1), child_b(elem2), FieldElem(elem1.name + "+" + elem2.name, _system) {};

int DiffFieldElem::eval() const {
    int val = child_a.eval() - child_b.eval();
    system.pb.val(pb_var) = val;
    return val;
}

ProdFieldElem::ProdFieldElem(const FieldElem &elem1, const FieldElem &elem2, ZKSystem &_system) :
    child_a(elem1), child_b(elem2), FieldElem(elem1.name + "+" + elem2.name, _system) {};

int ProdFieldElem::eval() const {
    int val = child_a.eval() * child_b.eval();
    system.pb.val(pb_var) = val;
    return val;
}

int main()
{

  // Initialize the curve parameters
  // Create zksystem
  ZKSystem system;

  auto a1 = system.def("a1");
  auto a0 = system.def("a0");
  auto b1 = system.def("b1");
  auto b0 = system.def("b0");

  auto a1gtb1 = (1 - b1) * a1;
  auto a0gtb0 = (1 - b0) * a0;
  auto out = a1gtb1 + (1 - a1gtb1) * a0gtb0;

  out.make_public();
  system.allocate();

  // Add witness values
  a1.set(1);
  a0.set(0);
  b1.set(0);
  b0.set(1);

  out.eval();

  auto keypair = system.make_keypair();
  auto proof = system.make_proof(keypair);
  bool verified = system.verify_proof(keypair, proof);

  cout << "Primary (public) input: " << system.pb.primary_input() << endl;
  cout << "Auxiliary (private) input: " << system.pb.auxiliary_input() << endl;
  cout << "Verification status: " << verified << endl;

  return 0;
}
