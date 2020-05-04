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
struct SumFieldElem;
struct DiffFieldElem;
struct ProdFieldElem;

struct FieldElem {
    ZKSystem &system;
    pb_variable<FieldT> pb_var;
    std::string name;
    bool pub, is_set;
    int val;

    FieldElem(std::string _name, ZKSystem &_system);

    virtual void set(int x) {
        std::cout << "Can't set the value of a non-leaf element" << std::endl;
        throw 1;
    }
    void make_public() {
        pub = true;
        cout << name << " public: " << pub << endl;
    }

    virtual int eval() {
        cout << "field eval" << endl;
    };

    friend SumFieldElem & operator+(FieldElem &elem1, FieldElem &elem2);
    friend DiffFieldElem & operator-(FieldElem &elem1, FieldElem &elem2);
    friend ProdFieldElem & operator*(FieldElem &elem1, FieldElem &elem2);

    friend SumFieldElem & operator+(int x, FieldElem &elem);
    friend DiffFieldElem & operator-(int x, FieldElem &elem);
    friend ProdFieldElem & operator*(int x, FieldElem &elem);

    friend SumFieldElem & operator+(FieldElem &elem, int x);
    friend DiffFieldElem & operator-(FieldElem &elem, int x);
    friend ProdFieldElem & operator*(FieldElem &elem, int x);
};

struct LeafFieldElem : public FieldElem {
    LeafFieldElem(std::string _name, ZKSystem &_system);

    virtual void set(int x) {
        cout << "setting " << name << " to " << x << endl;
        is_set = true;
        val = x;
    }

    virtual int eval();
};

struct SumFieldElem : public FieldElem {
    FieldElem &child_a, &child_b;

    SumFieldElem(FieldElem &elem1, FieldElem &elem2, ZKSystem &_system);

    virtual int eval();
};

struct DiffFieldElem : public FieldElem {
    FieldElem &child_a, &child_b;

    DiffFieldElem(FieldElem &elem1, FieldElem &elem2, ZKSystem &_system);

    virtual int eval();
};

struct ProdFieldElem : public FieldElem {
    FieldElem &child_a, &child_b;

    ProdFieldElem(FieldElem &elem1, FieldElem &elem2, ZKSystem &_system);

    virtual int eval();
};

struct ZKSystem {
    protoboard<FieldT> pb;
    std::vector<FieldElem *> elems;

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

    LeafFieldElem & def(std::string name) {
        LeafFieldElem *elem = new LeafFieldElem(name, *this);
        register_elem(elem);
        return *elem;
    }

    void register_elem(FieldElem *elem) {
        elems.push_back(elem);
    }

    void allocate() {
        int n_pub = 0;
        for (FieldElem *elem : elems) {
            if (elem->pub) {
                cout << "allocating public elem " << elem->name << endl;
                n_pub += 1;
                elem->pb_var.allocate(pb, elem->name);
            }
        }

        for (FieldElem *elem : elems) {
            if (!elem->pub) {
                cout << "allocating private elem " << elem->name << endl;
                elem->pb_var.allocate(pb, elem->name);
            }
        }

        pb.set_input_sizes(n_pub);
    }

    ~ZKSystem() {
        for (FieldElem *elem : elems) {
            delete elem;
        }
    }

};

FieldElem::FieldElem(std::string _name, ZKSystem &_system) : name(_name), system(_system), pub(false), is_set(false), val(0) {
    /* std::cout << "creating elem " << name << std::endl; */
};

SumFieldElem & operator+(FieldElem &elem1, FieldElem &elem2) {
    auto elem = new SumFieldElem(elem1, elem2, elem1.system);
    elem1.system.register_elem(elem);
    return *elem;
}

DiffFieldElem & operator-(FieldElem &elem1, FieldElem &elem2) {
    auto elem = new DiffFieldElem(elem1, elem2, elem1.system);
    elem1.system.register_elem(elem);
    return *elem;
}

ProdFieldElem & operator*(FieldElem &elem1, FieldElem &elem2) {
    auto elem = new ProdFieldElem(elem1, elem2, elem1.system);
    elem1.system.register_elem(elem);
    return *elem;
}

SumFieldElem & operator+(int x, FieldElem &elem) {
    std::string name = std::to_string(x);
    auto &constant = elem.system.def(name);
    constant.set(x);
    auto &ret = constant + elem;
    return ret;
}

DiffFieldElem & operator-(int x, FieldElem &elem) {
    std::string name = std::to_string(x);
    auto &constant = elem.system.def(name);
    constant.set(x);
    auto &ret = constant - elem;  // why is this needed to prevent a copy
    return ret;
}

ProdFieldElem & operator*(int x, FieldElem &elem) {
    std::string name = std::to_string(x);
    auto &constant = elem.system.def(name);
    constant.set(x);
    auto &ret = constant * elem;
    return ret;
}

SumFieldElem & operator+(FieldElem &elem, int x) {
    std::string name = std::to_string(x);
    auto &constant = elem.system.def(name);
    constant.set(x);
    auto &ret = elem + constant;
    return ret;
}

DiffFieldElem & operator-(FieldElem &elem, int x) {
    std::string name = std::to_string(x);
    auto &constant = elem.system.def(name);
    constant.set(x);
    auto &ret = elem - constant;
    return ret;
}

ProdFieldElem & operator*(FieldElem &elem, int x) {
    std::string name = std::to_string(x);
    auto &constant = elem.system.def(name);
    constant.set(x);
    auto &ret = elem * constant;
    return ret;
}

LeafFieldElem::LeafFieldElem(std::string _name, ZKSystem &_system) : FieldElem(_name, _system) {};

int LeafFieldElem::eval() {
    if (!is_set) {
        cout << "can't eval leaf element without a value" << endl;
        throw 1;
    }
    system.pb.val(pb_var) = val;
    return val;
}

SumFieldElem::SumFieldElem(FieldElem &elem1, FieldElem &elem2, ZKSystem &_system) :
    child_a(elem1), child_b(elem2), FieldElem("(" + elem1.name + "+" + elem2.name + ")", _system) {};

int SumFieldElem::eval() {
    if (!is_set) {
        val = child_a.eval() + child_b.eval();
        system.pb.val(pb_var) = val;
        is_set = true;
    }
    return val;
}

DiffFieldElem::DiffFieldElem(FieldElem &elem1, FieldElem &elem2, ZKSystem &_system) :
    child_a(elem1), child_b(elem2), FieldElem("(" + elem1.name + "-" + elem2.name + ")", _system) {};

int DiffFieldElem::eval() {
    if (!is_set) {
        val = child_a.eval() - child_b.eval();
        system.pb.val(pb_var) = val;
        is_set = true;
    }
    return val;
}

ProdFieldElem::ProdFieldElem(FieldElem &elem1, FieldElem &elem2, ZKSystem &_system) :
    child_a(elem1), child_b(elem2), FieldElem("(" + elem1.name + "*" + elem2.name + ")", _system) {};

int ProdFieldElem::eval() {
    if (!is_set) {
        val = child_a.eval() * child_b.eval();
        system.pb.val(pb_var) = val;
        is_set = true;
    }
    return val;
}

int main()
{
  // Create zksystem
  ZKSystem system;

  auto &a1 = system.def("a1");
  auto &a0 = system.def("a0");
  auto &b1 = system.def("b1");
  auto &b0 = system.def("b0");

  auto &a1gtb1 = (1 - b1) * a1;
  auto &a0gtb0 = (1 - b0) * a0;
  auto &out = a1gtb1 + (1 - a1gtb1) * a0gtb0;

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
