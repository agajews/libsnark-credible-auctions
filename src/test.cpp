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

struct BitArray {
    std::vector<FieldElem *> bits;
    int size;
    ZKSystem &system;

    BitArray(ZKSystem &_system, std::string name, int _size) : system(_system), size(_size) {
        for (int i=0; i<size; i++) {
            bits.push_back(&system.def(name + std::to_string(i)));
        }
    }

    FieldElem & operator[](int i) {
        return *bits[i];
    }

    void set(std::vector<int> elems) {
        for (int i=0; i<size; i++) {
            bits[i]->set(elems[i]);
        }
    }

    friend FieldElem & operator>(BitArray &arr1, BitArray &arr2);
};

FieldElem & operator>(BitArray &a, BitArray &b) {
    FieldElem *out = &((1 - b[0]) * a[0]);  // most significant bit lowest
    for (int i=1; i<a.size; i++) {
        out = &(*out + (1 - *out) * (1 - b[i]) * a[i]);
    }
    FieldElem &out_ref = *out;
    return out_ref;
}

int main()
{
  // Create zksystem
  ZKSystem system;

  BitArray a(system, "a", 2);
  BitArray b(system, "b", 2);

  auto &out = a > b;

  out.make_public();
  system.allocate();

  a.set({1, 0});
  b.set({0, 1});

  out.eval();

  auto keypair = system.make_keypair();
  auto proof = system.make_proof(keypair);
  bool verified = system.verify_proof(keypair, proof);

  cout << "Primary (public) input: " << system.pb.primary_input() << endl;
  cout << "Auxiliary (private) input: " << system.pb.auxiliary_input() << endl;
  cout << "Verification status: " << verified << endl;

  return 0;
}
