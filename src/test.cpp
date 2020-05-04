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
        /* cout << name << " public: " << pub << endl; */
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
        /* cout << "setting " << name << " to " << x << endl; */
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
                /* cout << "allocating public elem " << elem->name << endl; */
                n_pub += 1;
                elem->pb_var.allocate(pb, elem->name);
            }
        }

        for (FieldElem *elem : elems) {
            if (!elem->pub) {
                /* cout << "allocating private elem " << elem->name << endl; */
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

    BitArray(ZKSystem &_system, std::vector<FieldElem *> _bits) : system(_system), size(_bits.size()), bits(_bits) {}

    FieldElem & operator[](int i) {
        return *bits[i];
    }

    void set(std::vector<int> elems) {
        for (int i=0; i<size; i++) {
            bits[i]->set(elems[i]);
        }
    }

    void set(int x) {
        for (int i=0; i<size; i++) {
            bits[i]->set((x >> (size - i - 1)) % 2);
        }
    }

    void make_public() {
        for (auto bit : bits) {
            bit->make_public();
        }
    }

    std::vector<int> eval() {
        std::vector<int> vals;
        for (auto bit : bits) {
            vals.push_back(bit->eval());
        }
        return vals;
    }

    FieldElem & to_field_elem() {
        FieldElem *elem = &((1 << (size - 1)) * (*bits[0]));
        for (int i=1; i<size; i++) {
            elem = &(*elem + (1 << (size - i - 1)) * (*bits[i]));
        }
        FieldElem &elem_ref = *elem;
        return elem_ref;
    }

    friend FieldElem & operator>(BitArray &arr1, BitArray &arr2);
    friend FieldElem & operator<(BitArray &arr1, BitArray &arr2);
    friend FieldElem & operator>=(BitArray &arr1, BitArray &arr2);
    friend FieldElem & operator<=(BitArray &arr1, BitArray &arr2);
    friend FieldElem & operator==(BitArray &arr1, BitArray &arr2);

    friend BitArray operator^(BitArray &arr1, BitArray &arr2);
};

FieldElem & operator>(BitArray &a, BitArray &b) {
    FieldElem *out = &((1 - b[0]) * a[0]);  // most significant bit lowest
    FieldElem *equal = &(a[0] * b[0] + (1 - a[0]) * (1 - b[0]));
    for (int i=1; i<a.size; i++) {
        out = &(*out + (1 - *out) * (*equal) * ((1 - b[i]) * a[i]));
        equal = &(*equal * (a[i] * b[i] + (1 - a[i]) * (1 - b[i])));
    }
    FieldElem &out_ref = *out;
    return out_ref;
}

FieldElem & operator<(BitArray &a, BitArray &b) {
    FieldElem &out_ref = b > a;
    return out_ref;
}

FieldElem & operator==(BitArray &a, BitArray &b) {
    FieldElem *out = &(a[0] * b[0] + (1 - a[0]) * (1 - b[0]));
    for (int i=1; i<a.size; i++) {
        out = &(*out * (a[i] * b[i] + (1 - a[i]) * (1 - b[i])));
    }
    FieldElem &out_ref = *out;
    return out_ref;
}

FieldElem & operator>=(BitArray &a, BitArray &b) {
    FieldElem &agtb = a > b;
    FieldElem &out = agtb + (1 - agtb) * (a == b);
    return out;
}

FieldElem & operator<=(BitArray &a, BitArray &b) {
    FieldElem &out = b >= a;
    return out;
}

BitArray operator^(BitArray &a, BitArray &b) {
    std::vector<FieldElem *> elems;
    for (int i=0; i<a.size; i++) {
        elems.push_back(&(a[i] * (1 - b[i]) + (1 - a[i]) * b[i]));
    }
    return BitArray(a.system, elems);
}

int main()
{
  // Create zksystem
  ZKSystem system;

  BitArray a(system, "a", 8);
  BitArray b(system, "b", 8);
  BitArray c(system, "c", 8);

  BitArray key(system, "key", 8);

  auto &agtb = a > b;
  auto &bgtc = b > c;
  auto &agtc = a > c;

  auto &a_winner = agtb * agtc;
  auto &b_winner = (1 - a_winner) * bgtc;
  auto &c_winner = (1 - a_winner) * (1 - b_winner);

  auto &a_second = (1 - a_winner) * (agtb + (1 - agtb) * agtc);
  auto &b_second = (1 - b_winner) * (bgtc + (1 - bgtc) * (1 - agtb));
  auto &c_second = (1 - a_second) * (1 - b_second);

  auto &winner = 1 * a_winner + 2 * b_winner + 3 * c_winner;
  auto &price = a.to_field_elem() * a_second + b.to_field_elem() * b_second + c.to_field_elem() * c_second;

  auto ahash = a ^ key;
  auto bhash = b ^ key;
  auto chash = c ^ key;

  winner.make_public();
  ahash.make_public();
  bhash.make_public();
  chash.make_public();
  price.make_public();
  key.make_public();

  system.allocate();

  // set inputs
  a.set(5);
  b.set(12);
  c.set(14);
  key.set(1337);

  // compute intermediate variables and outputs
  int winner_output = winner.eval();
  auto ahash_output = ahash.eval();
  auto bhash_output = bhash.eval();
  auto chash_output = chash.eval();
  int price_output = price.eval();

  auto keypair = system.make_keypair();
  auto proof = system.make_proof(keypair);
  bool verified = system.verify_proof(keypair, proof);

  cout << "Verification status: " << verified << endl;
  cout << "Winner: " << winner_output << endl;
  cout << "Price: " << price_output << endl;

  cout << "ahash: ";
  for (auto val : ahash_output) {
      cout << val << ' ';
  }
  cout << endl;

  cout << "bhash: ";
  for (auto val : bhash_output) {
      cout << val << ' ';
  }
  cout << endl;

  cout << "chash: ";
  for (auto val : chash_output) {
      cout << val << ' ';
  }
  cout << endl;

  return 0;
}
