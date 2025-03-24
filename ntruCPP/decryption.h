#pragma once
#include "polynomial.h"
#include "params.h"
#include "keypair.h"

Polynomial decrypt(const Polynomial& ciphertext,
                  const KeyPair& keys,
                  const NTRUParams& params); // Declaration only