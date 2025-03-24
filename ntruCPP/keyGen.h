// keyGen.h
#pragma once
#include "params.h"
#include "polynomial.h"
#include "keypair.h"

// Key generation function declaration
KeyPair generate_keys(const NTRUParams& params);
