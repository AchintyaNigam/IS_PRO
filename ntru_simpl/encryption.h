#pragma once
#include "polynomial.h"
#include "params.h"

Polynomial encrypt(const Polynomial& message, 
                  const Polynomial& public_key,
                  const NTRUParams& params); // Declaration only


