#include <nan.h>
#include <node_buffer.h>
#include <node_api.h>
#include <stdint.h>
#include "crypto/equihash.h"


#include <vector>


int verifyEH(const char *hdr, const std::vector<unsigned char> &soln, unsigned int n = 200, unsigned int k = 9){
  // Hash state
  crypto_generichash_blake2b_state state;
  EhInitialiseState(n, k, state);

  crypto_generichash_blake2b_update(&state, (const unsigned char*)hdr, 140);

  bool isValid;
  if (n == 96 && k == 3) {
      isValid = Eh96_3.IsValidSolution(state, soln);
  } else if (n == 200 && k == 9) {
      isValid = Eh200_9.IsValidSolution(state, soln);
  } else if (n == 144 && k == 5) {
      isValid = Eh144_5.IsValidSolution(state, soln);
  } else if (n == 192 && k == 7) {
      isValid = Eh192_7.IsValidSolution(state, soln);
  } else if (n == 96 && k == 5) {
      isValid = Eh96_5.IsValidSolution(state, soln);
  } else if (n == 48 && k == 5) {
      isValid = Eh48_5.IsValidSolution(state, soln);
  } else {
      throw std::invalid_argument("Unsupported Equihash parameters");
  }
  
  return isValid;
}


napi_value Verify(napi_env env, napi_callback_info info) {
    napi_status status;
    size_t argc = 4;
    napi_value args[4];
    status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);

    if (status != napi_ok || argc < 2) {
        napi_throw_type_error(env, nullptr, "Wrong number of arguments");
        return nullptr;
    }

    // Check if the arguments are buffers
    bool isBuffer;
    size_t bufferLength;
    void* bufferData;

    // Header buffer
    status = napi_is_buffer(env, args[0], &isBuffer);
    if (!isBuffer || status != napi_ok) {
        napi_throw_type_error(env, nullptr, "First argument must be a buffer");
        return nullptr;
    }
    status = napi_get_buffer_info(env, args[0], &bufferData, &bufferLength);
    if (status != napi_ok || bufferLength != 140) {
        napi_throw_error(env, nullptr, "Invalid header buffer");
        return nullptr;
    }
    const char *hdr = static_cast<const char*>(bufferData);

    // Solution buffer
    status = napi_is_buffer(env, args[1], &isBuffer);
    if (!isBuffer || status != napi_ok) {
        napi_throw_type_error(env, nullptr, "Second argument must be a buffer");
        return nullptr;
    }
    status = napi_get_buffer_info(env, args[1], &bufferData, &bufferLength);
    if (status != napi_ok) {
        napi_throw_error(env, nullptr, "Invalid solution buffer");
        return nullptr;
    }
    const char *soln = static_cast<const char*>(bufferData);
    std::vector<unsigned char> vecSolution(soln, soln + bufferLength);

    // n and k values
    unsigned int n = 200, k = 9;
    if (argc == 4) {
        uint32_t temp;
        status = napi_get_value_uint32(env, args[2], &temp);
        n = static_cast<unsigned int>(temp);
        status = napi_get_value_uint32(env, args[3], &temp);
        k = static_cast<unsigned int>(temp);
    }

    bool result = verifyEH(hdr, vecSolution, n, k);
    napi_value returnValue;
    status = napi_get_boolean(env, result, &returnValue);
    return returnValue;
}


napi_value Init(napi_env env, napi_value exports) {
    napi_status status;
    napi_value fn;

    status = napi_create_function(env, nullptr, 0, Verify, nullptr, &fn);
    if (status != napi_ok) {
        napi_throw_error(env, nullptr, "Failed to create function");
        return nullptr;
    }

    status = napi_set_named_property(env, exports, "verify", fn);
    if (status != napi_ok) {
        napi_throw_error(env, nullptr, "Failed to set property");
        return nullptr;
    }

    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)