#pragma once

#include <string>

#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/rand.h"
#include "openssl/x509v3.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {
class CrtGenerator {
public:
CrtGenerator(std::string ca_key_path, std::string ca_crt_path);
~CrtGenerator();
int loadRootCaKeyAndCrt();
int generateCrtAndKey(EVP_PKEY **key, X509 **crt, const char *common_name);

private:
std::string ca_key_path_;
std::string ca_crt_path_;
EVP_PKEY *ca_key;
X509 *ca_crt;
int generateCsr(EVP_PKEY **key, X509_REQ **req, const char* common_name);
static int generateSetRandomSerial(X509 *crt);
};
} // Tls
} // TransportSockets
} // Extensions
} // Envoy