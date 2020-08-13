#include <string>

#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/rand.h"
#include "openssl/x509v3.h"

#include "common/common/utility.h"

#include "extensions/transport_sockets/tls/crt_generator.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

Envoy::Extensions::TransportSockets::
Tls::CrtGenerator::CrtGenerator(std::string ca_key_path, std::string ca_crt_path) : 
ca_key_path_(ca_key_path), ca_crt_path_(ca_crt_path) {
    this->loadRootCaKeyAndCrt();
    this->ca_crt = NULL;
    this->ca_key = NULL;
}

Envoy::Extensions::TransportSockets::Tls::CrtGenerator::~CrtGenerator() {
    X509_free(this->ca_crt);
	EVP_PKEY_free(this->ca_key);
}

int Envoy::Extensions::TransportSockets::Tls::CrtGenerator::loadRootCaKeyAndCrt() {
    BIO *bio = NULL;
	
	/* Load CA public key. */
	bio = BIO_new(BIO_s_file());
	if (!BIO_read_filename(bio, this->ca_crt_path_.c_str())) goto err;
	this->ca_crt = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (!this->ca_crt) goto err;
	BIO_free_all(bio);

	/* Load CA private key. */
	bio = BIO_new(BIO_s_file());
	if (!BIO_read_filename(bio, this->ca_key_path_.c_str())) goto err;
	this->ca_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	if (!this->ca_key) goto err;
	BIO_free_all(bio);
	std::cerr << "--->> rootCA key and crt loaded successfully\n" << std::flush;
	return 1;
err:
	BIO_free_all(bio);
	//X509_free(this->ca_crt);
	//EVP_PKEY_free(this->ca_key);
	ENVOY_LOG_MISC(debug, "--->> rootCA key and crt failed to load!");
	std::cerr << "--->> rootCA key and crt failed to load!\n" << std::flush;
	return 0;
}

int Envoy::Extensions::TransportSockets::Tls::CrtGenerator::generateCrtAndKey(EVP_PKEY **key, X509 **crt, const char *common_name) {
    /* Generate the private key and corresponding CSR. */
	X509_REQ *req = NULL;
	if (!this->generateCsr(key, &req, common_name)) {
		fprintf(stderr, "Failed to generate key and/or CSR!\n");
		return 0;
	}

	EVP_PKEY *req_pubkey = NULL;
	/* Sign with the CA. */
	*crt = X509_new();
	if (!*crt) goto err;

	X509_set_version(*crt, 2); /* Set version to X509v3 */

	/* Generate random 20 byte serial. */
	if (!this->generateSetRandomSerial(*crt)) goto err;

	/* Set issuer to CA's subject. */
	X509_set_issuer_name(*crt, X509_get_subject_name(ca_crt));

	/* Set validity of certificate to 2 years. */
	X509_gmtime_adj(X509_get_notBefore(*crt), 0);
	X509_gmtime_adj(X509_get_notAfter(*crt), static_cast<long>(2*365*3600));

	/* Get the request's subject and just use it (we don't bother checking it since we generated
	 * it ourself). Also take the request's public key. */
	X509_set_subject_name(*crt, X509_REQ_get_subject_name(req));
	req_pubkey = X509_REQ_get_pubkey(req);
	X509_set_pubkey(*crt, req_pubkey);
	EVP_PKEY_free(req_pubkey);

	/* Now perform the actual signing with the CA. */
	if (X509_sign(*crt, ca_key, EVP_sha256()) == 0) goto err;

	X509_REQ_free(req);
	return 1;
err:
	EVP_PKEY_free(*key);
	X509_REQ_free(req);
	X509_free(*crt);
	return 0;
}

int Envoy::Extensions::TransportSockets::Tls::CrtGenerator::generateCsr(EVP_PKEY **key, X509_REQ **req, const char* common_name) {
    *key = NULL;
	*req = NULL;
	RSA *rsa = NULL;
	BIGNUM *e = NULL;
   	X509_NAME *name = NULL;

	*key = EVP_PKEY_new();
	if (!*key) goto err;
	*req = X509_REQ_new();
	if (!*req) goto err;
	rsa = RSA_new();
	if (!rsa) goto err;
	e = BN_new();
	if (!e) goto err;

	BN_set_word(e, 65537);
	if (!RSA_generate_key_ex(rsa, 2048, e, NULL)) goto err;
	if (!EVP_PKEY_assign_RSA(*key, rsa)) goto err;

	X509_REQ_set_pubkey(*req, *key);

	/* Set the DN of the request. */
	name = X509_REQ_get_subject_name(*req);
	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,  reinterpret_cast<const unsigned char*>("US"), -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC,  reinterpret_cast<const unsigned char*>("CA"), -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC,  reinterpret_cast<const unsigned char*>(""), -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,  reinterpret_cast<const unsigned char*>("TraceData"), -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC,  reinterpret_cast<const unsigned char*>(""), -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,  reinterpret_cast<const unsigned char*>(common_name), -1, -1, 0);

	/* Self-sign the request to prove that we posses the key. */
	if (!X509_REQ_sign(*req, *key, EVP_sha256())) goto err;

	BN_free(e);

	return 1;
err:
	EVP_PKEY_free(*key);
	X509_REQ_free(*req);
	RSA_free(rsa);
	BN_free(e);
	return 0;
}

int Envoy::Extensions::TransportSockets::Tls::CrtGenerator::generateSetRandomSerial(X509 *crt) {
    /* Generates a 20 byte random serial number and sets in certificate. */
	unsigned char serial_bytes[20];
	if (RAND_bytes(serial_bytes, sizeof(serial_bytes)) != 1) return 0;
	serial_bytes[0] &= 0x7f; /* Ensure positive serial! */
	BIGNUM *bn = BN_new();
	BN_bin2bn(serial_bytes, sizeof(serial_bytes), bn);
	ASN1_INTEGER *serial = ASN1_INTEGER_new();
	BN_to_ASN1_INTEGER(bn, serial);

	X509_set_serialNumber(crt, serial); // Set serial.

	ASN1_INTEGER_free(serial);
	BN_free(bn);
	return 1;
}

} // Tls
} // TransportSockets
} // Extensions
} // Envoy