//  Enclave policy file. Determines which enclaves are accepted by the
//  service provider (after their quote data has been verified).
//
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//  This file is generated from policy.in after the signed enclave file is
//  created. MRSIGNER is calculated from Enclave.signed.so, and the
//  other values are hardcoded.
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

// This hex string should match the signer of the enclave. This is used to
// prevents unauthorized enclaves (those from unrecognized ISVs/developers)
// from using the remote service.
#define MRSIGNER "@MRSIGNER@"

 // The product ID for the enclave. This must match the ProdId in the
 // enclave configuration file.
#define SERVICE_PRODID 0

#define PROVISIONING_SERVICE_PRODID 1

// The ISV software version number (ISV SVN) must be >= this value. This
// allows service providers to enforce a minimum enclave version to utilize
// the remote service. ISV SVN is set in the enclave configuration file.
#define MIN_ISVSVN 1

// Set to 1 to allow enclaves compiled in DEBUG mode (this sample code uses
// debug mode). Otherwise, set to 0 to force only production (non-debuggable)
// enclaves. A production service should never allow debug-mode enclaves.
#define ALLOW_DEBUG 1
