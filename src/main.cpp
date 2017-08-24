#include "cxxopts.hpp"
#include <fstream>
#include <algorithm>

#include <cryptopp/eccrypto.h>
#include <cryptopp/cryptlib.h>

#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/ecp.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include "pem.h"

#include <ctype.h>

using namespace CryptoPP;

// ---------- Helper functions ----------------
inline bool exists_file (const std::string& name)  {

    std::ifstream f(name.c_str());
    return f.good();
}

inline bool is_pem_file(const std::string& name)  {

	if(name.substr(name.find_last_of(".") + 1) == "pem") {
		return true;
	} 
	return false;
}

inline bool is_hex_string(const std::string& str)  {
    return std::all_of(str.begin(), 
                       str.end(), 
                       [](char c) { return std::isxdigit(c); }
            );
}

void print_public_key(const DL_PublicKey_EC<ECP>& key) {

    Integer x = key.GetPublicElement().x;
    Integer y = key.GetPublicElement().y;
    std::cout << "Public key (X): " << std::hex << x << std::endl;
    std::cout << "Public key (Y): " << std::hex << y << std::endl;
    std::cout << std::endl;
}

void print_private_key(const DL_PrivateKey_EC<ECP>& key) {

    Integer x = key.GetPrivateExponent();
 
    std::cout << "Private key:    " << std::hex << x << std::endl;
    std::cout << std::endl;
}

void aggree_on_shared(const DL_PrivateKey_EC<ECP>& private_key, const DL_PublicKey_EC<ECP>& other_public_key) {

    OID curve = ASN1::secp256r1();
    ECDH<ECP>::Domain domain(curve);
    DL_GroupParameters_EC<ECP> params = domain.GetGroupParameters();

    std::vector<byte> sharedKey(domain.AgreedValueLength()); 
    std::vector<byte> privateKey(domain.PrivateKeyLength()); 
    std::vector<byte> publicKey(domain.PublicKeyLength()); 
   
    params.EncodeElement(true, other_public_key.GetPublicElement(), publicKey.data());
    private_key.GetPrivateExponent().Encode(privateKey.data(),privateKey.size());

    // make an agreement
    domain.Agree(&sharedKey[0], &privateKey[0], &publicKey[0]);
    
    std::string result;
    HexEncoder encoder;
    encoder.Attach( new StringSink(result) );
    encoder.Put(sharedKey.data(), sharedKey.size());
    encoder.MessageEnd();

    std::cout << "Agreed shared secret key: " << result << std::endl;
}

void ecc_converter(const cxxopts::Options& options, const std::string& privKeyStr, const std::string& pubKeyStr) {

    // Using the same Elliptic curve.
    OID curve = ASN1::secp256r1();
    ECDH<ECP>::Domain domain(curve);
    DL_GroupParameters_EC<ECP> params = domain.GetGroupParameters();
   
    DL_PrivateKey_EC<ECP> ec_private_key;
    DL_PublicKey_EC<ECP> ec_public_key;
    // other public key is needed to make an agreement.
    DL_PublicKey_EC<ECP> ec_other_public_key;
    
    if (options.count("g")) {
        AutoSeededRandomPool prng;
        ec_private_key.Initialize(prng, curve);
        ec_private_key.MakePublicKey(ec_public_key);
        
        std::cout << "---------- Generated private/public key pair ---------" << "\n\n" ;
        print_private_key(ec_private_key);
        print_public_key(ec_public_key);
        std::cout << "\n";
        
        std::string file_name = "ecc-gen-private-key.pem";
        std::cout << "--> Saving private key to '" << file_name << "'\n";
        FileSink fs1(file_name.c_str(), true);
        PEM_Save(fs1, ec_private_key); 

        file_name = "ecc-gen-public-key.pem";
        std::cout << "--> Saving public key to  '" << file_name << "'\n";
        FileSink fs2(file_name.c_str(), true);
        PEM_Save(fs2, ec_public_key); 
        
        std::cout << "\n";
        std::cout << "Start using those keys next time." << std::endl;
        exit(0);
    }

    // ----------------- Private key ---------------
    if (options.count("p") && is_pem_file(privKeyStr)) {
        FileSource fs1(privKeyStr.c_str(), true);
        PEM_Load(fs1, ec_private_key);
    }
    else if (options.count("p") && !is_pem_file(privKeyStr)) {
        // accept only 32 bit private key 
        if (privKeyStr.size() != 64) {
            std::cerr << "Private key should be 32 bit key" << std::endl;
            exit(0);            
        }
 
        if (!is_hex_string(privKeyStr)) {
            std::cerr << "Private key should should be in HEX format!" << std::endl;
            exit(0);            
        }
        
        std::string privKeyiHexStr = "0x"+ privKeyStr;
        Integer x(privKeyiHexStr.c_str());
        ec_private_key.Initialize(params, x);
    }
    
    // -------------- other Public key --------------
    if (options.count("b") && is_pem_file(pubKeyStr)) {
        FileSource fs1(pubKeyStr.c_str(), true);
        PEM_Load(fs1, ec_other_public_key);
    }
    else if (options.count("b") && !is_pem_file(pubKeyStr)) {
        // accept only 32 bit (compressed) or 64 bit uncompressed public key 
        if (pubKeyStr.size() != 64 && pubKeyStr.size() != 128 ) {
            std::cerr << "Public key should be 32 or 64 bit key" << std::endl;
            exit(0);            
        }
        
        if (!is_hex_string(pubKeyStr)) {
            std::cerr << "Public key should should be in HEX format!" << std::endl;
            exit(0);            
        }

        ECP::Point point;
		if (pubKeyStr.size() == 64) {
            
            std::string public_point_x = "02" + pubKeyStr;
            StringSource ss(public_point_x, true, new HexDecoder);   
            params.GetCurve().DecodePoint(point, ss, ss.MaxRetrievable());
		    // ------------ put Device public point on the curve ------------  
		}
		else if (pubKeyStr.size() == 128) {
			
            Integer int_x(pubKeyStr.substr(0, 64).c_str());
            Integer int_y(pubKeyStr.substr(64, 128).c_str());
            ECP::Point qpub(int_x, int_y);
		}
        
        ec_other_public_key.Initialize(params, point);
    }
    
    if (options.count("p") && options.count("b"))  {
        // ----------------------------
        // If public and private keys are there - generate shared key
        aggree_on_shared(ec_private_key, ec_other_public_key); 
    }
    else if (options.count("p") && !options.count("b")) {
        
        std::string outfile = "ecc-private-key.pem";
        if (options.count("o")) 
            outfile = options["o"].as<std::string>();

        std::cout << "--> Saving private key to '" << outfile << "'\n";
        FileSink fs(outfile.c_str(), true);
        PEM_Save(fs, ec_private_key);  

        print_private_key(ec_private_key);
        
    }
    else if (!options.count("p") && options.count("b")) {
        std::string outfile = "ecc-public-key.pem";
        if (options.count("o")) 
            outfile = options["o"].as<std::string>();
        
        std::cout << "--> Saving public key to  '" << outfile << "'\n";
        FileSink fs(outfile.c_str(), true);
        PEM_Save(fs, ec_other_public_key);         
        
        print_public_key(ec_other_public_key);
    }
}

int main(int argc, char* argv[])
{
    cxxopts::Options options(argv[0], "Convert HEX keys from/to PEM and generate agreement/shared key.");
    options.positional_help("[optional args]");
    
    std::string privKeyStr;
    std::string pubKeyStr;
    
    try {
        options.add_options()
        ("h, help", "Help for providing arguments to the program")
        ("g, generate", "Generate private public key pair and save to PEM files")
        ("p, private", "Private key in hex or in PEM file", cxxopts::value<std::string>(privKeyStr), "FILE/HEX")
        ("b, public",  "Public key in hex or in PEM file", cxxopts::value<std::string>(pubKeyStr), "FILE/HEX")
        ("o, output",  "Output file for private/public/shared key", cxxopts::value<std::string>(), "FILE")
        ;
        
        options.parse(argc, argv);

        if (options.count("help")) {
            std::cout << options.help({"", "Group"}) << std::endl;
            exit(0);
        }
        
    }
    catch (const cxxopts::OptionException& e) {
        std::cout << "error parsing options: " << e.what() << std::endl;
        exit(1);
    }

    ecc_converter(options, privKeyStr, pubKeyStr);

    return 0;
}
