#include <openssl/sha.h>
#include <iostream>
#include <string.h>
#include <sstream>
#include <iomanip>
#include <vector>

using namespace std;

std::vector<unsigned char> hexToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = (unsigned char)strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

std::vector<unsigned char> sha256(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), hash.data());
    return hash;
}

std::string base58Encode(const std::vector<unsigned char>& input) {
    const std::string base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    std::vector<int> zeros;
    for (unsigned char c : input) {
        if (c == 0) {
            zeros.push_back(1);
        }
        else {
            break;
        }
    }
    std::vector<int> result;
    for (unsigned char c : input) {
        int carry = c;
        for (size_t j = 0; j < result.size(); ++j) {
            carry += result[j] << 8;
            result[j] = carry % 58;
            carry /= 58;
        }
        while (carry > 0) {
            result.push_back(carry % 58);
            carry /= 58;
        }
    }
    for (int i : zeros) {
        result.push_back(0);
    }
    std::string output;
    for (auto it = result.rbegin(); it != result.rend(); ++it) {
        output += base58Alphabet[*it];
    }
    return output;
}


class PrivateKey {
public:
    PrivateKey(unsigned char ibuf[]){
        SHA256(ibuf, strlen((char*)ibuf), key);
        WIF =  GenerateUWIFkey();
    }
    std::string GenerateUWIFkey() 
    {
        std::stringstream ss;
        ss << std::hex;
        for (int i(0); i < 32; ++i)
            ss << std::setw(2) << std::setfill('0') << (int)key[i];
        std::string wif;
        auto privateKeyBytes = hexToBytes(ss.str());
        privateKeyBytes.insert(privateKeyBytes.begin(), 0x80);
        auto hash1 = sha256(privateKeyBytes);
        auto hash2 = sha256(hash1);
        privateKeyBytes.insert(privateKeyBytes.end(), hash2.begin(), hash2.begin() + 4);
        wif = base58Encode(privateKeyBytes);
        return wif;
    }
    unsigned char* getKey() {
        return key;
    }
    std::string getWIF() {
        return WIF;
    }
private:
    unsigned char key[32];
    std::string compressedWIF;
    std::string WIF;

};
class PublicKey {

};
class P2PKH {

};
class P2SH {

};
class BECH32 {

};


int main()
{
    unsigned char ibuf[] = "bitcoin is awesome";
    PrivateKey PK(ibuf);
    std::cout << "PrivateKey: ";
    for (int j = 0; j < 32; j++) {
        printf("%02x", PK.getKey()[j]);
    }
    printf("\n");
    std::cout << "WIF: ";
    std::cout << PK.getWIF();
}

