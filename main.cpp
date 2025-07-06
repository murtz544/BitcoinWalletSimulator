#include <iostream>
#include <openssl/evp.h>
#include <cstring>

int main() {
    const char* passphrase = "testpassphrase";
    const char* salt = "testsalt";
    unsigned char key[64];
    int iterations = 2048;

    int result = PKCS5_PBKDF2_HMAC(
        passphrase, strlen(passphrase),
        reinterpret_cast<const unsigned char*>(salt), strlen(salt),
        iterations, EVP_sha512(),
        sizeof(key), key
    );

    if (result != 1) {
        std::cerr << "Error in PBKDF2" << std::endl;
        return 1;
    }

    for (int i = 0; i < sizeof(key); i++)
        printf("%02x", key[i]);
    printf("\n");

    return 0;
}
