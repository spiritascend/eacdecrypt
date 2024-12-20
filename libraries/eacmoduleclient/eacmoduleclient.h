#define CURL_STATICLIB


#include "..\curl\curl.h"
#include <iostream>
#include <vector>
#include <chrono>
//#include "..\capstone\capstone.h"

#pragma comment(lib, "libcurl_a.lib")
#pragma comment(lib, "Normaliz.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Wldap32.lib")
#pragma comment(lib, "Crypt32.lib")
//#pragma comment(lib, "..\\capstone\\capstone.lib")


class EACModuleClient {
public:
    explicit EACModuleClient(const std::string& url);
    bool processModule();

    const std::vector<uint8_t>& getDecryptedUserModeDll() const;

private:
    std::string url_;
    std::vector<uint8_t> decryptedUserModeDll_;
    HANDLE hModule_ = NULL;


    bool downloadModule(std::vector<uint8_t>& buffer);

    std::vector<uint8_t> decryptModuleBuff(std::vector<uint8_t>& encryptedBuffer);

    HANDLE reflectiveLoadLibrary(const BYTE* dllBuffer, size_t size);

    bool freeReflectiveModule();

    bool IsValid(const unsigned char* buffer, size_t size);

    void logError(const std::string& message);
};


