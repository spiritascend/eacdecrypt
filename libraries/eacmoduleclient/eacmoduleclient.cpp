#include "eacmoduleclient.h"
#include <thread>
#include "..\xmem\xmem.hpp"


size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t totalSize = size * nmemb;
    std::vector<uint8_t>* buffer = static_cast<std::vector<uint8_t>*>(userp);
    buffer->insert(buffer->end(), static_cast<uint8_t*>(contents), static_cast<uint8_t*>(contents) + totalSize);
    return totalSize;
}

EACModuleClient::EACModuleClient(const std::string& url) : url_(url) {}

void EACModuleClient::logError(const std::string& message) {
    std::cerr << "[Error] " << message << std::endl;
}



bool EACModuleClient::downloadModule(std::vector<uint8_t>& buffer) {
    CURL* curl;
    CURLcode res;



    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (!curl) {
        logError("Failed to initialize CURL.");
        curl_global_cleanup();
        return false;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url_.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        logError("CURL perform failed: " + std::string(curl_easy_strerror(res)));
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return false;
    }

    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return true;
}

std::vector<uint8_t> EACModuleClient::decryptModuleBuff(std::vector<uint8_t>& encryptedBuffer) {
    size_t size = encryptedBuffer.size();

    if (size <= 1) {
        return {};
    }

    encryptedBuffer[size - 1] += 3 - 3 * size;

    for (size_t i = size - 2; i > 0; --i) {
        encryptedBuffer[i] += (-3 * static_cast<int32_t>(i)) - encryptedBuffer[i + 1];
    }

    encryptedBuffer[0] -= encryptedBuffer[1];


    return std::move(encryptedBuffer);
}




HANDLE EACModuleClient::reflectiveLoadLibrary(const BYTE* dllBuffer, size_t size) {
    typedef BOOL(WINAPI* DllMainFunc)(HINSTANCE, DWORD, LPVOID);

    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)dllBuffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        logError("Invalid DOS signature.");
        return NULL;
    }

    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(dllBuffer + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        logError("Invalid NT signature.");
        return NULL;
    }

    uintptr_t actualBase = (uintptr_t)VirtualAlloc(NULL, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!actualBase) {
        logError("VirtualAlloc failed.");
        return NULL;
    }

    memcpy((void*)actualBase, dllBuffer, ntHeaders->OptionalHeader.SizeOfHeaders);

    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeaders);
    for (unsigned i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        if (section->SizeOfRawData > 0) {
            memcpy((void*)(actualBase + section->VirtualAddress), (void*)(dllBuffer + section->PointerToRawData), section->SizeOfRawData);
        }
    }


    uintptr_t delta = actualBase - ntHeaders->OptionalHeader.ImageBase;
    if (delta != 0 && ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)(actualBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        IMAGE_BASE_RELOCATION* relocEnd = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

        while (reloc < relocEnd && reloc->SizeOfBlock) {
            DWORD relocCount = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* relocData = (WORD*)(reloc + 1);
            for (DWORD i = 0; i < relocCount; i++) {
                WORD type = relocData[i] >> 12;
                WORD offset = relocData[i] & 0xFFF;
                if (type == IMAGE_REL_BASED_HIGHLOW) {
                    *(DWORD*)(actualBase + reloc->VirtualAddress + offset) += (DWORD)delta;
                }
                else if (type == IMAGE_REL_BASED_DIR64) {
                    *(ULONGLONG*)(actualBase + reloc->VirtualAddress + offset) += (ULONGLONG)delta;
                }
            }
            reloc = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc + reloc->SizeOfBlock);
        }
    }



    if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        IMAGE_IMPORT_DESCRIPTOR* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)(actualBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (importDesc->Name) {
            char* moduleName = (char*)(actualBase + importDesc->Name);
            HMODULE hModule = LoadLibraryA(moduleName);
            if (!hModule) {
                logError("Failed to load imported module: " + std::string(moduleName));
                VirtualFree((LPVOID)actualBase, 0, MEM_RELEASE);
                return NULL;
            }

            IMAGE_THUNK_DATA* originalFirstThunk = (IMAGE_THUNK_DATA*)(actualBase + importDesc->OriginalFirstThunk);
            IMAGE_THUNK_DATA* firstThunk = (IMAGE_THUNK_DATA*)(actualBase + importDesc->FirstThunk);
            while (originalFirstThunk->u1.AddressOfData) {
                FARPROC procAddress = NULL;
                if (originalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    procAddress = GetProcAddress(hModule, (LPCSTR)(originalFirstThunk->u1.Ordinal & 0xFFFF));
                }
                else {
                    IMAGE_IMPORT_BY_NAME* importByName = (IMAGE_IMPORT_BY_NAME*)(actualBase + originalFirstThunk->u1.AddressOfData);
                    procAddress = GetProcAddress(hModule, importByName->Name);
                }

                if (!procAddress) {
                    logError("Failed to get procedure address.");
                    VirtualFree((LPVOID)actualBase, 0, MEM_RELEASE);
                    return NULL;
                }

                firstThunk->u1.Function = (uintptr_t)procAddress;
                originalFirstThunk++;
                firstThunk++;
            }
            importDesc++;
        }
    }

    DWORD entryPointRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    if (entryPointRVA != 0) {
        DllMainFunc dllMain = (DllMainFunc)(actualBase + entryPointRVA);
        if (dllMain && !dllMain((HINSTANCE)actualBase, DLL_PROCESS_ATTACH, NULL)) {
            logError("DllMain failed during process attach.");
            VirtualFree((LPVOID)actualBase, 0, MEM_RELEASE);
            return NULL;
        }
    }


    return (HANDLE)actualBase;
}


bool EACModuleClient::freeReflectiveModule() {
    if (!hModule_) return false;

    typedef BOOL(WINAPI* DllMainFunc)(HINSTANCE, DWORD, LPVOID);

    BYTE* baseAddress = (BYTE*)hModule_;
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)baseAddress;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(baseAddress + dosHeader->e_lfanew);

    SIZE_T moduleSize = ntHeaders->OptionalHeader.SizeOfImage;

    DWORD entryPointRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    if (entryPointRVA != 0) {
        DllMainFunc dllMain = (DllMainFunc)(baseAddress + entryPointRVA);
        if (dllMain) {
            dllMain((HINSTANCE)hModule_, DLL_PROCESS_DETACH, NULL);
        }
    }

    if (!VirtualFree(hModule_, 0, MEM_RELEASE)) {
        logError("Failed to release memory.");
        return false;
    }

    hModule_ = NULL;
    return true;
}

bool EACModuleClient::IsValid(const unsigned char* buffer, size_t size)
{
    if (size < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }

    const IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer);


    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }

    if (size < dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)) {
        return false;
    }

    const IMAGE_NT_HEADERS* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(buffer + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    if (ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
        ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return false;
    }

    if (!(ntHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL)) {
        return false;
    }
    return true;
}

bool EACModuleClient::processModule() {
    std::vector<uint8_t> encryptedModuleBuffer;

    if (!downloadModule(encryptedModuleBuffer)) {
        logError("Failed to fetch encrypted EAC module.");
        return false;
    }


    std::vector<uint8_t> decryptedBuffer = decryptModuleBuff(encryptedModuleBuffer);
    if (decryptedBuffer.empty()) {
        logError("Failed to decrypt module.");
        return false;
    }

    if (!IsValid(decryptedBuffer.data(), decryptedBuffer.size())) {
        logError("Decrypted Launcher Module is not a DLL.");
        freeReflectiveModule();
        return false;
    }


    hModule_ = reflectiveLoadLibrary(decryptedBuffer.data(), decryptedBuffer.size());
    if (!hModule_) {
        logError("failed to reflectively load library.");
        return false;
    }

    uint8_t* embeddedUserModeDllSizePtr = (uint8_t*)findPattern((ULONG64)hModule_, "8B 15 ? ? ? ? 48 89", true, 2);


    if (!embeddedUserModeDllSizePtr) {
        logError("Failed to locate the size of the embedded EAC_UserMode.dll in the module.");
        freeReflectiveModule();
        return false;
    }

    int embeddedUserModeDllSize = *reinterpret_cast<int*>(embeddedUserModeDllSizePtr);


    uint8_t* userModeDllEncryptedPtr = (uint8_t*)findPattern((ULONG64)hModule_, "48 8D 05 ? ? ? ? 89 54", true, 3);
    if (!userModeDllEncryptedPtr) {
        logError("Failed to locate encrypted EAC_UserMode.dll in the module.");
        freeReflectiveModule();
        return false;
    }

    std::vector<uint8_t> encryptedUserModeDll(embeddedUserModeDllSize);
    std::memcpy(encryptedUserModeDll.data(), userModeDllEncryptedPtr, embeddedUserModeDllSize);

    std::vector<uint8_t> decryptedUserModeDll = decryptModuleBuff(encryptedUserModeDll);
    if (decryptedUserModeDll.empty()) {
        logError("Failed to decrypt EAC_UserMode.dll.");
        freeReflectiveModule();
        return false;
    }

    if (!IsValid(decryptedUserModeDll.data(), decryptedUserModeDll.size())) {
        logError("Decrypted UserMode Module is not a DLL.");
        freeReflectiveModule();
        return false;
    }

    decryptedUserModeDll_ = decryptedUserModeDll;

    if (!freeReflectiveModule()) {
        logError("Failed to free reflective module.");
        return false;
    }

    return true;
}

const std::vector<uint8_t>& EACModuleClient::getDecryptedUserModeDll() const {
    return decryptedUserModeDll_;
}