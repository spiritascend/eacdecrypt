#include <vector>
#include <Windows.h>
#include <cctype>


bool matchPattern(const uint8_t* data, const std::vector<int>& pattern) {
    for (size_t i = 0; i < pattern.size(); ++i) {
        if (pattern[i] != -1 && data[i] != pattern[i]) {
            return false;
        }
    }
    return true;
}

std::vector<int> parsePattern(const char* idaSignature) {
    std::vector<int> pattern;
    size_t len = std::strlen(idaSignature);

    for (size_t i = 0; i < len;) {
        if (idaSignature[i] == '?') {
            pattern.push_back(-1);
            if (i + 1 < len && idaSignature[i + 1] == '?') {
                ++i;
            }
        }
        else if (std::isxdigit(idaSignature[i])) {
            unsigned int byte;
            sscanf_s(&idaSignature[i], "%2x", &byte);
            pattern.push_back(static_cast<int>(byte));
            i++;
        }
        i++;
    }
    return pattern;
}

static ULONG64 findPattern(ULONG64 baseAddress, const char* idaSignature, bool isrelative = false, int relativeoffset = 0) {
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)baseAddress;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(baseAddress + dosHeader->e_lfanew);

    SIZE_T size = ntHeaders->OptionalHeader.SizeOfImage;

    const size_t chunkSize = static_cast<size_t>(1 * 1024) * 1024;
    std::vector<uint8_t> buffer(chunkSize);

    std::vector<int> pattern = parsePattern(idaSignature);

    ULONG64 currentAddress = baseAddress;
    size_t remainingSize = size;

    while (remainingSize > 0) {
        size_t toRead = min(chunkSize, remainingSize);

        memcpy(buffer.data(), reinterpret_cast<void*>(currentAddress), toRead);

        for (size_t i = 0; i <= toRead - pattern.size(); ++i) {
            if (matchPattern(&buffer[i], pattern)) {
                if (isrelative) {
                    ULONG64 foundAddress = currentAddress + i;
                    int32_t offset = 0;
                    memcpy(&offset, reinterpret_cast<void*>(foundAddress + relativeoffset), sizeof(offset));
                    return foundAddress + relativeoffset + 4 + offset;
                }
                return currentAddress + i;
            }
        }

        currentAddress += toRead;
        remainingSize -= toRead;
    }

    return 0;
}

