#pragma once
#define NOMINMAX
#include <Windows.h>
#include <string>
#include <iostream>
#include <vector>
#include <string_view>
#include <set>
#include <algorithm>

typedef unsigned char byte;

// One matched string, with enough context to explain *why* it matched.
struct PatternHit {
    uintptr_t address = 0;
    std::string pattern;   // the ASCII pattern text that was matched
    bool wasUtf16 = false; // true if it matched the UTF-16LE-expanded form
    bool wasBoundary = false;
};

// Builds the UTF-16LE byte encoding of an ASCII pattern (each char -> char,0x00).
static std::vector<char> toUtf16LeBytes(std::string_view ascii) {
    std::vector<char> out;
    out.reserve(ascii.size() * 2);
    for (unsigned char c : ascii) {
        out.push_back(static_cast<char>(c));
        out.push_back('\0');
    }
    return out;
}

// Scans hProcess's committed, readable memory for each pattern in `patterns`.
static std::vector<PatternHit> pattern_scan(HANDLE hProcess, const std::vector<std::string_view>& patterns) {
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);

    struct Encoded {
        std::string_view ascii;
        std::vector<char> utf16;
    };
    std::vector<Encoded> encoded;
    encoded.reserve(patterns.size());
    size_t maxPatternLen = 0;
    for (const auto& p : patterns) {
        encoded.push_back({ p, toUtf16LeBytes(p) });
        maxPatternLen = std::max({ maxPatternLen, p.size(), encoded.back().utf16.size() });
    }

    std::set<uintptr_t> foundAddresses;
    std::vector<PatternHit> results;
    MEMORY_BASIC_INFORMATION memInfo;
    BYTE* address = (BYTE*)sys_info.lpMinimumApplicationAddress;
    std::vector<BYTE> carry;
    uintptr_t carryEndAddr = 0;

    auto reportHit = [&](uintptr_t addr, std::string_view patternText, bool isUtf16, bool isBoundary) {
        if (!foundAddresses.insert(addr).second) return;
        std::cout << "[*] Found string \"" << patternText << "\""
                   << (isUtf16 ? " (utf16)" : "")
                   << (isBoundary ? " (boundary)" : "")
                   << " at " << std::hex << std::uppercase << addr << std::dec << "\n";
        results.push_back(PatternHit{ addr, std::string(patternText), isUtf16, isBoundary });
    };

    while (address < sys_info.lpMaximumApplicationAddress && VirtualQueryEx(hProcess, address, &memInfo, sizeof(memInfo))) {
        bool readableProtect = (memInfo.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE |
                                                     PAGE_READONLY | PAGE_EXECUTE_READ |
                                                     PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) != 0
                                && !(memInfo.Protect & PAGE_GUARD);
        bool scannable = memInfo.State == MEM_COMMIT && readableProtect &&
            (memInfo.Type == MEM_PRIVATE || memInfo.Type == MEM_MAPPED || memInfo.Type == MEM_IMAGE);

        if (scannable) {
            std::vector<BYTE> buffer(memInfo.RegionSize);
            SIZE_T bytesRead;
            if (ReadProcessMemory(hProcess, memInfo.BaseAddress, buffer.data(), buffer.size(), &bytesRead)) {
                if (!carry.empty() && maxPatternLen > 1) {
                    size_t seamLen = std::min((size_t)buffer.size(), maxPatternLen - 1);
                    std::vector<BYTE> seam(carry);
                    seam.insert(seam.end(), buffer.begin(), buffer.begin() + seamLen);
                    std::string_view seamView(reinterpret_cast<char*>(seam.data()), seam.size());
                    for (const auto& enc : encoded) {
                        size_t pos = 0;
                        while ((pos = seamView.find(enc.ascii, pos)) != std::string_view::npos) {
                            reportHit(carryEndAddr - carry.size() + pos, enc.ascii, false, true);
                            ++pos;
                        }
                        if (!enc.utf16.empty()) {
                            std::string_view u16View(enc.utf16.data(), enc.utf16.size());
                            pos = 0;
                            while ((pos = seamView.find(u16View, pos)) != std::string_view::npos) {
                                reportHit(carryEndAddr - carry.size() + pos, enc.ascii, true, true);
                                ++pos;
                            }
                        }
                    }
                }

                std::string_view view(reinterpret_cast<char*>(buffer.data()), bytesRead);
                for (const auto& enc : encoded) {
                    size_t pos = 0;
                    while ((pos = view.find(enc.ascii, pos)) != std::string_view::npos) {
                        reportHit(reinterpret_cast<uintptr_t>(memInfo.BaseAddress) + pos, enc.ascii, false, false);
                        ++pos;
                    }
                    if (!enc.utf16.empty()) {
                        std::string_view u16View(enc.utf16.data(), enc.utf16.size());
                        pos = 0;
                        while ((pos = view.find(u16View, pos)) != std::string_view::npos) {
                            reportHit(reinterpret_cast<uintptr_t>(memInfo.BaseAddress) + pos, enc.ascii, true, false);
                            ++pos;
                        }
                    }
                }

                if (maxPatternLen > 1) {
                    size_t tailLen = std::min((size_t)buffer.size(), maxPatternLen - 1);
                    carry.assign(buffer.end() - tailLen, buffer.end());
                    carryEndAddr = reinterpret_cast<uintptr_t>(memInfo.BaseAddress) + buffer.size();
                } else {
                    carry.clear();
                }
            } else {
                carry.clear();
            }
        } else {
            carry.clear();
        }
        address = (BYTE*)(memInfo.BaseAddress) + memInfo.RegionSize;
    }
    return results;
}
