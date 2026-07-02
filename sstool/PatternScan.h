#pragma once
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string>
#include <iostream>
#include <vector>
#include <string_view>
#include <set>
#include <algorithm>
#include <cstdint>

// One matched string, with enough context to explain *why* it matched.
struct PatternHit {
    uintptr_t address = 0;
    std::string pattern;   // the ASCII pattern text that was matched
    bool wasUtf16 = false; // true if it matched the UTF-16LE-expanded form
    bool wasBoundary = false;
};

// Builds the UTF-16LE byte encoding of an ASCII pattern (each char -> char,0x00).
// The JVM stores Java Strings internally as UTF-16 (or Latin-1/compact-strings
// with a similar 2-bytes-per-char layout pre-Java 9 opt-out), so plaintext
// literals baked into cheat clients frequently sit in memory as
// "A\0u\0t\0o\0C\0r\0y\0s\0t\0a\0l\0" rather than "AutoCrystal". A pure
// single-byte scanner silently misses every one of those.
static std::vector<char> toUtf16LeBytes(std::string_view ascii) {
    std::vector<char> out;
    out.reserve(ascii.size() * 2);
    for (unsigned char c : ascii) {
        out.push_back(static_cast<char>(c));
        out.push_back('\0');
    }
    return out;
}

// Scans hProcess's committed, readable memory for each pattern in `patterns`,
// in both raw ASCII/UTF-8 form and UTF-16LE form. Regions are read and
// searched independently by VirtualQueryEx, which means a pattern could be
// split across the boundary between two regions and get missed entirely by
// a naive per-region search. Since some of our patterns are long
// fully-qualified class names (50+ chars, up to 100+ bytes once doubled for
// UTF-16), this is carried over explicitly below rather than left as a
// silent gap.
std::vector<PatternHit> pattern_scan(HANDLE hProcess, const std::vector<std::string_view>& patterns) {
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);

    // Precompute both encodings once, not once per region.
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

    std::set<uintptr_t> foundAddresses; // dedupes boundary-scan vs main-scan hits, across both encodings
    std::vector<PatternHit> results;
    MEMORY_BASIC_INFORMATION memInfo;
    uint8_t* address = reinterpret_cast<uint8_t*>(sys_info.lpMinimumApplicationAddress);

    std::vector<uint8_t> carry;      // tail bytes of the previous region's buffer
    uintptr_t carryEndAddr = 0;   // address immediately after the carried bytes

    auto reportHit = [&](uintptr_t addr, std::string_view patternText, bool isUtf16, bool isBoundary) {
        if (!foundAddresses.insert(addr).second) return; // already reported (e.g. same offset in both scans)
        std::cout << "[*] Found string \"" << patternText << "\""
                   << (isUtf16 ? " (utf16)" : "")
                   << (isBoundary ? " (boundary)" : "")
                   << " at " << std::hex << std::uppercase << addr << std::dec << "\n";
        results.push_back(PatternHit{ addr, std::string(patternText), isUtf16, isBoundary });
    };

    while (address < sys_info.lpMaximumApplicationAddress && VirtualQueryEx(hProcess, address, &memInfo, sizeof(memInfo))) {
        // Widened from MEM_PRIVATE-only: class/string data relevant to a
        // loaded cheat mod can also live in MEM_MAPPED regions (e.g. memory
        // mapped from the jar/class files themselves, or mapped heap
        // segments depending on JVM/GC configuration), and mods can also be
        // patched into MEM_IMAGE-backed regions post-classload. Restricting
        // to MEM_PRIVATE was silently skipping those. PAGE_GUARD/PAGE_NOACCESS
        // pages are still excluded since ReadProcessMemory can't touch them
        // anyway.
        bool readableProtect = (memInfo.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE |
                                                     PAGE_READONLY | PAGE_EXECUTE_READ |
                                                     PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) != 0
                                && !(memInfo.Protect & PAGE_GUARD);
        bool scannable = memInfo.State == MEM_COMMIT && readableProtect &&
            (memInfo.Type == MEM_PRIVATE || memInfo.Type == MEM_MAPPED || memInfo.Type == MEM_IMAGE);

        if (scannable) {
            std::vector<uint8_t> buffer(memInfo.RegionSize);
            SIZE_T bytesRead;
            if (ReadProcessMemory(hProcess, memInfo.BaseAddress, buffer.data(), buffer.size(), &bytesRead)) {

                // 1) Boundary check: stitch the end of the previous region's
                //    buffer to the start of this one and search just that
                //    seam, so patterns split across the two regions aren't lost.
                if (!carry.empty() && maxPatternLen > 1) {
                    size_t seamLen = std::min(buffer.size(), maxPatternLen - 1);
                    std::vector<uint8_t> seam(carry);
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

                // 2) Normal in-region scan, both encodings.
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

                // carry the tail of this buffer forward for the next region's seam check
                if (maxPatternLen > 1) {
                    size_t tailLen = std::min(buffer.size(), maxPatternLen - 1);
                    carry.assign(buffer.end() - tailLen, buffer.end());
                    carryEndAddr = reinterpret_cast<uintptr_t>(memInfo.BaseAddress) + buffer.size();
                } else {
                    carry.clear();
                }
            } else {
                carry.clear(); // unreadable region breaks contiguity assumptions; don't stitch across it
            }
        } else {
            carry.clear(); // non-scannable region breaks contiguity too
        }

        address = reinterpret_cast<uint8_t*>(memInfo.BaseAddress) + memInfo.RegionSize;
    }

    return results;
}
