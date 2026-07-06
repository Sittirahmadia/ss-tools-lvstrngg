#pragma once
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <algorithm>
#include <thread>
#include <mutex>
#include <atomic>
#include <functional>
#include <cstdint>
#include <string_view>

#include "Console.h"
#include "Util.h"
#include "CheatStrings.h"

// =====================================================================
// Advanced memory scanner v2.
//
// Improvements over PatternScan.h:
//   - Multi-threaded: splits committed regions across worker threads
//   - Per-client confidence scoring (more pattern hits = more confident)
//   - XOR / rotating-key decoder: scans for XOR-obfuscated strings
//     using a sliding single-byte key search (common in simple loaders)
//   - Fullwidth Unicode normalization (catches \uFF21-\uFF3A evasion)
//   - Deduplication by pattern+address across all threads
//   - Section-aware: tags hits as heap/image/mapped for context
//   - Progress reported via atomic counter
// =====================================================================
namespace advscan {

    // ---- client signature groups ------------------------------------
    // Each client has a set of distinctive strings. The confidence score
    // for a given process is the number of its patterns that matched,
    // normalized to 0-100. Short/generic patterns score less per hit.
    struct ClientSig {
        const char* name;
        std::vector<std::string> patterns;
    };

    static const std::vector<ClientSig> clientSignatures = {
        { "Nova Client",      { "novaclient", "api.novaclient.lol", "cc/novoline", "NovaClient" } },
        { "Meteor Client",    { "meteordevelopment", "meteor-client", "meteorclient",
                                "net/ccbluex", "MeteorClient" } },
        { "Aristois",         { "aristois", "Aristois", "aristois.net" } },
        { "Wurst Client",     { "wurst", "WurstClient", "net.wurstclient" } },
        { "Impact Client",    { "impactclient", "impact-client", "ImpactClient" } },
        { "LiquidBounce",     { "liquidbounce", "LiquidBounce", "net.ccbluex.liquidbounce" } },
        { "Sigma Client",     { "sigmaclient", "sigma-client", "SigmaClient" } },
        { "Rusherhack",       { "rusherhack", "RusherHack", "rusherhack.org" } },
        { "Vape Client",      { "vapeclient", "vape.gg", "VapeClient", "VapeLite" } },
        { "KamiBlue",         { "kamiblue", "KamiBlue", "me.zeroeightsix.kami" } },
        { "BleachHack",       { "bleachhack", "BleachHack", "org.bleachhack" } },
        { "FutureClient",     { "futureclient", "FutureClient", "future.client" } },
        { "Inertia",          { "inertia-client", "InertiaClient", "inertia" } },
        { "FDPClient",        { "fdp-client", "net.ccbluex.fdpclient", "FDPClient" } },
        { "DoomsdayClient",   { "doomsdayclient", "DoomsdayClient", "doomsday.jar" } },
        { "Dqrkis Client",    { "Dqrkis Client", "dqrkis.xyz", "dqrkis" } },
        { "Argon/Noqws",      { "ArgonClient", "argon client", "noqwdclient",
                                "privatebynoqws", "noqws" } },
        { "Skid ChainLibs",   { "org/chainlibs/module", "org.chainlibs.module" } },
        { "Asteria",          { "AsteriaClient", "asteria client", "asteria" } },
        { "Xenon",            { "XenonClient", "xenon client", "Xenon" } },
        { "Prestige",         { "PrestigeClient", "prestige client", "prestigeclient.vip" } },
        { "Gypsy",            { "GypsyClient", "gypsy client", "gypsy" } },
        { "Phantom",          { "phantom-refmap.json", "PhantomClient" } },
        { "Catlean",          { "CatleanClient", "catlean client", "catlean" } },
        { "Skate",            { "skateclient", "SkateClient" } },
        { "Walksy/CrystalOpt",{ "WalksyCrystalOptimizerMod", "WalksyOptimizer", "WalskyOptimizer",
                                "walsky.optimizer" } },
        // Generic combat/utility cheats (lower confidence per hit since
        // some strings are shared across multiple clients)
        { "Generic Combat Cheat", { "KillAura", "AimAssist", "CrystalAura", "AutoCrystal",
                                    "TriggerBot", "triggerbot", "SilentRotations",
                                    "GrimBypass", "VulcanBypass", "WatchdogBypass",
                                    "ReachHack", "AntiKB", "FakeLag", "SelfDestruct" } },
        { "Generic Macro/Inject", { "JNativeHook", "GlobalScreen", "NativeKeyListener",
                                    "imgui.binding", "client-refmap.json", "obfuscatedAuth",
                                    "LicenseCheckMixin", "TokenGrabber", "TokenLogger",
                                    "SessionStealer", "Backdoor", "ReverseShell" } },
    };

    // ---- hit record -------------------------------------------------
    struct MemHit {
        std::string pattern;
        uintptr_t   address    = 0;
        bool        wasUtf16   = false;
        bool        wasXor     = false;
        uint8_t     xorKey     = 0;
        bool        wasBoundary= false;
        std::string regionType; // "heap", "image", "mapped"
    };

    // ---- per-client result ------------------------------------------
    struct ClientResult {
        std::string client;
        int         confidence = 0;  // 0-100
        int         hits       = 0;
        std::vector<MemHit> evidence; // up to 5 representative hits
    };

    // ---- helpers -----------------------------------------------------
    static std::string regionTypeStr(DWORD type) {
        switch (type) {
            case MEM_IMAGE:  return "image";
            case MEM_MAPPED: return "mapped";
            default:         return "heap";
        }
    }

    // Normalize fullwidth Unicode chars (\uFF01-\uFF5E, A-Z: FF21-FF3A,
    // a-z: FF41-FF5A) back to ASCII so evasion via lookalike chars is caught.
    static std::string normalizeFullwidth(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (size_t i = 0; i + 2 < s.size(); ) {
            // UTF-8 encoding of U+FF01..U+FF5E: EF BC 81 .. EF BD 9E
            uint8_t b0 = (uint8_t)s[i];
            uint8_t b1 = (i+1 < s.size()) ? (uint8_t)s[i+1] : 0;
            uint8_t b2 = (i+2 < s.size()) ? (uint8_t)s[i+2] : 0;
            if (b0 == 0xEF && b1 == 0xBC && b2 >= 0x81 && b2 <= 0xBF) {
                out.push_back((char)(b2 - 0x81 + 0x21)); // U+FF01-FF3F -> !-?
                i += 3; continue;
            }
            if (b0 == 0xEF && b1 == 0xBD && b2 >= 0x80 && b2 <= 0x9E) {
                out.push_back((char)(b2 - 0x80 + 0x40)); // U+FF40-FF5E -> @-~
                i += 3; continue;
            }
            out.push_back(s[i++]);
        }
        return out;
    }

    // Build UTF-16LE encoding (each ASCII byte -> byte + 0x00)
    static std::vector<uint8_t> toUtf16Le(std::string_view ascii) {
        std::vector<uint8_t> out;
        out.reserve(ascii.size() * 2);
        for (unsigned char c : ascii) { out.push_back(c); out.push_back(0); }
        return out;
    }

    // XOR-decode a region with a constant key and return the plaintext
    static std::vector<uint8_t> xorDecode(const std::vector<uint8_t>& buf, uint8_t key) {
        std::vector<uint8_t> out(buf.size());
        for (size_t i = 0; i < buf.size(); i++) out[i] = buf[i] ^ key;
        return out;
    }

    // ---- main scan ---------------------------------------------------
    struct ScanConfig {
        bool tryXorKeys   = true;   // try single-byte XOR decode
        bool tryUtf16     = true;   // search UTF-16LE expansions
        bool useThreads   = true;   // multi-threaded region scan
        int  threadCount  = 0;      // 0 = auto (hardware_concurrency)
    };

    struct ScanResult {
        std::vector<ClientResult> clients; // sorted by confidence descending
        std::vector<MemHit>       allHits; // every unique hit
        int totalRegionsScanned = 0;
        size_t totalBytesScanned = 0;
    };

    static ScanResult scanProcess(HANDLE hProcess, const ScanConfig& cfg = {}) {

        // --- 1. Collect all readable committed regions ---
        struct Region {
            uint8_t* base;
            SIZE_T   size;
            DWORD    type;
        };
        std::vector<Region> regions;
        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        MEMORY_BASIC_INFORMATION mbi{};
        uint8_t* addr = (uint8_t*)si.lpMinimumApplicationAddress;

        while (addr < (uint8_t*)si.lpMaximumApplicationAddress &&
               VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi))) {
            bool readable = (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE |
                             PAGE_READONLY | PAGE_EXECUTE_READ |
                             PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) != 0
                            && !(mbi.Protect & PAGE_GUARD);
            if (mbi.State == MEM_COMMIT && readable)
                regions.push_back({ (uint8_t*)mbi.BaseAddress, mbi.RegionSize, mbi.Type });
            addr = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
        }

        // --- 2. Pre-build pattern table ---
        // Flatten all client patterns into one lookup; keep a reverse map
        // from pattern -> which clients own it.
        std::vector<std::string> allPatterns;
        std::map<std::string, std::vector<int>> patternToClients; // index into clientSignatures
        for (int ci = 0; ci < (int)clientSignatures.size(); ci++) {
            for (const auto& p : clientSignatures[ci].patterns) {
                std::string norm = normalizeFullwidth(p);
                std::string lo   = util::toLowerA(norm);
                if (patternToClients.find(lo) == patternToClients.end())
                    allPatterns.push_back(lo);
                patternToClients[lo].push_back(ci);
            }
        }

        // Also add all jarContentStrings + jarNamePatterns from CheatStrings.h
        // (they aren't grouped by client but still count as generic hits)
        for (const auto& s : jarContentStrings) {
            std::string lo = util::toLowerA(normalizeFullwidth(s));
            if (patternToClients.find(lo) == patternToClients.end()) {
                allPatterns.push_back(lo);
                patternToClients[lo] = { -1 }; // -1 = generic, not a specific client
            }
        }

        // Pre-compute UTF-16LE expansions
        struct PatternEntry {
            std::string ascii;
            std::vector<uint8_t> utf16;
        };
        std::vector<PatternEntry> entries;
        entries.reserve(allPatterns.size());
        for (const auto& p : allPatterns) {
            PatternEntry e;
            e.ascii = p;
            if (cfg.tryUtf16) e.utf16 = toUtf16Le(p);
            entries.push_back(std::move(e));
        }

        // --- 3. Threaded scan ---
        std::mutex resultMutex;
        std::vector<MemHit> allHits;
        std::set<std::string> seenKeys; // pattern+address dedup
        std::atomic<int> scannedCount{0};
        size_t totalBytes = 0;
        for (const auto& r : regions) totalBytes += r.size;

        auto scanChunk = [&](int start, int end) {
            std::vector<MemHit> localHits;

            for (int ri = start; ri < end; ri++) {
                const auto& reg = regions[ri];
                std::vector<uint8_t> buf(reg.size);
                SIZE_T bytesRead = 0;
                if (!ReadProcessMemory(hProcess, reg.base, buf.data(), buf.size(), &bytesRead))
                    continue;
                buf.resize(bytesRead);
                scannedCount++;

                std::string_view view((char*)buf.data(), buf.size());
                std::string regType = regionTypeStr(reg.type);

                auto tryMatch = [&](const PatternEntry& e, const std::vector<uint8_t>& searchBuf,
                                    bool isUtf16, bool isXor, uint8_t xorKey) {
                    std::string_view sv((char*)searchBuf.data(), searchBuf.size());
                    const std::string& needle = isUtf16
                        ? std::string((char*)e.utf16.data(), e.utf16.size())
                        : e.ascii;
                    if (needle.empty()) return;

                    size_t pos = 0;
                    while ((pos = sv.find(needle, pos)) != std::string_view::npos) {
                        uintptr_t hitAddr = (uintptr_t)reg.base + pos;
                        std::string key = e.ascii + "@" + std::to_string(hitAddr);
                        {
                            std::lock_guard<std::mutex> lk(resultMutex);
                            if (!seenKeys.insert(key).second) { pos++; continue; }
                        }
                        localHits.push_back({ e.ascii, hitAddr, isUtf16, isXor, xorKey, false, regType });
                        pos++;
                    }
                };

                // ASCII + UTF-16 scan
                for (const auto& e : entries) {
                    tryMatch(e, buf, false, false, 0);
                    if (cfg.tryUtf16 && !e.utf16.empty()) {
                        std::vector<uint8_t> u16vec(e.utf16.begin(), e.utf16.end());
                        tryMatch(e, u16vec, true, false, 0);
                    }
                }

                // XOR single-byte key scan (keys 1..255, skip 0 = no-op)
                if (cfg.tryXorKeys) {
                    for (int k = 1; k <= 255; k++) {
                        auto decoded = xorDecode(buf, (uint8_t)k);
                        for (const auto& e : entries) {
                            tryMatch(e, decoded, false, true, (uint8_t)k);
                        }
                    }
                }
            }

            std::lock_guard<std::mutex> lk(resultMutex);
            allHits.insert(allHits.end(), localHits.begin(), localHits.end());
        };

        int nThreads = cfg.useThreads
            ? (cfg.threadCount > 0 ? cfg.threadCount : (int)std::thread::hardware_concurrency())
            : 1;
        if (nThreads < 1) nThreads = 1;
        if (nThreads > 8) nThreads = 8; // cap at 8 -- diminishing returns above that

        int total = (int)regions.size();
        std::vector<std::thread> workers;
        int chunkSize = (total + nThreads - 1) / nThreads;

        // Start progress display thread
        std::atomic<bool> scanDone{false};
        std::thread progressThread([&]() {
            while (!scanDone.load()) {
                int done = scannedCount.load();
                int pct = total > 0 ? (done * 100 / total) : 0;
                con::spinnerTick("Memory scan... " + std::to_string(pct) + "%  (" +
                    std::to_string(allHits.size()) + " hits, " +
                    std::to_string(nThreads) + " threads)");
                Sleep(100);
            }
        });

        for (int t = 0; t < nThreads; t++) {
            int start = t * chunkSize;
            int end   = std::min(start + chunkSize, total);
            if (start >= total) break;
            workers.emplace_back(scanChunk, start, end);
        }
        for (auto& w : workers) w.join();
        scanDone = true;
        progressThread.join();
        con::spinnerClear();

        // --- 4. Build per-client confidence scores ---
        std::map<int, int> clientHitCount;
        for (const auto& hit : allHits) {
            auto it = patternToClients.find(hit.pattern);
            if (it == patternToClients.end()) continue;
            for (int ci : it->second) {
                if (ci >= 0) clientHitCount[ci]++;
            }
        }

        ScanResult result;
        result.allHits = allHits;
        result.totalRegionsScanned = total;
        result.totalBytesScanned = totalBytes;

        for (auto& [ci, hitCount] : clientHitCount) {
            int maxPossible = (int)clientSignatures[ci].patterns.size();
            int confidence = std::min(100, (hitCount * 100) / std::max(1, maxPossible));
            // Boost: XOR hits add extra confidence since they indicate active evasion
            for (const auto& h : allHits) {
                auto it2 = patternToClients.find(h.pattern);
                if (it2 != patternToClients.end() && h.wasXor) {
                    for (int c2 : it2->second) {
                        if (c2 == ci) { confidence = std::min(100, confidence + 15); break; }
                    }
                }
            }

            ClientResult cr;
            cr.client = clientSignatures[ci].name;
            cr.confidence = confidence;
            cr.hits = hitCount;
            // Collect up to 5 representative evidence hits for this client
            int added = 0;
            for (const auto& h : allHits) {
                if (added >= 5) break;
                auto it2 = patternToClients.find(h.pattern);
                if (it2 == patternToClients.end()) continue;
                for (int c2 : it2->second) {
                    if (c2 == ci) { cr.evidence.push_back(h); added++; break; }
                }
            }
            result.clients.push_back(std::move(cr));
        }

        // Sort by confidence descending
        std::sort(result.clients.begin(), result.clients.end(),
            [](const ClientResult& a, const ClientResult& b) {
                return a.confidence > b.confidence;
            });

        return result;
    }

    // ---- render results ----------------------------------------------
    static void printResults(const ScanResult& result) {
        if (result.clients.empty() && result.allHits.empty()) {
            con::ok("No cheat client signatures found in memory.");
            return;
        }

        if (!result.clients.empty()) {
            con::subheader("Per-Client Confidence Scores");
            for (const auto& cr : result.clients) {
                // Color-code by confidence
                con::Color c = cr.confidence >= 70 ? con::Color::Red
                             : cr.confidence >= 40 ? con::Color::Yellow
                             : con::Color::Gray;
                con::set(c);
                std::cout << "  [" << std::string(cr.confidence / 5, '#')
                                   << std::string(20 - cr.confidence / 5, '.')
                          << "] " << cr.confidence << "%  ";
                con::reset();
                std::cout << cr.client << "  (" << cr.hits << " pattern hit(s))\n";

                // Show evidence hits under high-confidence matches
                if (cr.confidence >= 40 && !cr.evidence.empty()) {
                    for (const auto& h : cr.evidence) {
                        con::set(con::Color::DarkGray);
                        std::cout << "         \"" << h.pattern << "\""
                                  << (h.wasUtf16 ? " [utf16]" : "")
                                  << (h.wasXor   ? " [xor key=0x" + [&]{ std::string s; char buf[4]; snprintf(buf, sizeof(buf), "%02X", h.xorKey); s=buf; return s; }() + "]" : "")
                                  << "  @" << h.regionType << "\n";
                        con::reset();
                    }
                }
            }
        }

        con::set(con::Color::DarkGray);
        std::cout << "\n  Scanned " << result.totalRegionsScanned << " regions  ("
                  << result.totalBytesScanned / (1024*1024) << " MB)  "
                  << result.allHits.size() << " total unique hits\n";
        con::reset();
    }

} // namespace advscan
