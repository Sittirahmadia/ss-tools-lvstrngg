#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include "Console.h"
#include "Util.h"
#include "PatternScan.h"
#include "ProcessScan.h"
#include "ModsScan.h"
#include "JvmScan.h"
#include "JavaProcessResolve.h"
#include "ModuleScan.h"
#include "SystemForensics.h"
#include "MacroSignature.h"
#include "AdvancedMemoryScan.h"
#include "LauncherDetect.h"
#include "EnhancedJarScan.h"
#include "ForensicsExtended.h"
#include <filesystem>
#include <cstdlib>
#include <string>
#include <iostream>

// =====================================================================
// Pattern lists
// =====================================================================

std::vector<std::string_view> novaPatterns = {
    "aHR0cDovL2FwaS5ub3ZhY2xpZW50LmxvbC93ZWJob29rLnR4dA==",
    "novaclient",
    "addFri",
    "antiAttack",
    "/assets/font/font.ttf",
    "Lithium is not initialized! Skipping event: ",
    "Error in hash"
};

std::vector<std::string_view> crystalPatterns = {
    "net.crystalpvphelper",
    "crystalpvphelper",
    "net.crystalpvphelper.module.ModuleManager",
    "net.crystalpvphelper.module.modules.combat.AnchorMacro",
    "net.crystalpvphelper.module.modules.combat.TriggerBot",
    "net.crystalpvphelper.module.modules.combat.AutoMace",
    "net.crystalpvphelper.module.modules.combat.WTap",
    "net.crystalpvphelper.module.modules.combat.Hitboxes",
    "net.crystalpvphelper.module.modules.combat.AimAssist",
    "net.crystalpvphelper.module.modules.combat.AutoInventoryTotem",
    "net.crystalpvphelper.module.modules.combat.AutoStun",
    "--- CrystalPvPHelper Commands ---",
    ".bind <module> <key> - Bind a module to a key",
    "Automated anchor explosion macro for Crystal PvP",
    "Automated Mace combat with density, breach, and crit mechanics",
    "Automatically breaks shields with an axe",
    "Expands player hitboxes and applies fake rotations",
    "Automatically attacks entities in crosshair",
    "Automatically resets sprint on hit for extra knockback"
};

std::vector<std::string_view> skatePatterns = {
    "hack.skate.client",
    "noqwdclient",
    "hack.skate.client.features.impl.combat.AnchorMacro",
    "hack.skate.client.features.impl.combat.AutoCrystal",
    "hack.skate.client.features.impl.combat.AutoCrystalV2",
    "hack.skate.client.features.impl.combat.AutoDoubleHand",
    "hack.skate.client.features.impl.combat.TriggerBot",
    "hack.skate.client.features.impl.combat.CrystalOptimizer",
    "hack.skate.client.features.impl.combat.BreachSwap",
    "hack.skate.client.features.impl.combat.AimAssistV2",
    "hack.skate.client.features.impl.client.SelfDestruct",
    "hack.skate.client.features.impl.client.ClickGUI",
    "Advanced smooth aim with movement prediction and AC bypass",
    "Bypasses stray's Anti-TriggerBot",
    "Stray Bypass"
};

std::vector<std::string_view> argonPatterns = {
    "dev.lvstrng.argon",
    "dev.lvstrng.argon.mixin",
    "dev.lvstrng.argon.module.ModuleManager",
    "dev.lvstrng.argon.module.modules.combat.AnchorMacro",
    "dev.lvstrng.argon.module.modules.combat.TriggerBotV2",
    "dev.lvstrng.argon.module.modules.combat.ShieldDisabler",
    "dev.lvstrng.argon.module.modules.combat.MaceStun",
    "dev.lvstrng.argon.module.modules.combat.AutoHitCrystal",
    "dev.lvstrng.argon.module.modules.combat.HoverTotem",
    "dev.lvstrng.argon.module.modules.client.SelfDestruct",
    "dev.lvstrng.argon.utils.EncryptedString"
};

// --- Shared across multiple clients (class-file signatures, behavioral strings, known package roots) ---
std::vector<std::string_view> universalPatterns = {
    // ---- .class file names (original set) ----
    "CwCrystal.class",
    "ADH.class",
    "ModuleManager.class",
    "AnchorMacro.class",
    "TriggerBot.class",
    "AutoDoubleHand.class",
    "AutoInventoryTotem.class",
    "AutoCrystal.class",
    "SelfDestruct.class",
    "ClickGUI.class",

    // ---- Crystal / AutoCrystal ----
    "AutoCrystal",
    "autocrystal",
    "Auto Crystal",
    "auto crystal",
    "cw crystal",
    "JDWP.VirtualMachine.AllModules",
    "dontPlaceCrystal",
    "dontBreakCrystal",
    "AutoHitCrystal",
    "autohitcrystal",
    "canPlaceCrystalServer",
    "CrystalAura",
    "autoCrystalPlaceClock",
    "WalksyCrystalOptimizerMod",
    "WalksyOptimizer",
    "WalskyOptimizer",

    // ---- Anchor ----
    "AutoAnchor",
    "autoanchor",
    "auto anchor",
    "DoubleAnchor",
    "HasAnchor",
    "anchortweaks",
    "anchor macro",
    "Anchor Macro",
    "safe anchor",
    "safeanchor",
    "SafeAnchor",
    "AirAnchor",
    "anchorMacro",
    "AnchorAura",
    "AnchorFill",
    "AnchorPlace",
    "AnchorAction",
    "Places two anchors for massive damage",
    "double_anchor",
    "safe_anchor",

    // ---- Totem ----
    "AutoTotem",
    "autototem",
    "auto totem",
    "InventoryTotem",
    "inventorytotem",
    "HoverTotem",
    "hover totem",
    "legittotem",
    "OffhandTotem",
    "TotemSwitch",
    "REOFFHAND_TOTEM",
    "Hover Totem",
    "Auto Inventory Totem",
    "Force Totem",
    "Only On Pop",
    "Hover Totem",

    // ---- Pot / Armor ----
    "AutoPot",
    "autopot",
    "auto pot",
    "speedPotSlot",
    "strengthPotSlot",
    "AutoArmor",
    "autoarmor",
    "auto armor",
    "AutoPotRefill",
    "auto_pot_refill",
    "healPotSlot",
    "auto_neth_pot",
    "AutoNethPot",

    // ---- Shield / Axe ----
    "ShieldDisabler",
    "ShieldBreaker",
    "Breaking shield with axe...",
    "preventSwordBlockBreaking",
    "preventSwordBlockAttack",
    "Require Hold Axe",

    // ---- Double Hand / Mace ----
    "AutoDoubleHand",
    "autodoublehand",
    "auto double hand",
    "AutoMace",
    "MaceSwap",
    "SpearSwap",
    "StunSlam",
    "Failed to switch to mace after axe!",
    "mace_swap",
    "stun_slam",
    "Mace Priority",

    // ---- Aim / TriggerBot ----
    "AimAssist",
    "aimassist",
    "aim assist",
    "aim_assist",
    "triggerbot",
    "trigger bot",
    "trigger_bot",
    "Silent Rotations",
    "SilentRotations",
    "SilentAim",
    "AimBot",
    "AutoAim",
    "AimLock",
    "HeadSnap",
    "BowAimbot",
    "Smooth Rotations",
    "Rotation Speed",

    // ---- KillAura / Combat ----
    "KillAura",
    "ClickAura",
    "MultiAura",
    "ForceField",
    "LegitAura",
    "WTap",
    "auto_dtap",
    "AutoDtap",
    "JumpReset",
    "Donut",
    "axespam",
    "axe spam",
    "findKnockbackSword",
    "attackRegisteredThisClick",
    "invokeDoAttack",
    "invokeDoItemUse",
    "invokeOnMouseButton",
    "TargetStrafe",
    "AutoWeapon",
    "AutoSword",
    "AutoCrit",
    "CritBypass",
    "AlwaysCrit",
    "CriticalHit",
    "AutoClicker",
    "DoubleClicker",
    "JitterClick",
    "ButterflyClick",
    "CPSBoost",

    // ---- Reach / Hitbox ----
    "ReachHack",
    "ExtendReach",
    "LongReach",
    "HitboxExpand",
    "onPushOutOfBlocks",
    "onIsGlowing",
    "Entity.isGlowing",
    "invokeOnMouseButton",

    // ---- Velocity / AntiKB ----
    "AntiKB",
    "NoKnockback",
    "Antiknockback",
    "GrimVelocity",
    "GrimDisabler",
    "VelocitySpoof",
    "KBReduce",

    // ---- Fake / Spoof ----
    "FakeInv",
    "FakeLag",
    "fakePunch",
    "Fake Punch",
    "FakeLatency",
    "FakePing",
    "pingspoof",
    "ping spoof",
    "SpoofRotation",
    "PositionSpoof",
    "PackSpoof",
    "swapBackToOriginalSlot",

    // ---- Web / Pearl ----
    "webmacro",
    "web macro",
    "AntiWeb",
    "AutoWeb",
    "auto_web",
    "KeyPearl",
    "key_pearl",
    "AutoPearl",
    "AutoGap",

    // ---- Movement / Flight ----
    "FlyHack",
    "CreativeFlight",
    "BoatFly",
    "PacketFly",
    "AirJump",
    "SpeedHack",
    "BHop",
    "BunnyHop",
    "AntiFall",
    "NoFallDamage",
    "SafeFall",
    "StepHack",
    "FastClimb",
    "AutoStep",
    "HighStep",
    "WaterWalk",
    "LiquidWalk",
    "LavaWalk",
    "NoSlow",
    "NoSlowdown",
    "NoWeb",
    "NoSoulSand",
    "ElytraSpeed",
    "InstantElytra",
    "ElytraSwap",
    "NoJumpDelay",

    // ---- Building / Mining ----
    "ScaffoldWalk",
    "FastBridge",
    "BuildHelper",
    "AutoBridge",
    "Nuker",
    "NukerLegit",
    "InstantBreak",
    "GhostHand",
    "NoSwing",
    "PlaceAssist",
    "AirPlace",
    "AutoPlace",
    "InstantPlace",
    "FastPlace",
    "setBlockBreakingCooldown",
    "getBlockBreakingCooldown",
    "blockBreakingCooldown",
    "onBlockBreaking",
    "setItemUseCooldown",
    "AutoBreach",
    "AutoCity",
    "Burrow",
    "SelfTrap",
    "HoleFiller",
    "AntiSurround",
    "AntiBurrow",

    // ---- ESP / Visuals ----
    "PlayerESP",
    "MobESP",
    "ItemESP",
    "StorageESP",
    "ChestESP",
    "Tracers",
    "NameTagsHack",
    "XRayHack",
    "OreFinder",
    "OreESP",
    "NewChunks",
    "ChunkBorders",
    "TunnelFinder",
    "TargetHUD",
    "WallHack",

    // ---- Macro state strings ----
    "DOUBLE_ESCAPE",
    "DOUBLE_RIGHTCLICK_FIRST",
    "DOUBLE_RIGHTCLICK_SECOND",
    "POST_CYCLE_DELAY",
    "PLACE_OBI",
    "WAIT_OBI",
    "PLACE_CRYSTAL",
    "BREAK_CRYSTAL",
    "ROTATING_DOWN",
    "ROTATING_BACK",
    "REFILLING",
    "PLANTING",
    "BONEMEALING",
    "macro_198",
    "quick_strike",
    "walksy_optimizer",
    "auto_dtap",
    "REOFFHAND_TOTEM",

    // ---- Misc module names ----
    "LootYeeter",
    "Loot Yeeter",
    "Auto Loot Yeeter",
    "ChestStealer",
    "FastXP",
    "FastExp",
    "AutoFirework",
    "BedAura",
    "AutoBed",
    "BedBomb",
    "BedPlace",
    "BowSpam",
    "AutoBow",
    "PopSwitch",
    "AutoSprint",
    "AntiAFK",
    "AutoRespawn",
    "BaseFinder",
    "invsee",
    "ItemExploit",
    "FreezePlayer",
    "GameSpeed",
    "SpeedTimer",
    "PacketMine",
    "PacketWalk",
    "PacketSneak",
    "PacketCancel",
    "PacketDupe",
    "PacketSpam",
    "AutoEat",
    "AutoMine",
    "AutoTPA",
    "InvManager",
    "InvMovebypass",
    "PopSwitch",

    // ---- Self-destruct / hide ----
    "selfdestruct",
    "self destruct",
    "Self Destruct",
    "SelfDestruct",
    "HideClient",
    "AuthBypass",
    "obfuscatedAuth",
    "LicenseCheckMixin",

    // ---- Anti-cheat bypass strings ----
    "GrimBypass",
    "VulcanBypass",
    "MatrixBypass",
    "AACBypass",
    "VerusDisabler",
    "IntaveBypass",
    "WatchdogBypass",
    "Bypasses stray's Anti-TriggerBot",
    "Stray Bypass",

    // ---- Malware / exfil indicators ----
    "SessionStealer",
    "TokenLogger",
    "TokenGrabber",
    "DiscordToken",
    "RemoteAccess",
    "ReverseShell",
    "C2Server",
    "Backdoor",
    "KeyLogger",
    "POT_CHEATS",
    "arrayOfString",

    // ---- Known client package roots ----
    "lvstrng",
    "dqrkis",
    "dqrkis.xyz",
    "Dqrkis Client",
    "LWFH Crystal",
    "imgui.binding",
    "JNativeHook",
    "GlobalScreen",
    "NativeKeyListener",
    "client-refmap.json",
    "cheat-refmap.json",
    "phantom-refmap.json",
    "meteordevelopment",
    "cc/novoline",
    "com/alan/clients",
    "club/maxstats",
    "wtf/moonlight",
    "me/zeroeightsix/kami",
    "net/ccbluex",
    "today/opai",
    "net/minecraft/injection",
    "org/chainlibs/module/impl/modules",
    "xyz/greaj",
    "com/cheatbreaker",
    "com/moonsworth",
    "doomsdayclient",
    "DoomsdayClient",
    "novaclient",
    "api.novaclient.lol",
    "vape.gg",
    "vapeclient",
    "VapeClient",
    "VapeLite",
    "intent.store",
    "IntentClient",
    "riseclient.com",
    "meteor-client",
    "meteorclient",
    "liquidbounce",
    "fdp-client",
    "net.ccbluex",
    "novoware",
    "aristois",
    "impactclient",
    "pandaware",
    "astolfo",
    "konas",
    "rusherhack",
    "inertia",
    "exhibition",
    "dev.krypton",
    "dev/krypton",
    "skid.krypton",
    "skid/krypton",
    "VirginClient",
    "CatleanClient",
    "catlean",
    "ArgonClient",
    "Asteria",
    "AsteriaClient",
    "Prestige",
    "PrestigeClient",
    "prestigeclient.vip",
    "gypsy",
    "GypsyClient",
    "Xenon",
    "XenonClient",
    "GrimClient",
    "aHR0cDovL2FwaS5ub3ZhY2xpZW50LmxvbC93ZWJob29rLnR4dA==",

    // ---- Behavioral signatures ----
    "Automatically switches to sword when hitting with totem",
    "Automatically resets sprint on hit for extra knockback",
};

// =====================================================================
// Helpers
// =====================================================================

static void waitEnter() {
    con::dim("Press Enter to continue...");
    std::cin.ignore(10000, '\n');
    std::cin.get();
}

// Read a single integer, return -1 on bad input
static int readInt() {
    int v = -1;
    if (!(std::cin >> v)) {
        std::cin.clear();
        std::cin.ignore(10000, '\n');
        return -1;
    }
    return v;
}

// =====================================================================
// Step-by-step: Memory Scan
// =====================================================================
void runMemoryScan() {
    con::header("MEMORY SCAN  --  Live Cheat Detection");

    // --- Step 1: Pick process ---
    con::step(1, 3, "Select Minecraft Process");
    con::dim("Looking for running java/javaw processes...\n");

    HANDLE handle = resolveJavawTarget();
    if (!handle) {
        con::bad("No process selected. Returning to main menu.");
        waitEnter();
        return;
    }

    // --- Step 2: Pick client ---
    con::step(2, 3, "Select Cheat Client to Scan For");
    con::dim("Choose a specific client for a faster, lower-noise scan,");
    con::dim("or scan All to cast the widest net.\n");

    struct ClientEntry { const char* name; const char* note; };
    static const ClientEntry clients[] = {
        { "Nova Client",                       "memory strings + encoded webhook URL"    },
        { "CrystalPvPHelper",                  "full package tree + command strings"     },
        { "Noqwd / Skate Client (AutoCrystal)","full package tree + AutoCrystal modules" },
        { "Argon",                             "encrypted strings, disguised mod id"     },
        { "All  (widest coverage)",            "all of the above + universal class names"},
    };

    for (int i = 0; i < 5; i++) {
        con::set(con::Color::Cyan);
        std::cout << "    [" << (i + 1) << "] ";
        con::set(con::Color::White);
        std::cout << clients[i].name;
        con::set(con::Color::Gray);
        std::cout << "  --  " << clients[i].note << "\n";
        con::reset();
    }

    con::prompt("Enter choice (1-5):");
    int option = readInt();

    std::vector<std::string_view> scannable;
    if      (option == 1) { scannable = novaPatterns; }
    else if (option == 2) { scannable = crystalPatterns; }
    else if (option == 3) { scannable = skatePatterns; }
    else if (option == 4) { scannable = argonPatterns; }
    else if (option == 5) {
        scannable.insert(scannable.end(), novaPatterns.begin(),    novaPatterns.end());
        scannable.insert(scannable.end(), crystalPatterns.begin(), crystalPatterns.end());
        scannable.insert(scannable.end(), skatePatterns.begin(),   skatePatterns.end());
        scannable.insert(scannable.end(), argonPatterns.begin(),   argonPatterns.end());
        scannable.insert(scannable.end(), universalPatterns.begin(),universalPatterns.end());
    } else {
        con::bad("Invalid choice. Returning to main menu.");
        CloseHandle(handle);
        waitEnter();
        return;
    }

    // --- Step 3: Scan ---
    con::step(3, 3, "Scanning Process Memory");
    con::info("Scanning " + std::to_string(scannable.size()) + " pattern(s) in both UTF-8 and UTF-16LE forms...");
    con::dim("(This may take a few seconds depending on how much RAM Minecraft is using)\n");

    auto results = pattern_scan(handle, scannable);
    CloseHandle(handle);

    // --- Results ---
    con::subheader("Scan Results");

    size_t utf16Hits = 0;
    size_t boundaryHits = 0;
    for (const auto& r : results) {
        if (r.wasUtf16)    utf16Hits++;
        if (r.wasBoundary) boundaryHits++;
    }

    if (!results.empty()) {
        for (const auto& r : results) {
            con::set(con::Color::Red);
            std::cout << "  [x] ";
            con::set(con::Color::White);
            std::cout << "\"" << r.pattern << "\"";
            con::set(con::Color::Gray);
            if (r.wasUtf16)    std::cout << "  [utf-16]";
            if (r.wasBoundary) std::cout << "  [boundary]";
            std::cout << "  @ 0x" << std::hex << std::uppercase << r.address << std::dec << "\n";
            con::reset();
        }
    }

    // Stat line
    std::cout << "\n";
    con::divider('-', 60);
    if (utf16Hits > 0) {
        con::info(std::to_string(utf16Hits) + " hit(s) only visible as UTF-16 Java strings (would be missed by a basic ASCII scan)");
    }
    if (boundaryHits > 0) {
        con::info(std::to_string(boundaryHits) + " hit(s) found straddling a memory region boundary");
    }

    con::resultSummary(results.empty(), (int)results.size(), "cheat client traces");
    waitEnter();
}

// =====================================================================
// Step-by-step: Mods Folder Scan
// =====================================================================
void runModsFolderScanMenu() {
    con::header("MODS FOLDER SCAN  --  Static JAR Analysis");

    // --- Step 1: Path ---
    con::step(1, 2, "Enter Mods Folder Path");

    wchar_t* userProfileRaw = nullptr;
    size_t userProfileLen = 0;
    _wdupenv_s(&userProfileRaw, &userProfileLen, L"USERPROFILE");
    std::filesystem::path defaultPath = userProfileRaw
        ? std::filesystem::path(userProfileRaw) / L"AppData" / L"Roaming" / L".minecraft" / L"mods"
        : std::filesystem::path();
    free(userProfileRaw);

    con::dim("What this scan checks:");
    con::dim("  - Cheat/macro class names and package paths inside each .jar");
    con::dim("  - Obfuscation heuristics (numeric, single-letter, fullwidth class names)");
    con::dim("  - Dangerous bytecode (Runtime.exec, HTTP exfil, HTTP download)");
    con::dim("  - Known cheat obfuscators (Skidfuscator, Paramorphism, etc.)");
    con::dim("  - Fake mod identity (jar claiming to be a legit mod but containing cheat code)");
    std::cout << "\n";

    if (!defaultPath.empty()) {
        con::info("Default path: " + defaultPath.string());
    }
    con::prompt("Paste mods folder path (or press Enter for default):");

    std::cin.ignore();
    std::string input;
    std::getline(std::cin, input);

    std::filesystem::path modsPath = input.empty() ? defaultPath : std::filesystem::path(input);
    if (modsPath.empty()) {
        con::bad("No path given and no default found. Returning.");
        waitEnter();
        return;
    }

    std::error_code ec;
    if (!std::filesystem::exists(modsPath, ec) || !std::filesystem::is_directory(modsPath, ec)) {
        con::bad("Path does not exist or is not a folder: " + modsPath.string());
        waitEnter();
        return;
    }

    // --- Step 2: Scan ---
    con::step(2, 2, "Analyzing .jar Files");

    std::vector<std::filesystem::path> jars;
    for (auto& entry : std::filesystem::directory_iterator(modsPath, ec)) {
        if (!entry.is_regular_file()) continue;
        std::string ext = entry.path().extension().string();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        if (ext == ".jar") jars.push_back(entry.path());
    }

    if (jars.empty()) {
        con::warn("No .jar files found in that folder.");
        waitEnter();
        return;
    }

    con::info("Found " + std::to_string(jars.size()) + " jar(s). Scanning...\n");

    int flaggedCount = 0;
    for (int i = 0; i < (int)jars.size(); i++) {
        con::progressBar(i, (int)jars.size());
        modscan::JarReport r = modscan::scanSingleJar(jars[i]);
        if (!r.findings.empty()) {
            flaggedCount++;
            std::cout << "\n";  // newline after progress bar before report
            modscan::printReport(r);
        }
    }
    con::progressBar((int)jars.size(), (int)jars.size());
    std::cout << "\n";

    con::resultSummary(flaggedCount == 0, flaggedCount,
        std::to_string(flaggedCount) + "/" + std::to_string(jars.size()) + " jar(s) flagged");
    waitEnter();
}

// =====================================================================
// Step-by-step: JVM Flags Scan
// =====================================================================
void runJvmFlagsScan() {
    con::header("JVM FLAGS SCAN  --  Agent Injection Detection");

    con::step(1, 2, "Locating Java Processes");
    con::dim("Checks the JVM command line of every running java/javaw for:");
    con::dim("  -javaagent  (bytecode-patches classes in memory at load time)");
    con::dim("  -Xbootclasspath/p  (overrides core Java classes)");
    con::dim("  -agentlib:jdwp  (JDWP remote debug port open)");
    con::dim("  -agentpath  (native agent, bypasses Java sandbox)\n");

    auto procs = jvmscan::findJavaProcesses();
    if (procs.empty()) {
        con::warn("No running java/javaw process found. Is Minecraft open?");
        waitEnter();
        return;
    }

    con::info("Found " + std::to_string(procs.size()) + " java process(es).");

    con::step(2, 2, "Reading JVM Command Lines");
    con::dim("(Queries WMI via PowerShell -- may take a moment)\n");

    bool anyFinding = false;

    for (const auto& p : procs) {
        std::string exeNameA(p.exeName.begin(), p.exeName.end());

        con::subheader("PID " + std::to_string(p.pid) + "  (" + exeNameA + ")");

        std::string cmdLine = jvmscan::getCommandLine(p.pid);

        if (cmdLine.empty()) {
            con::warn("Couldn't read command line (access denied, or WMI/PowerShell unavailable).");
            con::dim("Treat this as UNKNOWN, not clean.");
            continue;
        }

        // Print the raw command line (truncated if long)
        std::string display = cmdLine.size() > 200 ? cmdLine.substr(0, 200) + "..." : cmdLine;
        con::dim("CMD: " + display);
        std::cout << "\n";

        auto findings = jvmscan::analyzeCommandLine(cmdLine);
        if (findings.empty()) {
            con::ok("No suspicious JVM flags or unrecognized agents found.");
        } else {
            anyFinding = true;
            for (const auto& f : findings) con::finding(f.severity, f.text);
        }
    }

    con::resultSummary(!anyFinding, anyFinding ? 1 : 0, "suspicious JVM flags");
    waitEnter();
}

// =====================================================================
// Step-by-step: Macro Software Scan
// =====================================================================
void runMacroSoftwareScan() {
    con::header("MACRO SOFTWARE SCAN  --  198M / Zenith Detection");

    con::step(1, 4, "What This Scan Checks");
    con::dim("Looks for macro software in four places:");
    con::dim("  1. Running processes (exe name match)");
    con::dim("  2. Open window titles (catches renamed executables)");
    con::dim("  3. Installed programs via Windows registry");
    con::dim("  4. Executable signatures (embedded strings + import table --");
    con::dim("     catches renamed AND repacked copies of known macro builds)");
    std::cout << "\n";
    con::dim("Keywords searched: '198m macro', '198macro', 'zenith macro'\n");

    con::step(2, 4, "Scanning Running Processes & Window Titles");

    // Uses the single canonical keyword list defined in ProcessScan.h
    // (also shared with MacroSignature.h's signature sweep), rather than
    // a second copy that could quietly drift out of sync with it.

    auto procHits = scanRunningProcesses(macroKeywords);
    auto winHits  = scanWindowTitles(macroKeywords);

    // Collect all live hits (process + window) into one list so we can
    // attempt to bring each macro window to the foreground once.
    std::vector<MacroHit> liveHits;
    liveHits.insert(liveHits.end(), procHits.begin(), procHits.end());
    liveHits.insert(liveHits.end(), winHits.begin(),  winHits.end());

    if (!liveHits.empty()) {
        con::subheader("Live Macro Software Detected");
        for (const auto& h : liveHits) {
            if (h.source == "process")
                con::bad("Process: " + h.name + "  (PID " + std::to_string(h.pid) + ")");
            else
                con::bad("Window:  \"" + h.name + "\"  (PID " + std::to_string(h.pid) + ")");
        }

        // Auto-bring every matched macro window to the foreground so the
        // SS-er can see the app on-screen immediately, without giving the
        // suspect time to hide or close it.
        std::cout << "\n";
        con::set(con::Color::Yellow);
        std::cout << "  [>>] Bringing macro window(s) to the foreground...\n";
        con::reset();

        int surfaced = 0;
        for (const auto& h : liveHits) {
            if (bringMacroWindowToForeground(h)) {
                con::ok("Surfaced window for: " + h.name +
                    "  (PID " + std::to_string(h.pid) + ")");
                surfaced++;
                Sleep(300); // brief delay between windows so they don't overlap instantly
            }
        }

        if (surfaced == 0) {
            con::warn("Process found but no visible window located -- may be running as");
            con::dim("a tray/background app. Check the system tray manually.");
        } else {
            con::dim("The macro app is now visible on screen.");
            con::dim("Take a screenshot now as evidence before continuing.");
        }
    } else {
        con::ok("No macro processes or windows found.");
    }

    con::step(3, 5, "Scanning Installed Programs (Registry)");

    auto installHits = scanInstalledPrograms(macroKeywords);

    if (!installHits.empty()) {
        con::subheader("Installed Program Matches");
        for (const auto& h : installHits)
            con::bad("Installed: " + h.name);
    } else {
        con::ok("No macro software found in installed programs.");
    }

    // If macro is installed but NOT currently running, offer to launch it
    // so the SS-er can see it on screen as evidence. User must confirm.
    if (!installHits.empty() && liveHits.empty()) {
        con::step(4, 5, "Macro App Found (Not Running) -- Launch Offer");
        auto macroExes = findInstalledMacroExes();
        for (const auto& app : macroExes) {
            offerToLaunchMacroApp(app);
        }
    } else if (!liveHits.empty()) {
        con::step(4, 5, "Macro Already Running -- Skipping Launch Offer");
        con::ok("App is already running -- window should be visible above.");
    } else {
        con::step(4, 5, "No Installed Macro Found");
        con::ok("No macro software installed.");
    }

    con::step(5, 5, "Executable Signature Sweep (Embedded Strings + Import Table)");
    con::dim("Checking every running process' exe on disk for known build strings");
    con::dim("(\"macros-unprotected.pdb\", \"AVMacro\" RTTI, \"/hwidLogin\") and the");
    con::dim("SetWindowsHookExW + SendInput import combo -- catches renamed copies.\n");

    auto sigMatches = macrosig::scanAllProcessesForSignatures();

    if (!sigMatches.empty()) {
        con::subheader("Executable Signature Matches");
        for (const auto& m : sigMatches) {
            std::string line = m.processName + "  (PID " + std::to_string(m.pid) + ")  --  " + m.finding.text;
            con::finding(m.finding.severity, line);
            con::dim(m.exePath);
        }
    } else {
        con::ok("No executable signature matches found.");
    }

    int total = (int)(liveHits.size() + installHits.size() + sigMatches.size());
    con::resultSummary(total == 0, total, "macro software trace(s)");
    waitEnter();
}

// =====================================================================
// Step-by-step: Loaded Module (DLL Injection) Scan
// =====================================================================
void runModuleScan() {
    con::header("MODULE SCAN  --  Native DLL Injection Detection");

    con::step(1, 2, "Select Minecraft Process");
    con::dim("Looking for running java/javaw processes...\n");

    HANDLE handle = resolveJavawTarget();
    if (!handle) {
        con::bad("No process selected. Returning to main menu.");
        waitEnter();
        return;
    }
    DWORD pid = GetProcessId(handle);
    CloseHandle(handle);

    con::step(2, 2, "Enumerating Loaded Modules");
    con::dim("Checks every DLL loaded into the process for:");
    con::dim("  - Suspicious names (inject/hook/cheat/bypass, etc.)");
    con::dim("  - Loading from Temp/Downloads/Desktop instead of a real install");
    con::dim("  - Randomized-looking filenames (common injector payload naming)");
    con::dim("  - Any location outside the JRE/Windows/Minecraft natives dirs\n");

    auto findings = modulescan::scanProcessModules(pid);

    con::subheader("Scan Results");

    int dangerCount = 0, warnCount = 0;
    for (const auto& f : findings) {
        std::string line = f.name + "  --  " + f.reason;
        if (f.severity == modulescan::Severity::Danger) dangerCount++;
        else if (f.severity == modulescan::Severity::Warning) warnCount++;
        else continue;
        con::finding(f.severity, line);
        con::dim(f.path);
    }

    if (dangerCount == 0 && warnCount == 0) {
        con::ok("All loaded modules resolve to trusted, standard locations.");
    } else {
        con::info(std::to_string(dangerCount) + " high-confidence and " +
            std::to_string(warnCount) + " lower-confidence finding(s). Review paths above --");
        con::dim("this is heuristic, not a signature match; confirm manually before acting.");
    }

    con::resultSummary(dangerCount == 0, dangerCount, "suspicious loaded module(s)");
    waitEnter();
}

// =====================================================================
// Step-by-step: System Forensics Scan
// =====================================================================
void runSystemForensicsScan() {
    con::header("SYSTEM FORENSICS SCAN  --  Persistence & Usage Traces");

    con::dim("Looks for OS-level traces a cheat client or injector leaves behind");
    con::dim("even after the jar/exe itself has been deleted.\n");

    struct CheckStep {
        const char* title;
        std::vector<sysforensics::Finding> (*fn)();
    };
    static const CheckStep steps[] = {
        { "Prefetch Execution History",      sysforensics::checkPrefetchTraces      },
        { "Startup / Autorun Persistence",   sysforensics::checkStartupPersistence  },
        { "Recently Opened .jar Files",      sysforensics::checkRecentJarFiles      },
        { "Scheduled Tasks",                 sysforensics::checkScheduledTasks      },
        { "Hosts File Tampering",            sysforensics::checkHostsFile           },
        { "Suspicious Standalone Processes", sysforensics::checkSuspiciousProcesses },
    };

    int total = (int)(sizeof(steps) / sizeof(steps[0]));
    int dangerCount = 0;

    for (int i = 0; i < total; i++) {
        con::step(i + 1, total, steps[i].title);
        auto findings = steps[i].fn();
        for (const auto& f : findings) {
            if (f.severity == sysforensics::Severity::Danger) dangerCount++;
            con::finding(f.severity, f.text);
        }
    }

    con::resultSummary(dangerCount == 0, dangerCount, "persistence/usage trace(s)");
    waitEnter();
}

// =====================================================================
// Enhanced JAR Scan standalone
// =====================================================================
void runEnhancedJarScan() {
    con::header("ENHANCED JAR SCAN  --  Deep Bytecode + Obfuscation Analysis");

    con::step(1, 2, "Select Mods Folder");
    con::dim("Auto-detecting Minecraft installations...\n");

    auto instances = launcherdetect::detectAll();
    std::filesystem::path modsPath;

    if (!instances.empty()) {
        con::subheader("Detected Installations");
        launcherdetect::printInstances(instances);
        std::cout << "\n";
        con::prompt("Choose instance (1-" + std::to_string(instances.size()) + "), or 0 for manual path:");
        int c = readInt();
        if (c >= 1 && c <= (int)instances.size()) {
            modsPath = instances[c - 1].modsDir;
            con::ok("Using: " + modsPath.string());
        }
    }

    if (modsPath.empty()) {
        con::prompt("Enter mods folder path:");
        std::string line;
        std::getline(std::cin, line);
        modsPath = line;
    }

    std::error_code ec;
    if (!std::filesystem::exists(modsPath, ec)) {
        con::bad("Path does not exist: " + modsPath.string());
        waitEnter(); return;
    }

    con::step(2, 2, "Deep JAR Analysis");
    con::dim("Checks: cheat strings, obfuscation ratio, mixin targets,");
    con::dim("        obfuscator fingerprint, native libs, ASM usage,");
    con::dim("        fullwidth Unicode evasion, ghost-client impersonation\n");

    auto results = enhancedjarscan::scanDirectory(modsPath);
    enhancedjarscan::printResults(results);

    int flagged = 0;
    for (const auto& r : results) if (r.flagged()) flagged++;
    con::resultSummary(flagged == 0, flagged, "suspicious jar(s)");
    waitEnter();
}

// =====================================================================
// Advanced Memory Scan (v2) -- multithreaded, confidence scores
// =====================================================================
void runAdvancedMemoryScan() {
    con::header("ADVANCED MEMORY SCAN  v2  --  Multi-threaded + Confidence Scores");

    con::step(1, 2, "Select Minecraft Process");
    HANDLE handle = resolveJavawTarget();
    if (!handle) { con::bad("No process selected."); waitEnter(); return; }
    DWORD pid = GetProcessId(handle);

    con::step(2, 2, "Scanning Memory");
    con::dim("Multi-threaded scanning with XOR decoding + UTF-16 + fullwidth normalization\n");

    advscan::ScanConfig cfg;
    cfg.tryXorKeys  = true;
    cfg.tryUtf16    = true;
    cfg.useThreads  = true;

    auto result = advscan::scanProcess(handle, cfg);
    CloseHandle(handle);

    advscan::printResults(result);

    con::resultSummary(result.clients.empty(), (int)result.allHits.size(), "cheat signature(s)");
    waitEnter();
}

// =====================================================================
// Smart Auto-Scan -- auto-detect launcher + run all relevant scans
// =====================================================================
void runSmartAutoScan() {
    con::header("SMART AUTO SCAN  --  Auto-Detect Minecraft + Full Analysis");

    con::step(1, 4, "Detecting Minecraft Installations");
    auto instances = launcherdetect::detectAll();
    launcherdetect::printInstances(instances);

    if (instances.empty()) {
        con::warn("No Minecraft installations found.");
        waitEnter();
        return;
    }

    // Pick instance: prefer active, else let user choose
    int chosen = -1;
    for (int i = 0; i < (int)instances.size(); i++) {
        if (instances[i].isActive) { chosen = i; break; }
    }

    if (chosen == -1) {
        con::prompt("Choose instance to scan (1-" + std::to_string(instances.size()) + "):");
        int c = readInt();
        if (c < 1 || c > (int)instances.size()) {
            con::bad("Invalid choice."); waitEnter(); return;
        }
        chosen = c - 1;
    } else {
        con::ok("Auto-selected active instance: " + instances[chosen].instanceName);
    }

    const auto& inst = instances[chosen];
    std::cout << "\n";
    con::info("Scanning: " + inst.launcherName + " -- " + inst.instanceName);
    con::dim(inst.rootDir.string());

    // Step 2: Enhanced JAR scan
    con::step(2, 4, "Deep JAR Analysis (Enhanced)");
    std::error_code ec;
    if (std::filesystem::exists(inst.modsDir, ec)) {
        auto jarResults = enhancedjarscan::scanDirectory(inst.modsDir);
        enhancedjarscan::printResults(jarResults);
        int flagged = 0;
        for (const auto& r : jarResults) if (r.flagged()) flagged++;
        con::resultSummary(flagged == 0, flagged, "suspicious jar(s)");
    } else {
        con::warn("No mods folder found for this instance.");
    }

    // Step 3: Extended forensics
    con::step(3, 4, "Extended Forensics (Logs, Configs, Temp, Clipboard)");
    forensicsext::runFullForensics(inst.rootDir);

    // Step 4: Live memory scan if MC is running
    con::step(4, 4, "Live Memory Scan (if Minecraft is running)");
    HANDLE javaHandle = resolveJavawTarget();
    if (javaHandle) {
        advscan::ScanConfig cfg;
        auto memResult = advscan::scanProcess(javaHandle, cfg);
        CloseHandle(javaHandle);
        advscan::printResults(memResult);
        con::resultSummary(memResult.clients.empty(), (int)memResult.allHits.size(), "memory hit(s)");
    } else {
        con::info("Minecraft not running -- skipping memory scan.");
    }

    waitEnter();
}

// =====================================================================
// Extended Forensics standalone menu
// =====================================================================
void runExtendedForensics() {
    con::header("EXTENDED FORENSICS  --  Logs, Configs, Temp, Clipboard");

    con::step(1, 2, "Locate Minecraft Root");
    auto instances = launcherdetect::detectAll();

    std::filesystem::path mcRoot;
    if (!instances.empty()) {
        // Find first with a valid root
        for (const auto& inst : instances) {
            std::error_code ec;
            if (std::filesystem::exists(inst.rootDir, ec)) {
                mcRoot = inst.rootDir;
                con::ok("Using: " + inst.launcherName + " -- " + inst.rootDir.string());
                break;
            }
        }
    }

    if (mcRoot.empty()) {
        con::prompt("Enter .minecraft path manually:");
        std::string line;
        std::getline(std::cin, line);
        mcRoot = line;
    }

    con::step(2, 2, "Running Forensic Checks");
    forensicsext::runFullForensics(mcRoot);

    waitEnter();
}

// =====================================================================
// Startup banner
// =====================================================================
static const char* kToolVersion = "v2.0";

static void printBanner() {
    // Enable ANSI / virtual terminal (Windows 10+)
    DWORD mode = 0;
    GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &mode);
    SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    con::box({
        "",
        std::string("SS TOOL  --  by lvstrng  ") + kToolVersion,
        "Minecraft Screenshare / Cheat Detection",
        "",
    }, 60, con::Color::Cyan);

    std::cout << "\n";
    bool elevated = util::isRunningElevated();
    con::statusLine("Mode", "Read-only  (nothing on this PC is modified)", con::Color::Green);
    con::statusLine("Running as", elevated ? "Administrator" : "Standard user",
        elevated ? con::Color::Green : con::Color::Yellow);
    if (!elevated) {
        con::statusLine("", "Re-run as Administrator for full memory read access.", con::Color::Gray);
    }
    con::statusLine("Modules", "6 scans  (Memory / Mods / JVM / Macro / Module / Forensics)", con::Color::White);
    std::cout << "\n";
}

// =====================================================================
// Main menu
// =====================================================================
int main() {
    printBanner();

    while (true) {
        con::box({ "MAIN MENU  --  SS Tool v2.0" }, 62, con::Color::Cyan);
        std::cout << "\n";

        con::set(con::Color::Magenta);
        std::cout << "  -- Smart Scan --\n";
        con::reset();
        con::menuItem(1, "Smart Auto-Scan       Auto-detect launcher + JAR + memory + forensics");

        std::cout << "\n";
        con::set(con::Color::Magenta);
        std::cout << "  -- Live Process Scans --\n";
        con::reset();
        con::menuItem(2, "Memory Scan v2        Multi-threaded, XOR decode, per-client confidence");
        con::menuItem(3, "JVM Flags Scan        Detect -javaagent injection + suspicious flags");
        con::menuItem(4, "Module Scan           Detect injected/suspicious DLLs in java process");

        std::cout << "\n";
        con::set(con::Color::Magenta);
        std::cout << "  -- Static / On-disk Scans --\n";
        con::reset();
        con::menuItem(5, "Enhanced JAR Scan     Bytecode heuristics, obfuscation, mixin, whitelist");
        con::menuItem(6, "Mods Folder Scan      Classic static JAR analysis");
        con::menuItem(7, "Macro Scan            198M/Zenith: process, window, registry, exe signature");

        std::cout << "\n";
        con::set(con::Color::Magenta);
        std::cout << "  -- Forensics --\n";
        con::reset();
        con::menuItem(8, "Extended Forensics    Logs, crash-reports, configs, temp, clipboard");
        con::menuItem(9, "System Forensics      Prefetch, autorun, tasks, hosts file, recent jars");

        std::cout << "\n";
        con::menuItem(0, "Exit");

        con::prompt("Choose (0-9):");
        int choice = readInt();
        std::cout << "\n";

        switch (choice) {
            case 1: runSmartAutoScan();       break;
            case 2: runAdvancedMemoryScan();  break;
            case 3: runJvmFlagsScan();        break;
            case 4: runModuleScan();          break;
            case 5: runEnhancedJarScan();     break;
            case 6: runModsFolderScanMenu();  break;
            case 7: runMacroSoftwareScan();   break;
            case 8: runExtendedForensics();   break;
            case 9: runSystemForensicsScan(); break;
            case 0: goto exitLoop;
            default: con::warn("Invalid choice. Enter 0-9.");
        }
    }
    exitLoop:

    con::box({ "Exiting SS Tool. Goodbye." }, 60, con::Color::Gray);
    std::cout << "\n";

    return 0;
}
