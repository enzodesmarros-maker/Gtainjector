/*
 * DLLance - Copyright (c) 2026 enzodesmarros-maker
 *
 * Licenca de uso restrito:
 * - Uso pessoal e educacional permitido.
 * - E proibido redistribuir, modificar ou usar este codigo
 *   para fins comerciais sem autorizacao expressa do autor.
 * - E proibido remover este aviso de copyright.
 * - O autor nao se responsabiliza por qualquer uso indevido.
 */

#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <inttypes.h>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <atomic>
#include <fstream>
#include <commdlg.h>

#include "imgui/imgui.h"
#include "imgui/imgui_impl_win32.h"
#include "imgui/imgui_impl_dx11.h"

#include <d3d11.h>
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "comdlg32.lib")

struct ModuleEntry {
    std::string name;
    HMODULE     handle;
};

struct LogEntry {
    std::string msg;
    ImVec4      color;
};

static ID3D11Device*            g_pd3dDevice            = nullptr;
static ID3D11DeviceContext*     g_pd3dDeviceContext     = nullptr;
static IDXGISwapChain*          g_pSwapChain            = nullptr;
static ID3D11RenderTargetView*  g_mainRenderTargetView  = nullptr;
static HWND                     g_hWnd                  = nullptr;

static DWORD                    g_gtaPID                = 0;
static char                     g_selectedGame[256]     = "Nenhum jogo selecionado";
static std::vector<ModuleEntry> g_modules;
static std::vector<LogEntry>    g_log;
static float                    g_titleScroll           = 0.0f;

static std::atomic<bool>        g_ready(false);
static DWORD                    g_startTick             = 0;

static char     g_dllPath[MAX_PATH] = "";

struct InjectedEntry {
    std::string modName;
    HMODULE     handle;
};
static std::vector<InjectedEntry> g_injected;

const ImVec4 COL_GOLD       = ImVec4(1.00f, 0.84f, 0.00f, 1.0f);
const ImVec4 COL_GOLD_DIM   = ImVec4(0.70f, 0.58f, 0.00f, 1.0f);
const ImVec4 COL_BG         = ImVec4(0.06f, 0.06f, 0.06f, 1.0f);
const ImVec4 COL_GREEN      = ImVec4(0.20f, 0.90f, 0.20f, 1.0f);
const ImVec4 COL_RED        = ImVec4(0.95f, 0.20f, 0.20f, 1.0f);
const ImVec4 COL_GRAY       = ImVec4(0.60f, 0.60f, 0.60f, 1.0f);

static const char* _stristr(const char* haystack, const char* needle) {
    if (!*needle) return haystack;
    for (; *haystack; ++haystack) {
        if (tolower((unsigned char)*haystack) == tolower((unsigned char)*needle)) {
            const char* h = haystack, *n = needle;
            for (; *h && *n; ++h, ++n)
                if (tolower((unsigned char)*h) != tolower((unsigned char)*n)) break;
            if (!*n) return haystack;
        }
    }
    return nullptr;
}

static void WriteDebugLog(const std::string& msg) {
    char exePath[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    std::string path(exePath);
    size_t last = path.find_last_of("\\/");
    if (last != std::string::npos) path = path.substr(0, last + 1);
    path += "debug.log";

    std::ofstream f(path, std::ios::app);
    if (!f.is_open()) return;

    SYSTEMTIME st{};
    GetLocalTime(&st);
    char ts[32];
    sprintf_s(ts, "[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
    f << ts << msg << "\n";
    f.flush();
}

void AddLog(const std::string& msg, ImVec4 color = ImVec4(0.85f,0.85f,0.85f,1.0f)) {
    g_log.push_back({ msg, color });
    if (g_log.size() > 200) g_log.erase(g_log.begin());
    WriteDebugLog(msg);
}

DWORD FindProcessByName(const char* procName) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe32{};
    pe32.dwSize = sizeof(pe32);
    DWORD pid = 0;

    if (Process32First(snap, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, procName) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe32));
    }
    CloseHandle(snap);
    return pid;
}

void RefreshModules() {
    g_modules.clear();
    if (!g_gtaPID) { AddLog("[!] Nenhum processo selecionado.", COL_RED); return; }

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, g_gtaPID);
    if (!hProc) { AddLog("[!] Falha ao abrir processo.", COL_RED); return; }

    HMODULE mods[1024];
    DWORD needed = 0;
    if (EnumProcessModules(hProc, mods, sizeof(mods), &needed)) {
        DWORD count = needed / sizeof(HMODULE);
        for (DWORD i = 0; i < count; i++) {
            wchar_t name[MAX_PATH];
            if (GetModuleBaseNameW(hProc, mods[i], name, MAX_PATH)) {
                char narrow[MAX_PATH];
                WideCharToMultiByte(CP_UTF8, 0, name, -1, narrow, MAX_PATH, nullptr, nullptr);
                g_modules.push_back({ narrow, mods[i] });
            }
        }
        AddLog("[+] " + std::to_string(g_modules.size()) + " modulos listados.", COL_GREEN);
    } else {
        AddLog("[!] EnumProcessModules falhou.", COL_RED);
    }
    CloseHandle(hProc);
}

static DWORD RvaToOffset(DWORD rva, PIMAGE_SECTION_HEADER sec, int secCount) {
    for (int i = 0; i < secCount; i++)
        if (rva >= sec[i].VirtualAddress &&
            rva <  sec[i].VirtualAddress + sec[i].Misc.VirtualSize)
            return sec[i].PointerToRawData + (rva - sec[i].VirtualAddress);
    return 0;
}

static DWORD SectionProtection(DWORD characteristics) {
    bool exec  = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    bool read  = (characteristics & IMAGE_SCN_MEM_READ)    != 0;
    bool write = (characteristics & IMAGE_SCN_MEM_WRITE)   != 0;

    if (exec  && write) return PAGE_EXECUTE_READWRITE;
    if (exec  && read)  return PAGE_EXECUTE_READ;
    if (exec)           return PAGE_EXECUTE;
    if (write)          return PAGE_READWRITE;
    return PAGE_READONLY;
}

#pragma pack(push, 1)
struct LoaderData {
    LPVOID  imageBase;
    FARPROC fnLoadLibraryA;
    FARPROC fnGetProcAddr;
    FARPROC fnDllMain;
    DWORD   initialized;
};
#pragma pack(pop)

static BYTE g_shellcode64[] = {
    0x48,0x83,0xEC,0x28,
    0x48,0x89,0xC8,
    0x48,0x8B,0x08,
    0xBA,0x01,0x00,0x00,0x00,
    0x45,0x33,0xC0,
    0xFF,0x50,0x18,
    0x48,0x8B,0x4C,0x24,0x28,
    0xC7,0x41,0x20,0x01,0x00,0x00,0x00,
    0x48,0x83,0xC4,0x28,
    0xC3
};

static BYTE g_shellcode32[] = {
    0x55,
    0x89,0xE5,
    0x53,
    0x8B,0x5D,0x08,
    0x6A,0x00,
    0x6A,0x01,
    0xFF,0x33,
    0xFF,0x53,0x0C,
    0xC7,0x43,0x10,0x01,0x00,0x00,0x00,
    0x5B,
    0x5D,
    0xC2,0x04,0x00
};

bool InjectDLL(const char* dllPath) {
    if (!g_gtaPID) { AddLog("[!] Processo nao selecionado.", COL_RED); return false; }
    if (!dllPath || dllPath[0] == '\0') { AddLog("[!] Caminho da DLL vazio.", COL_RED); return false; }

    std::string fullPath(dllPath);
    size_t sep = fullPath.find_last_of("\\/");
    std::string modName = (sep != std::string::npos) ? fullPath.substr(sep+1) : fullPath;

    std::string pathLower = fullPath;
    for (auto& c : pathLower) c = (char)tolower(c);

    if (pathLower.find("system32") != std::string::npos ||
        pathLower.find("syswow64") != std::string::npos ||
        pathLower.find("windows\\") != std::string::npos) {
        AddLog("[!] Bloqueado: DLL do sistema nao pode ser injetada.", COL_RED);
        AddLog("[!] Selecione uma DLL de mod (ex: C:\\Mods\\cleo.dll)", COL_RED);
        return false;
    }

    static const char* SYSTEM_DLLS[] = {
        "ntdll.dll","kernel32.dll","kernelbase.dll","user32.dll","gdi32.dll",
        "advapi32.dll","shell32.dll","ole32.dll","oleaut32.dll","comctl32.dll",
        "comdlg32.dll","ws2_32.dll","winspool.drv","winmm.dll","msvcrt.dll",
        "msvcp140.dll","vcruntime140.dll","d3d11.dll","d3d9.dll","dxgi.dll",
        "psapi.dll","shlwapi.dll","sechost.dll","rpcrt4.dll","bcrypt.dll",
        "bcryptprimitives.dll","cryptsp.dll","imm32.dll","msacm32.dll",
        "version.dll","uxtheme.dll","dwmapi.dll","setupapi.dll",nullptr
    };
    for (int i = 0; SYSTEM_DLLS[i]; i++) {
        if (_stricmp(modName.c_str(), SYSTEM_DLLS[i]) == 0) {
            AddLog("[!] Bloqueado: '" + modName + "' e uma DLL do sistema.", COL_RED);
            return false;
        }
    }

    for (auto& e : g_injected)
        if (_stricmp(e.modName.c_str(), modName.c_str()) == 0)
            { AddLog("[!] '" + modName + "' ja esta ativo.", COL_RED); return false; }

    for (auto& m : g_modules)
        if (_stricmp(m.name.c_str(), modName.c_str()) == 0) {
            AddLog("[!] '" + modName + "' ja esta carregado no processo.", COL_RED);
            return false;
        }

    AddLog("[*] Carregando: " + modName, COL_GRAY);
    std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) { AddLog("[!] Arquivo nao encontrado.", COL_RED); return false; }

    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<BYTE> buf(static_cast<size_t>(fileSize));
    if (!file.read(reinterpret_cast<char*>(buf.data()), fileSize))
        { AddLog("[!] Erro ao ler arquivo.", COL_RED); return false; }
    file.close();
    AddLog("[*] " + std::to_string(fileSize) + " bytes carregados.", COL_GRAY);

    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(buf.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        { AddLog("[!] Arquivo invalido.", COL_RED); return false; }

    auto* nt32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(buf.data() + dos->e_lfanew);
    if (nt32->Signature != IMAGE_NT_SIGNATURE)
        { AddLog("[!] PE corrompido.", COL_RED); return false; }

    bool is64 = (nt32->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);
    bool is32 = (nt32->FileHeader.Machine == IMAGE_FILE_MACHINE_I386);
    if (!is64 && !is32) { AddLog("[!] Arquitetura nao suportada.", COL_RED); return false; }

    AddLog("[*] Arquitetura detectada: " + std::string(is64 ? "x64 (AMD64)" : "x86 (i386)"), COL_GRAY);

    auto* nt64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(buf.data() + dos->e_lfanew);

    DWORD  secCount  = nt32->FileHeader.NumberOfSections;
    auto*  secHdr    = is64
        ? IMAGE_FIRST_SECTION(nt64)
        : IMAGE_FIRST_SECTION(nt32);

    SIZE_T   imageSize   = is64 ? nt64->OptionalHeader.SizeOfImage   : nt32->OptionalHeader.SizeOfImage;
    SIZE_T   hdrsSize    = is64 ? nt64->OptionalHeader.SizeOfHeaders : nt32->OptionalHeader.SizeOfHeaders;
    ULONGLONG prefBase   = is64 ? nt64->OptionalHeader.ImageBase     : nt32->OptionalHeader.ImageBase;
    DWORD    entryRVA    = is64 ? nt64->OptionalHeader.AddressOfEntryPoint : nt32->OptionalHeader.AddressOfEntryPoint;

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, g_gtaPID);
    if (!hProc) { AddLog("[!] Acesso ao processo negado. Rode como Admin.", COL_RED); return false; }

    LPVOID imageBase = VirtualAllocEx(hProc,
        reinterpret_cast<LPVOID>(prefBase), imageSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!imageBase)
        imageBase = VirtualAllocEx(hProc, nullptr, imageSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!imageBase) {
        CloseHandle(hProc);
        AddLog("[!] Falha ao alocar regiao. Cod: " + std::to_string(GetLastError()), COL_RED);
        return false;
    }

    char addrBuf[32]; sprintf_s(addrBuf, "%" PRIXPTR, reinterpret_cast<uintptr_t>(imageBase));
    AddLog("[*] Regiao alocada: 0x" + std::string(addrBuf), COL_GRAY);

    WriteProcessMemory(hProc, imageBase, buf.data(), hdrsSize, nullptr);

    AddLog("[*] Mapeando " + std::to_string(secCount) + " secoes...", COL_GRAY);
    for (DWORD i = 0; i < secCount; i++) {
        if (!secHdr[i].SizeOfRawData) continue;

        LPVOID dst = reinterpret_cast<LPVOID>(
            reinterpret_cast<uintptr_t>(imageBase) + secHdr[i].VirtualAddress);

        WriteProcessMemory(hProc, dst,
            buf.data() + secHdr[i].PointerToRawData,
            secHdr[i].SizeOfRawData, nullptr);

        DWORD prot = SectionProtection(secHdr[i].Characteristics);
        DWORD old  = 0;
        VirtualProtectEx(hProc, dst, secHdr[i].Misc.VirtualSize, prot, &old);
    }

    uintptr_t delta = reinterpret_cast<uintptr_t>(imageBase) - static_cast<uintptr_t>(prefBase);
    if (delta != 0) {
        AddLog("[*] Corrigindo relocacoes...", COL_GRAY);

        auto& relocDir = is64
            ? nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
            : nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

        if (relocDir.Size) {
            auto* reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
                buf.data() + RvaToOffset(relocDir.VirtualAddress, secHdr, secCount));

            while (reloc && reloc->VirtualAddress) {
                DWORD  cnt     = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                auto*  entries = reinterpret_cast<WORD*>(reloc + 1);

                for (DWORD j = 0; j < cnt; j++) {
                    int type   = entries[j] >> 12;
                    int offset = entries[j] & 0x0FFF;

                    LPVOID target = reinterpret_cast<LPVOID>(
                        reinterpret_cast<uintptr_t>(imageBase) + reloc->VirtualAddress + offset);

                    if (type == IMAGE_REL_BASED_DIR64) {
                        ULONGLONG val = 0;
                        ReadProcessMemory(hProc, target, &val, 8, nullptr);
                        val += delta;
                        WriteProcessMemory(hProc, target, &val, 8, nullptr);
                    } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                        DWORD val = 0;
                        ReadProcessMemory(hProc, target, &val, 4, nullptr);
                        val += static_cast<DWORD>(delta);
                        WriteProcessMemory(hProc, target, &val, 4, nullptr);
                    }
                }
                reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
                    reinterpret_cast<uintptr_t>(reloc) + reloc->SizeOfBlock);
            }
        }
    }

    AddLog("[*] Resolvendo importacoes...", COL_GRAY);
    {
        auto& importDir = is64
            ? nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
            : nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

        if (importDir.Size) {
            auto* desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
                buf.data() + RvaToOffset(importDir.VirtualAddress, secHdr, secCount));

            for (; desc->Name; desc++) {
                char* libName = reinterpret_cast<char*>(
                    buf.data() + RvaToOffset(desc->Name, secHdr, secCount));

                HMODULE hLib = LoadLibraryA(libName);
                if (!hLib) { AddLog("[!] Import nao resolvido: " + std::string(libName), COL_RED); continue; }

                DWORD iatRva  = desc->FirstThunk;
                DWORD origRva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;

                for (size_t k = 0; ; k++) {
                    size_t thunkSize = is64 ? sizeof(IMAGE_THUNK_DATA64) : sizeof(IMAGE_THUNK_DATA32);
                    DWORD  origOff   = RvaToOffset(origRva, secHdr, secCount) + k * thunkSize;
                    DWORD  iatOff    = RvaToOffset(iatRva,  secHdr, secCount) + k * thunkSize;

                    if (is64) {
                        auto* orig = reinterpret_cast<PIMAGE_THUNK_DATA64>(buf.data() + origOff);
                        if (!orig->u1.AddressOfData) break;

                        FARPROC fn = nullptr;
                        if (IMAGE_SNAP_BY_ORDINAL64(orig->u1.Ordinal))
                            fn = GetProcAddress(hLib, MAKEINTRESOURCEA(IMAGE_ORDINAL64(orig->u1.Ordinal)));
                        else {
                            auto* ibn = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                                buf.data() + RvaToOffset((DWORD)orig->u1.AddressOfData, secHdr, secCount));
                            fn = GetProcAddress(hLib, ibn->Name);
                        }

                        if (fn) {
                            ULONGLONG addr = reinterpret_cast<ULONGLONG>(fn);
                            LPVOID iatPtr  = reinterpret_cast<LPVOID>(
                                reinterpret_cast<uintptr_t>(imageBase) + iatRva + k * thunkSize);
                            WriteProcessMemory(hProc, iatPtr, &addr, 8, nullptr);
                        }
                    } else {
                        auto* orig = reinterpret_cast<PIMAGE_THUNK_DATA32>(buf.data() + origOff);
                        if (!orig->u1.AddressOfData) break;

                        FARPROC fn = nullptr;
                        if (IMAGE_SNAP_BY_ORDINAL32(orig->u1.Ordinal))
                            fn = GetProcAddress(hLib, MAKEINTRESOURCEA(IMAGE_ORDINAL32(orig->u1.Ordinal)));
                        else {
                            auto* ibn = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                                buf.data() + RvaToOffset((DWORD)orig->u1.AddressOfData, secHdr, secCount));
                            fn = GetProcAddress(hLib, ibn->Name);
                        }

                        if (fn) {
                            DWORD  addr = reinterpret_cast<DWORD>(fn);
                            LPVOID iatPtr = reinterpret_cast<LPVOID>(
                                reinterpret_cast<uintptr_t>(imageBase) + iatRva + k * thunkSize);
                            WriteProcessMemory(hProc, iatPtr, &addr, 4, nullptr);
                        }
                    }
                }
                FreeLibrary(hLib);
            }
        }
    }

    {
        auto& tlsDir = is64
            ? nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]
            : nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

        if (tlsDir.Size) {
            AddLog("[*] Executando TLS callbacks...", COL_GRAY);

            if (is64) {
                auto* tls = reinterpret_cast<PIMAGE_TLS_DIRECTORY64>(
                    buf.data() + RvaToOffset(tlsDir.VirtualAddress, secHdr, secCount));

                if (tls && tls->AddressOfCallBacks) {
                    DWORD cbRva = static_cast<DWORD>(tls->AddressOfCallBacks - prefBase);
                    DWORD cbOff = RvaToOffset(cbRva, secHdr, secCount);
                    auto* cbArr = reinterpret_cast<ULONGLONG*>(buf.data() + cbOff);

                    for (int ci = 0; cbArr[ci]; ci++) {
                        LPVOID cbAddr = reinterpret_cast<LPVOID>(
                            reinterpret_cast<uintptr_t>(imageBase) +
                            static_cast<uintptr_t>(cbArr[ci] - prefBase));

                        LoaderData cbData{};
                        cbData.imageBase   = imageBase;
                        cbData.fnDllMain   = reinterpret_cast<FARPROC>(cbAddr);
                        cbData.initialized = 0;

                        SIZE_T sz = sizeof(g_shellcode64) + sizeof(LoaderData);
                        LPVOID mem = VirtualAllocEx(hProc, nullptr, sz, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                        if (!mem) continue;

                        WriteProcessMemory(hProc, mem, &cbData, sizeof(LoaderData), nullptr);
                        LPVOID code = reinterpret_cast<LPVOID>(reinterpret_cast<uintptr_t>(mem)+sizeof(LoaderData));
                        WriteProcessMemory(hProc, code, g_shellcode64, sizeof(g_shellcode64), nullptr);

                        HANDLE ht = CreateRemoteThread(hProc, nullptr, 0,
                            reinterpret_cast<LPTHREAD_START_ROUTINE>(code), mem, 0, nullptr);
                        if (ht) { WaitForSingleObject(ht, 3000); CloseHandle(ht); }
                        VirtualFreeEx(hProc, mem, 0, MEM_RELEASE);
                    }
                }
            } else {
                auto* tls = reinterpret_cast<PIMAGE_TLS_DIRECTORY32>(
                    buf.data() + RvaToOffset(tlsDir.VirtualAddress, secHdr, secCount));

                if (tls && tls->AddressOfCallBacks) {
                    DWORD cbRva = tls->AddressOfCallBacks - static_cast<DWORD>(prefBase);
                    DWORD cbOff = RvaToOffset(cbRva, secHdr, secCount);
                    auto* cbArr = reinterpret_cast<DWORD*>(buf.data() + cbOff);

                    for (int ci = 0; cbArr[ci]; ci++) {
                        LPVOID cbAddr = reinterpret_cast<LPVOID>(
                            reinterpret_cast<uintptr_t>(imageBase) +
                            static_cast<uintptr_t>(cbArr[ci] - static_cast<DWORD>(prefBase)));

                        LoaderData cbData{};
                        cbData.imageBase   = imageBase;
                        cbData.fnDllMain   = reinterpret_cast<FARPROC>(cbAddr);
                        cbData.initialized = 0;

                        SIZE_T sz = sizeof(g_shellcode32) + sizeof(LoaderData);
                        LPVOID mem = VirtualAllocEx(hProc, nullptr, sz, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                        if (!mem) continue;

                        WriteProcessMemory(hProc, mem, &cbData, sizeof(LoaderData), nullptr);
                        LPVOID code = reinterpret_cast<LPVOID>(reinterpret_cast<uintptr_t>(mem)+sizeof(LoaderData));
                        WriteProcessMemory(hProc, code, g_shellcode32, sizeof(g_shellcode32), nullptr);

                        HANDLE ht = CreateRemoteThread(hProc, nullptr, 0,
                            reinterpret_cast<LPTHREAD_START_ROUTINE>(code), mem, 0, nullptr);
                        if (ht) { WaitForSingleObject(ht, 3000); CloseHandle(ht); }
                        VirtualFreeEx(hProc, mem, 0, MEM_RELEASE);
                    }
                }
            }
        }
    }

    AddLog("[*] Inicializando modulo...", COL_GRAY);

    LPVOID dllMainAddr = reinterpret_cast<LPVOID>(
        reinterpret_cast<uintptr_t>(imageBase) + entryRVA);

    LoaderData loaderData{};
    loaderData.imageBase      = imageBase;
    loaderData.fnLoadLibraryA = reinterpret_cast<FARPROC>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"));
    loaderData.fnGetProcAddr  = reinterpret_cast<FARPROC>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcAddress"));
    loaderData.fnDllMain      = reinterpret_cast<FARPROC>(dllMainAddr);
    loaderData.initialized    = 0;

    BYTE*  shellPtr  = is64 ? g_shellcode64 : g_shellcode32;
    SIZE_T shellSz   = is64 ? sizeof(g_shellcode64) : sizeof(g_shellcode32);
    SIZE_T totalSz   = sizeof(LoaderData) + shellSz;

    LPVOID shellMem = VirtualAllocEx(hProc, nullptr, totalSz, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!shellMem) {
        VirtualFreeEx(hProc, imageBase, 0, MEM_RELEASE);
        CloseHandle(hProc);
        AddLog("[!] Falha ao alocar shellcode.", COL_RED);
        return false;
    }

    LPVOID dataAddr = shellMem;
    LPVOID codeAddr = reinterpret_cast<LPVOID>(reinterpret_cast<uintptr_t>(shellMem) + sizeof(LoaderData));
    WriteProcessMemory(hProc, dataAddr, &loaderData, sizeof(LoaderData), nullptr);
    WriteProcessMemory(hProc, codeAddr, shellPtr,    shellSz,            nullptr);

    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(codeAddr), dataAddr, 0, nullptr);

    if (!hThread) {
        VirtualFreeEx(hProc, shellMem,  0, MEM_RELEASE);
        VirtualFreeEx(hProc, imageBase, 0, MEM_RELEASE);
        CloseHandle(hProc);
        AddLog("[!] Falha ao inicializar. Cod: " + std::to_string(GetLastError()), COL_RED);
        return false;
    }

    WaitForSingleObject(hThread, 8000);

    LoaderData result{};
    ReadProcessMemory(hProc, dataAddr, &result, sizeof(result), nullptr);

    VirtualFreeEx(hProc, shellMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProc);

    if (!result.initialized) {
        AddLog("[!] Modulo nao inicializou corretamente.", COL_RED);
        return false;
    }

    g_injected.push_back({ modName, reinterpret_cast<HMODULE>(imageBase) });

    sprintf_s(addrBuf, "%" PRIXPTR, reinterpret_cast<uintptr_t>(imageBase));
    AddLog("[+] " + modName + " carregado com sucesso.", COL_GREEN);
    AddLog("[*] Base: 0x" + std::string(addrBuf) + " | Arq: " + std::string(is64 ? "x64" : "x86"), COL_GOLD);
    RefreshModules();
    return true;
}

bool EjectDLL(const std::string& modName, HMODULE forceHandle = nullptr) {
    if (!g_gtaPID) { AddLog("[!] Processo nao selecionado.", COL_RED); return false; }

    LPVOID imageBase = reinterpret_cast<LPVOID>(forceHandle);
    bool isOurs = false;

    if (!imageBase) {
        for (auto& e : g_injected)
            if (_stricmp(e.modName.c_str(), modName.c_str()) == 0)
                { imageBase = reinterpret_cast<LPVOID>(e.handle); isOurs = true; break; }
    } else {
        for (auto& e : g_injected)
            if (_stricmp(e.modName.c_str(), modName.c_str()) == 0)
                { isOurs = true; break; }
    }

    if (!isOurs) {
        HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, g_gtaPID);
        if (!hProc) { AddLog("[!] OpenProcess falhou.", COL_RED); return false; }

        HMODULE mods[1024]; DWORD needed = 0;
        if (EnumProcessModules(hProc, mods, sizeof(mods), &needed)) {
            DWORD count = needed / sizeof(HMODULE);
            for (DWORD i = 0; i < count; i++) {
                char name[MAX_PATH] = {};
                GetModuleBaseNameA(hProc, mods[i], name, MAX_PATH);
                if (_stricmp(name, modName.c_str()) == 0) {
                    FARPROC pFree = GetProcAddress(GetModuleHandleA("kernel32.dll"), "FreeLibrary");
                    HANDLE ht = CreateRemoteThread(hProc, nullptr, 0,
                        reinterpret_cast<LPTHREAD_START_ROUTINE>(pFree), mods[i], 0, nullptr);
                    if (ht) { WaitForSingleObject(ht, 3000); CloseHandle(ht); }
                    CloseHandle(hProc);
                    AddLog("[-] Modulo ejetado: " + modName, COL_GOLD);
                    RefreshModules();
                    return true;
                }
            }
        }
        CloseHandle(hProc);
        AddLog("[!] Modulo nao encontrado no processo: " + modName, COL_RED);
        return false;
    }

    if (!imageBase) { AddLog("[!] Base nao encontrada para: " + modName, COL_RED); return false; }

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, g_gtaPID);
    if (!hProc) { AddLog("[!] OpenProcess falhou.", COL_RED); return false; }

    BOOL ok = VirtualFreeEx(hProc, imageBase, 0, MEM_RELEASE);
    CloseHandle(hProc);

    if (!ok) { AddLog("[!] VirtualFreeEx falhou. Cod: " + std::to_string(GetLastError()), COL_RED); return false; }

    g_injected.erase(std::remove_if(g_injected.begin(), g_injected.end(),
        [&](const InjectedEntry& e){ return _stricmp(e.modName.c_str(), modName.c_str()) == 0; }),
        g_injected.end());

    AddLog("[-] Regiao liberada: " + modName, COL_GOLD);
    AddLog("[✓] '" + modName + "' removida da memoria.", COL_GREEN);
    RefreshModules();
    return true;
}

struct ProcessInfo { DWORD pid; std::string name; };

std::vector<ProcessInfo> ListRunningProcesses() {
    std::vector<ProcessInfo> result;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return result;
    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            if (pe.th32ProcessID == 0) continue;
            result.push_back({ pe.th32ProcessID, pe.szExeFile });
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    std::sort(result.begin(), result.end(), [](const ProcessInfo& a, const ProcessInfo& b){
        return _stricmp(a.name.c_str(), b.name.c_str()) < 0;
    });
    return result;
}

void ApplyGTATheme() {
    ImGuiStyle& s = ImGui::GetStyle();
    s.WindowRounding    = 6.0f;
    s.FrameRounding     = 4.0f;
    s.ScrollbarRounding = 4.0f;
    s.GrabRounding      = 4.0f;
    s.FramePadding      = ImVec2(8, 5);
    s.ItemSpacing       = ImVec2(8, 6);
    s.WindowBorderSize  = 1.0f;

    ImVec4* c = s.Colors;
    c[ImGuiCol_WindowBg]            = ImVec4(0.07f, 0.07f, 0.07f, 1.0f);
    c[ImGuiCol_ChildBg]             = ImVec4(0.05f, 0.05f, 0.05f, 1.0f);
    c[ImGuiCol_PopupBg]             = ImVec4(0.08f, 0.08f, 0.08f, 1.0f);
    c[ImGuiCol_Border]              = ImVec4(0.55f, 0.44f, 0.00f, 0.7f);
    c[ImGuiCol_FrameBg]             = ImVec4(0.12f, 0.12f, 0.12f, 1.0f);
    c[ImGuiCol_FrameBgHovered]      = ImVec4(0.20f, 0.17f, 0.00f, 1.0f);
    c[ImGuiCol_FrameBgActive]       = ImVec4(0.28f, 0.23f, 0.00f, 1.0f);
    c[ImGuiCol_TitleBg]             = ImVec4(0.05f, 0.05f, 0.05f, 1.0f);
    c[ImGuiCol_TitleBgActive]       = ImVec4(0.10f, 0.08f, 0.00f, 1.0f);
    c[ImGuiCol_MenuBarBg]           = ImVec4(0.05f, 0.05f, 0.05f, 1.0f);
    c[ImGuiCol_ScrollbarBg]         = ImVec4(0.03f, 0.03f, 0.03f, 1.0f);
    c[ImGuiCol_ScrollbarGrab]       = ImVec4(0.50f, 0.40f, 0.00f, 1.0f);
    c[ImGuiCol_ScrollbarGrabHovered]= ImVec4(0.70f, 0.56f, 0.00f, 1.0f);
    c[ImGuiCol_ScrollbarGrabActive] = ImVec4(1.00f, 0.84f, 0.00f, 1.0f);
    c[ImGuiCol_CheckMark]           = ImVec4(1.00f, 0.84f, 0.00f, 1.0f);
    c[ImGuiCol_SliderGrab]          = ImVec4(0.80f, 0.65f, 0.00f, 1.0f);
    c[ImGuiCol_SliderGrabActive]    = ImVec4(1.00f, 0.84f, 0.00f, 1.0f);
    c[ImGuiCol_Button]              = ImVec4(0.18f, 0.14f, 0.00f, 1.0f);
    c[ImGuiCol_ButtonHovered]       = ImVec4(0.50f, 0.40f, 0.00f, 1.0f);
    c[ImGuiCol_ButtonActive]        = ImVec4(1.00f, 0.84f, 0.00f, 1.0f);
    c[ImGuiCol_Header]              = ImVec4(0.25f, 0.20f, 0.00f, 1.0f);
    c[ImGuiCol_HeaderHovered]       = ImVec4(0.45f, 0.36f, 0.00f, 1.0f);
    c[ImGuiCol_HeaderActive]        = ImVec4(0.65f, 0.52f, 0.00f, 1.0f);
    c[ImGuiCol_Separator]           = ImVec4(0.50f, 0.40f, 0.00f, 0.6f);
    c[ImGuiCol_Text]                = ImVec4(0.92f, 0.92f, 0.92f, 1.0f);
    c[ImGuiCol_TextDisabled]        = ImVec4(0.45f, 0.45f, 0.45f, 1.0f);
    c[ImGuiCol_Tab]                 = ImVec4(0.12f, 0.10f, 0.00f, 1.0f);
    c[ImGuiCol_TabHovered]          = ImVec4(0.50f, 0.40f, 0.00f, 1.0f);
    c[ImGuiCol_TabActive]           = ImVec4(0.30f, 0.24f, 0.00f, 1.0f);
}

void DrawAnimatedTitle(const char* text) {
    float panelW = ImGui::GetContentRegionAvail().x;
    float speed  = 60.0f;
    g_titleScroll += ImGui::GetIO().DeltaTime * speed;

    ImVec2 textSize = ImGui::CalcTextSize(text);
    float  maxScroll = textSize.x + panelW;
    if (g_titleScroll > maxScroll) g_titleScroll = 0.0f;

    float posX = panelW - g_titleScroll;

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 pMin = ImGui::GetCursorScreenPos();
    ImVec2 pMax = ImVec2(pMin.x + panelW, pMin.y + textSize.y + 4);
    dl->PushClipRect(pMin, pMax, true);

    dl->AddText(ImVec2(pMin.x + posX, pMin.y + 2),
        IM_COL32(255, 215, 0, 255), text);

    dl->PopClipRect();
    ImGui::Dummy(ImVec2(panelW, textSize.y + 6));
}

void RenderUI() {
    ImGuiIO& io = ImGui::GetIO();
    ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Always);
    ImGui::SetNextWindowSize(io.DisplaySize, ImGuiCond_Always);

    ImGuiWindowFlags wf = ImGuiWindowFlags_NoDecoration |
                          ImGuiWindowFlags_NoMove       |
                          ImGuiWindowFlags_NoResize     |
                          ImGuiWindowFlags_NoBringToFrontOnFocus;

    ImGui::Begin("##root", nullptr, wf);
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.05f,0.05f,0.05f,1.0f));

    ImGui::Spacing();
    DrawAnimatedTitle("  Injector .dll  |  Mod: v1 Beta  |  xitzinho: Black rock  |  auralobo: clean da pista  |  Preto & Ouro Edition  |  ");
    ImGui::Separator();
    ImGui::Spacing();

    {
        static std::vector<ProcessInfo> s_procList;
        static char s_procFilter[128] = "";
        static bool s_openPopup = false;

        bool found = g_gtaPID != 0;
        ImGui::TextColored(COL_GOLD, "Jogo Selecionado:");
        ImGui::SameLine();
        if (found)
            ImGui::TextColored(COL_GREEN, "%s  [PID: %lu]", g_selectedGame, g_gtaPID);
        else
            ImGui::TextColored(COL_RED, "%s", g_selectedGame);

        ImGui::SameLine(ImGui::GetContentRegionAvail().x - 200);

        ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.20f,0.15f,0.00f,1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.55f,0.43f,0.00f,1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(1.00f,0.84f,0.00f,1.0f));
        if (ImGui::Button("  Selecionar Jogo  ", ImVec2(180, 0))) {
            s_procList = ListRunningProcesses();
            memset(s_procFilter, 0, sizeof(s_procFilter));
            s_openPopup = true;
        }
        ImGui::PopStyleColor(3);

        if (s_openPopup) {
            ImGui::OpenPopup("##selectgame");
            s_openPopup = false;
        }

        ImGui::SetNextWindowSize(ImVec2(420, 460), ImGuiCond_Always);
        ImGui::SetNextWindowPos(ImVec2(io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f),
            ImGuiCond_Always, ImVec2(0.5f, 0.5f));

        if (ImGui::BeginPopupModal("##selectgame", nullptr,
            ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove))
        {
            ImGui::TextColored(COL_GOLD, "SELECIONAR JOGO / PROCESSO");
            ImGui::Separator();
            ImGui::Spacing();

            ImGui::TextColored(COL_GRAY, "Filtrar:");
            ImGui::SameLine();
            ImGui::SetNextItemWidth(-1);
            ImGui::InputText("##filter", s_procFilter, sizeof(s_procFilter));
            ImGui::Spacing();

            ImGui::BeginChild("##proclist", ImVec2(0, 340), true);
            for (auto& p : s_procList) {
                if (s_procFilter[0] != '\0' &&
                    _stristr(p.name.c_str(), s_procFilter) == nullptr) continue;

                std::string label = p.name + "  [" + std::to_string(p.pid) + "]";
                if (ImGui::Selectable(label.c_str())) {
                    g_gtaPID = p.pid;
                    strcpy_s(g_selectedGame, p.name.c_str());
                    AddLog("[+] Jogo selecionado: " + p.name +
                           " (PID " + std::to_string(p.pid) + ")", COL_GREEN);
                    RefreshModules();
                    ImGui::CloseCurrentPopup();
                }
            }
            ImGui::EndChild();

            ImGui::Spacing();
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.30f,0.05f,0.05f,1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.60f,0.08f,0.08f,1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.90f,0.10f,0.10f,1.0f));
            if (ImGui::Button("Cancelar", ImVec2(-1, 0)))
                ImGui::CloseCurrentPopup();
            ImGui::PopStyleColor(3);

            ImGui::EndPopup();
        }
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    float leftW  = ImGui::GetContentRegionAvail().x * 0.52f;
    float rightW = ImGui::GetContentRegionAvail().x - leftW - 8;
    float colH   = ImGui::GetContentRegionAvail().y - 8;

    ImGui::BeginChild("##left", ImVec2(leftW, colH), true);

    ImGui::TextColored(COL_GOLD, "DLL");
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::TextColored(COL_GRAY, "Caminho:");
    ImGui::SetNextItemWidth(leftW - 110);
    ImGui::InputText("##dllpath", g_dllPath, MAX_PATH, ImGuiInputTextFlags_ReadOnly);
    ImGui::SameLine();
    if (ImGui::Button("Procurar##f", ImVec2(80, 0))) {
        OPENFILENAMEA ofn{};
        char tmp[MAX_PATH] = "";
        ofn.lStructSize = sizeof(ofn); ofn.hwndOwner = g_hWnd;
        ofn.lpstrFilter = "DLL Files\0*.dll;*.dat\0All Files\0*.*\0";
        ofn.lpstrFile = tmp; ofn.nMaxFile = MAX_PATH;
        ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
        ofn.lpstrTitle = "Selecione a DLL";
        if (GetOpenFileNameA(&ofn)) strcpy_s(g_dllPath, tmp);
    }

    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.25f,0.04f,0.04f,1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.55f,0.06f,0.06f,1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.85f,0.08f,0.08f,1.0f));
    if (ImGui::Button("X##clr", ImVec2(22, 0)))
        g_dllPath[0] = '\0';
    ImGui::PopStyleColor(3);

    ImGui::Spacing();

    if (!g_injected.empty()) {
        ImGui::TextColored(COL_GOLD, "DLLs ativas (%zu):", g_injected.size());
        for (auto& e : g_injected) {
            ImGui::TextColored(COL_GREEN, "  ● %s", e.modName.c_str());
            ImGui::SameLine(leftW - 130);
            std::string ejLbl = "Dessinjetar##ej_" + e.modName;
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.28f,0.04f,0.04f,1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.55f,0.06f,0.06f,1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.88f,0.08f,0.08f,1.0f));
            if (ImGui::SmallButton(ejLbl.c_str()))
                EjectDLL(e.modName, e.handle);
            ImGui::PopStyleColor(3);
        }
        ImGui::Spacing();
    }

    {
        ImDrawList* dl = ImGui::GetWindowDrawList();
        ImVec2 p = ImGui::GetCursorScreenPos();
        float w = leftW - ImGui::GetStyle().WindowPadding.x * 2;
        float h = 28.0f;

        if (!g_ready.load()) {
            dl->AddRectFilled(p, ImVec2(p.x+w, p.y+h), IM_COL32(20,16,0,200), 4.0f);
            dl->AddRect      (p, ImVec2(p.x+w, p.y+h), IM_COL32(160,120,0,255), 4.0f);
            ImGui::Dummy(ImVec2(w,h));
            ImVec2 ts = ImGui::CalcTextSize("~ Inicializando modulos, aguarde...");
            dl->AddText(ImVec2(p.x+(w-ts.x)*.5f, p.y+(h-ts.y)*.5f), IM_COL32(180,140,0,255), "~ Inicializando modulos, aguarde...");
        } else if (g_injected.empty()) {
            dl->AddRectFilled(p, ImVec2(p.x+w, p.y+h), IM_COL32(120,30,0,180), 4.0f);
            dl->AddRect      (p, ImVec2(p.x+w, p.y+h), IM_COL32(220,60,0,255), 4.0f);
            ImGui::Dummy(ImVec2(w,h));
            ImVec2 ts = ImGui::CalcTextSize("! Nenhuma DLL injetada no momento");
            dl->AddText(ImVec2(p.x+(w-ts.x)*.5f, p.y+(h-ts.y)*.5f), IM_COL32(255,140,0,255), "! Nenhuma DLL injetada no momento");
        } else {
            dl->AddRectFilled(p, ImVec2(p.x+w, p.y+h), IM_COL32(10,80,10,180), 4.0f);
            dl->AddRect      (p, ImVec2(p.x+w, p.y+h), IM_COL32(30,200,30,255), 4.0f);
            ImGui::Dummy(ImVec2(w,h));
            std::string txt = std::to_string(g_injected.size()) + " DLL(s) ativa(s) no processo";
            ImVec2 ts = ImGui::CalcTextSize(txt.c_str());
            dl->AddText(ImVec2(p.x+(w-ts.x)*.5f, p.y+(h-ts.y)*.5f), IM_COL32(80,255,80,255), txt.c_str());
        }
    }

    ImGui::Spacing();

    float btnW = (leftW - ImGui::GetStyle().ItemSpacing.x * 2 - ImGui::GetStyle().WindowPadding.x * 2) * 0.5f;
    bool canAct = g_ready.load() && g_gtaPID != 0;

    if (!canAct) ImGui::BeginDisabled();
    ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.08f,0.28f,0.04f,1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.12f,0.50f,0.06f,1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.18f,0.75f,0.09f,1.0f));
    if (ImGui::Button("  INJETAR  ", ImVec2(btnW, 44)))
        InjectDLL(g_dllPath);
    ImGui::PopStyleColor(3);
    if (!canAct) ImGui::EndDisabled();

    ImGui::SameLine();

    bool canEjectAll = canAct && !g_injected.empty();
    if (!canEjectAll) ImGui::BeginDisabled();
    ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.28f,0.04f,0.04f,1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.55f,0.06f,0.06f,1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.88f,0.08f,0.08f,1.0f));
    if (ImGui::Button("DESSINJ. TODAS", ImVec2(btnW, 44))) {
        AddLog("[*] Removendo todas as DLLs injetadas...", COL_GOLD);
        std::vector<InjectedEntry> toRemove = g_injected;
        for (auto& e : toRemove)
            EjectDLL(e.modName, e.handle);
    }
    ImGui::PopStyleColor(3);
    if (!canEjectAll) ImGui::EndDisabled();

    ImGui::Spacing();
    ImGui::Spacing();

    ImGui::TextColored(COL_GOLD, "MODULOS CARREGADOS");
    ImGui::SameLine(leftW - 130);
    if (ImGui::SmallButton("Atualizar Lista")) RefreshModules();
    ImGui::Separator();

    ImGui::BeginChild("##modlist", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);

    if (!g_injected.empty()) {
        ImDrawList* dl = ImGui::GetWindowDrawList();

        for (auto& e : g_injected) {
            ImVec2 rowMin = ImGui::GetCursorScreenPos();
            float  rowW   = ImGui::GetContentRegionAvail().x;
            dl->AddRectFilled(rowMin,
                ImVec2(rowMin.x + rowW, rowMin.y + ImGui::GetTextLineHeightWithSpacing()),
                IM_COL32(10, 60, 10, 120), 3.0f);

            ImGui::TextColored(COL_GREEN, "  ● %s", e.modName.c_str());
            ImGui::SameLine();

            char baseBuf[32];
            sprintf_s(baseBuf, " 0x%" PRIXPTR, reinterpret_cast<uintptr_t>(e.handle));
            ImGui::TextColored(COL_GOLD_DIM, "%s", baseBuf);

            ImGui::SameLine(leftW - 120);
            std::string ejLbl = "Remover##ml_" + e.modName;
            ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.28f,0.04f,0.04f,1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.55f,0.06f,0.06f,1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.88f,0.08f,0.08f,1.0f));
            if (ImGui::SmallButton(ejLbl.c_str()))
                EjectDLL(e.modName, e.handle);
            ImGui::PopStyleColor(3);
        }

        ImGui::Spacing();
        ImGui::PushStyleColor(ImGuiCol_Separator, ImVec4(0.30f,0.24f,0.00f,0.8f));
        ImGui::Separator();
        ImGui::PopStyleColor();
        ImGui::Spacing();
    }

    for (auto& m : g_modules) {
        ImGui::TextColored(COL_GRAY, "  %s", m.name.c_str());
        ImGui::SameLine(leftW - 120);

        std::string btnLabel = "Ejetar##" + m.name;
        ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.30f,0.05f,0.05f,1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.60f,0.08f,0.08f,1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.90f,0.10f,0.10f,1.0f));
        if (ImGui::SmallButton(btnLabel.c_str()))
            EjectDLL(m.name, nullptr);
        ImGui::PopStyleColor(3);
    }

    if (g_modules.empty() && g_injected.empty())
        ImGui::TextColored(COL_GRAY, "  (Nenhum modulo listado)");

    ImGui::EndChild();

    ImGui::EndChild();

    ImGui::SameLine();

    ImGui::BeginChild("##right", ImVec2(rightW, colH), true);
    ImGui::TextColored(COL_GOLD, "LOG DE OPERACOES");
    ImGui::SameLine(rightW - 80);
    if (ImGui::SmallButton("Limpar")) g_log.clear();
    ImGui::Separator();

    float credH = 72.0f;
    ImGui::BeginChild("##logscroll", ImVec2(0, -(credH + 10)), false);
    for (auto& e : g_log)
        ImGui::TextColored(e.color, "%s", e.msg.c_str());
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
        ImGui::SetScrollHereY(1.0f);
    ImGui::EndChild();

    ImGui::Separator();
    ImGui::Spacing();
    ImGui::TextColored(COL_GOLD, "CREDITOS");
    ImGui::Spacing();

    ImGui::TextColored(ImVec4(0.75f,0.75f,0.75f,1.0f), "  xitzinho");
    ImGui::SameLine();
    ImGui::TextColored(COL_GOLD, ":");
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.55f,0.85f,1.0f,1.0f), "Black rock");

    ImGui::TextColored(ImVec4(0.75f,0.75f,0.75f,1.0f), "  auralobo");
    ImGui::SameLine();
    ImGui::TextColored(COL_GOLD, ":");
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.55f,0.85f,1.0f,1.0f), "clean da pista");

    ImGui::EndChild();

    if (!g_ready.load()) {
        DWORD elapsed = (GetTickCount() - g_startTick) / 1000;
        int   restante = 15 - (int)elapsed;
        if (restante < 0) restante = 0;

        ImDrawList* bg = ImGui::GetForegroundDrawList();
        ImVec2 scr = io.DisplaySize;

        bg->AddRectFilled(ImVec2(0,0), scr, IM_COL32(0, 0, 0, 170));

        float bw = 340.0f, bh = 110.0f;
        float bx = (scr.x - bw) * 0.5f, by = (scr.y - bh) * 0.5f;
        bg->AddRectFilled(ImVec2(bx, by), ImVec2(bx+bw, by+bh),
            IM_COL32(14, 11, 0, 245), 8.0f);
        bg->AddRect(ImVec2(bx, by), ImVec2(bx+bw, by+bh),
            IM_COL32(180, 140, 0, 255), 8.0f, 0, 1.5f);

        const char* l1 = "Inicializando modulos...";
        ImVec2 s1 = ImGui::CalcTextSize(l1);
        bg->AddText(ImVec2(bx + (bw - s1.x)*0.5f, by + 14),
            IM_COL32(180, 140, 0, 255), l1);

        char countBuf[32];
        sprintf_s(countBuf, "Faltam  %d  segundo%s",
            restante, restante == 1 ? "" : "s");
        ImVec2 s2 = ImGui::CalcTextSize(countBuf);
        bg->AddText(ImVec2(bx + (bw - s2.x)*0.5f, by + 38),
            IM_COL32(255, 215, 0, 255), countBuf);

        float prog  = 1.0f - (restante / 15.0f);
        float pbx   = bx + 20, pby = by + 72;
        float pbw   = bw - 40, pbh = 8.0f;
        bg->AddRectFilled(ImVec2(pbx, pby), ImVec2(pbx+pbw, pby+pbh),
            IM_COL32(30, 24, 0, 255), 4.0f);
        bg->AddRectFilled(ImVec2(pbx, pby), ImVec2(pbx + pbw*prog, pby+pbh),
            IM_COL32(255, 215, 0, 210), 4.0f);

        const char* l3 = "Voce pode selecionar o jogo enquanto aguarda";
        ImVec2 s3 = ImGui::CalcTextSize(l3);
        bg->AddText(ImVec2(bx + (bw - s3.x)*0.5f, by + 88),
            IM_COL32(90, 70, 0, 255), l3);
    }

    ImGui::PopStyleColor();
    ImGui::End();
}

bool CreateD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount = 2;
    sd.BufferDesc.Width = sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    D3D_FEATURE_LEVEL fl;
    if (D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
        nullptr, 0, D3D11_SDK_VERSION, &sd, &g_pSwapChain,
        &g_pd3dDevice, &fl, &g_pd3dDeviceContext) != S_OK)
        return false;

    ID3D11Texture2D* pBack = nullptr;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBack));
    g_pd3dDevice->CreateRenderTargetView(pBack, nullptr, &g_mainRenderTargetView);
    pBack->Release();
    return true;
}

void CleanupD3D() {
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
    if (g_pSwapChain)           { g_pSwapChain->Release();           g_pSwapChain           = nullptr; }
    if (g_pd3dDeviceContext)    { g_pd3dDeviceContext->Release();     g_pd3dDeviceContext    = nullptr; }
    if (g_pd3dDevice)           { g_pd3dDevice->Release();           g_pd3dDevice           = nullptr; }
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam)) return true;
    switch (msg) {
    case WM_SIZE:
        if (g_pd3dDevice && wParam != SIZE_MINIMIZED) {
            if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
            g_pSwapChain->ResizeBuffers(0, LOWORD(lParam), HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
            ID3D11Texture2D* pBack = nullptr;
            g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBack));
            g_pd3dDevice->CreateRenderTargetView(pBack, nullptr, &g_mainRenderTargetView);
            pBack->Release();
        }
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

DWORD WINAPI DelayThread(LPVOID) {
    Sleep(15000);
    g_ready = true;
    return 0;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int) {
    WNDCLASSEXW wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_CLASSDC;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.lpszClassName = L"GTAInjector";
    wc.hIcon         = LoadIcon(nullptr, IDI_APPLICATION);
    wc.hIconSm       = LoadIcon(nullptr, IDI_APPLICATION);
    wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    RegisterClassExW(&wc);

    g_hWnd = CreateWindowExW(
        0,
        wc.lpszClassName,
        L"Injector .dll  —  v1 Beta",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        100, 100, 900, 600,
        nullptr, nullptr, hInst, nullptr);

    if (!g_hWnd) { UnregisterClassW(wc.lpszClassName, hInst); return 1; }
    if (!CreateD3D(g_hWnd)) { CleanupD3D(); UnregisterClassW(wc.lpszClassName, hInst); return 1; }

    ShowWindow(g_hWnd, SW_SHOWDEFAULT);
    UpdateWindow(g_hWnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename  = nullptr;

    ApplyGTATheme();
    ImGui_ImplWin32_Init(g_hWnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    AddLog("[*] Injector .dll  |  Mod: v1 Beta", COL_GOLD);
    AddLog("[*] Clique em 'Selecionar Jogo' para comecar.", COL_GRAY);
    AddLog("[~] Aguarde — inicializando modulos...", COL_GOLD_DIM);

    g_startTick = GetTickCount();
    HANDLE hDelayThread = CreateThread(nullptr, 0, DelayThread, nullptr, 0, nullptr);

    MSG msg{};
    while (msg.message != WM_QUIT) {
        if (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            continue;
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        RenderUI();

        ImGui::Render();
        const float cc[4] = {0.06f, 0.06f, 0.06f, 1.0f};
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, cc);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_pSwapChain->Present(1, 0);
    }

    if (hDelayThread) {
        WaitForSingleObject(hDelayThread, INFINITE);
        CloseHandle(hDelayThread);
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupD3D();
    DestroyWindow(g_hWnd);
    UnregisterClassW(wc.lpszClassName, hInst);
    return 0;
}
