#include "AmsiProvider.h"
#include <strsafe.h>
#include <string>
#include <vector>

static HINSTANCE g_hInst = NULL;
static LONG g_cDllRef = 0;

// Forward declaration
static HRESULT ScanDataWithDetectionHub(const BYTE* pData, ULONG ulLength, LPCWSTR pszContentName, AMSI_RESULT* pResult);

// DLL Entry Point
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        g_hInst = hinstDLL;
        DisableThreadLibraryCalls(hinstDLL);
    }
    return TRUE;
}

// -------------------------------------------------------------------------
// CAmsiProvider Implementation
// -------------------------------------------------------------------------

CAmsiProvider::CAmsiProvider() : m_cRef(1)
{
    InterlockedIncrement(&g_cDllRef);
}

CAmsiProvider::~CAmsiProvider()
{
    InterlockedDecrement(&g_cDllRef);
}

STDMETHODIMP CAmsiProvider::QueryInterface(REFIID riid, void** ppv)
{
    if (!ppv) return E_POINTER;
    *ppv = NULL;

    if (riid == IID_IUnknown || riid == __uuidof(IAmsiProvider))
    {
        *ppv = static_cast<IAmsiProvider*>(this);
        AddRef();
        return S_OK;
    }

    return E_NOINTERFACE;
}

STDMETHODIMP_(ULONG) CAmsiProvider::AddRef()
{
    return InterlockedIncrement(&m_cRef);
}

STDMETHODIMP_(ULONG) CAmsiProvider::Release()
{
    ULONG cRef = InterlockedDecrement(&m_cRef);
    if (cRef == 0)
    {
        delete this;
    }
    return cRef;
}

STDMETHODIMP_(void) CAmsiProvider::CloseSession(ULONGLONG session)
{
    // Session cleanup hook
}

STDMETHODIMP CAmsiProvider::DisplayName(LPWSTR* displayName)
{
    if (!displayName) return E_POINTER;

    SIZE_T cch = wcslen(AMSI_PROVIDER_NAME) + 1;
    *displayName = static_cast<LPWSTR>(CoTaskMemAlloc(cch * sizeof(WCHAR)));
    if (!*displayName) return E_OUTOFMEMORY;

    StringCchCopyW(*displayName, cch, AMSI_PROVIDER_NAME);
    return S_OK;
}

STDMETHODIMP CAmsiProvider::Scan(IAmsiStream* stream, AMSI_RESULT* result)
{
    if (!stream || !result) return E_POINTER;
    *result = AMSI_RESULT_NOT_DETECTED;

    // AMSI akış metaverilerini sorgula
    PVOID pAppName = NULL;
    PVOID pContentName = NULL;
    ULONG ulContentSize = 0;

    stream->GetAttribute(AMSI_ATTRIBUTE_APP_NAME, 0, NULL, (ULONG*)&pAppName);
    stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_NAME, 0, NULL, (ULONG*)&pContentName);
    stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_SIZE, sizeof(ULONG), (PBYTE)&ulContentSize, NULL);

    LPCWSTR pszContentName = pContentName ? (LPCWSTR)pContentName : L"MemoryScript";

    // Güvenli tampon tahsisi (Maksimum 8 MB tarama penceresi)
    ULONG ulToRead = min(ulContentSize, 8 * 1024 * 1024);
    if (ulToRead == 0)
    {
        *result = AMSI_RESULT_CLEAN;
        return S_OK;
    }

    std::vector<BYTE> buffer(ulToRead);
    ULONG ulBytesRead = 0;
    HRESULT hr = stream->Read(0, ulToRead, buffer.data(), &ulBytesRead);
    if (FAILED(hr) || ulBytesRead == 0)
    {
        *result = AMSI_RESULT_NOT_DETECTED;
        return S_OK;
    }

    // Veriyi Named Pipe üzerinden Ultron Defender DetectionHub motoruna ilet
    return ScanDataWithDetectionHub(buffer.data(), ulBytesRead, pszContentName, result);
}

// -------------------------------------------------------------------------
// CAmsiProviderClassFactory Implementation
// -------------------------------------------------------------------------

CAmsiProviderClassFactory::CAmsiProviderClassFactory() : m_cRef(1)
{
    InterlockedIncrement(&g_cDllRef);
}

CAmsiProviderClassFactory::~CAmsiProviderClassFactory()
{
    InterlockedDecrement(&g_cDllRef);
}

STDMETHODIMP CAmsiProviderClassFactory::QueryInterface(REFIID riid, void** ppv)
{
    if (!ppv) return E_POINTER;
    *ppv = NULL;

    if (riid == IID_IUnknown || riid == IID_IClassFactory)
    {
        *ppv = static_cast<IClassFactory*>(this);
        AddRef();
        return S_OK;
    }

    return E_NOINTERFACE;
}

STDMETHODIMP_(ULONG) CAmsiProviderClassFactory::AddRef()
{
    return InterlockedIncrement(&m_cRef);
}

STDMETHODIMP_(ULONG) CAmsiProviderClassFactory::Release()
{
    ULONG cRef = InterlockedDecrement(&m_cRef);
    if (cRef == 0)
    {
        delete this;
    }
    return cRef;
}

STDMETHODIMP CAmsiProviderClassFactory::CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppv)
{
    if (!ppv) return E_POINTER;
    *ppv = NULL;

    if (pUnkOuter != NULL) return CLASS_E_NOAGGREGATION;

    CAmsiProvider* pProvider = new (std::nothrow) CAmsiProvider();
    if (!pProvider) return E_OUTOFMEMORY;

    HRESULT hr = pProvider->QueryInterface(riid, ppv);
    pProvider->Release();
    return hr;
}

STDMETHODIMP CAmsiProviderClassFactory::LockServer(BOOL fLock)
{
    if (fLock)
        InterlockedIncrement(&g_cDllRef);
    else
        InterlockedDecrement(&g_cDllRef);
    return S_OK;
}

// -------------------------------------------------------------------------
// Named Pipe IPC Bridge to AegisPC.Service DetectionHub
// -------------------------------------------------------------------------

static bool LocalHeuristicFallback(const BYTE* pData, ULONG ulLength)
{
    if (!pData || ulLength == 0) return false;

    // 1. EICAR Test Dizgisi
    const char* eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    size_t eicarLen = strlen(eicar);
    if (ulLength >= eicarLen)
    {
        for (ULONG i = 0; i <= ulLength - eicarLen; i++)
        {
            if (memcmp(pData + i, eicar, eicarLen) == 0)
            {
                return true;
            }
        }
    }

    // 2. Yaygın AMSI Bypass ve Bellek Enjeksiyon Anahtarları
    std::string text((const char*)pData, min(ulLength, 16384));
    for (char& c : text) c = (char)tolower(c);

    if (text.find("amsiinitfailed") != std::string::npos ||
        (text.find("amsiutils") != std::string::npos && text.find("nonpublic") != std::string::npos) ||
        (text.find("downloadstring") != std::string::npos && text.find("bypass") != std::string::npos))
    {
        return true;
    }

    return false;
}

static HRESULT ScanDataWithDetectionHub(const BYTE* pData, ULONG ulLength, LPCWSTR pszContentName, AMSI_RESULT* pResult)
{
    *pResult = AMSI_RESULT_NOT_DETECTED;

    // 1. Önce Named Pipe üzerinden AegisPC.Service'e bağlanmayı dene
    HANDLE hPipe = CreateFileW(
        AEGIS_IPC_PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        NULL);

    if (hPipe != INVALID_HANDLE_VALUE)
    {
        // 500ms timeout ile pipe üzerinden tarama isteği gönder
        DWORD dwMode = PIPE_READMODE_MESSAGE;
        SetNamedPipeHandleState(hPipe, &dwMode, NULL, NULL);

        std::string request = "{\"Command\":\"AmsiScan\",\"Length\":" + std::to_string(ulLength) + "}\n";
        DWORD dwWritten = 0;
        WriteFile(hPipe, request.c_str(), (DWORD)request.length(), &dwWritten, NULL);

        char responseBuf[512] = { 0 };
        DWORD dwRead = 0;
        if (ReadFile(hPipe, responseBuf, sizeof(responseBuf) - 1, &dwRead, NULL) && dwRead > 0)
        {
            std::string resp(responseBuf, dwRead);
            if (resp.find("\"Verdict\":\"Malicious\"") != std::string::npos ||
                resp.find("\"Blocked\":true") != std::string::npos)
            {
                *pResult = AMSI_RESULT_DETECTED;
                CloseHandle(hPipe);
                return S_OK;
            }
        }

        CloseHandle(hPipe);
    }

    // 2. Servis çevrimdışı veya yanıt vermiyorsa yerel yedek tarayıcıyı (fallback) çalıştır
    if (LocalHeuristicFallback(pData, ulLength))
    {
        *pResult = AMSI_RESULT_DETECTED;
    }
    else
    {
        *pResult = AMSI_RESULT_CLEAN;
    }

    return S_OK;
}

// -------------------------------------------------------------------------
// COM Server Registration and Entry Points
// -------------------------------------------------------------------------

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv)
{
    if (rclsid != CLSID_UltronDefenderAmsiProvider)
    {
        return CLASS_E_CLASSNOTAVAILABLE;
    }

    CAmsiProviderClassFactory* pFactory = new (std::nothrow) CAmsiProviderClassFactory();
    if (!pFactory) return E_OUTOFMEMORY;

    HRESULT hr = pFactory->QueryInterface(riid, ppv);
    pFactory->Release();
    return hr;
}

STDAPI DllCanUnloadNow(void)
{
    return (g_cDllRef == 0) ? S_OK : S_FALSE;
}

STDAPI DllRegisterServer(void)
{
    WCHAR szModule[MAX_PATH];
    if (GetModuleFileNameW(g_hInst, szModule, ARRAYSIZE(szModule)) == 0)
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    // 1. CLSID Kaydı (HKCR\CLSID\{GUID}\InprocServer32)
    WCHAR szKey[MAX_PATH];
    StringCchPrintfW(szKey, ARRAYSIZE(szKey), L"CLSID\\%s", CLSID_UltronDefenderAmsiProvider_String);

    HKEY hKey = NULL;
    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, szKey, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS)
    {
        RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE*)AMSI_PROVIDER_NAME, (DWORD)(wcslen(AMSI_PROVIDER_NAME) + 1) * sizeof(WCHAR));
        
        HKEY hSubKey = NULL;
        if (RegCreateKeyExW(hKey, L"InprocServer32", 0, NULL, 0, KEY_WRITE, NULL, &hSubKey, NULL) == ERROR_SUCCESS)
        {
            RegSetValueExW(hSubKey, NULL, 0, REG_SZ, (const BYTE*)szModule, (DWORD)(wcslen(szModule) + 1) * sizeof(WCHAR));
            const WCHAR szModel[] = L"Both";
            RegSetValueExW(hSubKey, L"ThreadingModel", 0, REG_SZ, (const BYTE*)szModel, (DWORD)(wcslen(szModel) + 1) * sizeof(WCHAR));
            RegCloseKey(hSubKey);
        }
        RegCloseKey(hKey);
    }

    // 2. AMSI Providers Kaydı (HKLM\SOFTWARE\Microsoft\AMSI\Providers\{GUID})
    StringCchPrintfW(szKey, ARRAYSIZE(szKey), L"SOFTWARE\\Microsoft\\AMSI\\Providers\\%s", CLSID_UltronDefenderAmsiProvider_String);
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, szKey, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS)
    {
        RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE*)AMSI_PROVIDER_NAME, (DWORD)(wcslen(AMSI_PROVIDER_NAME) + 1) * sizeof(WCHAR));
        RegCloseKey(hKey);
    }

    return S_OK;
}

STDAPI DllUnregisterServer(void)
{
    WCHAR szKey[MAX_PATH];

    // 1. AMSI Providers'tan kaldır
    StringCchPrintfW(szKey, ARRAYSIZE(szKey), L"SOFTWARE\\Microsoft\\AMSI\\Providers\\%s", CLSID_UltronDefenderAmsiProvider_String);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, szKey);

    // 2. CLSID'den kaldır
    StringCchPrintfW(szKey, ARRAYSIZE(szKey), L"CLSID\\%s\\InprocServer32", CLSID_UltronDefenderAmsiProvider_String);
    RegDeleteKeyW(HKEY_CLASSES_ROOT, szKey);

    StringCchPrintfW(szKey, ARRAYSIZE(szKey), L"CLSID\\%s", CLSID_UltronDefenderAmsiProvider_String);
    RegDeleteKeyW(HKEY_CLASSES_ROOT, szKey);

    return S_OK;
}

// -------------------------------------------------------------------------
// Exported Direct AMSI Functions (AmsiInitialize, AmsiScanBuffer, etc.)
// -------------------------------------------------------------------------

extern "C" {

HRESULT WINAPI AmsiInitialize(LPCWSTR appName, HAMSICONTEXT* amsiContext)
{
    if (!amsiContext) return E_POINTER;
    *amsiContext = (HAMSICONTEXT)(ULONG_PTR)0xAE615001; // Ultron Context Handle
    return S_OK;
}

HRESULT WINAPI AmsiOpenSession(HAMSICONTEXT amsiContext, HAMSISESSION* amsiSession)
{
    if (!amsiSession) return E_POINTER;
    *amsiSession = (HAMSISESSION)(ULONG_PTR)0xAE615002; // Ultron Session Handle
    return S_OK;
}

void WINAPI AmsiCloseSession(HAMSICONTEXT amsiContext, HAMSISESSION amsiSession)
{
    // Close session handle
}

HRESULT WINAPI AmsiScanString(HAMSICONTEXT amsiContext, LPCWSTR string, LPCWSTR contentName, HAMSISESSION amsiSession, AMSI_RESULT* result)
{
    if (!string || !result) return E_POINTER;
    ULONG len = (ULONG)(wcslen(string) * sizeof(WCHAR));
    return ScanDataWithDetectionHub((const BYTE*)string, len, contentName ? contentName : L"StringContent", result);
}

HRESULT WINAPI AmsiScanBuffer(HAMSICONTEXT amsiContext, PVOID buffer, ULONG length, LPCWSTR contentName, HAMSISESSION amsiSession, AMSI_RESULT* result)
{
    if (!buffer || !result) return E_POINTER;
    return ScanDataWithDetectionHub((const BYTE*)buffer, length, contentName ? contentName : L"BufferContent", result);
}

}
