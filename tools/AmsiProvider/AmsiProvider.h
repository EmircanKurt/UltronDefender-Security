#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <unknwn.h>
#include <amsi.h>

// Ultron Defender AMSI Provider COM CLSID: {638DC8E4-1B1C-4328-8C67-DF52445EFA10}
// GUID: 638dc8e4-1b1c-4328-8c67-df52445efa10
static const GUID CLSID_UltronDefenderAmsiProvider = 
{ 0x638dc8e4, 0x1b1c, 0x4328, { 0x8c, 0x67, 0xdf, 0x52, 0x44, 0x5e, 0xfa, 0x10 } };

static const WCHAR CLSID_UltronDefenderAmsiProvider_String[] = L"{638DC8E4-1B1C-4328-8C67-DF52445EFA10}";
static const WCHAR AMSI_PROVIDER_NAME[] = L"Ultron Defender AMSI Security Provider";
static const WCHAR AEGIS_IPC_PIPE_NAME[] = L"\\\\.\\pipe\\AegisPC_ScanPipe";

#ifndef HAMSICONTEXT
typedef PVOID HAMSICONTEXT;
#endif

#ifndef HAMSISESSION
typedef PVOID HAMSISESSION;
#endif

/// <summary>
/// Ultron Defender unmanaged IAmsiProvider COM implementation.
/// </summary>
class CAmsiProvider : public IAmsiProvider
{
public:
    CAmsiProvider();
    virtual ~CAmsiProvider();

    // IUnknown
    STDMETHODIMP QueryInterface(REFIID riid, void** ppv) override;
    STDMETHODIMP_(ULONG) AddRef() override;
    STDMETHODIMP_(ULONG) Release() override;

    // IAmsiProvider
    STDMETHODIMP_(void) CloseSession(ULONGLONG session) override;
    STDMETHODIMP Scan(IAmsiStream* stream, AMSI_RESULT* result) override;
    STDMETHODIMP DisplayName(LPWSTR* displayName) override;

private:
    LONG m_cRef;
};

/// <summary>
/// Class factory for CAmsiProvider.
/// </summary>
class CAmsiProviderClassFactory : public IClassFactory
{
public:
    CAmsiProviderClassFactory();
    virtual ~CAmsiProviderClassFactory();

    // IUnknown
    STDMETHODIMP QueryInterface(REFIID riid, void** ppv) override;
    STDMETHODIMP_(ULONG) AddRef() override;
    STDMETHODIMP_(ULONG) Release() override;

    // IClassFactory
    STDMETHODIMP CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppv) override;
    STDMETHODIMP LockServer(BOOL fLock) override;

private:
    LONG m_cRef;
};

// Exported Direct Win32 AMSI API Functions
extern "C" {
    __declspec(dllexport) HRESULT WINAPI AmsiInitialize(LPCWSTR appName, HAMSICONTEXT* amsiContext);
    __declspec(dllexport) HRESULT WINAPI AmsiOpenSession(HAMSICONTEXT amsiContext, HAMSISESSION* amsiSession);
    __declspec(dllexport) void WINAPI AmsiCloseSession(HAMSICONTEXT amsiContext, HAMSISESSION amsiSession);
    __declspec(dllexport) HRESULT WINAPI AmsiScanString(HAMSICONTEXT amsiContext, LPCWSTR string, LPCWSTR contentName, HAMSISESSION amsiSession, AMSI_RESULT* result);
    __declspec(dllexport) HRESULT WINAPI AmsiScanBuffer(HAMSICONTEXT amsiContext, PVOID buffer, ULONG length, LPCWSTR contentName, HAMSISESSION amsiSession, AMSI_RESULT* result);
}
