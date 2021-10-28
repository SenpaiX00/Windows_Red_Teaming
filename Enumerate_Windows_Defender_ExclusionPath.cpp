
/*Enumerate Windows Defender ExclusionPath
The following function prints the path or paths that are excluded from Windows Defender scans. Requires Administrator privileges.

Use case: In Simulated Attack engagements, this function can be converted into a Beacon Object File and be executed with inline-execute to enumerate exclusion paths that 
can be used to drop additional payloads.
*/




INT EnumDefenderExclussions()
{
	// PowerShell equivalent:
	// Get-MpPreference | Select-Object -Property ExclusionPath
	//
	// References:
	//  - https://social.msdn.microsoft.com/Forums/vstudio/en-US/74e8dca7-e557-47df-94a2-016822494f78/wmi-defender-exploring-and-configuration-through-com-in-c?forum=windowsgeneraldevelopmentissues
	//  - https://docs.microsoft.com/en-us/windows/win32/wmisdk/example--getting-wmi-data-from-the-local-computer
	
	HRESULT hr;
	hr = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hr))
	{
		::wprintf(L"[-] CoInitializeEx has failed\n");
		return 0;
	}

	hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
	if (FAILED(hr))
	{
		::wprintf(L"[-] CoInitializeSecurity has failed\n");
		CoUninitialize();
		return 0;
	}

	IWbemLocator *pLoc = 0;
	hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
	if (FAILED(hr))
	{
		::wprintf(L"[-] CoCreateInstance has failed\n");
		CoUninitialize();
		return 0;
	}

	IWbemServices* pSvc = 0;
	hr = pLoc->ConnectServer(BSTR(L"ROOT\\Microsoft\\Windows\\Defender"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
	if (FAILED(hr))
	{
		::wprintf(L"[-] ConnectServer has failed\n");
		pLoc->Release();
		CoUninitialize();
		return 0;
	}

	hr = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT,	RPC_C_AUTHZ_NONE, NULL,	RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
	if (FAILED(hr))
	{
		::wprintf(L"[-] CoSetProxyBlanket has failed\n");
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 0;
	}
	
	BSTR Language = BSTR(L"WQL");
	BSTR Query = BSTR(L"SELECT * FROM MSFT_MpPreference");
	IEnumWbemClassObject* pEnum = 0;
	hr = pSvc->ExecQuery(Language, Query, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 0, &pEnum);
	if (FAILED(hr))
	{
		::wprintf(L"[-] ExecQuery has failed\n");
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 0;
	}
	
	IWbemClassObject* pObj = 0;
	ULONG uRet = 0;

	while (pEnum)
	{
		hr = pEnum->Next(WBEM_INFINITE, 1, &pObj, &uRet);
				
		if (uRet == 0) { break; }
		
		VARIANT v;
		CIMTYPE ctype = 0;
		hr = pObj->Get(L"ExclusionPath", 0, &v, &ctype, NULL);

		SAFEARRAY* sa = V_ARRAY(&v);
		LONG lstart, lend;
		hr = SafeArrayGetLBound(sa, 1, &lstart);
		if (FAILED(hr)) { ::wprintf(L"[-] SafeArrayGetLBound has failed\n"); }

		hr = SafeArrayGetUBound(sa, 1, &lend);
		if (FAILED(hr)) { ::wprintf(L"[-] SafeArrayGetUBound has failed\n"); }

		BSTR* pexpath;
		hr = SafeArrayAccessData(sa, (void HUGEP**)&pexpath);
		if (SUCCEEDED(hr))
		{
			::wprintf(L"[+] Exclusion path:\n");
			for (LONG idx = lstart; idx <= lend; idx++)
			{
				::wprintf(L"\t%s\n", pexpath[idx]);
			}
			SafeArrayUnaccessData(sa);
		}

		VariantClear(&v);
		pObj->Release();
	}

	pLoc->Release();
	pSvc->Release();
	pEnum->Release();
	CoUninitialize();

	return 1;
}
