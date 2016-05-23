
//=======================================================================
// IsEmailValid
//=======================================================================
int IsEmailValid(const char * szAddress)
{
	int dwCount = 0;
	const char* szC;
	const char* szDomain;
	static char* RFC822_Specials = "°|{}*'£+!$%&?=^#()<>@,;:\\\"[]";

	for (szC = szAddress; *szC; szC++)
	{
		if (*szC == '\"' && (szC == szAddress || *(szC - 1) == '.' || *(szC - 1) == '\"'))
		{
			while (*++szC)
			{
				if (*szC == '\"') break;
				if (*szC == '\\' && (*++szC == ' ')) continue;
				if (*szC <= ' ' || *szC >= 127) return 0;
			}
			if (!*szC++) return 0;
			if (*szC == '@') break;
			if (*szC != '.') return 0;
			continue;
		}

		if (*szC == '@') break;
		if (*szC <= ' ' || *szC >= 127) return 0;
		if (strchr(RFC822_Specials, *szC)) return 0;
	}

	if (szC == szAddress || *(szC - 1) == '.') return 0;

	if (!*(szDomain = ++szC)) return 0;

	do
	{
		if (*szC == '.')
		{
			if (szC == szDomain || *(szC - 1) == '.') return 0;
			dwCount++;
		}
		if (*szC <= ' ' || *szC >= 127) return 0;
		if (strchr(RFC822_Specials, *szC)) return 0;
	} while (*++szC);

	return (dwCount >= 1);
}

//=======================================================================
// ReplaceAllChar
//=======================================================================
std::string ReplaceAllChar(std::string szString, const std::string& szFrom, const std::string& szTo)
{
	size_t dwStartPos = 0;

	while ((dwStartPos = szString.find(szFrom, dwStartPos)) != std::string::npos)
	{
		szString.replace(dwStartPos, szFrom.length(), szTo);
		dwStartPos += szTo.length();
	}

	return szString;
}

//=======================================================================
// GetStringInToArray
//=======================================================================
void GetStringInToArray(const char* szStrings, std::vector<std::string>& szStringArray, bool bReplaceSpace = false)
{
	std::string szCurrentString;
	std::string szTemp;

	szStringArray.clear();

	szCurrentString.append(szStrings);
	szCurrentString = ReplaceAllChar(szCurrentString, std::string(","), std::string(";"));

	if (bReplaceSpace)
		szCurrentString = ReplaceAllChar(szCurrentString, std::string(" "), std::string(""));

	std::istringstream pStringStream(szCurrentString.c_str());

	while (getline(pStringStream, szTemp, ';'))
	{
		szStringArray.push_back(szTemp);
	}
}

//=======================================================================
// IsFileExists
//=======================================================================
errno_t IsFileExists(const char* szFileName)
{
	FILE* pFile;
	errno_t pErr;

	pErr = fopen_s(&pFile, szFileName, "r");

	if (pErr != NULL)
		return pErr;

	fclose(pFile);

	return pErr;
}

//=======================================================================
// GetAttachmentStringInToArray
//=======================================================================
void GetAttachmentStringInToArray(const char* szStrings, std::vector<std::string>& szStringArray)
{
	std::string szCurrentString;
	std::string szTemp;

	szStringArray.clear();

	char szDrive[_MAX_DRIVE] = { 0 };
	char szDir[_MAX_DIR] = { 0 };
	char szFileName[_MAX_FNAME] = { 0 };
	char szExt[_MAX_EXT] = { 0 };
	char szResultName[MAX_PATH] = { 0 };
	char szResultPath[MAX_PATH] = { 0 };
	char szResultSize[MAX_PATH] = { 0 };

	szCurrentString.append(szStrings);
	szCurrentString = ReplaceAllChar(szCurrentString, std::string(","), std::string(";"));

	std::istringstream pStringStream(szCurrentString.c_str());

	while (getline(pStringStream, szTemp, ';'))
	{
		_splitpath_s(szTemp.c_str(), szDrive, _MAX_DRIVE, szDir, _MAX_DIR, szFileName, _MAX_FNAME, szExt, _MAX_EXT);

		sprintf_s(szResultName, MAX_PATH, "%s%s", szFileName, szExt);

		szTemp.clear();
		szTemp.append(szResultName);

		szStringArray.push_back(szTemp);
	}
}