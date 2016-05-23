
//=======================================================================
// ERROR_CSMTP_CONSOLE
//=======================================================================
enum ERROR_CSMTP_CONSOLE
{
	CONSOLE_PARAM_SERVER_NOT_FOUND = 2,
	CONSOLE_PARAM_USER_NOT_FOUND,
	CONSOLE_PARAM_PWD_NOT_FOUND,
	CONSOLE_PARAM_FROM_NOT_FOUND,
	CONSOLE_PARAM_FROM_NOT_VALID,
	CONSOLE_PARAM_TO_NOT_FOUND,
	CONSOLE_PARAM_TO_NOT_VALID,
	CONSOLE_PARAM_CC_NOT_VALID,
	CONSOLE_PARAM_BCC_NOT_VALID,
	CONSOLE_PARAM_ATTACHMENT_NOT_FOUND,
	CONSOLE_PARAM_SUBJECT_NOT_FOUND,
	CONSOLE_PARAM_PORT_NOT_VALID,
	CONSOLE_PARAM_SECURITY_NOT_VALID,
	CONSOLE_PARAM_AUTH_NOT_VALID,
	CONSOLE_PARAM_URGENT_NOT_VALID,
	CONSOLE_PARAM_READ_NOT_VALID,
	CONSOLE_ENCODE_STRING_NOT_FOUND,
	CONSOLE_GLOBALALLOC_FAILED,
	CONSOLE_GLOBALUNLOCK_FAILED,
	CONSOLE_OPENCLIPBOARD_FAILED,
	CONSOLE_GENERAL_ERROR
};

//=======================================================================
// getCmdOption
//=======================================================================
char* getCmdOption(char** szBegin, char** szEnd, const std::string & szOption)
{
	char** szItr = std::find(szBegin, szEnd, szOption);

	if (szItr != szEnd && ++szItr != szEnd)
			return *szItr;
	
	return "";
}

//=======================================================================
// cmdOptionExists
//=======================================================================
bool cmdOptionExists(char** szBegin, char** szEnd, const std::string& szOption)
{
	return std::find(szBegin, szEnd, szOption) != szEnd;
}

//=======================================================================
// SMTP_SendMail
//=======================================================================
int SMTP_SendMail(std::string szSMTPAddr,
					int dwPort,
					int dwSecurityType,
					int dwAuth,
					std::string szUser,
					std::string szPwd,
					std::string szSenderName,
					std::string szSender,
					std::vector<std::string> szTo,
					std::vector<std::string> szCC,
					std::vector<std::string> szBCC,
					std::string szSubject,
					std::string szBody,
					std::vector<std::string> szAttachment,
					int dwPriority,
					int dwHTML,
					std::string szBodyHTML,
					int dwRead)
{
	CSmtp CMail;

	try
	{
		// Impostazione SMTP Server
		if (dwAuth == 1)
			CMail.SetSMTPServer(szSMTPAddr.c_str(), dwPort, true);
		else
			CMail.SetSMTPServer(szSMTPAddr.c_str(), dwPort, false);

		// Impostazione tipo connessione
		switch (dwSecurityType)
		{
		case 0:
			CMail.SetSecurityType(NO_SECURITY);
			break;
		case 1:
			CMail.SetSecurityType(USE_TLS);
			break;
		case 2:
			CMail.SetSecurityType(USE_SSL);
			break;
		case 3:
			CMail.SetSecurityType(DO_NOT_SET);
			break;
		}

		// Impostazione autenticazione
		if (dwAuth == 1)
		{
			CMail.SetLogin(szUser.c_str());
			CMail.SetPassword(szPwd.c_str());
		}

		// Imposta nome mittente
		if (szSenderName.size() > 0)
			CMail.SetSenderName(szSenderName.c_str());

		// Imposta indirizzo mittente
		CMail.SetSenderMail(szSender.c_str());

		std::vector<std::string>::iterator pEmailIterator;

		// To
		for (pEmailIterator = szTo.begin(); pEmailIterator != szTo.end(); pEmailIterator++)
		{
			std::string pCurrentString = *pEmailIterator;
			CMail.AddRecipient(pCurrentString.c_str());
		}

		// CC
		if (szCC.size() > 0)
		{
			for (pEmailIterator = szCC.begin(); pEmailIterator != szCC.end(); pEmailIterator++)
			{
				std::string pCurrentString = *pEmailIterator;
				CMail.AddCCRecipient(pCurrentString.c_str());
			}
		}

		// BCC
		if (szBCC.size() > 0)
		{
			for (pEmailIterator = szBCC.begin(); pEmailIterator != szBCC.end(); pEmailIterator++)
			{
				std::string pCurrentString = *pEmailIterator;
				CMail.AddBCCRecipient(pCurrentString.c_str());
			}
		}

		// Imposta oggetto mail
		CMail.SetSubject(szSubject.c_str());

		// Imposta corpo mail
		CMail.AddMsgLine(szBody.c_str());

		// Allegati
		if (szAttachment.size() > 0)
		{
			for (pEmailIterator = szAttachment.begin(); pEmailIterator != szAttachment.end(); pEmailIterator++)
			{
				std::string pCurrentString = *pEmailIterator;
				CMail.AddAttachment(pCurrentString.c_str());
			}
		}

		// Imposta priorità mail
		switch (dwPriority)
		{
		case 2:
			CMail.SetXPriority(XPRIORITY_HIGH);
			break;
		case 4:
			CMail.SetXPriority(XPRIORITY_LOW);
			break;
		default:
			CMail.SetXPriority(XPRIORITY_NORMAL);
		}

		if (dwHTML == 1)
		{
			CMail.m_bHTML = true;
			CMail.MsgBodyHTML = szBodyHTML.c_str();
		}

		if (dwRead == 1)
			CMail.SetReadReceipt(true);

		CMail.Send();

		return 0;
	}
	catch (ECSmtp e)
	{
		std::cout << "\n[!] - " << e.GetErrorText() << "\n";
		return 1;
	}
	catch (...)
	{
		std::cout << "\n[!] - General Error -> " << GetLastError() << " !\n";
		return 1;
	}
}

//=======================================================================
// HandleConsoleParam
//=======================================================================
int HandleConsoleParam(int argc, char** argv)
{
	if (cmdOptionExists(argv, argv + argc, "-encode"))
	{
		try
		{
			std::string	szEncodedString = getCmdOption(argv, argv + argc, "-encode");

			if (strcmp(szEncodedString.c_str(), "") == 0)
			{
				szEncodedString.clear();
				std::cout << "\n[!] - " << CONSOLE_ENCODE_STRING_NOT_FOUND << " - Stringa da codificare non trovata!\n";
				return 1;
			}

			// Codifica Base64
			szEncodedString = base64_encode(reinterpret_cast<const unsigned char*>(szEncodedString.c_str()), static_cast<unsigned int>(strlen(szEncodedString.c_str())));
			int dwTextLen = static_cast<int>(strlen(szEncodedString.c_str()));

			// CopyToClipboard
			HGLOBAL hTextMem = GlobalAlloc(GHND, (dwTextLen + 1) * sizeof(char));

			if (hTextMem != NULL)
			{
				memcpy(GlobalLock(hTextMem), szEncodedString.c_str(), dwTextLen * sizeof(char));
				
				if (GlobalUnlock(hTextMem) != 0)
				{
					szEncodedString.clear();
					std::cout << "\n[!] - " << CONSOLE_GLOBALUNLOCK_FAILED << " - Deallocazione memoria non riuscita!\n";
					return 1;
				}

				if (OpenClipboard(NULL))
				{
					EmptyClipboard();
					SetClipboardData(CF_TEXT, hTextMem);
					CloseClipboard();
					std::cout << "\nRisultato codifica: " << szEncodedString.c_str() << "\n";
					std::cout << "Il risultato della codifica e' stato copiato nella clipboard\n";
				}
				else
				{
					GlobalFree(hTextMem);
					szEncodedString.clear();
					std::cout << "\n[!] - " << CONSOLE_OPENCLIPBOARD_FAILED << " - OpenClipboard() function errore!\n";
					return 1;
				}
			}
			else
			{
				szEncodedString.clear();
				std::cout << "\n[!] - " << CONSOLE_GLOBALALLOC_FAILED << " - Allocazione memoria non riuscita!\n";
				return 1;
			}

			szEncodedString.clear();
		}
		catch (...)
		{
			std::cout << "\n[!] - " << CONSOLE_GENERAL_ERROR << " - General Error -> " << GetLastError() << " !\n";
			return 1;
		}
	}
	else
	{
		if (!cmdOptionExists(argv, argv + argc, "-server"))
		{
			std::cout << "\n[!] - " << CONSOLE_PARAM_SERVER_NOT_FOUND << " - Parametro -server non trovato!\n";
			return 1;
		}

		if (!cmdOptionExists(argv, argv + argc, "-from"))
		{
			std::cout << "\n[!] - " << CONSOLE_PARAM_FROM_NOT_FOUND << " - Parametro -from non trovato!\n";
			return 1;
		}

		if (!cmdOptionExists(argv, argv + argc, "-to"))
		{
			std::cout << "\n[!] - " << CONSOLE_PARAM_TO_NOT_FOUND << " - Parametro -to non trovato!\n";
			return 1;
		}

		if (!cmdOptionExists(argv, argv + argc, "-subject"))
		{
			std::cout << "\n[!] - " << CONSOLE_PARAM_SUBJECT_NOT_FOUND << " - Parametro -subject non trovato!\n";
			return 1;
		}

		// Server
		std::string	szServerName = getCmdOption(argv, argv + argc, "-server");

		// Porta
		std::string	szPort;

		if (!cmdOptionExists(argv, argv + argc, "-port"))
			szPort = "25";
		else
			szPort = getCmdOption(argv, argv + argc, "-port");

		if (atoi(szPort.c_str()) <= 0 || atoi(szPort.c_str()) > 65535)
		{
			std::cout << "\n[!] - " << CONSOLE_PARAM_PORT_NOT_VALID << " - Valore parametro -port non compreso tra 1 e 65535!\n";
			return 1;
		}

		// Sicurezza
		std::string	szSecurity;

		if (!cmdOptionExists(argv, argv + argc, "-security"))
			szSecurity = "0";
		else
			szSecurity = getCmdOption(argv, argv + argc, "-security");

		if (strcmp(szSecurity.c_str(), "0") != 0 && (atoi(szSecurity.c_str()) < 0 || atoi(szSecurity.c_str()) > 3))
		{
			std::cout << "\n[!] - " << CONSOLE_PARAM_SECURITY_NOT_VALID << " - Valore parametro -security non compreso tra 0 e 3!\n";
			return 1;
		}

		// Autenticazione
		std::string	szAuth;

		if (!cmdOptionExists(argv, argv + argc, "-auth"))
			szAuth = "0";
		else
			szAuth = getCmdOption(argv, argv + argc, "-auth");

		if (strcmp(szAuth.c_str(), "0") != 0 && (atoi(szAuth.c_str()) < 0 || atoi(szAuth.c_str()) > 1))
		{
			std::cout << "\n[!] - " << CONSOLE_PARAM_AUTH_NOT_VALID << " - Valore parametro -auth non compreso tra 0 e 1!\n";
			return 1;
		}

		// Utente / Password
		std::string	szUser;
		std::string	szPwd;

		if (atoi(szAuth.c_str()) == 1)
		{
			if (!cmdOptionExists(argv, argv + argc, "-user"))
				return CONSOLE_PARAM_USER_NOT_FOUND;

			if (!cmdOptionExists(argv, argv + argc, "-pwd"))
				return CONSOLE_PARAM_PWD_NOT_FOUND;

			szUser = getCmdOption(argv, argv + argc, "-user");
			szPwd = getCmdOption(argv, argv + argc, "-pwd");
			szPwd = base64_decode(szPwd);
		}

		// Mittente
		std::string	szFrom = getCmdOption(argv, argv + argc, "-from");

		if (IsEmailValid(szFrom.c_str()) == 0)
		{
			std::cout << "\n[!] - " << CONSOLE_PARAM_FROM_NOT_VALID << " - Indirizzo mail mittente non valido!\n";
			return 1;
		}

		std::vector<std::string>::iterator pEmailIterator;

		// Destinatari
		std::string	szTempTo = getCmdOption(argv, argv + argc, "-to");
		std::vector<std::string> szTo;

		GetStringInToArray(szTempTo.c_str(), szTo, true);

		szTempTo.clear();

		for (pEmailIterator = szTo.begin(); pEmailIterator != szTo.end(); pEmailIterator++)
		{
			std::string pCurrentString = *pEmailIterator;

			if (IsEmailValid(pCurrentString.c_str()) == 0)
			{		
				std::cout << "\n[!] - " << CONSOLE_PARAM_TO_NOT_VALID << " - Indirizzo mail destinatario: " << pCurrentString.c_str()  << " non valido!\n";
				return 1;
			}
		}

		// Oggetto
		std::string	szSubject = getCmdOption(argv, argv + argc, "-subject");

		// Corpo
		std::string	szBody;

		if (cmdOptionExists(argv, argv + argc, "-body"))
			szBody = getCmdOption(argv, argv + argc, "-body");
		else
			szBody = "-";

		std::string szTempCC;
		std::vector<std::string> szCC;

		// CC
		if (cmdOptionExists(argv, argv + argc, "-cc"))
			szTempCC = getCmdOption(argv, argv + argc, "-cc");

		if (szTempCC.length() > 0)
		{
			GetStringInToArray(szTempCC.c_str(), szCC, true);

			szTempCC.clear();

			for (pEmailIterator = szCC.begin(); pEmailIterator != szCC.end(); pEmailIterator++)
			{
				std::string pCurrentString = *pEmailIterator;

				if (IsEmailValid(pCurrentString.c_str()) == 0)
				{
					std::cout << "\n[!] - " << CONSOLE_PARAM_CC_NOT_VALID << " - Indirizzo mail CC: " << pCurrentString.c_str() << " non valido!\n";
					return 1;
				}
			}
		}

		std::string szTempBCC;
		std::vector<std::string> szBCC;

		// BCC
		if (cmdOptionExists(argv, argv + argc, "-bcc"))
			szTempBCC = getCmdOption(argv, argv + argc, "-bcc");

		if (szTempBCC.length() > 0)
		{
			GetStringInToArray(szTempBCC.c_str(), szBCC, true);

			szTempBCC.clear();

			for (pEmailIterator = szBCC.begin(); pEmailIterator != szBCC.end(); pEmailIterator++)
			{
				std::string pCurrentString = *pEmailIterator;

				if (IsEmailValid(pCurrentString.c_str()) == 0)
				{
					std::cout << "\n[!] - " << CONSOLE_PARAM_BCC_NOT_VALID << " - Indirizzo mail BCC: " << pCurrentString.c_str() << " non valido!\n";
					return 1;
				}
			}
		}

		// Allegati
		std::string szTempAttachment;
		std::vector<std::string> szAttachment;
		std::vector<std::string>::iterator pAttachmentIterator;

		if (cmdOptionExists(argv, argv + argc, "-attachment"))
			szTempAttachment = getCmdOption(argv, argv + argc, "-attachment");

		if (szTempAttachment.length() > 0)
		{
			GetStringInToArray(szTempAttachment.c_str(), szAttachment);

			szTempAttachment.clear();

			// Verifica percorsi allegati
			for (pAttachmentIterator = szAttachment.begin(); pAttachmentIterator != szAttachment.end(); pAttachmentIterator++)
			{
				std::string pCurrentString = *pAttachmentIterator;

				errno_t pErrAttFile = IsFileExists(pCurrentString.c_str());

				if (pErrAttFile != NULL)
				{
					std::cout << "\n[!] - " << CONSOLE_PARAM_ATTACHMENT_NOT_FOUND << " - Allegato: " << pCurrentString.c_str() << " non trovato!\n";
					return 1;
				}
			}
		}

		// Urgente
		std::string szUrgent;

		if (cmdOptionExists(argv, argv + argc, "-urgent"))
			szUrgent = getCmdOption(argv, argv + argc, "-urgent");

		if (strcmp(szUrgent.c_str(), "0") != 0 && (atoi(szUrgent.c_str()) < 0 || atoi(szUrgent.c_str()) > 1))
		{
			std::cout << "\n[!] - " << CONSOLE_PARAM_AUTH_NOT_VALID << " - Valore parametro -urgent non compreso tra 0 e 1!\n";
			return 1;
		}

		if (atoi(szUrgent.c_str()) == 1)
			szUrgent = "2";
		else
			szUrgent = "3";

		// Conferma lettura
		std::string szRead;

		if (cmdOptionExists(argv, argv + argc, "-read"))
			szRead = getCmdOption(argv, argv + argc, "-read");

		if (strcmp(szRead.c_str(), "0") != 0 && (atoi(szRead.c_str()) < 0 || atoi(szRead.c_str()) > 1))
		{
			std::cout << "\n[!] - " << CONSOLE_PARAM_AUTH_NOT_VALID << " - Valore parametro -read non compreso tra 0 e 1!\n";
			return 1;
		}

		int dwResult = SMTP_SendMail(szServerName, atoi(szPort.c_str()), atoi(szSecurity.c_str()), atoi(szAuth.c_str()), 
										szUser, szPwd, szFrom, szFrom, szTo, szCC, szBCC, 
										szSubject, szBody, szAttachment, atoi(szUrgent.c_str()), 0, "", atoi(szRead.c_str()));

		szServerName.clear();
		szPort.clear();
		szSecurity.clear();
		szAuth.clear();
		szUser.clear();
		szPwd.clear();
		szFrom.clear();
		szTo.clear();
		szSubject.clear();
		szBody.clear();
		szCC.clear();
		szBCC.clear();
		szAttachment.clear();
		szUrgent.clear();
		szRead.clear();

		return dwResult;
	}

	return 0;
}
