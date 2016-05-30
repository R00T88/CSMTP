////////////////////////////////////////////////////////////////////////////////
// IMAP Class
////////////////////////////////////////////////////////////////////////////////

#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>

#include "CImap.h"

#include "..\\Security\base64.h"

// OpenSSL 1.0.2h
#include "openssl/err.h"
#include "openssl/md5.h"

#include <cassert>

// OpenSSL 1.0.2h - /MT
#pragma comment(lib, "ssleay32.lib")
#pragma comment(lib, "libeay32.lib")

Imap_Command_Entry Imap_command_list[] = 
{
	{command_INIT_IMAP,          0,     5*60,  NULL,  NULL,	 1, ECImap::SERVER_NOT_RESPONDING},
	{command_CAPABILITY,		 5*60,  5*60,  "A01", "A01", 0, ECImap::COMMAND_COMPATIBILITY},
	{command_STARTTLS_IMAP,      5*60,  5*60,  "A02", "A02", 0, ECImap::COMMAND_EHLO_STARTTLS},
	{command_LOGIN,              5*60,  5*60,  "A03", "A03", 0, ECImap::COMMAND_AUTH_LOGIN},
	{command_SELECT,             5*60,  5*60,  "A04", "A04", 0, ECImap::COMMAND_SELECT},
	{command_APPEND,             5*60,  5*60,  "A05", "+", 0, ECImap::COMMAND_APPEND},
	{command_APPEND_DONE,        5*60,  5*60,  "A05", "A05", 0, ECImap::COMMAND_APPEND},
	{command_LOGOUT,			 5*60,  5*60,  "A06", "A06", 0, ECImap::COMMAND_LOGOUT}
};

Imap_Content_Type Imap_content_list[] = 
{
	{".bmp", "image/bmp"},
    {".gif", "image/gif"},
    {".jpeg", "image/jpeg"},
    {".jpg", "image/jpeg"},
    {".png", "image/png"},
    {".tif", "image/tiff"},
    {".tiff", "image/tiff"},
	{".rtf", "application/rtf"},
    {".doc", "application/msword"},
    {".docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    {".pdf", "application/pdf"},
    {".ppt", "application/vnd.ms-powerpoint"},
    {".pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
    {".xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    {".xls", "application/vnd.ms-excel"},
    {".csv", "text/csv"},
    {".xml", "text/xml"},
    {".txt", "text/plain"},
    {".zip", "application/zip"},
    {".ogg", "application/ogg"},
    {".mp3", "audio/mpeg"},
    {".wma", "audio/x-ms-wma"},
    {".wav", "audio/x-wav"},
    {".wmv", "audio/x-ms-wmv"},
    {".swf", "application/x-shockwave-flash"},
    {".avi", "video/avi"},
    {".mp4", "video/mp4"},
    {".mpeg", "video/mpeg"},
    {".mpg", "video/mpeg"},
    {".qt", "video/quicktime"}
};

char* Imap_FindContentType(char* FileExt)
{
	for(size_t i = 0; i < sizeof(Imap_content_list)/sizeof(Imap_content_list[0]); ++i)
	{
		if(strcmp(Imap_content_list[i].FileExt, FileExt) == 0)
		{
			return Imap_content_list[i].FileExtContent;
		}
	}

	return "application/octet-stream";
}

Imap_Command_Entry* Imap_FindCommandEntry(IMAP_COMMAND command)
{
	Imap_Command_Entry* pEntry = NULL;
	for(size_t i = 0; i < sizeof(Imap_command_list)/sizeof(Imap_command_list[0]); ++i)
	{
		if(Imap_command_list[i].command == command)
		{
			pEntry = &Imap_command_list[i];
			break;
		}
	}
	assert(pEntry != NULL);
	return pEntry;
}

bool Imap_IsKeywordSupported(const char* response, const char* keyword)
{
	assert(response != NULL && keyword != NULL);

	if(response == NULL || keyword == NULL)
		return false;

	int res_len = static_cast<int>(strlen(response));
	int key_len = static_cast<int>(strlen(keyword));

	if(res_len < key_len)
		return false;

	int pos = 0;

	for(; pos < res_len - key_len + 1; ++pos)
	{
		if(_strnicmp(keyword, response+pos, key_len) == 0)
		{
			if(pos > 0 &&
				(response[pos - 1] == '-' ||
				 response[pos - 1] == ' ' ||
				 response[pos - 1] == '='))
			{
				if(pos+key_len < res_len)
				{
					if(response[pos+key_len] == ' ' ||
					   response[pos+key_len] == '=')
					{
						return true;
					}
					else if(pos+key_len+1 < res_len)
					{
						if(response[pos+key_len] == '\r' &&
						   response[pos+key_len+1] == '\n')
						{
							return true;
						}
					}
				}
			}
		}
	}
	return false;
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: CImap
// DESCRIPTION: Constructor of CSmtp class.
//   ARGUMENTS: none
// USES GLOBAL: none
// MODIFIES GL: m_iXPriority, m_iSMTPSrvPort, RecvBuf, SendBuf
//     RETURNS: none
//      AUTHOR: Sebastiano Bertini
// AUTHOR/DATE: 25-06-2016				
////////////////////////////////////////////////////////////////////////////////
CImap::CImap()
{
	hSocket = INVALID_SOCKET;
	m_bConnected = false;
	m_iXPriority = IMAP_XPRIORITY_NORMAL;
	m_iIMAPSrvPort = 0;
	m_bAuthenticate = true;

	// Initialize WinSock
	WSADATA wsaData;
	WORD wVer = MAKEWORD(2, 2);

	if (WSAStartup(wVer, &wsaData) != NO_ERROR)
		throw ECImap(ECImap::WSA_STARTUP);
	
	if (LOBYTE( wsaData.wVersion ) != 2 || HIBYTE( wsaData.wVersion ) != 2 ) 
	{
		WSACleanup();
		throw ECImap(ECImap::WSA_VER);
	}

	char* hostname;
		
	if((hostname = new  char[MAX_PATH]) == NULL)
		throw ECImap(ECImap::LACK_OF_MEMORY);

	if(gethostname(hostname, MAX_PATH) == SOCKET_ERROR) 
		throw ECImap(ECImap::WSA_HOSTNAME);
	
	m_sLocalHostName = hostname;
	
	delete[] hostname;
	hostname = NULL;

	if((RecvBuf = new char[BUFFER_SIZE]) == NULL)
		throw ECImap(ECImap::LACK_OF_MEMORY);
	
	if((SendBuf = new char[BUFFER_SIZE]) == NULL)
		throw ECImap(ECImap::LACK_OF_MEMORY);

	if((szMsgId = new char[BUFFER_MSGID_SIZE]) == NULL)
		throw ECImap(ECImap::LACK_OF_MEMORY);

	m_type = IMAP_NO_SECURITY;
	m_ctx = NULL;
	m_ssl = NULL;
	m_bHTML = false;
	m_bReadReceipt = false;

	dwNumChar = 0;
	dwNumCharSent = 0;

	m_sCharSet = "ISO-8859-15";
	m_sCharEncoding = "8bit";

	std::transform(m_sCharSet.begin(), m_sCharSet.end(), m_sCharSet.begin(), ::toupper);

	m_sXMailer = "v5.0";
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: CImap
// DESCRIPTION: Destructor of CSmtp class.
//   ARGUMENTS: none
// USES GLOBAL: RecvBuf, SendBuf
// MODIFIES GL: RecvBuf, SendBuf
//     RETURNS: none
//      AUTHOR: Sebastiano Bertini
// AUTHOR/DATE: 25-06-2016							
////////////////////////////////////////////////////////////////////////////////
CImap::~CImap()
{
	if(m_bConnected) 
		DisconnectRemoteServer();

	if(SendBuf)
	{
		delete[] SendBuf;
		SendBuf = NULL;
	}

	if(RecvBuf)
	{
		delete[] RecvBuf;
		RecvBuf = NULL;
	}

	if(szMsgId)
	{
		delete[] szMsgId;
		szMsgId = NULL;
	}

	CleanupOpenSSL();
	WSACleanup();
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: AddAttachment
// DESCRIPTION: New attachment is added.
//   ARGUMENTS: const char *Path - name of attachment added
// USES GLOBAL: Attachments
// MODIFIES GL: Attachments
//     RETURNS: void
//      AUTHOR: Sebastiano Bertini
// AUTHOR/DATE: 25-06-2016							
////////////////////////////////////////////////////////////////////////////////
void CImap::AddAttachment(const char *Path)
{
	assert(Path);
	Attachments.insert(Attachments.end(), Path);
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: AddRecipient
// DESCRIPTION: New recipient data is added i.e.: email and name. .
//   ARGUMENTS: const char *email - mail of the recipient
//              const char *name - name of the recipient
// USES GLOBAL: Recipients
// MODIFIES GL: Recipients
//     RETURNS: void
//      AUTHOR: Sebastiano Bertini
// AUTHOR/DATE: 25-06-2016							
////////////////////////////////////////////////////////////////////////////////
void CImap::AddRecipient(const char *email, const char *name)
{	
	if(!email)
		throw ECImap(ECImap::UNDEF_RECIPIENT_MAIL);

	Recipient recipient;

	recipient.Mail = email;

	if(name != NULL) 
		recipient.Name = name;
	else 
		recipient.Name.clear();

	Recipients.insert(Recipients.end(), recipient);   
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: AddCCRecipient
// DESCRIPTION: New cc-recipient data is added i.e.: email and name. .
//   ARGUMENTS: const char *email - mail of the cc-recipient
//              const char *name - name of the ccc-recipient
// USES GLOBAL: CCRecipients
// MODIFIES GL: CCRecipients
//     RETURNS: void
//      AUTHOR: Sebastiano Bertini
// AUTHOR/DATE: 25-06-2016					
////////////////////////////////////////////////////////////////////////////////
void CImap::AddCCRecipient(const char *email, const char *name)
{	
	if(!email)
		throw ECImap(ECImap::UNDEF_RECIPIENT_MAIL);

	Recipient recipient;

	recipient.Mail = email;

	if(name != NULL) 
		recipient.Name = name;
	else 
		recipient.Name.clear();

	CCRecipients.insert(CCRecipients.end(), recipient);
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: AddBCCRecipient
// DESCRIPTION: New bcc-recipient data is added i.e.: email and name. .
//   ARGUMENTS: const char *email - mail of the bcc-recipient
//              const char *name - name of the bccc-recipient
// USES GLOBAL: BCCRecipients
// MODIFIES GL: BCCRecipients
//     RETURNS: void
//      AUTHOR: Sebastiano Bertini
// AUTHOR/DATE: 25-06-2016							
////////////////////////////////////////////////////////////////////////////////
void CImap::AddBCCRecipient(const char *email, const char *name)
{	
	if(!email)
		throw ECImap(ECImap::UNDEF_RECIPIENT_MAIL);

	Recipient recipient;

	recipient.Mail = email;

	if(name != NULL) 
		recipient.Name = name;
	else 
		recipient.Name.empty();

	BCCRecipients.insert(BCCRecipients.end(), recipient);
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: AddMsgLine
// DESCRIPTION: Adds new line in a message.
//   ARGUMENTS: const char *Text - text of the new line
// USES GLOBAL: MsgBody
// MODIFIES GL: MsgBody
//     RETURNS: void
//      AUTHOR: Sebastiano Bertini
// AUTHOR/DATE: 25-06-2016				
////////////////////////////////////////////////////////////////////////////////
void CImap::AddMsgLine(const char* Text)
{
	MsgBody.insert(MsgBody.end(), Text);
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: SaveMessage
// DESCRIPTION: Append message to folder "Sent"
//   ARGUMENTS: none
// USES GLOBAL: m_sIMAPSrvName, m_iIMAPSrvPort, SendBuf, RecvBuf, m_sLogin,
//              m_sPassword, m_sMailFrom, Recipients, CCRecipients,
//              BCCRecipients, m_sMsgBody, Attachments, 
// MODIFIES GL: SendBuf 
//     RETURNS: void
//      AUTHOR: Sebastiano Bertini
// AUTHOR/DATE: 25-06-2016			
////////////////////////////////////////////////////////////////////////////////
void CImap::SaveMessage()
{
	unsigned int i, res, FileId;
	char *FileBuf = NULL, *FileName = NULL;
	FILE* hFile = NULL;
	unsigned long int FileSize, TotalSize, MsgPart;

	// ***** CONNECTING TO IMAP SERVER *****

	// connecting to remote host if not already connected:
	if(hSocket == INVALID_SOCKET)
	{
		if(!ConnectRemoteServer(m_sIMAPSrvName.c_str(), m_iIMAPSrvPort, m_type, m_bAuthenticate))
			throw ECImap(ECImap::WSA_INVALID_SOCKET);
	}

	try
	{
		// ***** VERIFY SENT FOLDER *****

		Imap_Command_Entry* pEntry = Imap_FindCommandEntry(command_SELECT);
		sprintf_s(SendBuf, BUFFER_SIZE, "%s SELECT \"%s\"\r\n", pEntry->Token, SentFolder.c_str());
		SendData(pEntry);
		ReceiveResponse(pEntry);
		
		// ***** APPEND E-MAIL *****
		
		pEntry = Imap_FindCommandEntry(command_APPEND);
		sprintf_s(SendBuf, BUFFER_SIZE, "%s APPEND \"%s\" (\\Seen) {%lld}\r\n", pEntry->Token, SentFolder.c_str(), dwNumChar);
		SendData(pEntry);
		ReceiveResponse(pEntry);

		// send header(s)
		FormatHeader(SendBuf);
		SendData(pEntry);
		dwNumCharSent += strlen(SendBuf);

		const char *ResultLine;

		// send text message
		if(GetMsgLines())
		{
			for(i = 0; i < GetMsgLines(); i++)
			{
				ResultLine = GetMsgLineText(i);
				int dwSize = static_cast<int>(strlen(ResultLine));
				int Offset = 0;

				if(dwSize >= BUFFER_SIZE/2)
				{
					int dwIndex = 0;

					while(Offset<(dwSize-1))
					{
						strncpy_s(SendBuf, BUFFER_SIZE, ResultLine + Offset, BUFFER_SIZE/2);
						SendBuf[BUFFER_SIZE/2] = '\0';
						SendData(pEntry);
						dwNumCharSent += strlen(SendBuf);
						Offset += BUFFER_SIZE/2;
					}

					strcpy_s(SendBuf, BUFFER_SIZE, "\r\n");
					SendData(pEntry);
					dwNumCharSent += strlen(SendBuf);
				}
				else
				{
					sprintf_s(SendBuf, BUFFER_SIZE, "%s\r\n", ResultLine);
					SendData(pEntry);
					dwNumCharSent += strlen(SendBuf);
				}
			}
		}
		else
		{
			sprintf_s(SendBuf, BUFFER_SIZE, "%s\r\n", " ");
			SendData(pEntry);
			dwNumCharSent += strlen(SendBuf);
		}

		// send html text
		if(m_bHTML)
		{
			MsgBody.clear();
			MsgBody.insert(MsgBody.end(), MsgBodyHTML.c_str());

			sprintf_s(SendBuf, BUFFER_SIZE, "\r\n");
			strcat_s(SendBuf, BUFFER_SIZE, "--");
			strcat_s(SendBuf, BUFFER_SIZE, IMAP_BOUNDARY_ALTERNATIVE);
			strcat_s(SendBuf, BUFFER_SIZE, "\r\n");

			strcat_s(SendBuf, BUFFER_SIZE, "Content-Type: text/html; charset=\"");
			strcat_s(SendBuf, BUFFER_SIZE, m_sCharSet.c_str());
			strcat_s(SendBuf, BUFFER_SIZE, "\"\r\n");
			strcat_s(SendBuf, BUFFER_SIZE, "Content-Transfer-Encoding: ");
			strcat_s(SendBuf, BUFFER_SIZE, m_sCharEncoding.c_str());
			strcat_s(SendBuf, BUFFER_SIZE, "\r\n");
			strcat_s(SendBuf, BUFFER_SIZE, "\r\n");

			SendData(pEntry);
			dwNumCharSent += strlen(SendBuf);

			if(GetMsgLines())
			{
				for(i = 0; i < GetMsgLines(); i++)
				{
					ResultLine = GetMsgLineText(i);
					int dwSize = static_cast<int>(strlen(ResultLine));
					int Offset = 0;

					if(dwSize >= BUFFER_SIZE/2)
					{
						int dwIndex = 0;

						while(Offset<(dwSize-1))
						{
							strncpy_s(SendBuf, BUFFER_SIZE, ResultLine+Offset, BUFFER_SIZE/2);
							SendBuf[BUFFER_SIZE/2] = '\0';
							SendData(pEntry);
							dwNumCharSent += strlen(SendBuf);
							Offset+=BUFFER_SIZE/2;
						}

						strcpy_s(SendBuf, BUFFER_SIZE, "\r\n");
						SendData(pEntry);
						dwNumCharSent += strlen(SendBuf);
					}
					else
					{
						sprintf_s(SendBuf, BUFFER_SIZE, "%s\r\n", ResultLine);
						SendData(pEntry);
						dwNumCharSent += strlen(SendBuf);
					}
				}
			}
			else
			{
				sprintf_s(SendBuf, BUFFER_SIZE, "%s\r\n", " ");
				SendData(pEntry);
				dwNumCharSent += strlen(SendBuf);
			}

			sprintf_s(SendBuf, BUFFER_SIZE, "\r\n");
			strcat_s(SendBuf, BUFFER_SIZE, "--");
			strcat_s(SendBuf, BUFFER_SIZE, IMAP_BOUNDARY_ALTERNATIVE);
			strcat_s(SendBuf, BUFFER_SIZE, "--\r\n");

			SendData(pEntry);
			dwNumCharSent += strlen(SendBuf);
		}

		sprintf_s(SendBuf, BUFFER_SIZE, "\r\n");
		SendData(pEntry);
		dwNumCharSent += strlen(SendBuf);

		// next goes attachments (if they are)
		if((FileBuf = new char[55]) == NULL)
			throw ECImap(ECImap::LACK_OF_MEMORY);

		if((FileName = new char[MAX_PATH]) == NULL)
			throw ECImap(ECImap::LACK_OF_MEMORY);

		TotalSize = 0;

		for(FileId = 0; FileId < Attachments.size(); FileId++)
		{
			strcpy_s(FileName, MAX_PATH, Attachments[FileId].c_str());

			sprintf_s(SendBuf, BUFFER_SIZE, "--%s\r\n", IMAP_BOUNDARY_MIXED);

			char* FileExt = NULL;
			
			FileExt = strrchr(&FileName[Attachments[FileId].find_last_of("\\") + 1], '.');

			if(FileExt != NULL)
			{
				strcat_s(SendBuf, BUFFER_SIZE, "Content-Type: ");
				strcat_s(SendBuf, BUFFER_SIZE, Imap_FindContentType(FileExt));
				strcat_s(SendBuf, BUFFER_SIZE, ";\r\n\tname=");
			}
			else
				strcat_s(SendBuf, BUFFER_SIZE, "Content-Type: application/octet-stream;\r\n\tname=");
			
			FileExt = NULL;

			if (strcmp(m_sCharSet.c_str(), "UTF-8") == 0)
			{
				std::string szAttNameEncoded;

				strcat_s(SendBuf, BUFFER_SIZE, "\"");

				szAttNameEncoded.append("=?UTF-8?B?");
				szAttNameEncoded.append(base64_encode(reinterpret_cast<const unsigned char*>(&FileName[Attachments[FileId].find_last_of("\\") + 1]), static_cast<unsigned int>(strlen(&FileName[Attachments[FileId].find_last_of("\\") + 1]))));
				szAttNameEncoded.append("?=");

				strcat_s(SendBuf, BUFFER_SIZE, szAttNameEncoded.c_str());

				strcat_s(SendBuf, BUFFER_SIZE, "\"");

				szAttNameEncoded.clear();
			}
			else
			{
				strcat_s(SendBuf, BUFFER_SIZE, "\"");
				strcat_s(SendBuf, BUFFER_SIZE, &FileName[Attachments[FileId].find_last_of("\\") + 1]);
				strcat_s(SendBuf, BUFFER_SIZE, "\"");
			}

			strcat_s(SendBuf, BUFFER_SIZE, "\r\n");
			strcat_s(SendBuf, BUFFER_SIZE, "Content-Transfer-Encoding: base64\r\n");
			strcat_s(SendBuf, BUFFER_SIZE, "Content-Disposition: attachment;\r\n\tfilename=");

			if (strcmp(m_sCharSet.c_str(), "UTF-8") == 0)
			{
				std::string szAttNameEncoded;

				strcat_s(SendBuf, BUFFER_SIZE, "\"");

				szAttNameEncoded.append("=?UTF-8?B?");
				szAttNameEncoded.append(base64_encode(reinterpret_cast<const unsigned char*>(&FileName[Attachments[FileId].find_last_of("\\") + 1]), static_cast<unsigned int>(strlen(&FileName[Attachments[FileId].find_last_of("\\") + 1]))));
				szAttNameEncoded.append("?=");

				strcat_s(SendBuf, BUFFER_SIZE, szAttNameEncoded.c_str());

				strcat_s(SendBuf, BUFFER_SIZE, "\"");

				szAttNameEncoded.clear();
			}
			else
			{
				strcat_s(SendBuf, BUFFER_SIZE, "\"");
				strcat_s(SendBuf, BUFFER_SIZE, &FileName[Attachments[FileId].find_last_of("\\") + 1]);
				strcat_s(SendBuf, BUFFER_SIZE, "\"");
			}

			strcat_s(SendBuf, BUFFER_SIZE, "\r\n");
			strcat_s(SendBuf, BUFFER_SIZE, "\r\n");

			SendData(pEntry);
			dwNumCharSent += strlen(SendBuf);

			errno_t err;

			// opening the file
			err = fopen_s(&hFile, FileName, "rb");
			
			if(err != NULL)
			{
				if(err == EPERM)
					throw ECImap(ECImap::ERRNO_EPERM);
				else if(err == ENOENT)
					throw ECImap(ECImap::ERRNO_ENOENT);
				else if(err == ESRCH)
					throw ECImap(ECImap::ERRNO_ESRCH);
				else if(err == EINTR)
					throw ECImap(ECImap::ERRNO_EINTR);
				else if(err == EIO)
					throw ECImap(ECImap::ERRNO_EIO);
				else if(err == ENXIO)
					throw ECImap(ECImap::ERRNO_ENXIO);
				else if(err == E2BIG)
					throw ECImap(ECImap::ERRNO_E2BIG);
				else if(err == ENOEXEC)
					throw ECImap(ECImap::ERRNO_ENOEXEC);
				else if(err == EBADF)
					throw ECImap(ECImap::ERRNO_EBADF);
				else if(err == ECHILD)
					throw ECImap(ECImap::ERRNO_ECHILD);
				else if(err == EAGAIN)
					throw ECImap(ECImap::ERRNO_EAGAIN);
				else if(err == ENOMEM)
					throw ECImap(ECImap::ERRNO_ENOMEM);
				else if(err == EACCES)
					throw ECImap(ECImap::ERRNO_EACCES);
				else if(err == EFAULT)
					throw ECImap(ECImap::ERRNO_EFAULT);
				else if(err == EBUSY)
					throw ECImap(ECImap::ERRNO_EBUSY);
				else if(err == EEXIST)
					throw ECImap(ECImap::ERRNO_EEXIST);
				else if(err == EXDEV)
					throw ECImap(ECImap::ERRNO_EXDEV);
				else if(err == ENODEV)
					throw ECImap(ECImap::ERRNO_ENODEV);
				else if(err == ENOTDIR)
					throw ECImap(ECImap::ERRNO_ENOTDIR);
				else if(err == EISDIR)
					throw ECImap(ECImap::ERRNO_EISDIR);
				else if(err == EINVAL)
					throw ECImap(ECImap::ERRNO_EINVAL);
				else if(err == ENFILE)
					throw ECImap(ECImap::ERRNO_ENFILE);
				else if(err == EMFILE)
					throw ECImap(ECImap::ERRNO_EMFILE);
				else if(err == ENOTTY)
					throw ECImap(ECImap::ERRNO_ENOTTY);
				else if(err == EFBIG)
					throw ECImap(ECImap::ERRNO_EFBIG);
				else if(err == ENOSPC)
					throw ECImap(ECImap::ERRNO_ENOSPC);
				else if(err == ESPIPE)
					throw ECImap(ECImap::ERRNO_ESPIPE);
				else if(err == EROFS)
					throw ECImap(ECImap::ERRNO_EROFS);
				else if(err == EMLINK)
					throw ECImap(ECImap::ERRNO_EMLINK);
				else if(err == EPIPE)
					throw ECImap(ECImap::ERRNO_EPIPE);
				else if(err == EDOM)
					throw ECImap(ECImap::ERRNO_EDOM);
				else if(err == ERANGE)
					throw ECImap(ECImap::ERRNO_ERANGE);
				else if(err == EDEADLK)
					throw ECImap(ECImap::ERRNO_EDEADLK);
				else if(err == ENAMETOOLONG)
					throw ECImap(ECImap::ERRNO_ENAMETOOLONG);
				else if(err == ENOLCK)
					throw ECImap(ECImap::ERRNO_ENOLCK);
				else if(err == ENOSYS)
					throw ECImap(ECImap::ERRNO_ENOSYS);
				else if(err == ENOTEMPTY)
					throw ECImap(ECImap::ERRNO_ENOTEMPTY);
				else if(err == EILSEQ)
					throw ECImap(ECImap::ERRNO_EILSEQ);
				else if(err == STRUNCATE)
					throw ECImap(ECImap::ERRNO_STRUNCATE);
				else
					throw ECImap(ECImap::FILE_NOT_EXIST);
			}

			// checking file size
			FileSize = 0;

			fseek(hFile, 0, SEEK_END);
			FileSize = ftell(hFile);
			fseek (hFile, 0, SEEK_SET);

			// sending the file
			MsgPart = 0;
				
			for(i = 0; i < FileSize / IMAP_BYTE_SIZE_FILE+1; i++)
			{
				res = static_cast<unsigned int>(fread(FileBuf, sizeof(char), IMAP_BYTE_SIZE_FILE, hFile));
				MsgPart ? strcat_s(SendBuf, BUFFER_SIZE, base64_encode(reinterpret_cast<const unsigned char*>(FileBuf), res).c_str())
						  : strcpy_s(SendBuf, BUFFER_SIZE, base64_encode(reinterpret_cast<const unsigned char*>(FileBuf), res).c_str());
				strcat_s(SendBuf, BUFFER_SIZE, "\r\n");
				MsgPart += res + 2;
				if(MsgPart >= (BUFFER_SIZE / 2))
				{ // sending part of the message
					MsgPart = 0;
					SendData(pEntry);
					dwNumCharSent += strlen(SendBuf);
				}
			}

			if(MsgPart)
			{
				SendData(pEntry);
				dwNumCharSent += strlen(SendBuf);
			}

			fclose(hFile);
		}

		delete[] FileBuf;
		delete[] FileName;
		
		FileBuf = NULL;
		FileName =  NULL;

		// sending last message block (if there is one or more attachments)
		if(Attachments.size())
		{
			sprintf_s(SendBuf, BUFFER_SIZE, "\r\n--%s--\r\n", IMAP_BOUNDARY_MIXED);
			SendData(pEntry);
			dwNumCharSent += strlen(SendBuf);
		}
		
		strcpy_s(SendBuf, BUFFER_SIZE, "\r\n");
		SendData(pEntry);

		pEntry = Imap_FindCommandEntry(command_APPEND_DONE);
		ReceiveResponse(pEntry);
	}
	catch(const ECImap&)
	{
		DisconnectRemoteServer();
		throw;
	}
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: ConnectRemoteServer
// DESCRIPTION: Connecting to the service running on the remote server. 
//   ARGUMENTS: const char *server - service name
//              const unsigned short port - service port
// USES GLOBAL: m_pcIMAPSrvName, m_iIMAPSrvPort, SendBuf, RecvBuf, m_pcLogin,
//              m_pcPassword, m_pcMailFrom, Recipients, CCRecipients,
//              BCCRecipients, m_pcMsgBody, Attachments, 
// MODIFIES GL: m_oError 
//     RETURNS: socket of the remote service
//      AUTHOR: Sebastiano Bertini
// AUTHOR/DATE: 25-06-2016
////////////////////////////////////////////////////////////////////////////////
bool CImap::ConnectRemoteServer(const char* szServer, const unsigned short nPort_/*=0*/, 
								IMAP_SECURITY_TYPE securityType/*=DO_NOT_SET*/,
								bool authenticate/*=true*/, const char* login/*=NULL*/,
								const char* password/*=NULL*/)
{
	unsigned short nPort = 0;
	LPSERVENT lpServEnt;
	SOCKADDR_IN sockAddr;
	unsigned long ul = 1;
	fd_set fdwrite, fdexcept;
	timeval timeout;
	int res = 0;

	try
	{
		timeout.tv_sec = TIME_IN_SEC;
		timeout.tv_usec = 0;

		hSocket = INVALID_SOCKET;

		if((hSocket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
			throw ECImap(ECImap::WSA_INVALID_SOCKET);

		if(nPort_ != 0)
			nPort = htons(nPort_);
		else
		{
			lpServEnt = getservbyname("mail", 0);
			if (lpServEnt == NULL)
				nPort = htons(143);
			else 
				nPort = lpServEnt->s_port;
		}
				
		sockAddr.sin_family = AF_INET;
		sockAddr.sin_port = nPort;

		struct addrinfo hints, *hres;

		memset(&hints, 0, sizeof(hints));
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_family = AF_INET;

		if (getaddrinfo(szServer, NULL, &hints, &hres) != 0)
		{
			closesocket(hSocket);
			throw ECImap(ECImap::WSA_GETHOSTBY_NAME_ADDR);
		}

		sockAddr.sin_addr = ((struct sockaddr_in *)(hres->ai_addr))->sin_addr;
		freeaddrinfo(hres);

		// start non-blocking mode for socket:
		if(ioctlsocket(hSocket, FIONBIO, (unsigned long*)&ul) == SOCKET_ERROR)
		{
			closesocket(hSocket);
			throw ECImap(ECImap::WSA_IOCTLSOCKET);
		}

		if(connect(hSocket, (LPSOCKADDR)&sockAddr, sizeof(sockAddr)) == SOCKET_ERROR)
		{
			if(WSAGetLastError() != WSAEWOULDBLOCK)
			{
				closesocket(hSocket);
				throw ECImap(ECImap::WSA_CONNECT);
			}
		}
		else
			return true;

		while(true)
		{
			FD_ZERO(&fdwrite);
			FD_ZERO(&fdexcept);

			FD_SET(hSocket, &fdwrite);
			FD_SET(hSocket, &fdexcept);

			if((res = select(0, NULL, &fdwrite, &fdexcept, &timeout)) == SOCKET_ERROR)
			{
				closesocket(hSocket);
				throw ECImap(ECImap::WSA_SELECT);
			}

			if(!res)
			{
				closesocket(hSocket);
				throw ECImap(ECImap::SELECT_TIMEOUT);
			}
			if(res && FD_ISSET(hSocket, &fdwrite))
				break;
			if(res && FD_ISSET(hSocket, &fdexcept))
			{
				closesocket(hSocket);
				throw ECImap(ECImap::WSA_SELECT);
			}
		} // while

		FD_CLR(hSocket, &fdwrite);
		FD_CLR(hSocket, &fdexcept);

		if(securityType!=IMAP_DO_NOT_SET) SetSecurityType(securityType);
		if(GetSecurityType() == IMAP_USE_TLS || GetSecurityType() == IMAP_USE_SSL)
		{
			InitOpenSSL();
			if(GetSecurityType() == IMAP_USE_SSL)
			{
				OpenSSLConnect();
			}
		}

		Imap_Command_Entry* pEntry = Imap_FindCommandEntry(command_INIT_IMAP);
		ReceiveResponse(pEntry);
		
		pEntry = Imap_FindCommandEntry(command_CAPABILITY);
		sprintf_s(SendBuf, BUFFER_SIZE, "%s CAPABILITY\r\n", pEntry->Token);
		SendData(pEntry);
		ReceiveResponse(pEntry);

		m_bConnected = true;

		if(GetSecurityType() == IMAP_USE_TLS)
		{
			StartTls();
		}

		if(authenticate)
		{
			if(login) SetLogin(login);
			if(!m_sLogin.size())
				throw ECImap(ECImap::UNDEF_LOGIN);

			if(password) SetPassword(password);
			if(!m_sPassword.size())
				throw ECImap(ECImap::UNDEF_PASSWORD);

			pEntry = Imap_FindCommandEntry(command_LOGIN);
			sprintf_s(SendBuf, BUFFER_SIZE, "%s LOGIN %s %s\r\n", pEntry->Token, m_sLogin.c_str(), m_sPassword.c_str());
			SendData(pEntry);
			ReceiveResponse(pEntry);
		}
	}
	catch(const ECImap&)
	{
		DisconnectRemoteServer();
		throw;
		return false;
	}

	return true;
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: DisconnectRemoteServer
// DESCRIPTION: Disconnects from the SMTP server and closes the socket
//   ARGUMENTS: none
// USES GLOBAL: none
// MODIFIES GL: none
//     RETURNS: void
//      AUTHOR: David Johns
// AUTHOR/DATE: DRJ 2010-08-14
////////////////////////////////////////////////////////////////////////////////
void CImap::DisconnectRemoteServer()
{
	if(m_bConnected) SayQuit();
	if(hSocket)
	{
		closesocket(hSocket);
	}
	hSocket = INVALID_SOCKET;
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: FormatHeader
// DESCRIPTION: Prepares a header of the message.
//   ARGUMENTS: char* header - formated header string
// USES GLOBAL: Recipients, CCRecipients, BCCRecipients
// MODIFIES GL: none
//     RETURNS: void
//      AUTHOR: Sebastiano Bertini
// AUTHOR/DATE: 25-06-2016
//							
////////////////////////////////////////////////////////////////////////////////
void CImap::FormatHeader(char* header)
{
	char month[][4] = {"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};
	char weekday[][4] = {"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
	size_t i;
	std::string to;
	std::string cc;
	time_t rawtime;
	struct tm timeinfo;

	unsigned char day[2];
	long long num[2];
	long long dwResult;

	// date/time check
	time(&rawtime);

	// UTC
	gmtime_s(&timeinfo, &rawtime);
	day[0] = timeinfo.tm_mday;
	num[0] = (timeinfo.tm_hour * 3600) + (timeinfo.tm_min * 60);
	
	// LocalTime
	localtime_s(&timeinfo, &rawtime);
	day[1] = timeinfo.tm_mday;
	num[1] = (timeinfo.tm_hour * 3600) + (timeinfo.tm_min * 60);

	dwResult = 0;

	if(day[0] == day[1]) // No date difference
	{ 
        if(num[0] < num[1])
            dwResult = num[1]-num[0]; // Positive ex. CUT +1
        else if (num[0] > num[1])
            dwResult = num[0]-num[1]; // Negative ex. Pacific -8
    }
    else if(day[0] < day[1]) // Ex. 1: 30 am Jan 1 : 11: 30 pm Dec 31
        dwResult = (86400-num[0]) + num[1];
    else 
		dwResult = (86400-num[1]) + num[0]; // Opposite

	if(dwResult != 0)
		dwResult = dwResult/3600;

	// check for at least one recipient
	if(Recipients.size())
	{
		for (i = 0; i < Recipients.size(); i++)
		{
			if(i > 0)
				to.append(",");
			to += Recipients[i].Name;
			to.append("<");
			to += Recipients[i].Mail;
			to.append(">");
		}
	}
	else
		throw ECImap(ECImap::UNDEF_RECIPIENTS);

	if(CCRecipients.size())
	{
		for (i = 0; i < CCRecipients.size(); i++)
		{
			if(i > 0)
				cc. append(",");
			cc += CCRecipients[i].Name;
			cc.append("<");
			cc += CCRecipients[i].Mail;
			cc.append(">");
		}
	}

	// Date: <SP> <dd> <SP> <mon> <SP> <yy> <SP> <hh> ":" <mm> ":" <ss> <SP> <zone> <CRLF>
	if(dwResult>=0)
		sprintf_s(header, BUFFER_SIZE, "Date: %s, %d %s %d %02d:%02d:%02d +%02lld00\r\n", weekday[timeinfo.tm_wday], timeinfo.tm_mday,
																	month[timeinfo.tm_mon],
																	timeinfo.tm_year+1900,
																	timeinfo.tm_hour,
																	timeinfo.tm_min,
																	timeinfo.tm_sec,
																	dwResult); 
	else
		sprintf_s(header, BUFFER_SIZE, "Date: %s, %d %s %d %02d:%02d:%02d -%02lld00\r\n", weekday[timeinfo.tm_wday], timeinfo.tm_mday,
																	month[timeinfo.tm_mon],
																	timeinfo.tm_year+1900,
																	timeinfo.tm_hour,
																	timeinfo.tm_min,
																	timeinfo.tm_sec,
																	dwResult*-1); 
	
	int dwRandomHash;

	// Message-Id:
	strcat_s(header, BUFFER_SIZE, "Message-Id: <");

	dwRandomHash = timeinfo.tm_min + (rand() % timeinfo.tm_min);

	sprintf_s(szMsgId, BUFFER_MSGID_SIZE, "%d%02d%02d%02d%02d%02d.%011X@", timeinfo.tm_year + 1900, 
												timeinfo.tm_mon + 1, 
												timeinfo.tm_mday,
												timeinfo.tm_hour,
												timeinfo.tm_min,
												timeinfo.tm_sec,
												dwRandomHash);

	strcat_s(header, BUFFER_SIZE, szMsgId);
	strcat_s(header, BUFFER_SIZE, m_sIMAPSrvName.c_str());
	strcat_s(header, BUFFER_SIZE, ">\r\n");

	// From: <SP> <sender>  <SP> "<" <sender-email> ">" <CRLF>
	if(!m_sMailFrom.size()) 
		throw ECImap(ECImap::UNDEF_MAIL_FROM);
	 
	strcat_s(header, BUFFER_SIZE, "From: ");
	
	if (m_sNameFrom.size())
	{
		if (strcmp(m_sCharSet.c_str(), "UTF-8") == 0)
		{
			std::string szFromNameEncoded;

			szFromNameEncoded.append("=?UTF-8?B?");
			szFromNameEncoded.append(base64_encode(reinterpret_cast<const unsigned char*>(m_sNameFrom.c_str()), static_cast<unsigned int>(m_sNameFrom.size())));
			szFromNameEncoded.append("?=");

			strcat_s(header, BUFFER_SIZE, szFromNameEncoded.c_str());

			szFromNameEncoded.clear();
		}
		else
		{
			strcat_s(header, BUFFER_SIZE, "\"");
			strcat_s(header, BUFFER_SIZE, m_sNameFrom.c_str());
			strcat_s(header, BUFFER_SIZE, "\"");
		}
	}
	else
	{
		if (strcmp(m_sCharSet.c_str(), "UTF-8") == 0)
		{
			std::string szFromNameEncoded;

			szFromNameEncoded.append("=?UTF-8?B?");
			szFromNameEncoded.append(base64_encode(reinterpret_cast<const unsigned char*>(m_sMailFrom.c_str()), static_cast<unsigned int>(m_sMailFrom.size())));
			szFromNameEncoded.append("?=");

			strcat_s(header, BUFFER_SIZE, szFromNameEncoded.c_str());

			szFromNameEncoded.clear();
		}
		else
		{
			strcat_s(header, BUFFER_SIZE, "\"");
			strcat_s(header, BUFFER_SIZE, m_sMailFrom.c_str());
			strcat_s(header, BUFFER_SIZE, "\"");
		}
	}

	strcat_s(header, BUFFER_SIZE, " <");
	strcat_s(header, BUFFER_SIZE, m_sMailFrom.c_str());
	strcat_s(header, BUFFER_SIZE, ">\r\n");

	// X-Mailer: <SP> <xmailer-app> <CRLF>
	if(m_sXMailer.size())
	{
		strcat_s(header, BUFFER_SIZE, "X-Mailer: ");
		strcat_s(header, BUFFER_SIZE, m_sXMailer.c_str());
		strcat_s(header, BUFFER_SIZE, "\r\n");
	}

	// Reply-To: <SP> <reverse-path> <CRLF>
	if(m_sReplyTo.size())
	{
		strcat_s(header, BUFFER_SIZE, "Reply-To: ");
		strcat_s(header, BUFFER_SIZE, m_sReplyTo.c_str());
		strcat_s(header, BUFFER_SIZE, "\r\n");
	}

	// Disposition-Notification-To: <SP> <reverse-path or sender-email> <CRLF>
	if(m_bReadReceipt)
	{
		strcat_s(header, BUFFER_SIZE, "Disposition-Notification-To: ");
		if(m_sReplyTo.size()) strcat_s(header, BUFFER_SIZE, m_sReplyTo.c_str());
		else strcat_s(header, BUFFER_SIZE, m_sNameFrom.c_str());
		strcat_s(header, BUFFER_SIZE, "\r\n");
	}

	// X-Priority: <SP> <number> <CRLF>
	switch(m_iXPriority)
	{
		case IMAP_XPRIORITY_HIGH:
			strcat_s(header, BUFFER_SIZE, "X-Priority: 2 (High)\r\n");
			break;
		case IMAP_XPRIORITY_NORMAL:
			strcat_s(header, BUFFER_SIZE, "X-Priority: 3 (Normal)\r\n");
			break;
		case IMAP_XPRIORITY_LOW:
			strcat_s(header, BUFFER_SIZE, "X-Priority: 4 (Low)\r\n");
			break;
		default:
			strcat_s(header, BUFFER_SIZE, "X-Priority: 3 (Normal)\r\n");
	}

	// To: <SP> <remote-user-mail> <CRLF>
	strcat_s(header, BUFFER_SIZE, "To: ");
	strcat_s(header, BUFFER_SIZE, to.c_str());
	strcat_s(header, BUFFER_SIZE, "\r\n");

	// Cc: <SP> <remote-user-mail> <CRLF>
	if(CCRecipients.size())
	{
		strcat_s(header, BUFFER_SIZE, "Cc: ");
		strcat_s(header, BUFFER_SIZE, cc.c_str());
		strcat_s(header, BUFFER_SIZE, "\r\n");
	}

	// Subject: <SP> <subject-text> <CRLF>
	if (!m_sSubject.size())
		strcat_s(header, BUFFER_SIZE, "Subject:  ");
	else
	{
		if (strcmp(m_sCharSet.c_str(), "UTF-8") == 0)
		{
			std::string szSubjectEncoded;

			szSubjectEncoded.append("=?UTF-8?B?");
			szSubjectEncoded.append(base64_encode(reinterpret_cast<const unsigned char*>(m_sSubject.c_str()), static_cast<unsigned int>(m_sSubject.size())));
			szSubjectEncoded.append("?=");

			strcat_s(header, BUFFER_SIZE, "Subject: ");
			strcat_s(header, BUFFER_SIZE, szSubjectEncoded.c_str());

			szSubjectEncoded.clear();
		}
		else
		{
			strcat_s(header, BUFFER_SIZE, "Subject: ");
			strcat_s(header, BUFFER_SIZE, m_sSubject.c_str());
		}
	}

	strcat_s(header, BUFFER_SIZE, "\r\n");
	
	// MIME-Version: <SP> 1.0 <CRLF>
	strcat_s(header, BUFFER_SIZE, "MIME-Version: 1.0\r\n");

	if(!Attachments.size())
	{ // No attachments
		if(m_bHTML) 
		{
			strcat_s(header, BUFFER_SIZE, "Content-Type: multipart/alternative;\r\n\tboundary=\"");
			strcat_s(header, BUFFER_SIZE, IMAP_BOUNDARY_ALTERNATIVE);
			strcat_s(header, BUFFER_SIZE, "\"\r\n");
			strcat_s(header, BUFFER_SIZE, "\r\n");	
			
			strcat_s(header, BUFFER_SIZE, "This is a multi-part message in MIME format.\r\n");

			strcat_s(header, BUFFER_SIZE, "--");
			strcat_s(header, BUFFER_SIZE, IMAP_BOUNDARY_ALTERNATIVE);
			strcat_s(header, BUFFER_SIZE, "\r\n");

			strcat_s(header, BUFFER_SIZE, "Content-Type: text/plain; charset=\"");
			strcat_s(header, BUFFER_SIZE, m_sCharSet.c_str());
			strcat_s(header, BUFFER_SIZE, "\"\r\n");
			strcat_s(header, BUFFER_SIZE, "Content-Transfer-Encoding: ");
			strcat_s(header, BUFFER_SIZE, m_sCharEncoding.c_str());
			strcat_s(header, BUFFER_SIZE, "\r\n");
			strcat_s(header, BUFFER_SIZE, "\r\n");
		}
		else
		{
			strcat_s(header, BUFFER_SIZE, "Content-Type: text/plain; charset=\"");
			strcat_s(header, BUFFER_SIZE, m_sCharSet.c_str());
			strcat_s(header, BUFFER_SIZE, "\"\r\n");
			strcat_s(header, BUFFER_SIZE, "Content-Transfer-Encoding: ");
			strcat_s(header, BUFFER_SIZE, m_sCharEncoding.c_str());
			strcat_s(header, BUFFER_SIZE, "\r\n");
			strcat_s(header, BUFFER_SIZE, "\r\n");
		}
	}
	else
	{ // there is one or more attachments
		strcat_s(header, BUFFER_SIZE, "Content-Type: multipart/mixed;\r\n\tboundary=\"");
		strcat_s(header, BUFFER_SIZE, IMAP_BOUNDARY_MIXED);
		strcat_s(header, BUFFER_SIZE, "\"\r\n");
		strcat_s(header, BUFFER_SIZE, "\r\n");

		strcat_s(header, BUFFER_SIZE, "This is a multi-part message in MIME format.\r\n");

		strcat_s(header, BUFFER_SIZE, "--");
		strcat_s(header, BUFFER_SIZE, IMAP_BOUNDARY_MIXED);
		strcat_s(header, BUFFER_SIZE, "\r\n");

		if(m_bHTML) 
		{
			strcat_s(header, BUFFER_SIZE, "Content-Type: multipart/alternative;\r\n\tboundary=\"");
			strcat_s(header, BUFFER_SIZE, IMAP_BOUNDARY_ALTERNATIVE);
			strcat_s(header, BUFFER_SIZE, "\"\r\n");
			strcat_s(header, BUFFER_SIZE, "\r\n");	
			
			strcat_s(header, BUFFER_SIZE, "\r\n");

			strcat_s(header, BUFFER_SIZE, "--");
			strcat_s(header, BUFFER_SIZE, IMAP_BOUNDARY_ALTERNATIVE);
			strcat_s(header, BUFFER_SIZE, "\r\n");

			strcat_s(header, BUFFER_SIZE, "Content-Type: text/plain; charset=\"");
			strcat_s(header, BUFFER_SIZE, m_sCharSet.c_str());
			strcat_s(header, BUFFER_SIZE, "\"\r\n");
			strcat_s(header, BUFFER_SIZE, "Content-Transfer-Encoding: ");
			strcat_s(header, BUFFER_SIZE, m_sCharEncoding.c_str());
			strcat_s(header, BUFFER_SIZE, "\r\n");
			strcat_s(header, BUFFER_SIZE, "\r\n");
		}
		else
		{
			strcat_s(header, BUFFER_SIZE, "Content-Type: text/plain; charset=\"");
			strcat_s(header, BUFFER_SIZE, m_sCharSet.c_str());
			strcat_s(header, BUFFER_SIZE, "\"\r\n");
			strcat_s(header, BUFFER_SIZE, "Content-Transfer-Encoding: ");
			strcat_s(header, BUFFER_SIZE, m_sCharEncoding.c_str());
			strcat_s(header, BUFFER_SIZE, "\r\n");
			strcat_s(header, BUFFER_SIZE, "\r\n");
		}
	}

	// done
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: ReceiveData
// DESCRIPTION: Receives a row terminated '\n'.
//   ARGUMENTS: none
// USES GLOBAL: RecvBuf
// MODIFIES GL: RecvBuf
//     RETURNS: void
//      AUTHOR: Sebastiano Bertini
// AUTHOR/DATE: 25-06-2016			
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
// MODIFICATION: Receives data as much as possible. Another function ReceiveResponse
//               will ensure the received data contains '\n'
// AUTHOR/DATE:  John Tang 2010-08-01
////////////////////////////////////////////////////////////////////////////////
void CImap::ReceiveData(Imap_Command_Entry* pEntry)
{
	if(m_ssl != NULL)
	{
		ReceiveData_SSL(m_ssl, pEntry);
		return;
	}

	int res = 0;
	fd_set fdread;
	timeval time;

	time.tv_sec = pEntry->recv_timeout;
	time.tv_usec = 0;

	assert(RecvBuf);

	if(RecvBuf == NULL)
		throw ECImap(ECImap::RECVBUF_IS_EMPTY);

	FD_ZERO(&fdread);

	FD_SET(hSocket, &fdread);

	if((res = select(0, &fdread, NULL, NULL, &time)) == SOCKET_ERROR)
	{
		FD_CLR(hSocket, &fdread);
		throw ECImap(ECImap::WSA_SELECT);
	}

	if(!res)
	{
		//timeout
		FD_CLR(hSocket, &fdread);
		throw ECImap(ECImap::SERVER_NOT_RESPONDING);
	}

	if(FD_ISSET(hSocket,&fdread))
	{
		res = recv(hSocket, RecvBuf, BUFFER_SIZE, 0);
		if(res == SOCKET_ERROR)
		{
			FD_CLR(hSocket,&fdread);
			throw ECImap(ECImap::WSA_RECV);
		}
	}

	FD_CLR(hSocket, &fdread);
	RecvBuf[res] = 0;

	if(res == 0)
	{
		throw ECImap(ECImap::CONNECTION_CLOSED);
	}
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: SendData
// DESCRIPTION: Sends data from SendBuf buffer.
//   ARGUMENTS: none
// USES GLOBAL: SendBuf
// MODIFIES GL: none
//     RETURNS: void
//      AUTHOR: Sebastiano Bertini
// AUTHOR/DATE: 25-06-2016
////////////////////////////////////////////////////////////////////////////////
void CImap::SendData(Imap_Command_Entry* pEntry)
{
	if(m_ssl != NULL)
	{
		SendData_SSL(m_ssl, pEntry);
		return;
	}

	int idx = 0, res, nLeft = static_cast<int>(strlen(SendBuf));
	fd_set fdwrite;
	timeval time;

	time.tv_sec = pEntry->send_timeout;
	time.tv_usec = 0;

	assert(SendBuf);

	if(SendBuf == NULL)
		throw ECImap(ECImap::SENDBUF_IS_EMPTY);

	std::cout << "C: " << SendBuf;

	while(nLeft > 0)
	{
		FD_ZERO(&fdwrite);

		FD_SET(hSocket, &fdwrite);

		if((res = select(0, NULL, &fdwrite, NULL, &time)) == SOCKET_ERROR)
		{
			FD_CLR(hSocket, &fdwrite);
			throw ECImap(ECImap::WSA_SELECT);
		}

		if(!res)
		{
			//timeout
			FD_CLR(hSocket,&fdwrite);
			throw ECImap(ECImap::SERVER_NOT_RESPONDING);
		}

		if(res && FD_ISSET(hSocket, &fdwrite))
		{
			res = send(hSocket, &SendBuf[idx], nLeft, 0);

			if(res == SOCKET_ERROR || res == 0)
			{
				FD_CLR(hSocket, &fdwrite);
				throw ECImap(ECImap::WSA_SEND);
			}

			nLeft -= res;
			idx += res;
		}
	}

	FD_CLR(hSocket, &fdwrite);
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: GetLocalHostName
// DESCRIPTION: Returns local host name. 
//   ARGUMENTS: none
// USES GLOBAL: m_pcLocalHostName
// MODIFIES GL: m_oError, m_pcLocalHostName 
//     RETURNS: socket of the remote service
//      AUTHOR: Sebastiano Bertini
// AUTHOR/DATE: 25-06-2016
////////////////////////////////////////////////////////////////////////////////
const char* CImap::GetLocalHostName()
{
	return m_sLocalHostName.c_str();
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: GetRecipientCount
// DESCRIPTION: Returns the number of recipents.
//   ARGUMENTS: none
// USES GLOBAL: Recipients
// MODIFIES GL: none 
//     RETURNS: number of recipents
//      AUTHOR: Sebastiano Bertini
// AUTHOR/DATE: 25-06-2016
////////////////////////////////////////////////////////////////////////////////
unsigned int CImap::GetRecipientCount() const
{
	return static_cast<unsigned int>(Recipients.size());
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: GetBCCRecipientCount
// DESCRIPTION: Returns the number of bcc-recipents. 
//   ARGUMENTS: none
// USES GLOBAL: BCCRecipients
// MODIFIES GL: none 
//     RETURNS: number of bcc-recipents
//      AUTHOR: Sebastiano Bertini
// AUTHOR/DATE: 25-06-2016
////////////////////////////////////////////////////////////////////////////////
unsigned int CImap::GetBCCRecipientCount() const
{
	return static_cast<unsigned int>(BCCRecipients.size());
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: GetCCRecipientCount
// DESCRIPTION: Returns the number of cc-recipents.
//   ARGUMENTS: none
// USES GLOBAL: CCRecipients
// MODIFIES GL: none 
//     RETURNS: number of cc-recipents
//      AUTHOR: Sebastiano Bertini
// AUTHOR/DATE: 25-06-2016
////////////////////////////////////////////////////////////////////////////////
unsigned int CImap::GetCCRecipientCount() const
{
	return static_cast<unsigned int>(CCRecipients.size());
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: GetReplyTo
// DESCRIPTION: Returns m_pcReplyTo string.
//   ARGUMENTS: none
// USES GLOBAL: m_sReplyTo
// MODIFIES GL: none 
//     RETURNS: m_sReplyTo string
//      AUTHOR: Sebastiano Bertini
// AUTHOR/DATE: 25-06-2016
////////////////////////////////////////////////////////////////////////////////
const char* CImap::GetReplyTo() const
{
	return m_sReplyTo.c_str();
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: GetMailFrom
// DESCRIPTION: Returns m_pcMailFrom string.
//   ARGUMENTS: none
// USES GLOBAL: m_sMailFrom
// MODIFIES GL: none 
//     RETURNS: m_sMailFrom string
//      AUTHOR: Sebastiano Bertini
// AUTHOR/DATE: 25-06-2016
////////////////////////////////////////////////////////////////////////////////
const char* CImap::GetMailFrom() const
{
	return m_sMailFrom.c_str();
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: GetSenderName
// DESCRIPTION: Returns m_pcNameFrom string.
//   ARGUMENTS: none
// USES GLOBAL: m_sNameFrom
// MODIFIES GL: none 
//     RETURNS: m_sNameFrom string
//      AUTHOR: Sebastiano Bertini
// AUTHOR/DATE: 25-06-2016
////////////////////////////////////////////////////////////////////////////////
const char* CImap::GetSenderName() const
{
	return m_sNameFrom.c_str();
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: GetSubject
// DESCRIPTION: Returns m_pcSubject string.
//   ARGUMENTS: none
// USES GLOBAL: m_sSubject
// MODIFIES GL: none 
//     RETURNS: m_sSubject string
//      AUTHOR: Sebastiano Bertini
// AUTHOR/DATE: 25-06-2016
////////////////////////////////////////////////////////////////////////////////
const char* CImap::GetSubject() const
{
	return m_sSubject.c_str();
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: GetXMailer
// DESCRIPTION: Returns m_pcXMailer string.
//   ARGUMENTS: none
// USES GLOBAL: m_pcXMailer
// MODIFIES GL: none 
//     RETURNS: m_pcXMailer string
//      AUTHOR: Sebastiano Bertini
// AUTHOR/DATE: 25-06-2016
////////////////////////////////////////////////////////////////////////////////
const char* CImap::GetXMailer() const
{
	return m_sXMailer.c_str();
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: GetXPriority
// DESCRIPTION: Returns m_iXPriority string.
//   ARGUMENTS: none
// USES GLOBAL: m_iXPriority
// MODIFIES GL: none 
//     RETURNS: CSmptXPriority m_pcXMailer
//      AUTHOR: Sebastiano Bertini
// AUTHOR/DATE: 25-06-2016
////////////////////////////////////////////////////////////////////////////////
CImapXPriority CImap::GetXPriority() const
{
	return m_iXPriority;
}

const char* CImap::GetMsgLineText(unsigned int Line) const
{
	if(Line >= MsgBody.size())
		throw ECImap(ECImap::OUT_OF_MSG_RANGE);

	return MsgBody.at(Line).c_str();
}

unsigned int CImap::GetMsgLines() const
{
	return static_cast<unsigned int>(MsgBody.size());
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: SetCharSet
// DESCRIPTION: Allows the character set to be changed from default of US-ASCII. 
//   ARGUMENTS: const char *sCharSet 
// USES GLOBAL: m_sCharSet
// MODIFIES GL: m_sCharSet
//     RETURNS: none
//      AUTHOR: David Johns
// AUTHOR/DATE: DJ 2012-11-03
////////////////////////////////////////////////////////////////////////////////
void CImap::SetCharSet(const char *sCharSet)
{
    m_sCharSet = sCharSet;
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: SetLocalHostName
// DESCRIPTION: Allows the local host name to be set externally. 
//   ARGUMENTS: const char *sLocalHostName 
// USES GLOBAL: m_sLocalHostName
// MODIFIES GL: m_sLocalHostName
//     RETURNS: none
//      AUTHOR: jerko
// AUTHOR/DATE: J 2011-12-01
////////////////////////////////////////////////////////////////////////////////
void CImap::SetLocalHostName(const char *sLocalHostName)
{
    m_sLocalHostName = sLocalHostName;
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: SetXPriority
// DESCRIPTION: Setting priority of the message.
//   ARGUMENTS: CSmptXPriority priority - priority of the message (	XPRIORITY_HIGH,
//              XPRIORITY_NORMAL, XPRIORITY_LOW)
// USES GLOBAL: none
// MODIFIES GL: m_iXPriority 
//     RETURNS: none
//      AUTHOR: Sebastiano Bertini
// AUTHOR/DATE: 25-06-2016
////////////////////////////////////////////////////////////////////////////////
void CImap::SetXPriority(CImapXPriority priority)
{
	m_iXPriority = priority;
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: SetReplyTo
// DESCRIPTION: Setting the return address.
//   ARGUMENTS: const char *ReplyTo - return address
// USES GLOBAL: m_sReplyTo
// MODIFIES GL: m_sReplyTo
//     RETURNS: none
//      AUTHOR: Sebastiano Bertini
// AUTHOR/DATE: 25-06-2016
//							
////////////////////////////////////////////////////////////////////////////////
void CImap::SetReplyTo(const char *ReplyTo)
{
	m_sReplyTo = ReplyTo;
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: SetReadReceipt
// DESCRIPTION: Setting whether to request a read receipt.
//   ARGUMENTS: bool requestReceipt - whether or not to request a read receipt
// USES GLOBAL: m_bReadReceipt
// MODIFIES GL: m_bReadReceipt
//     RETURNS: none
//      AUTHOR: David Johns
// AUTHOR/DATE: DRJ 2012-11-03
////////////////////////////////////////////////////////////////////////////////
void CImap::SetReadReceipt(bool requestReceipt/*=true*/)
{
	m_bReadReceipt = requestReceipt;
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: SetSenderMail
// DESCRIPTION: Setting sender's mail.
//   ARGUMENTS: const char *EMail - sender's e-mail
// USES GLOBAL: m_sMailFrom
// MODIFIES GL: m_sMailFrom
//     RETURNS: none
//      AUTHOR: Sebastiano Bertini
// AUTHOR/DATE: 25-06-2016
//							
////////////////////////////////////////////////////////////////////////////////
void CImap::SetSenderMail(const char *EMail)
{
	m_sMailFrom = EMail;
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: SetSenderName
// DESCRIPTION: Setting sender's name.
//   ARGUMENTS: const char *Name - sender's name
// USES GLOBAL: m_sNameFrom
// MODIFIES GL: m_sNameFrom
//     RETURNS: none
//      AUTHOR: Sebastiano Bertini
// AUTHOR/DATE: 25-06-2016
//							
////////////////////////////////////////////////////////////////////////////////
void CImap::SetSenderName(const char *Name)
{
	m_sNameFrom = Name;
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: SetSubject
// DESCRIPTION: Setting subject of the message.
//   ARGUMENTS: const char *Subject - subject of the message
// USES GLOBAL: m_sSubject
// MODIFIES GL: m_sSubject
//     RETURNS: none
//      AUTHOR: Sebastiano Bertini
// AUTHOR/DATE: 25-06-2016
//							
////////////////////////////////////////////////////////////////////////////////
void CImap::SetSubject(const char *Subject)
{
	m_sSubject = Subject;
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: SetSubject
// DESCRIPTION: Setting the name of program which is sending the mail.
//   ARGUMENTS: const char *XMailer - programe name
// USES GLOBAL: m_sXMailer
// MODIFIES GL: m_sXMailer
//     RETURNS: none
//      AUTHOR: Sebastiano Bertini
// AUTHOR/DATE: 25-06-2016
//							
////////////////////////////////////////////////////////////////////////////////
void CImap::SetXMailer(const char *XMailer)
{
	m_sXMailer = XMailer;
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: SetLogin
// DESCRIPTION: Setting the login of SMTP account's owner.
//   ARGUMENTS: const char *Login - login of SMTP account's owner
// USES GLOBAL: m_sLogin
// MODIFIES GL: m_sLogin
//     RETURNS: none
//      AUTHOR: Sebastiano Bertini
// AUTHOR/DATE: 25-06-2016
//							
////////////////////////////////////////////////////////////////////////////////
void CImap::SetLogin(const char *Login)
{
	m_sLogin = Login;
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: SetPassword
// DESCRIPTION: Setting the password of SMTP account's owner.
//   ARGUMENTS: const char *Password - password of SMTP account's owner
// USES GLOBAL: m_sPassword
// MODIFIES GL: m_sPassword
//     RETURNS: none
//      AUTHOR: Sebastiano Bertini
// AUTHOR/DATE: 25-06-2016
//							
////////////////////////////////////////////////////////////////////////////////
void CImap::SetPassword(const char *Password)
{
	m_sPassword = Password;
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: SetSMTPServer
// DESCRIPTION: Setting the SMTP service name and port.
//   ARGUMENTS: const char* SrvName - SMTP service name
//              const unsigned short SrvPort - SMTO service port
// USES GLOBAL: m_sSMTPSrvName
// MODIFIES GL: m_sSMTPSrvName 
//     RETURNS: none
//      AUTHOR: Sebastiano Bertini
// AUTHOR/DATE: 25-06-2016
//							JO 2010-0708
////////////////////////////////////////////////////////////////////////////////
void CImap::SetIMAPServer(const char* SrvName, const unsigned short SrvPort, bool authenticate)
{
	m_iIMAPSrvPort = SrvPort;
	m_sIMAPSrvName = SrvName;
	m_bAuthenticate = authenticate;
}

void CImap::SayQuit()
{
	// ***** CLOSING CONNECTION *****
	
	Imap_Command_Entry* pEntry = Imap_FindCommandEntry(command_LOGOUT);
	sprintf_s(SendBuf, BUFFER_SIZE, "%s LOGOUT\r\n", pEntry->Token);
	m_bConnected=false;
	SendData(pEntry);
	ReceiveResponse(pEntry);
}

void CImap::StartTls()
{
	if(Imap_IsKeywordSupported(RecvBuf, "STARTTLS") == false)
	{
		throw ECImap(ECImap::STARTTLS_NOT_SUPPORTED);
	}

	Imap_Command_Entry* pEntry = Imap_FindCommandEntry(command_STARTTLS_IMAP);
	sprintf_s(SendBuf, BUFFER_SIZE, "%s STARTTLS\r\n", pEntry->Token);
	SendData(pEntry);
	ReceiveResponse(pEntry);

	OpenSSLConnect();
}

void CImap::ReceiveData_SSL(SSL* ssl, Imap_Command_Entry* pEntry)
{
	int res = 0;
	int offset = 0;
	fd_set fdread;
	fd_set fdwrite;
	timeval time;

	int read_blocked_on_write = 0;

	time.tv_sec = pEntry->recv_timeout;
	time.tv_usec = 0;

	assert(RecvBuf);

	if(RecvBuf == NULL)
		throw ECImap(ECImap::RECVBUF_IS_EMPTY);

	bool bFinish = false;

	while(!bFinish)
	{
		FD_ZERO(&fdread);
		FD_ZERO(&fdwrite);

		FD_SET(hSocket, &fdread);

		if(read_blocked_on_write)
		{
			FD_SET(hSocket, &fdwrite);
		}

		if((res = select(0, &fdread, &fdwrite, NULL, &time)) == SOCKET_ERROR)
		{
			FD_ZERO(&fdread);
			FD_ZERO(&fdwrite);
			throw ECImap(ECImap::WSA_SELECT);
		}

		if(!res)
		{
			//timeout
			FD_ZERO(&fdread);
			FD_ZERO(&fdwrite);
			throw ECImap(ECImap::SERVER_NOT_RESPONDING);
		}

		if(FD_ISSET(hSocket, &fdread) || (read_blocked_on_write && FD_ISSET(hSocket, &fdwrite)) )
		{
			while(1)
			{
				read_blocked_on_write=0;

				const int buff_len = 1024;
				char* buff;

				if((buff = new char[buff_len]) == NULL)
					throw ECImap(ECImap::LACK_OF_MEMORY);

				res = SSL_read(ssl, buff, buff_len);

				int ssl_err = SSL_get_error(ssl, res);
				if(ssl_err == SSL_ERROR_NONE)
				{
					if(offset + res > BUFFER_SIZE - 1)
					{
						FD_ZERO(&fdread);
						FD_ZERO(&fdwrite);
						throw ECImap(ECImap::LACK_OF_MEMORY);
					}
					strncpy_s(RecvBuf + offset, BUFFER_SIZE, buff, res);
					delete[] buff;
					buff = NULL;
					offset += res;
					if(SSL_pending(ssl))
					{
						continue;
					}
					else
					{
						bFinish = true;
						break;
					}
				}
				else if(ssl_err == SSL_ERROR_ZERO_RETURN)
				{
					bFinish = true;
					delete[] buff;
					buff = NULL;
					break;
				}
				else if(ssl_err == SSL_ERROR_WANT_READ)
				{
					delete[] buff;
					buff = NULL;
					break;
				}
				else if(ssl_err == SSL_ERROR_WANT_WRITE)
				{
					/* We get a WANT_WRITE if we're
					trying to rehandshake and we block on
					a write during that rehandshake.

					We need to wait on the socket to be 
					writeable but reinitiate the read
					when it is */
					read_blocked_on_write=1;
					delete[] buff;
					buff = NULL;
					break;
				}
				else
				{
					FD_ZERO(&fdread);
					FD_ZERO(&fdwrite);
					delete[] buff;
					buff = NULL;
					throw ECImap(ECImap::SSL_PROBLEM);
				}
			}
		}
	}

	FD_ZERO(&fdread);
	FD_ZERO(&fdwrite);
	RecvBuf[offset] = 0;

	if(offset == 0)
	{
		throw ECImap(ECImap::CONNECTION_CLOSED);
	}
}

void CImap::ReceiveResponse(Imap_Command_Entry* pEntry)
{
	std::string line;
	bool bFinish = false;
	
	while(!bFinish)
	{
		ReceiveData(pEntry);

		line.append(RecvBuf);
		size_t len = line.length();
		size_t offset = 0;

		std::cout << RecvBuf;

		std::string::size_type bErrorFound = line.rfind("Error:");

		if(line.npos != bErrorFound)
		{
			line.clear();
			throw ECImap(pEntry->error);
		}

		if(offset + 1 < len)
		{
			while(offset + 1 < len)
			{
				if(line[offset] == '\r' && line[offset+1] == '\n')
				{
					if(!pEntry->bSkipToken)
					{
						std::string::size_type bFound = line.rfind(pEntry->TokenRecv);

						if(line.npos != bFound)
						{
							bFinish = true;
							break;
						}
					}
					else
					{
						bFinish = true;
						break;
					}
				}
				++offset;
			}
		}
	}

	// check return string for success
	if(!pEntry->bSkipToken && pEntry->command != command_APPEND)
	{
		std::string szTokenOK;

		szTokenOK.append(pEntry->TokenRecv);
		szTokenOK.append(" ");
		szTokenOK.append("OK");

		std::string::size_type bFound = line.find(szTokenOK.c_str());

		if(line.npos == bFound)
		{
			line.clear();
			szTokenOK.clear();
			throw ECImap(pEntry->error);
		}

		szTokenOK.clear();
	}

	strcpy_s(RecvBuf, BUFFER_SIZE, line.c_str());
	line.clear();
}

void CImap::SendData_SSL(SSL* ssl, Imap_Command_Entry* pEntry)
{
	int offset = 0, res, nLeft = static_cast<int>(strlen(SendBuf));
	fd_set fdwrite;
	fd_set fdread;
	timeval time;

	int write_blocked_on_read = 0;

	time.tv_sec = pEntry->send_timeout;
	time.tv_usec = 0;

	assert(SendBuf);

	if(SendBuf == NULL)
		throw ECImap(ECImap::SENDBUF_IS_EMPTY);

	while(nLeft > 0)
	{
		FD_ZERO(&fdwrite);
		FD_ZERO(&fdread);

		FD_SET(hSocket, &fdwrite);

		if(write_blocked_on_read)
		{
			FD_SET(hSocket, &fdread);
		}

		if((res = select(0, &fdread, &fdwrite, NULL, &time)) == SOCKET_ERROR)
		{
			FD_ZERO(&fdwrite);
			FD_ZERO(&fdread);
			throw ECImap(ECImap::WSA_SELECT);
		}

		if(!res)
		{
			//timeout
			FD_ZERO(&fdwrite);
			FD_ZERO(&fdread);
			throw ECImap(ECImap::SERVER_NOT_RESPONDING);
		}

		if(FD_ISSET(hSocket, &fdwrite) || (write_blocked_on_read && FD_ISSET(hSocket, &fdread)) )
		{
			write_blocked_on_read = 0;

			/* Try to write */
			res = SSL_write(ssl, SendBuf + offset, nLeft);
	          
			switch(SSL_get_error(ssl, res))
			{
			  /* We wrote something*/
			  case SSL_ERROR_NONE:
				nLeft -= res;
				offset += res;
				break;
	              
				/* We would have blocked */
			  case SSL_ERROR_WANT_WRITE:
				break;

				/* We get a WANT_READ if we're
				   trying to rehandshake and we block on
				   write during the current connection.
	               
				   We need to wait on the socket to be readable
				   but reinitiate our write when it is */
			  case SSL_ERROR_WANT_READ:
				write_blocked_on_read = 1;
				break;
	              
				  /* Some other error */
			  default:	      
				FD_ZERO(&fdread);
				FD_ZERO(&fdwrite);
				throw ECImap(ECImap::SSL_PROBLEM);
			}

		}
	}

	FD_ZERO(&fdwrite);
	FD_ZERO(&fdread);
}

void CImap::InitOpenSSL()
{
	SSL_library_init();
	SSL_load_error_strings();

	m_ctx = SSL_CTX_new (SSLv23_client_method());

	if(m_ctx == NULL)
		throw ECImap(ECImap::SSL_PROBLEM);
}

void CImap::OpenSSLConnect()
{
	if(m_ctx == NULL)
		throw ECImap(ECImap::SSL_PROBLEM);

	m_ssl = SSL_new (m_ctx);   

	if(m_ssl == NULL)
		throw ECImap(ECImap::SSL_PROBLEM);

	SSL_set_fd (m_ssl, (int)hSocket);
    SSL_set_mode(m_ssl, SSL_MODE_AUTO_RETRY);

	int res = 0;
	fd_set fdwrite;
	fd_set fdread;
	int write_blocked = 0;
	int read_blocked = 0;

	timeval time;
	time.tv_sec = TIME_IN_SEC;
	time.tv_usec = 0;

	while(1)
	{
		FD_ZERO(&fdwrite);
		FD_ZERO(&fdread);

		if(write_blocked)
			FD_SET(hSocket, &fdwrite);

		if(read_blocked)
			FD_SET(hSocket, &fdread);

		if(write_blocked || read_blocked)
		{
			write_blocked = 0;
			read_blocked = 0;

			if((res = select(0, &fdread, &fdwrite, NULL, &time)) == SOCKET_ERROR)
			{
				FD_ZERO(&fdwrite);
				FD_ZERO(&fdread);
				throw ECImap(ECImap::WSA_SELECT);
			}

			if(!res)
			{
				//timeout
				FD_ZERO(&fdwrite);
				FD_ZERO(&fdread);
				throw ECImap(ECImap::SERVER_NOT_RESPONDING);
			}
		}

		res = SSL_connect(m_ssl);

		switch(SSL_get_error(m_ssl, res))
		{
		  case SSL_ERROR_NONE:
			FD_ZERO(&fdwrite);
			FD_ZERO(&fdread);
			return;
			break;
              
		  case SSL_ERROR_WANT_WRITE:
			write_blocked = 1;
			break;

		  case SSL_ERROR_WANT_READ:
			read_blocked = 1;
			break;
              
		  default:	      
			FD_ZERO(&fdwrite);
			FD_ZERO(&fdread);
			throw ECImap(ECImap::SSL_PROBLEM);
		}
	}
}

void CImap::CleanupOpenSSL()
{
	if(m_ssl != NULL) 
	{
		SSL_shutdown (m_ssl);  /* send SSL/TLS close_notify */
		SSL_free (m_ssl);
		m_ssl = NULL;
	}

	if(m_ctx != NULL)
	{
		SSL_CTX_free (m_ctx);	
		m_ctx = NULL;
		ERR_remove_state(0);
		ERR_free_strings();
		EVP_cleanup();
		CRYPTO_cleanup_all_ex_data();
	}
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: GetErrorText (friend function)
// DESCRIPTION: Returns the string for specified error code.
//   ARGUMENTS: CImapError ErrorId - error code
// USES GLOBAL: none
// MODIFIES GL: none 
//     RETURNS: error string
//      AUTHOR: Sebastiano Bertini
// AUTHOR/DATE: 25-06-2016
////////////////////////////////////////////////////////////////////////////////
std::string ECImap::GetErrorText() const
{
	switch(ErrorCode)
	{
		case ECImap::CIMAP_NO_ERROR:
			return "";
		case ECImap::WSA_STARTUP:
			return "IMAP - WSA_STARTUP - Impossibile inizializzare WinSock2";
		case ECImap::WSA_VER:
			return "IMAP - WSA_VER - Versione errata di WinSock2";
		case ECImap::WSA_SEND:
			return "IMAP - WSA_SEND - Errore funzione send()";
		case ECImap::WSA_RECV:
			return "IMAP - WSA_RECV - Errore funzione recv()";
		case ECImap::WSA_CONNECT:
			return "IMAP - WSA_CONNECT - Errore funzione connect()";
		case ECImap::WSA_GETHOSTBY_NAME_ADDR:
			return "IMAP - WSA_GETHOSTBY_NAME_ADDR - Impossibile determinare il server remoto";
		case ECImap::WSA_INVALID_SOCKET:
			return "IMAP - WSA_INVALID_SOCKET - WinSock2 non valido";
		case ECImap::WSA_HOSTNAME:
			return "IMAP - WSA_HOSTNAME - Errore funzione hostname()";
		case ECImap::WSA_IOCTLSOCKET:
			return "IMAP - WSA_IOCTLSOCKET - Errore funzione ioctlsocket()";
		case ECImap::WSA_SELECT:
			return "IMAP - WSA_SELECT - Errore di rete";
		case ECImap::BAD_IPV4_ADDR:
			return "IMAP - BAD_IPV4_ADDR - Indirizzo IPv4 errato";
		case ECImap::UNDEF_MSG_HEADER:
			return "IMAP - UNDEF_MSG_HEADER - Header messaggio non definito";
		case ECImap::UNDEF_MAIL_FROM:
			return "IMAP - UNDEF_MAIL_FROM - Mittente non definito";
		case ECImap::UNDEF_SUBJECT:
			return "IMAP - UNDEF_SUBJECT - Soggetto non definito";
		case ECImap::UNDEF_RECIPIENTS:
			return "IMAP - UNDEF_RECIPIENTS - Definire almento un destinatario";
		case ECImap::UNDEF_LOGIN:
			return "IMAP - UNDEF_LOGIN - User non definito";
		case ECImap::UNDEF_PASSWORD:
			return "IMAP - UNDEF_PASSWORD - Password non definita";
		case ECImap::BAD_LOGIN_PASSWORD:
			return "IMAP - BAD_LOGIN_PASSWORD - Utente o password non valida";
		case ECImap::BAD_DIGEST_RESPONSE:
			return "IMAP - BAD_DIGEST_RESPONSE - Risposta MD5 errata da server";
		case ECImap::BAD_SERVER_NAME:
			return "IMAP - BAD_SERVER_NAME - Impossibile determinare il nome del server dalla risposta MD5";
		case ECImap::UNDEF_RECIPIENT_MAIL:
			return "IMAP - UNDEF_RECIPIENT_MAIL - Destinatario non definito";
		case ECImap::COMMAND_MAIL_FROM:
			return "IMAP - COMMAND_MAIL_FROM - Errore comando FROM";
		case ECImap::COMMAND_EHLO:
			return "IMAP - COMMAND_EHLO - Errore comando EHLO";
		case ECImap::COMMAND_COMPATIBILITY:
			return "IMAP - COMMAND_COMPATIBILITY - Errore comando COMPATIBILITY";
		case ECImap::COMMAND_APPEND:
			return "IMAP - COMMAND_APPEND - Errore comando APPEND";
		case ECImap::COMMAND_AUTH_PLAIN:
			return "IMAP - COMMAND_AUTH_PLAIN - Errore comando AUTH PLAIN";
		case ECImap::COMMAND_AUTH_LOGIN:
			return "IMAP - COMMAND_AUTH_LOGIN - Errore comando AUTH LOGIN";
		case ECImap::COMMAND_AUTH_CRAMMD5:
			return "IMAP - COMMAND_AUTH_CRAMMD5 - Errore comando AUTH CRAM-MD5";
		case ECImap::COMMAND_AUTH_DIGESTMD5:
			return "IMAP - COMMAND_AUTH_DIGESTMD5 - Errore comando AUTH DIGEST-MD5";
		case ECImap::COMMAND_DIGESTMD5:
			return "IMAP - COMMAND_DIGESTMD5 - Errore comando MD5 DIGEST";
		case ECImap::COMMAND_DATA:
			return "IMAP - COMMAND_DATA - Errore comando DATA";
		case ECImap::COMMAND_QUIT:
			return "IMAP - COMMAND_QUIT - Errore comando QUIT";
		case ECImap::COMMAND_RCPT_TO:
			return "IMAP - COMMAND_RCPT_TO - Errore comando RCPT TO";
		case ECImap::COMMAND_LOGOUT:
			return "IMAP - COMMAND_LOGOUT - Errore comando LOGOUT";
		case ECImap::COMMAND_FAILED:
			return "IMAP - COMMAND_FAILED - Comando fallito";
		case ECImap::COMMAND_SELECT:
			return "IMAP - COMMAND_SELECT - Comando fallito";
		case ECImap::MSG_BODY_ERROR:
			return "IMAP - MSG_BODY_ERROR - Errore nel testo della mail";
		case ECImap::CONNECTION_CLOSED:
			return "IMAP - CONNECTION_CLOSED - Il server ha chiuso la connessione";
		case ECImap::SERVER_NOT_READY:
			return "IMAP - SERVER_NOT_READY - Il server non è pronto";
		case ECImap::SERVER_NOT_RESPONDING:
			return "IMAP - SERVER_NOT_RESPONDING - Il server non risponde";
		case ECImap::SELECT_TIMEOUT:
			return "IMAP - SELECT_TIMEOUT - Timeout";
		case ECImap::FILE_NOT_EXIST:
			return "IMAP - FILE_NOT_EXIST - File non trovato";
		case ECImap::MSG_TOO_BIG:
			return "IMAP - MSG_TOO_BIG - Il messaggio supera il limite consentito di 5MB";
		case ECImap::BAD_LOGIN_PASS:
			return "IMAP - BAD_LOGIN_PASS - User o password errati";
		case ECImap::UNDEF_XYZ_RESPONSE:
			return "IMAP - UNDEF_XYZ_RESPONSE - Risposta xyz SMTP non definita";
		case ECImap::LACK_OF_MEMORY:
			return "IMAP - LACK_OF_MEMORY - Errore memoria";
		case ECImap::TIME_ERROR:
			return "IMAP - TIME_ERROR - Errore funzione time()";
		case ECImap::RECVBUF_IS_EMPTY:
			return "IMAP - RECVBUF_IS_EMPTY - Il buffer RecvBuf è vuoto";
		case ECImap::SENDBUF_IS_EMPTY:
			return "IMAP - SENDBUF_IS_EMPTY - Il buffer SendBuf è vuoto";
		case ECImap::OUT_OF_MSG_RANGE:
			return "IMAP - OUT_OF_MSG_RANGE - La linea corrente è fuori dalle dimensioni del messaggio";
		case ECImap::COMMAND_EHLO_STARTTLS:
			return "IMAP - COMMAND_EHLO_STARTTLS - Errore comando STARTTLS";
		case ECImap::SSL_PROBLEM:
			return "IMAP - SSL_PROBLEM - Errore SSL";
		case ECImap::COMMAND_DATABLOCK:
			return "IMAP - COMMAND_DATABLOCK - Errore invio blocco dati";
		case ECImap::STARTTLS_NOT_SUPPORTED:
			return "IMAP - STARTTLS_NOT_SUPPORTED - STARTTLS non supportato dal serverr";
		case ECImap::LOGIN_NOT_SUPPORTED:
			return "IMAP - LOGIN_NOT_SUPPORTED - AUTH LOGIN non supportato dal server";
		case ECImap::ERRNO_EPERM:
			return "IMAP - ERRNO_EPERM - Operation not permitted";
		case ECImap::ERRNO_ENOENT:
			return "IMAP - ERRNO_EPERM - No such file or directory";
		case ECImap::ERRNO_ESRCH:
			return "IMAP - ERRNO_ESRCH - No such process";
		case ECImap::ERRNO_EINTR:
			return "IMAP - ERRNO_EINTR - Interrupted function";
		case ECImap::ERRNO_EIO:
			return "IMAP - ERRNO_EIO - I/O error";
		case ECImap::ERRNO_ENXIO:
			return "IMAP - ERRNO_ENXIO - No such device or address";
		case ECImap::ERRNO_E2BIG:
			return "IMAP - ERRNO_E2BIG - Argument list too long";
		case ECImap::ERRNO_ENOEXEC:
			return "IMAP - ERRNO_ENOEXEC - Exec format error";
		case ECImap::ERRNO_EBADF:
			return "IMAP - ERRNO_EBADF - Bad file number";
		case ECImap::ERRNO_ECHILD:
			return "IMAP - ERRNO_ECHILD - No spawned processes";
		case ECImap::ERRNO_EAGAIN:
			return "IMAP - ERRNO_EAGAIN - No more processes or not enough memory or maximum nesting level reached";
		case ECImap::ERRNO_ENOMEM:
			return "IMAP - ERRNO_ENOMEM - Not enough memory";
		case ECImap::ERRNO_EACCES:
			return "IMAP - ERRNO_EACCES - Permission denied";
		case ECImap::ERRNO_EFAULT:
			return "IMAP - ERRNO_EFAULT - Bad address";
		case ECImap::ERRNO_EBUSY:
			return "IMAP - ERRNO_EBUSY - Device or resource busy";
		case ECImap::ERRNO_EEXIST:
			return "IMAP - ERRNO_EEXIST - File exists";
		case ECImap::ERRNO_EXDEV:
			return "IMAP - ERRNO_EXDEV - Cross-device link";
		case ECImap::ERRNO_ENODEV:
			return "IMAP - ERRNO_ENODEV - No such device";
		case ECImap::ERRNO_ENOTDIR:
			return "IMAP - ERRNO_ENOTDIR - Not a directory";
		case ECImap::ERRNO_EISDIR:
			return "IMAP - ERRNO_EISDIR - Is a directory";
		case ECImap::ERRNO_EINVAL:
			return "IMAP - ERRNO_EINVAL - Invalid argument";
		case ECImap::ERRNO_ENFILE:
			return "IMAP - ERRNO_ENFILE - Too many files open in system";
		case ECImap::ERRNO_EMFILE:
			return "IMAP - ERRNO_EMFILE - Too many open files";
		case ECImap::ERRNO_ENOTTY:
			return "IMAP - ERRNO_ENOTTY - Inappropriate I/O control operation";
		case ECImap::ERRNO_EFBIG:
			return "IMAP - ERRNO_EFBIG - File too large";
		case ECImap::ERRNO_ENOSPC:
			return "IMAP - ERRNO_ENOSPC - No space left on device";
		case ECImap::ERRNO_ESPIPE:
			return "IMAP - ERRNO_ESPIPE - Invalid seek";
		case ECImap::ERRNO_EROFS:
			return "IMAP - ERRNO_EROFS - Read-only file system";
		case ECImap::ERRNO_EMLINK:
			return "IMAP - ERRNO_EMLINK - Too many links";
		case ECImap::ERRNO_EPIPE:
			return "IMAP - ERRNO_EPIPE - Broken pipe";
		case ECImap::ERRNO_EDOM:
			return "IMAP - ERRNO_EDOM - Math argument";
		case ECImap::ERRNO_ERANGE:
			return "IMAP - ERRNO_ERANGE - Result too large";
		case ECImap::ERRNO_EDEADLK:
			return "IMAP - ERRNO_EDEADLK - Resource deadlock would occur";
		case ECImap::ERRNO_ENAMETOOLONG:
			return "IMAP - ERRNO_ENAMETOOLONG - Filename too long";
		case ECImap::ERRNO_ENOLCK:
			return "IMAP - ERRNO_ENOLCK - No locks available";
		case ECImap::ERRNO_ENOSYS:
			return "IMAP - ERRNO_ENOSYS - Function not supported";
		case ECImap::ERRNO_ENOTEMPTY:
			return "IMAP - ERRNO_ENOTEMPTY - Directory not empty";
		case ECImap::ERRNO_EILSEQ:
			return "IMAP - ERRNO_EILSEQ - Illegal byte sequence";
		case ECImap::ERRNO_STRUNCATE:
			return "IMAP - ERRNO_STRUNCATE - String was truncated";
		default:
			return "IMAP - Undefined error Id";
	}
}