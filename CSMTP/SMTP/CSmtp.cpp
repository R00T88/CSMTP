////////////////////////////////////////////////////////////////////////////////
// SMTP Class
////////////////////////////////////////////////////////////////////////////////

#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>

#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include "CSmtp.h"

#include "..\\Security\base64.h"

// OpenSSL 1.0.2h
#include "openssl/err.h"
#include "openssl/md5.h"

#include <cassert>

// OpenSSL 1.0.2h - /MT
#pragma comment(lib, "ssleay32.lib")
#pragma comment(lib, "libeay32.lib")

Command_Entry command_list[] = 
{
	{command_INIT,          0,     5*60,  220, ECSmtp::SERVER_NOT_RESPONDING},
	{command_EHLO,          5*60,  5*60,  250, ECSmtp::COMMAND_EHLO},
	{command_AUTHPLAIN,     5*60,  5*60,  235, ECSmtp::COMMAND_AUTH_PLAIN},
	{command_AUTHLOGIN,     5*60,  5*60,  334, ECSmtp::COMMAND_AUTH_LOGIN},
	{command_AUTHCRAMMD5,   5*60,  5*60,  334, ECSmtp::COMMAND_AUTH_CRAMMD5},
	{command_AUTHDIGESTMD5, 5*60,  5*60,  334, ECSmtp::COMMAND_AUTH_DIGESTMD5},
	{command_DIGESTMD5,     5*60,  5*60,  335, ECSmtp::COMMAND_DIGESTMD5},
	{command_USER,          5*60,  5*60,  334, ECSmtp::UNDEF_XYZ_RESPONSE},
	{command_PASSWORD,      5*60,  5*60,  235, ECSmtp::BAD_LOGIN_PASS},
	{command_MAILFROM,      5*60,  5*60,  250, ECSmtp::COMMAND_MAIL_FROM},
	{command_RCPTTO,        5*60,  5*60,  250, ECSmtp::COMMAND_RCPT_TO},
	{command_DATA,          5*60,  2*60,  354, ECSmtp::COMMAND_DATA},
	{command_DATABLOCK,     3*60,  0,     0,   ECSmtp::COMMAND_DATABLOCK},	// Here the valid_reply_code is set to zero because there are no replies when sending data blocks
	{command_DATAEND,       3*60,  10*60, 250, ECSmtp::MSG_BODY_ERROR},
	{command_QUIT,          5*60,  5*60,  221, ECSmtp::COMMAND_QUIT},
	{command_STARTTLS,      5*60,  5*60,  220, ECSmtp::COMMAND_EHLO_STARTTLS}
};

Smtp_Content_Type Smtp_content_list[] = 
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

char* Smtp_FindContentType(char* FileExt)
{
	for(size_t i = 0; i < sizeof(Smtp_content_list)/sizeof(Smtp_content_list[0]); ++i)
	{
		if(strcmp(Smtp_content_list[i].FileExt, FileExt) == 0)
		{
			return Smtp_content_list[i].FileExtContent;
		}
	}

	return "application/octet-stream";
}

Command_Entry* FindCommandEntry(SMTP_COMMAND command)
{
	Command_Entry* pEntry = NULL;
	for(size_t i = 0; i < sizeof(command_list)/sizeof(command_list[0]); ++i)
	{
		if(command_list[i].command == command)
		{
			pEntry = &command_list[i];
			break;
		}
	}
	assert(pEntry != NULL);
	return pEntry;
}

// A simple string match
bool IsKeywordSupported(const char* response, const char* keyword)
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
//        NAME: CSmtp
// DESCRIPTION: Constructor of CSmtp class.
//   ARGUMENTS: none
// USES GLOBAL: none
// MODIFIES GL: m_iXPriority, m_iSMTPSrvPort, RecvBuf, SendBuf
//     RETURNS: none
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013							
////////////////////////////////////////////////////////////////////////////////
CSmtp::CSmtp()
{
	hSocket = INVALID_SOCKET;
	m_bConnected = false;
	m_iXPriority = XPRIORITY_NORMAL;
	m_iSMTPSrvPort = 0;
	m_bAuthenticate = true;

	// Initialize WinSock
	WSADATA wsaData;
	WORD wVer = MAKEWORD(2, 2);    
	
	if (WSAStartup(wVer, &wsaData) != NO_ERROR)
		throw ECSmtp(ECSmtp::WSA_STARTUP);

	if (LOBYTE( wsaData.wVersion ) != 2 || HIBYTE( wsaData.wVersion ) != 2 ) 
	{
		WSACleanup();
		throw ECSmtp(ECSmtp::WSA_VER);
	}

	char* hostname;
	
	if((hostname = new  char[MAX_PATH]) == NULL)
		throw ECSmtp(ECSmtp::LACK_OF_MEMORY);

	if(gethostname(hostname, MAX_PATH) == SOCKET_ERROR) 
		throw ECSmtp(ECSmtp::WSA_HOSTNAME);
	
	m_sLocalHostName = hostname;
	
	delete[] hostname;
	hostname = NULL;

	if((RecvBuf = new char[BUFFER_SIZE]) == NULL)
		throw ECSmtp(ECSmtp::LACK_OF_MEMORY);
	
	if((SendBuf = new char[BUFFER_SIZE]) == NULL)
		throw ECSmtp(ECSmtp::LACK_OF_MEMORY);

	if((szMsgId= new char[BUFFER_MSGID_SIZE]) == NULL)
		throw ECSmtp(ECSmtp::LACK_OF_MEMORY);

	m_type = NO_SECURITY;
	m_ctx = NULL;
	m_ssl = NULL;
	m_bHTML = false;
	m_bReadReceipt = false;

	m_sCharSet = "utf-8";
	m_sCharEncoding = "8bit";

	m_sXMailer = "v5.0";

	dwNumChar = 0;
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: CSmtp
// DESCRIPTION: Destructor of CSmtp class.
//   ARGUMENTS: none
// USES GLOBAL: RecvBuf, SendBuf
// MODIFIES GL: RecvBuf, SendBuf
//     RETURNS: none
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013							
////////////////////////////////////////////////////////////////////////////////
CSmtp::~CSmtp()
{
	if(m_bConnected) 
		DisconnectRemoteServer();

	if(SendBuf != NULL)
	{
		delete[] SendBuf;
		SendBuf = NULL;
	}

	if(RecvBuf != NULL)
	{
		delete[] RecvBuf;
		RecvBuf = NULL;
	}

	if(szMsgId != NULL)
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
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013						
////////////////////////////////////////////////////////////////////////////////
void CSmtp::AddAttachment(const char *Path)
{
	assert(Path);
	Attachments.insert(Attachments.end(), Path);
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: AddAttachmentName
// DESCRIPTION: New attachment name is added.
//   ARGUMENTS: const char *Path - file name of attachment added
// USES GLOBAL: AttachmentsName
// MODIFIES GL: AttachmentsName
//     RETURNS: void
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 21-11-2014						
////////////////////////////////////////////////////////////////////////////////
void CSmtp::AddAttachmentName(const char *Path)
{
	assert(Path);
	AttachmentsName.insert(AttachmentsName.end(), Path);
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: AddRecipient
// DESCRIPTION: New recipient data is added i.e.: email and name. .
//   ARGUMENTS: const char *email - mail of the recipient
//              const char *name - name of the recipient
// USES GLOBAL: Recipients
// MODIFIES GL: Recipients
//     RETURNS: void
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013						
////////////////////////////////////////////////////////////////////////////////
void CSmtp::AddRecipient(const char *email, const char *name)
{	
	if(!email)
		throw ECSmtp(ECSmtp::UNDEF_RECIPIENT_MAIL);

	Recipient recipient;
	
	recipient.Mail = email;

	if (name != NULL)
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
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013							
////////////////////////////////////////////////////////////////////////////////
void CSmtp::AddCCRecipient(const char *email, const char *name)
{	
	if(!email)
		throw ECSmtp(ECSmtp::UNDEF_RECIPIENT_MAIL);

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
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013							
////////////////////////////////////////////////////////////////////////////////
void CSmtp::AddBCCRecipient(const char *email, const char *name)
{	
	if(!email)
		throw ECSmtp(ECSmtp::UNDEF_RECIPIENT_MAIL);

	Recipient recipient;
	
	recipient.Mail = email;
	
	if(name != NULL) 
		recipient.Name = name;
	else 
		recipient.Name.clear();

	BCCRecipients.insert(BCCRecipients.end(), recipient);
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: AddMsgLine
// DESCRIPTION: Adds new line in a message.
//   ARGUMENTS: const char *Text - text of the new line
// USES GLOBAL: MsgBody
// MODIFIES GL: MsgBody
//     RETURNS: void
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013						
////////////////////////////////////////////////////////////////////////////////
void CSmtp::AddMsgLine(const char* Text)
{
	MsgBody.insert(MsgBody.end(), Text);
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: DelMsgLine
// DESCRIPTION: Deletes specified line in text message.. .
//   ARGUMENTS: unsigned int Line - line to be delete
// USES GLOBAL: MsgBody
// MODIFIES GL: MsgBody
//     RETURNS: void
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013						
////////////////////////////////////////////////////////////////////////////////
void CSmtp::DelMsgLine(unsigned int Line)
{
	if(Line >= MsgBody.size())
		throw ECSmtp(ECSmtp::OUT_OF_MSG_RANGE);

	MsgBody.erase(MsgBody.begin() + Line);
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: DelRecipients
// DESCRIPTION: Deletes all recipients. .
//   ARGUMENTS: void
// USES GLOBAL: Recipients
// MODIFIES GL: Recipients
//     RETURNS: void
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013						
////////////////////////////////////////////////////////////////////////////////
void CSmtp::DelRecipients()
{
	Recipients.clear();
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: DelBCCRecipients
// DESCRIPTION: Deletes all BCC recipients. .
//   ARGUMENTS: void
// USES GLOBAL: BCCRecipients
// MODIFIES GL: BCCRecipients
//     RETURNS: void
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013						
////////////////////////////////////////////////////////////////////////////////
void CSmtp::DelBCCRecipients()
{
	BCCRecipients.clear();
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: DelCCRecipients
// DESCRIPTION: Deletes all CC recipients. .
//   ARGUMENTS: void
// USES GLOBAL: CCRecipients
// MODIFIES GL: CCRecipients
//     RETURNS: void
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013					
////////////////////////////////////////////////////////////////////////////////
void CSmtp::DelCCRecipients()
{
	CCRecipients.clear();
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: DelMsgLines
// DESCRIPTION: Deletes message text.
//   ARGUMENTS: void
// USES GLOBAL: MsgBody
// MODIFIES GL: MsgBody
//     RETURNS: void
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013
////////////////////////////////////////////////////////////////////////////////
void CSmtp::DelMsgLines()
{
	MsgBody.clear();
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: DelAttachments
// DESCRIPTION: Deletes all recipients. .
//   ARGUMENTS: void
// USES GLOBAL: Attchments
// MODIFIES GL: Attachments
//     RETURNS: void
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013							
////////////////////////////////////////////////////////////////////////////////
void CSmtp::DelAttachments()
{
	Attachments.clear();
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: AddBCCRecipient
// DESCRIPTION: New bcc-recipient data is added i.e.: email and name. .
//   ARGUMENTS: const char *email - mail of the bcc-recipient
//              const char *name - name of the bccc-recipient
// USES GLOBAL: BCCRecipients
// MODIFIES GL: BCCRecipients, m_oError
//     RETURNS: void
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013						
////////////////////////////////////////////////////////////////////////////////
void CSmtp::ModMsgLine(unsigned int Line,const char* Text)
{
	if(Text != NULL)
	{
		if(Line >= MsgBody.size())
			throw ECSmtp(ECSmtp::OUT_OF_MSG_RANGE);

		MsgBody.at(Line) = std::string(Text);
	}
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: Send
// DESCRIPTION: Sending the mail. .
//   ARGUMENTS: none
// USES GLOBAL: m_sSMTPSrvName, m_iSMTPSrvPort, SendBuf, RecvBuf, m_sLogin,
//              m_sPassword, m_sMailFrom, Recipients, CCRecipients,
//              BCCRecipients, m_sMsgBody, Attachments, 
// MODIFIES GL: SendBuf 
//     RETURNS: void
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013					
////////////////////////////////////////////////////////////////////////////////
void CSmtp::Send()
{
	unsigned int i, rcpt_count, res, FileId;
	char* FileBuf = NULL;
	char* FileName = NULL;
	FILE* hFile = NULL;
	unsigned long int FileSize, TotalSize, MsgPart;
	errno_t err;

	// ***** CONNECTING TO SMTP SERVER *****

	// connecting to remote host if not already connected:
	if(hSocket == INVALID_SOCKET)
	{
		if(!ConnectRemoteServer(m_sSMTPSrvName.c_str(), m_iSMTPSrvPort, m_type, m_bAuthenticate))
			throw ECSmtp(ECSmtp::WSA_INVALID_SOCKET);
	}

	try
	{
		// Allocate Memory
		if((FileBuf = new char[55]) == NULL)
			throw ECSmtp(ECSmtp::LACK_OF_MEMORY);

		if((FileName = new char[MAX_PATH]) == NULL)
			throw ECSmtp(ECSmtp::LACK_OF_MEMORY);

		//Check that any attachments specified can be opened
		TotalSize = 0;

		for(FileId = 0; FileId < Attachments.size(); FileId++)
		{
			sprintf_s(FileName, MAX_PATH, "%s", Attachments[FileId].c_str());

			// Opening the file:
			err = fopen_s(&hFile, FileName, "rb");
			
			// Error checking
			if(err != NULL)
			{
				if(err == EPERM)
					throw ECSmtp(ECSmtp::ERRNO_EPERM);
				else if(err == ENOENT)
					throw ECSmtp(ECSmtp::ERRNO_ENOENT);
				else if(err == ESRCH)
					throw ECSmtp(ECSmtp::ERRNO_ESRCH);
				else if(err == EINTR)
					throw ECSmtp(ECSmtp::ERRNO_EINTR);
				else if(err == EIO)
					throw ECSmtp(ECSmtp::ERRNO_EIO);
				else if(err == ENXIO)
					throw ECSmtp(ECSmtp::ERRNO_ENXIO);
				else if(err == E2BIG)
					throw ECSmtp(ECSmtp::ERRNO_E2BIG);
				else if(err == ENOEXEC)
					throw ECSmtp(ECSmtp::ERRNO_ENOEXEC);
				else if(err == EBADF)
					throw ECSmtp(ECSmtp::ERRNO_EBADF);
				else if(err == ECHILD)
					throw ECSmtp(ECSmtp::ERRNO_ECHILD);
				else if(err == EAGAIN)
					throw ECSmtp(ECSmtp::ERRNO_EAGAIN);
				else if(err == ENOMEM)
					throw ECSmtp(ECSmtp::ERRNO_ENOMEM);
				else if(err == EACCES)
					throw ECSmtp(ECSmtp::ERRNO_EACCES);
				else if(err == EFAULT)
					throw ECSmtp(ECSmtp::ERRNO_EFAULT);
				else if(err == EBUSY)
					throw ECSmtp(ECSmtp::ERRNO_EBUSY);
				else if(err == EEXIST)
					throw ECSmtp(ECSmtp::ERRNO_EEXIST);
				else if(err == EXDEV)
					throw ECSmtp(ECSmtp::ERRNO_EXDEV);
				else if(err == ENODEV)
					throw ECSmtp(ECSmtp::ERRNO_ENODEV);
				else if(err == ENOTDIR)
					throw ECSmtp(ECSmtp::ERRNO_ENOTDIR);
				else if(err == EISDIR)
					throw ECSmtp(ECSmtp::ERRNO_EISDIR);
				else if(err == EINVAL)
					throw ECSmtp(ECSmtp::ERRNO_EINVAL);
				else if(err == ENFILE)
					throw ECSmtp(ECSmtp::ERRNO_ENFILE);
				else if(err == EMFILE)
					throw ECSmtp(ECSmtp::ERRNO_EMFILE);
				else if(err == ENOTTY)
					throw ECSmtp(ECSmtp::ERRNO_ENOTTY);
				else if(err == EFBIG)
					throw ECSmtp(ECSmtp::ERRNO_EFBIG);
				else if(err == ENOSPC)
					throw ECSmtp(ECSmtp::ERRNO_ENOSPC);
				else if(err == ESPIPE)
					throw ECSmtp(ECSmtp::ERRNO_ESPIPE);
				else if(err == EROFS)
					throw ECSmtp(ECSmtp::ERRNO_EROFS);
				else if(err == EMLINK)
					throw ECSmtp(ECSmtp::ERRNO_EMLINK);
				else if(err == EPIPE)
					throw ECSmtp(ECSmtp::ERRNO_EPIPE);
				else if(err == EDOM)
					throw ECSmtp(ECSmtp::ERRNO_EDOM);
				else if(err == ERANGE)
					throw ECSmtp(ECSmtp::ERRNO_ERANGE);
				else if(err == EDEADLK)
					throw ECSmtp(ECSmtp::ERRNO_EDEADLK);
				else if(err == ENAMETOOLONG)
					throw ECSmtp(ECSmtp::ERRNO_ENAMETOOLONG);
				else if(err == ENOLCK)
					throw ECSmtp(ECSmtp::ERRNO_ENOLCK);
				else if(err == ENOSYS)
					throw ECSmtp(ECSmtp::ERRNO_ENOSYS);
				else if(err == ENOTEMPTY)
					throw ECSmtp(ECSmtp::ERRNO_ENOTEMPTY);
				else if(err == EILSEQ)
					throw ECSmtp(ECSmtp::ERRNO_EILSEQ);
				else if(err == STRUNCATE)
					throw ECSmtp(ECSmtp::ERRNO_STRUNCATE);
				else
					throw ECSmtp(ECSmtp::FILE_NOT_EXIST);
			}
			
			// Checking file size:
			FileSize = 0;
			
			fseek(hFile, 0, SEEK_END);
			FileSize = ftell(hFile);
			TotalSize += FileSize;

			fclose(hFile);

			// Check TotalSize
			if((TotalSize / 1024.) > (MSG_SIZE_IN_MB * 1024.))
				throw ECSmtp(ECSmtp::MSG_TOO_BIG);
		}

		// ***** SENDING E-MAIL *****
		
		// MAIL <SP> FROM:<reverse-path> <CRLF>
		if(!m_sMailFrom.size())
			throw ECSmtp(ECSmtp::UNDEF_MAIL_FROM);

		Command_Entry* pEntry = FindCommandEntry(command_MAILFROM);
		sprintf_s(SendBuf, BUFFER_SIZE, "MAIL FROM:<%s>\r\n", m_sMailFrom.c_str());
		SendData(pEntry);
		ReceiveResponse(pEntry);

		// RCPT <SP> TO:<forward-path> <CRLF>
		if(!(rcpt_count = static_cast<unsigned int>(Recipients.size())))
			throw ECSmtp(ECSmtp::UNDEF_RECIPIENTS);
		
		pEntry = FindCommandEntry(command_RCPTTO);
		
		for(i = 0; i < Recipients.size(); i++)
		{
			sprintf_s(SendBuf, BUFFER_SIZE, "RCPT TO:<%s>\r\n", (Recipients.at(i).Mail).c_str());
			SendData(pEntry);
			ReceiveResponse(pEntry);
		}

		for(i = 0; i < CCRecipients.size(); i++)
		{
			sprintf_s(SendBuf, BUFFER_SIZE, "RCPT TO:<%s>\r\n", (CCRecipients.at(i).Mail).c_str());
			SendData(pEntry);
			ReceiveResponse(pEntry);
		}

		for(i = 0; i < BCCRecipients.size(); i++)
		{
			sprintf_s(SendBuf, BUFFER_SIZE, "RCPT TO:<%s>\r\n", (BCCRecipients.at(i).Mail).c_str());
			SendData(pEntry);
			ReceiveResponse(pEntry);
		}
		
		pEntry = FindCommandEntry(command_DATA);
		// DATA <CRLF>
		strcpy_s(SendBuf, BUFFER_SIZE, "DATA\r\n");
		SendData(pEntry);
		ReceiveResponse(pEntry);
		
		dwNumChar = 0;

		pEntry = FindCommandEntry(command_DATABLOCK);
		// send header(s)
		FormatHeader(SendBuf);
		SendData(pEntry);
		dwNumChar+=strlen(SendBuf);

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

					while(Offset<(dwSize - 1))
					{
						strncpy_s(SendBuf, BUFFER_SIZE, ResultLine + Offset, BUFFER_SIZE / 2);
						SendBuf[BUFFER_SIZE / 2] = '\0';
						SendData(pEntry);
						dwNumChar+=strlen(SendBuf);
						Offset+=BUFFER_SIZE / 2;
					}

					strcpy_s(SendBuf, BUFFER_SIZE, "\r\n");
					SendData(pEntry);
					dwNumChar+=strlen(SendBuf);
				}
				else
				{
					sprintf_s(SendBuf, BUFFER_SIZE, "%s\r\n", ResultLine);
					SendData(pEntry);
					dwNumChar+=strlen(SendBuf);
				}
			}
		}
		else
		{
			sprintf_s(SendBuf, BUFFER_SIZE, "%s\r\n", " ");
			SendData(pEntry);
			dwNumChar+=strlen(SendBuf);
		}

		// send html text
		if(m_bHTML)
		{
			MsgBody.clear();
			MsgBody.insert(MsgBody.end(), MsgBodyHTML.c_str());
			
			sprintf_s(SendBuf, BUFFER_SIZE, "\r\n");
			strcat_s(SendBuf, BUFFER_SIZE, "--");
			strcat_s(SendBuf, BUFFER_SIZE, SMTP_BOUNDARY_ALTERNATIVE);
			strcat_s(SendBuf, BUFFER_SIZE, "\r\n");

			strcat_s(SendBuf, BUFFER_SIZE, "Content-Type: text/html; charset=");
			strcat_s(SendBuf, BUFFER_SIZE, m_sCharSet.c_str());
			strcat_s(SendBuf, BUFFER_SIZE, "\r\n");
			strcat_s(SendBuf, BUFFER_SIZE, "Content-Transfer-Encoding: ");
			strcat_s(SendBuf, BUFFER_SIZE, m_sCharEncoding.c_str());
			strcat_s(SendBuf, BUFFER_SIZE, "\r\n");
			strcat_s(SendBuf, BUFFER_SIZE, "\r\n");

			SendData(pEntry);
			dwNumChar+=strlen(SendBuf);

			if(GetMsgLines())
			{
				for(i = 0; i < GetMsgLines(); i++)
				{
					ResultLine = GetMsgLineText(i);
					int dwSize = static_cast<int>(strlen(ResultLine));
					int Offset = 0;

					if(dwSize >= BUFFER_SIZE / 2)
					{
						int dwIndex = 0;

						while(Offset < (dwSize - 1))
						{
							strncpy_s(SendBuf, BUFFER_SIZE, ResultLine + Offset, BUFFER_SIZE / 2);
							SendBuf[BUFFER_SIZE / 2] = '\0';
							SendData(pEntry);
							dwNumChar+=strlen(SendBuf);
							Offset+=BUFFER_SIZE / 2;
						}

						strcpy_s(SendBuf, BUFFER_SIZE, "\r\n");
						SendData(pEntry);
						dwNumChar+=strlen(SendBuf);
					}
					else
					{
						sprintf_s(SendBuf, BUFFER_SIZE, "%s\r\n", ResultLine);
						SendData(pEntry);
						dwNumChar+=strlen(SendBuf);
					}
				}
			}
			else
			{
				sprintf_s(SendBuf, BUFFER_SIZE, "%s\r\n", " ");
				SendData(pEntry);
				dwNumChar+=strlen(SendBuf);
			}

			sprintf_s(SendBuf, BUFFER_SIZE, "\r\n");
			strcat_s(SendBuf, BUFFER_SIZE, "--");
			strcat_s(SendBuf, BUFFER_SIZE, SMTP_BOUNDARY_ALTERNATIVE);
			strcat_s(SendBuf, BUFFER_SIZE, "--\r\n");

			SendData(pEntry);
			dwNumChar+=strlen(SendBuf);
		}

		sprintf_s(SendBuf, BUFFER_SIZE, "\r\n");
		SendData(pEntry);
		dwNumChar+=strlen(SendBuf);

		TotalSize = 0;
		
		for(FileId = 0; FileId < Attachments.size(); FileId++)
		{
			sprintf_s(FileName, MAX_PATH, "%s", Attachments[FileId].c_str());

			sprintf_s(SendBuf, BUFFER_SIZE, "--%s\r\n", SMTP_BOUNDARY_MIXED);

			char* FileExt = NULL;

			FileExt = strrchr(&FileName[Attachments[FileId].find_last_of("\\") + 1], '.');

			if(FileExt != NULL)
			{
				strcat_s(SendBuf, BUFFER_SIZE, "Content-Type: ");
				strcat_s(SendBuf, BUFFER_SIZE, Smtp_FindContentType(FileExt));
				strcat_s(SendBuf, BUFFER_SIZE, ";\r\n\tname=\"");
			}
			else
				strcat_s(SendBuf, BUFFER_SIZE, "Content-Type: application/octet-stream;\r\n\tname=\"");

			FileExt = NULL;

			if(AttachmentsName.size() > FileId)
				strcat_s(SendBuf, BUFFER_SIZE, AttachmentsName[FileId].c_str());
			else
				strcat_s(SendBuf, BUFFER_SIZE, &FileName[Attachments[FileId].find_last_of("\\") + 1]);

			strcat_s(SendBuf, BUFFER_SIZE, "\"\r\n");
			strcat_s(SendBuf, BUFFER_SIZE, "Content-Transfer-Encoding: base64\r\n");
			strcat_s(SendBuf, BUFFER_SIZE, "Content-Disposition: attachment;\r\n\tfilename=\"");

			if(AttachmentsName.size() > FileId)
				strcat_s(SendBuf, BUFFER_SIZE, AttachmentsName[FileId].c_str());
			else
				strcat_s(SendBuf, BUFFER_SIZE, &FileName[Attachments[FileId].find_last_of("\\") + 1]);

			strcat_s(SendBuf, BUFFER_SIZE, "\"\r\n");
			strcat_s(SendBuf, BUFFER_SIZE, "\r\n");

			SendData(pEntry);
			dwNumChar+=strlen(SendBuf);

			// opening the file
			err = fopen_s(&hFile, FileName, "rb");

			if(err != NULL)
			{
				if(err == EPERM)
					throw ECSmtp(ECSmtp::ERRNO_EPERM);
				else if(err == ENOENT)
					throw ECSmtp(ECSmtp::ERRNO_ENOENT);
				else if(err == ESRCH)
					throw ECSmtp(ECSmtp::ERRNO_ESRCH);
				else if(err == EINTR)
					throw ECSmtp(ECSmtp::ERRNO_EINTR);
				else if(err == EIO)
					throw ECSmtp(ECSmtp::ERRNO_EIO);
				else if(err == ENXIO)
					throw ECSmtp(ECSmtp::ERRNO_ENXIO);
				else if(err == E2BIG)
					throw ECSmtp(ECSmtp::ERRNO_E2BIG);
				else if(err == ENOEXEC)
					throw ECSmtp(ECSmtp::ERRNO_ENOEXEC);
				else if(err == EBADF)
					throw ECSmtp(ECSmtp::ERRNO_EBADF);
				else if(err == ECHILD)
					throw ECSmtp(ECSmtp::ERRNO_ECHILD);
				else if(err == EAGAIN)
					throw ECSmtp(ECSmtp::ERRNO_EAGAIN);
				else if(err == ENOMEM)
					throw ECSmtp(ECSmtp::ERRNO_ENOMEM);
				else if(err == EACCES)
					throw ECSmtp(ECSmtp::ERRNO_EACCES);
				else if(err == EFAULT)
					throw ECSmtp(ECSmtp::ERRNO_EFAULT);
				else if(err == EBUSY)
					throw ECSmtp(ECSmtp::ERRNO_EBUSY);
				else if(err == EEXIST)
					throw ECSmtp(ECSmtp::ERRNO_EEXIST);
				else if(err == EXDEV)
					throw ECSmtp(ECSmtp::ERRNO_EXDEV);
				else if(err == ENODEV)
					throw ECSmtp(ECSmtp::ERRNO_ENODEV);
				else if(err == ENOTDIR)
					throw ECSmtp(ECSmtp::ERRNO_ENOTDIR);
				else if(err == EISDIR)
					throw ECSmtp(ECSmtp::ERRNO_EISDIR);
				else if(err == EINVAL)
					throw ECSmtp(ECSmtp::ERRNO_EINVAL);
				else if(err == ENFILE)
					throw ECSmtp(ECSmtp::ERRNO_ENFILE);
				else if(err == EMFILE)
					throw ECSmtp(ECSmtp::ERRNO_EMFILE);
				else if(err == ENOTTY)
					throw ECSmtp(ECSmtp::ERRNO_ENOTTY);
				else if(err == EFBIG)
					throw ECSmtp(ECSmtp::ERRNO_EFBIG);
				else if(err == ENOSPC)
					throw ECSmtp(ECSmtp::ERRNO_ENOSPC);
				else if(err == ESPIPE)
					throw ECSmtp(ECSmtp::ERRNO_ESPIPE);
				else if(err == EROFS)
					throw ECSmtp(ECSmtp::ERRNO_EROFS);
				else if(err == EMLINK)
					throw ECSmtp(ECSmtp::ERRNO_EMLINK);
				else if(err == EPIPE)
					throw ECSmtp(ECSmtp::ERRNO_EPIPE);
				else if(err == EDOM)
					throw ECSmtp(ECSmtp::ERRNO_EDOM);
				else if(err == ERANGE)
					throw ECSmtp(ECSmtp::ERRNO_ERANGE);
				else if(err == EDEADLK)
					throw ECSmtp(ECSmtp::ERRNO_EDEADLK);
				else if(err == ENAMETOOLONG)
					throw ECSmtp(ECSmtp::ERRNO_ENAMETOOLONG);
				else if(err == ENOLCK)
					throw ECSmtp(ECSmtp::ERRNO_ENOLCK);
				else if(err == ENOSYS)
					throw ECSmtp(ECSmtp::ERRNO_ENOSYS);
				else if(err == ENOTEMPTY)
					throw ECSmtp(ECSmtp::ERRNO_ENOTEMPTY);
				else if(err == EILSEQ)
					throw ECSmtp(ECSmtp::ERRNO_EILSEQ);
				else if(err == STRUNCATE)
					throw ECSmtp(ECSmtp::ERRNO_STRUNCATE);
				else
					throw ECSmtp(ECSmtp::FILE_NOT_EXIST);
			}
			
			// checking file size
			FileSize = 0;

			fseek(hFile, 0, SEEK_END);
			FileSize = ftell(hFile);
			fseek (hFile, 0, SEEK_SET);

			// sending the file
			MsgPart = 0;
				
			for(i = 0; i < FileSize / SMTP_BYTE_SIZE_FILE + 1; i++)
			{
				res = static_cast<unsigned int>(fread(FileBuf, sizeof(char), SMTP_BYTE_SIZE_FILE, hFile));
				MsgPart ? strcat_s(SendBuf, BUFFER_SIZE, base64_encode(reinterpret_cast<const unsigned char*>(FileBuf), res).c_str())
						  : strcpy_s(SendBuf, BUFFER_SIZE, base64_encode(reinterpret_cast<const unsigned char*>(FileBuf), res).c_str());
				strcat_s(SendBuf, BUFFER_SIZE, "\r\n");
				MsgPart += res + 2;
				if(MsgPart >= (BUFFER_SIZE / 2))
				{ // sending part of the message
					MsgPart = 0;
					SendData(pEntry);
					dwNumChar+=strlen(SendBuf);
				}
			}

			if(MsgPart)
			{
				SendData(pEntry);
				dwNumChar+=strlen(SendBuf);
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
			sprintf_s(SendBuf, BUFFER_SIZE, "\r\n--%s--\r\n", SMTP_BOUNDARY_MIXED);
			SendData(pEntry);
			dwNumChar+=strlen(SendBuf);
		}
		
		pEntry = FindCommandEntry(command_DATAEND);
		// <CRLF> . <CRLF>
		strcpy_s(SendBuf, BUFFER_SIZE, "\r\n.\r\n");
		SendData(pEntry);
		dwNumChar+=(strlen(SendBuf)-1);
		ReceiveResponse(pEntry);
	}
	catch(const ECSmtp&)
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
// USES GLOBAL: m_pcSMTPSrvName, m_iSMTPSrvPort, SendBuf, RecvBuf, m_pcLogin,
//              m_pcPassword, m_pcMailFrom, Recipients, CCRecipients,
//              BCCRecipients, m_pcMsgBody, Attachments, 
// MODIFIES GL: m_oError 
//     RETURNS: socket of the remote service
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013
////////////////////////////////////////////////////////////////////////////////
bool CSmtp::ConnectRemoteServer(const char* szServer, const unsigned short nPort_/*=0*/, 
								SMTP_SECURITY_TYPE securityType/*=DO_NOT_SET*/,
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

		if((hSocket = socket(PF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
			throw ECSmtp(ECSmtp::WSA_INVALID_SOCKET);

		if(nPort_ != 0)
			nPort = htons(nPort_);
		else
		{
			lpServEnt = getservbyname("mail", 0);
			if (lpServEnt == NULL)
				nPort = htons(25);
			else 
				nPort = lpServEnt->s_port;
		}
				
		sockAddr.sin_family = AF_INET;
		sockAddr.sin_port = nPort;

		if((sockAddr.sin_addr.s_addr = inet_addr(szServer)) == INADDR_NONE)
		{			
			host = gethostbyname(szServer);
			if (host)
				memcpy(&sockAddr.sin_addr, host->h_addr_list[0], host->h_length);
			else
			{
				closesocket(hSocket);
				throw ECSmtp(ECSmtp::WSA_GETHOSTBY_NAME_ADDR);
			}				
		}

		// start non-blocking mode for socket:
		if(ioctlsocket(hSocket, FIONBIO, (unsigned long*)&ul) == SOCKET_ERROR)
		{
			closesocket(hSocket);
			throw ECSmtp(ECSmtp::WSA_IOCTLSOCKET);
		}

		if(connect(hSocket, (LPSOCKADDR)&sockAddr, sizeof(sockAddr)) == SOCKET_ERROR)
		{
			if(WSAGetLastError() != WSAEWOULDBLOCK)
			{
				closesocket(hSocket);
				throw ECSmtp(ECSmtp::WSA_CONNECT);
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
				throw ECSmtp(ECSmtp::WSA_SELECT);
			}

			if(!res)
			{
				closesocket(hSocket);
				throw ECSmtp(ECSmtp::SELECT_TIMEOUT);
			}
			if(res && FD_ISSET(hSocket, &fdwrite))
				break;
			if(res && FD_ISSET(hSocket, &fdexcept))
			{
				closesocket(hSocket);
				throw ECSmtp(ECSmtp::WSA_SELECT);
			}
		} // while

		FD_CLR(hSocket, &fdwrite);
		FD_CLR(hSocket, &fdexcept);

		if(securityType != DO_NOT_SET) SetSecurityType(securityType);
		if(GetSecurityType() == USE_TLS || GetSecurityType() == USE_SSL)
		{
			InitOpenSSL();
			if(GetSecurityType() == USE_SSL)
			{
				OpenSSLConnect();
			}
		}

		Command_Entry* pEntry = FindCommandEntry(command_INIT);
		ReceiveResponse(pEntry);

		SayHello();

		if(GetSecurityType() == USE_TLS)
		{
			StartTls();
			SayHello();
		}

		if(authenticate && IsKeywordSupported(RecvBuf, "AUTH") == true)
		{
			if(login) SetLogin(login);
			if(!m_sLogin.size())
				throw ECSmtp(ECSmtp::UNDEF_LOGIN);

			if(password) SetPassword(password);
			if(!m_sPassword.size())
				throw ECSmtp(ECSmtp::UNDEF_PASSWORD);

			if(IsKeywordSupported(RecvBuf, "LOGIN") == true)
			{
				pEntry = FindCommandEntry(command_AUTHLOGIN);
				strcpy_s(SendBuf, BUFFER_SIZE, "AUTH LOGIN\r\n");
				SendData(pEntry);
				ReceiveResponse(pEntry);

				// send login:
				std::string encoded_login = base64_encode(reinterpret_cast<const unsigned char*>(m_sLogin.c_str()), static_cast<unsigned int>(m_sLogin.size()));
				pEntry = FindCommandEntry(command_USER);
				sprintf_s(SendBuf, BUFFER_SIZE, "%s\r\n", encoded_login.c_str());
				SendData(pEntry);
				ReceiveResponse(pEntry);
				
				// send password:
				std::string encoded_password = base64_encode(reinterpret_cast<const unsigned char*>(m_sPassword.c_str()), static_cast<unsigned int>(m_sPassword.size()));
				pEntry = FindCommandEntry(command_PASSWORD);
				sprintf_s(SendBuf, BUFFER_SIZE, "%s\r\n", encoded_password.c_str());
				SendData(pEntry);
				ReceiveResponse(pEntry);
			}
			else if(IsKeywordSupported(RecvBuf, "PLAIN") == true)
			{
				pEntry = FindCommandEntry(command_AUTHPLAIN);

				std::string m_sAuthPlain;

				m_sAuthPlain.append(m_sLogin.c_str());
				m_sAuthPlain.append(" ");
				m_sAuthPlain.append(m_sLogin.c_str());
				m_sAuthPlain.append(" ");
				m_sAuthPlain.append(m_sPassword.c_str());

				std::string encoded_login = base64_encode(reinterpret_cast<const unsigned char*>(m_sAuthPlain.c_str()), static_cast<unsigned int>(m_sAuthPlain.size()));

				m_sAuthPlain.clear();
				sprintf_s(SendBuf, BUFFER_SIZE, "AUTH PLAIN %s\r\n", encoded_login.c_str());
				SendData(pEntry);
				ReceiveResponse(pEntry);
			}
			else if(IsKeywordSupported(RecvBuf, "CRAM-MD5") == true)
			{
				pEntry = FindCommandEntry(command_AUTHCRAMMD5);
				strcpy_s(SendBuf, BUFFER_SIZE, "AUTH CRAM-MD5\r\n");
				SendData(pEntry);
				ReceiveResponse(pEntry);

				std::string encoded_challenge = RecvBuf;
				encoded_challenge = encoded_challenge.substr(4);
				std::string decoded_challenge = base64_decode(encoded_challenge);
				
				/////////////////////////////////////////////////////////////////////
				//test data from RFC 2195
				//decoded_challenge = "<1896.697170952@postoffice.reston.mci.net>";
				//m_sLogin = "tim";
				//m_sPassword = "tanstaaftanstaaf";
				//MD5 should produce b913a602c7eda7a495b4e6e7334d3890
				//should encode as dGltIGI5MTNhNjAyYzdlZGE3YTQ5NWI0ZTZlNzMzNGQzODkw
				/////////////////////////////////////////////////////////////////////

				std::string ustrPassword;

				if(static_cast<int>(decoded_challenge.size()) == 0)
					throw ECSmtp(ECSmtp::BAD_DECODE_CHALLENGE);

				if(static_cast<int>(m_sPassword.size()) == 0)
					throw ECSmtp(ECSmtp::BAD_LOGIN_PASSWORD);

				ustrPassword = m_sPassword;

				// if ustrPassword is longer than 64 bytes reset it to ustrPassword = MD5(ustrPassword)
				if(static_cast<int>(m_sPassword.size()) > 64)
				{
					MD5_CTX ctx;
					unsigned char digest[16];

					memset(digest, 0, 16);

					MD5_Init(&ctx);
					MD5_Update(&ctx, ustrPassword.c_str(), strlen(ustrPassword.c_str()));
					MD5_Final(digest, &ctx);

					ustrPassword.clear();
					ustrPassword.append(reinterpret_cast<char*>(digest));

					memset(digest, 0, 16);
				}

				// Storing ustrPassword in pads
				std::string ipad(ustrPassword.c_str());
				std::string opad(ustrPassword.c_str());
				
				ipad.resize(64, '\0');
				opad.resize(64, '\0');

				// XOR ustrPassword with ipad and opad values
				for(int i = 0; i < 64; i++)
				{
					ipad[i] ^= 0x36;
					opad[i] ^= 0x5c;
				}

				unsigned char ustrDigestResult[16];
				char ustrResults[33];

				memset(ustrDigestResult, 0, 16);
				memset(ustrResults, 0, 33);

				// Perform inner MD5
				MD5_CTX ictx;

				MD5_Init(&ictx);
				MD5_Update(&ictx, ipad.c_str(), strlen(ipad.c_str()));
				MD5_Update(&ictx, decoded_challenge.c_str(), strlen(decoded_challenge.c_str()));
				MD5_Final(ustrDigestResult, &ictx);

				// Perform outer MD5
				MD5_CTX octx;

				MD5_Init(&octx);
				MD5_Update(&octx, opad.c_str(), strlen(opad.c_str()));
				MD5_Update(&octx, ustrDigestResult, 16);
				MD5_Final(ustrDigestResult, &octx);

				for (int i = 0; i < 16; i++)
					sprintf_s(&ustrResults[i * 2], 33, "%02x", (unsigned int)ustrDigestResult[i]);

				decoded_challenge.clear();
				decoded_challenge.append(reinterpret_cast<char*>(ustrResults));

				memset(ustrDigestResult, 0, 16);
				memset(ustrResults, 0, 33);

				// Final
				decoded_challenge = m_sLogin + " " + decoded_challenge;
				encoded_challenge = base64_encode(reinterpret_cast<const unsigned char*>(decoded_challenge.c_str()), static_cast<unsigned int>(decoded_challenge.size()));

				sprintf_s(SendBuf, BUFFER_SIZE, "%s\r\n", encoded_challenge.c_str());
				pEntry = FindCommandEntry(command_PASSWORD);
				SendData(pEntry);
				ReceiveResponse(pEntry);
			}
			else if(IsKeywordSupported(RecvBuf, "DIGEST-MD5") == true)
			{
				pEntry = FindCommandEntry(command_DIGESTMD5);
				strcpy_s(SendBuf, BUFFER_SIZE, "AUTH DIGEST-MD5\r\n");
				SendData(pEntry);
				ReceiveResponse(pEntry);

				std::string encoded_challenge = RecvBuf;
				encoded_challenge = encoded_challenge.substr(4);
				std::string decoded_challenge = base64_decode(encoded_challenge);

				/////////////////////////////////////////////////////////////////////
				//Test data from RFC 2831
				//To test jump into authenticate and read this line and the ones down to next test data section
				//decoded_challenge = "realm=\"elwood.innosoft.com\",nonce=\"OA6MG9tEQGm2hh\",qop=\"auth\",algorithm=md5-sess,charset=utf-8";
				/////////////////////////////////////////////////////////////////////
				
				//Get the nonce (manditory)
				int find = static_cast<int>(decoded_challenge.find("nonce"));
				
				if(find < 0)
					throw ECSmtp(ECSmtp::BAD_DIGEST_RESPONSE);
				
				std::string nonce = decoded_challenge.substr(find+7);
				
				find = static_cast<int>(nonce.find("\""));
				
				if(find < 0)
					throw ECSmtp(ECSmtp::BAD_DIGEST_RESPONSE);

				nonce = nonce.substr(0, find);

				//Get the realm (optional)
				std::string realm;
				
				find = static_cast<int>(decoded_challenge.find("realm"));
				
				if(find >= 0)
				{
					realm = decoded_challenge.substr(find + 7);
					find = static_cast<int>(realm.find("\""));

					if(find < 0)
						throw ECSmtp(ECSmtp::BAD_DIGEST_RESPONSE);
					
					realm = realm.substr(0, find);
				}

				//Create a cnonce
				char cnonce[17], nc[9];
				sprintf_s(cnonce, 17, "%x", (unsigned int) time(NULL));

				//Set nonce count
				sprintf_s(nc, 9, "%08d", 1);

				//Set QOP
				std::string qop = "auth";

				//Get server address and set uri
				//Skip this step during test

				int len;

				struct sockaddr_storage addr;
				len = sizeof addr;

				if(!getpeername(hSocket, (struct sockaddr*)&addr, &len))
					throw ECSmtp(ECSmtp::BAD_SERVER_NAME);

				struct sockaddr_in *s = (struct sockaddr_in *)&addr;
				std::string uri = inet_ntoa(s->sin_addr);
				uri = "smtp/" + uri;

				/////////////////////////////////////////////////////////////////////
				//test data from RFC 2831
				//m_sLogin = "chris";
				//m_sPassword = "secret";
				//strcpy(cnonce, "OA6MHXh6VqTrRk");
				//uri = "imap/elwood.innosoft.com";
				//Should form the response:
				//    charset=utf-8,username="chris",
				//    realm="elwood.innosoft.com",nonce="OA6MG9tEQGm2hh",nc=00000001,
				//    cnonce="OA6MHXh6VqTrRk",digest-uri="imap/elwood.innosoft.com",
				//    response=d388dad90d4bbd760a152321f2143af7,qop=auth
				//This encodes to:
				//    Y2hhcnNldD11dGYtOCx1c2VybmFtZT0iY2hyaXMiLHJlYWxtPSJlbHdvb2
				//    QuaW5ub3NvZnQuY29tIixub25jZT0iT0E2TUc5dEVRR20yaGgiLG5jPTAw
				//    MDAwMDAxLGNub25jZT0iT0E2TUhYaDZWcVRyUmsiLGRpZ2VzdC11cmk9Im
				//    ltYXAvZWx3b29kLmlubm9zb2Z0LmNvbSIscmVzcG9uc2U9ZDM4OGRhZDkw
				//    ZDRiYmQ3NjBhMTUyMzIxZjIxNDNhZjcscW9wPWF1dGg=
				/////////////////////////////////////////////////////////////////////

				//Calculate digest response
				if(static_cast<int>(realm.size()) == 0 || static_cast<int>(m_sLogin .size()) == 0 || 
						static_cast<int>(m_sPassword.size()) == 0 || static_cast<int>(nonce.size()) == 0 || 
						strlen(cnonce) == 0 || static_cast<int>(uri.size()) == 0 || strlen(nc) == 0 || 
						static_cast<int>(qop.size()) == 0)
					throw ECSmtp(ECSmtp::BAD_LOGIN_PASSWORD);

				MD5_CTX A1Actx;
				unsigned char uA1A[16];

				memset(uA1A, '\0', 16);

				MD5_Init(&A1Actx);
				MD5_Update(&A1Actx, m_sLogin.c_str(), static_cast<unsigned int>(m_sLogin.size()));
				MD5_Update(&A1Actx, ":", 1);
				MD5_Update(&A1Actx, realm.c_str(), static_cast<unsigned int>(realm.size()));
				MD5_Update(&A1Actx, ":", 1);
				MD5_Update(&A1Actx, m_sPassword.c_str(), static_cast<unsigned int>(m_sPassword.size()));
				MD5_Final(uA1A, &A1Actx);

				MD5_CTX A1Bctx;
				unsigned char uA1B[16];

				memset(uA1B, '\0', 16);

				MD5_Init(&A1Bctx);
				MD5_Update(&A1Bctx, uA1A, 16);
				MD5_Update(&A1Bctx, ":", 1);
				MD5_Update(&A1Bctx, nonce.c_str(), static_cast<unsigned int>(nonce.size()));
				MD5_Update(&A1Bctx, ":", 1);
				MD5_Update(&A1Bctx, cnonce, static_cast<unsigned int>(strlen(cnonce)));
				//authzid could be added here
				MD5_Final(uA1B, &A1Bctx);

				MD5_CTX A2ctx;
				unsigned char uA2A[16];

				memset(uA2A, '\0', 16);

				MD5_Init(&A2ctx);
				MD5_Update(&A2ctx, "AUTHENTICATE:", 13);
				MD5_Update(&A2ctx, uri.c_str(), static_cast<unsigned int>(uri.size()));
				//authint and authconf add an additional line here	
				MD5_Final(uA2A, &A2ctx);

				memset(uA1A, '\0', 16);
				
				char uA1[33];
				char uA2[33];

				for (int i = 0; i < 16; i++)
				{
					sprintf_s(&uA1[i * 2], 33, "%02x", (unsigned int)uA1B[i]);
					sprintf_s(&uA2[i * 2], 33, "%02x", (unsigned int)uA2A[i]);
				}
					
				//compute KD
				MD5_CTX KDctx;
				unsigned char KDResult[16];
				char KDdecoded_challenge[33];

				memset(KDResult, '\0', 16);

				MD5_Init(&KDctx);
				MD5_Update(&KDctx, uA1, 33);
				MD5_Update(&KDctx, ":", 1);
				MD5_Update(&KDctx, nonce.c_str(), static_cast<unsigned int>(nonce.size()));
				MD5_Update(&KDctx, ":", 1);
				MD5_Update(&KDctx, nc, static_cast<unsigned int>(strlen(nc)));
				MD5_Update(&KDctx, ":", 1);
				MD5_Update(&KDctx, cnonce, static_cast<unsigned int>(strlen(cnonce)));
				MD5_Update(&KDctx, ":", 1);
				MD5_Update(&KDctx, qop.c_str(), static_cast<unsigned int>(qop.size()));
				MD5_Update(&KDctx, ":", 1);
				MD5_Update(&KDctx, uA2, 33);
				MD5_Final(KDResult, &KDctx);

				for (int i = 0; i < 16; i++)
					sprintf_s(&KDdecoded_challenge[i * 2], 33, "%02x", (unsigned int)KDResult[i]);

				memset(uA1, '\0', 33);
				memset(uA2, '\0', 33);
				memset(KDResult, '\0', 16);
				memset(KDdecoded_challenge, '\0', 33);

				decoded_challenge.clear();
				decoded_challenge = KDdecoded_challenge;

				//send the response
				if(strstr(RecvBuf, "charset") >= 0) 
					sprintf_s(SendBuf, BUFFER_SIZE, "charset=utf-8,username=\"%s\"", m_sLogin.c_str());
				else 
					sprintf_s(SendBuf, BUFFER_SIZE, "username=\"%s\"", m_sLogin.c_str());

				if(!realm.empty())
				{
					sprintf_s(RecvBuf, BUFFER_SIZE, ",realm=\"%s\"", realm.c_str());
					strcat_s(SendBuf, BUFFER_SIZE, RecvBuf);
				}

				sprintf_s(RecvBuf, BUFFER_SIZE, ",nonce=\"%s\"", nonce.c_str());
				strcat_s(SendBuf, BUFFER_SIZE, RecvBuf);
				sprintf_s(RecvBuf, BUFFER_SIZE, ",nc=%s", nc);
				strcat_s(SendBuf, BUFFER_SIZE, RecvBuf);
				sprintf_s(RecvBuf, BUFFER_SIZE, ",cnonce=\"%s\"", cnonce);
				strcat_s(SendBuf, BUFFER_SIZE, RecvBuf);
				sprintf_s(RecvBuf, BUFFER_SIZE, ",digest-uri=\"%s\"", uri.c_str());
				strcat_s(SendBuf, BUFFER_SIZE, RecvBuf);
				sprintf_s(RecvBuf, BUFFER_SIZE, ",response=%s", decoded_challenge.c_str());
				strcat_s(SendBuf, BUFFER_SIZE, RecvBuf);
				sprintf_s(RecvBuf, BUFFER_SIZE, ",qop=%s", qop.c_str());
				strcat_s(SendBuf, BUFFER_SIZE, RecvBuf);

				std::string  ustrDigest = SendBuf;
				encoded_challenge = base64_encode(reinterpret_cast<const unsigned char*>(ustrDigest.c_str()), static_cast<unsigned int>(ustrDigest.size()));

				// Send econded result
				sprintf_s(SendBuf, BUFFER_SIZE, "%s\r\n", encoded_challenge.c_str());
				pEntry = FindCommandEntry(command_DIGESTMD5);
				SendData(pEntry);
				ReceiveResponse(pEntry);

				// Send completion carraige return
				sprintf_s(SendBuf, BUFFER_SIZE, "\r\n");				
				pEntry = FindCommandEntry(command_PASSWORD);
				SendData(pEntry);
				ReceiveResponse(pEntry);
			}
			else throw ECSmtp(ECSmtp::LOGIN_NOT_SUPPORTED);
		}
	}
	catch(const ECSmtp&)
	{
		if(RecvBuf[0] == '5' && RecvBuf[1] == '3' && RecvBuf[2] == '0')
			m_bConnected = false;

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
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013
////////////////////////////////////////////////////////////////////////////////
void CSmtp::DisconnectRemoteServer()
{
	if(m_bConnected) 
		SayQuit();
	
	if(hSocket)
		closesocket(hSocket);

	hSocket = INVALID_SOCKET;
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: SmtpXYZdigits
// DESCRIPTION: Converts three letters from RecvBuf to the number.
//   ARGUMENTS: none
// USES GLOBAL: RecvBuf
// MODIFIES GL: none
//     RETURNS: integer number
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013
////////////////////////////////////////////////////////////////////////////////
int CSmtp::SmtpXYZdigits()
{
	assert(RecvBuf);

	if(RecvBuf == NULL)
		return 0;

	return (RecvBuf[0]-'0')*100 + (RecvBuf[1]-'0')*10 + RecvBuf[2]-'0';
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: FormatHeader
// DESCRIPTION: Prepares a header of the message.
//   ARGUMENTS: char* header - formated header string
// USES GLOBAL: Recipients, CCRecipients, BCCRecipients
// MODIFIES GL: none
//     RETURNS: void
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013
//							
////////////////////////////////////////////////////////////////////////////////
void CSmtp::FormatHeader(char* header)
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
		throw ECSmtp(ECSmtp::UNDEF_RECIPIENTS);

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
	if(dwResult >= 0)
		sprintf_s(header, BUFFER_SIZE, "Date: %s, %02d %s %04d %02d:%02d:%02d +%I64d00\r\n", weekday[timeinfo.tm_wday], timeinfo.tm_mday,
																	month[timeinfo.tm_mon],
																	timeinfo.tm_year+1900,
																	timeinfo.tm_hour,
																	timeinfo.tm_min,
																	timeinfo.tm_sec,
																	dwResult); 
	else
		sprintf_s(header, BUFFER_SIZE, "Date: %s, %02d %s %04d %02d:%02d:%02d -%I64d00\r\n", weekday[timeinfo.tm_wday], timeinfo.tm_mday,
																	month[timeinfo.tm_mon],
																	timeinfo.tm_year+1900,
																	timeinfo.tm_hour,
																	timeinfo.tm_min,
																	timeinfo.tm_sec,
																	dwResult*-1); 
	
	unsigned long long dwRandomHash;

	// Message-Id:
	strcat_s(header, BUFFER_SIZE, "Message-Id: <");

	dwRandomHash = ((timeinfo.tm_year + 1900 * rand()) + (timeinfo.tm_mon + rand()) + (timeinfo.tm_mday + rand()) + (timeinfo.tm_hour * rand()) + (timeinfo.tm_min + rand()) + (timeinfo.tm_sec * rand()) + rand()) * rand();

	sprintf_s(szMsgId, BUFFER_MSGID_SIZE, "%04d%02d%02d%02d%02d%02d.%I64d@", timeinfo.tm_year+1900, 
												timeinfo.tm_mon, 
												timeinfo.tm_mday,
												timeinfo.tm_hour,
												timeinfo.tm_min,
												timeinfo.tm_sec,
												dwRandomHash);

	strcat_s(header, BUFFER_SIZE, szMsgId);
	strcat_s(header, BUFFER_SIZE, host->h_name);
	strcat_s(header, BUFFER_SIZE, ">\r\n");

	// From: <SP> <sender>  <SP> "<" <sender-email> ">" <CRLF>
	if(!m_sMailFrom.size()) throw ECSmtp(ECSmtp::UNDEF_MAIL_FROM);
	 
	strcat_s(header, BUFFER_SIZE, "From: \"");
	
	if(m_sNameFrom.size()) 
		strcat_s(header, BUFFER_SIZE, m_sNameFrom.c_str());
	else
		strcat_s(header, BUFFER_SIZE, m_sMailFrom.c_str());

	strcat_s(header, BUFFER_SIZE, "\"");

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
		case XPRIORITY_HIGH:
			strcat_s(header, BUFFER_SIZE, "X-Priority: 2 (High)\r\n");
			break;
		case XPRIORITY_NORMAL:
			strcat_s(header, BUFFER_SIZE, "X-Priority: 3 (Normal)\r\n");
			break;
		case XPRIORITY_LOW:
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
	if(!m_sSubject.size()) 
		strcat_s(header, BUFFER_SIZE, "Subject:  ");
	else
	{
	  strcat_s(header, BUFFER_SIZE, "Subject: ");
	  strcat_s(header, BUFFER_SIZE, m_sSubject.c_str());
	}

	strcat_s(header, BUFFER_SIZE, "\r\n");
	
	// MIME-Version: <SP> 1.0 <CRLF>
	strcat_s(header, BUFFER_SIZE, "MIME-Version: 1.0\r\n");

	if(!Attachments.size())
	{ // No attachments
		if(m_bHTML) 
		{
			strcat_s(header, BUFFER_SIZE, "Content-Type: multipart/alternative;\r\n\tboundary=\"");
			strcat_s(header, BUFFER_SIZE, SMTP_BOUNDARY_ALTERNATIVE);
			strcat_s(header, BUFFER_SIZE, "\"\r\n");
			strcat_s(header, BUFFER_SIZE, "\r\n");	
			
			strcat_s(header, BUFFER_SIZE, "This is a multi-part message in MIME format.\r\n");

			strcat_s(header, BUFFER_SIZE, "--");
			strcat_s(header, BUFFER_SIZE, SMTP_BOUNDARY_ALTERNATIVE);
			strcat_s(header, BUFFER_SIZE, "\r\n");

			strcat_s(header, BUFFER_SIZE, "Content-Type: text/plain; charset=");
			strcat_s(header, BUFFER_SIZE, m_sCharSet.c_str());
			strcat_s(header, BUFFER_SIZE, "\r\n");
			strcat_s(header, BUFFER_SIZE, "Content-Transfer-Encoding: ");
			strcat_s(header, BUFFER_SIZE, m_sCharEncoding.c_str());
			strcat_s(header, BUFFER_SIZE, "\r\n");
			strcat_s(header, BUFFER_SIZE, "\r\n");
		}
		else
		{
			strcat_s(header, BUFFER_SIZE, "Content-Type: text/plain; charset=");
			strcat_s(header, BUFFER_SIZE, m_sCharSet.c_str());
			strcat_s(header, BUFFER_SIZE, "\r\n");
			strcat_s(header, BUFFER_SIZE, "Content-Transfer-Encoding: ");
			strcat_s(header, BUFFER_SIZE, m_sCharEncoding.c_str());
			strcat_s(header, BUFFER_SIZE, "\r\n");
			strcat_s(header, BUFFER_SIZE, "\r\n");
		}
	}
	else
	{ // there is one or more attachments
		strcat_s(header, BUFFER_SIZE, "Content-Type: multipart/mixed;\r\n\tboundary=\"");
		strcat_s(header, BUFFER_SIZE, SMTP_BOUNDARY_MIXED);
		strcat_s(header, BUFFER_SIZE, "\"\r\n");
		strcat_s(header, BUFFER_SIZE, "\r\n");

		strcat_s(header, BUFFER_SIZE, "This is a multi-part message in MIME format.\r\n");

		strcat_s(header, BUFFER_SIZE, "--");
		strcat_s(header, BUFFER_SIZE, SMTP_BOUNDARY_MIXED);
		strcat_s(header, BUFFER_SIZE, "\r\n");

		if(m_bHTML) 
		{
			strcat_s(header, BUFFER_SIZE, "Content-Type: multipart/alternative;\r\n\tboundary=\"");
			strcat_s(header, BUFFER_SIZE, SMTP_BOUNDARY_ALTERNATIVE);
			strcat_s(header, BUFFER_SIZE, "\"\r\n");
			strcat_s(header, BUFFER_SIZE, "\r\n");	
			
			strcat_s(header, BUFFER_SIZE, "\r\n");

			strcat_s(header, BUFFER_SIZE, "--");
			strcat_s(header, BUFFER_SIZE, SMTP_BOUNDARY_ALTERNATIVE);
			strcat_s(header, BUFFER_SIZE, "\r\n");

			strcat_s(header, BUFFER_SIZE, "Content-Type: text/plain; charset=");
			strcat_s(header, BUFFER_SIZE, m_sCharSet.c_str());
			strcat_s(header, BUFFER_SIZE, "\r\n");
			strcat_s(header, BUFFER_SIZE, "Content-Transfer-Encoding: ");
			strcat_s(header, BUFFER_SIZE, m_sCharEncoding.c_str());
			strcat_s(header, BUFFER_SIZE, "\r\n");
			strcat_s(header, BUFFER_SIZE, "\r\n");
		}
		else
		{
			strcat_s(header, BUFFER_SIZE, "Content-Type: text/plain; charset=");
			strcat_s(header, BUFFER_SIZE, m_sCharSet.c_str());
			strcat_s(header, BUFFER_SIZE, "\r\n");
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
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013						
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
// MODIFICATION: Receives data as much as possible. Another function ReceiveResponse
//               will ensure the received data contains '\n'
// AUTHOR/DATE:  John Tang 2010-08-01
////////////////////////////////////////////////////////////////////////////////
void CSmtp::ReceiveData(Command_Entry* pEntry)
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
		throw ECSmtp(ECSmtp::RECVBUF_IS_EMPTY);

	FD_ZERO(&fdread);

	FD_SET(hSocket,&fdread);

	if((res = select(0, &fdread, NULL, NULL, &time)) == SOCKET_ERROR)
	{
		FD_CLR(hSocket,&fdread);
		throw ECSmtp(ECSmtp::WSA_SELECT);
	}

	if(!res)
	{
		//timeout
		FD_CLR(hSocket, &fdread);
		throw ECSmtp(ECSmtp::SERVER_NOT_RESPONDING);
	}

	if(FD_ISSET(hSocket, &fdread))
	{
		res = recv(hSocket, RecvBuf, BUFFER_SIZE, 0);

		if(res == SOCKET_ERROR)
		{
			FD_CLR(hSocket, &fdread);
			throw ECSmtp(ECSmtp::WSA_RECV);
		}
	}

	FD_CLR(hSocket, &fdread);
	RecvBuf[res] = 0;

	if(res == 0)
	{
		throw ECSmtp(ECSmtp::CONNECTION_CLOSED);
	}
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: SendData
// DESCRIPTION: Sends data from SendBuf buffer.
//   ARGUMENTS: none
// USES GLOBAL: SendBuf
// MODIFIES GL: none
//     RETURNS: void
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013
////////////////////////////////////////////////////////////////////////////////
void CSmtp::SendData(Command_Entry* pEntry)
{
	if(m_ssl != NULL)
	{
		SendData_SSL(m_ssl, pEntry);
		return;
	}

	std::string szTempDot;
	int idx = 0, res, nLeft = static_cast<int>(strlen(SendBuf));
	fd_set fdwrite;
	timeval time;

	time.tv_sec = pEntry->send_timeout;
	time.tv_usec = 0;

	assert(SendBuf);

	if(SendBuf == NULL)
		throw ECSmtp(ECSmtp::SENDBUF_IS_EMPTY);

	while(nLeft > 0)
	{
		FD_ZERO(&fdwrite);

		FD_SET(hSocket, &fdwrite);

		if((res = select(0, NULL, &fdwrite, NULL, &time)) == SOCKET_ERROR)
		{
			FD_CLR(hSocket, &fdwrite);
			throw ECSmtp(ECSmtp::WSA_SELECT);
		}

		if(!res)
		{
			//timeout
			FD_CLR(hSocket, &fdwrite);
			throw ECSmtp(ECSmtp::SERVER_NOT_RESPONDING);
		}

		if(res && FD_ISSET(hSocket, &fdwrite))
		{
			if(*&SendBuf[0] == '.')
			{
				szTempDot.append(".");
				szTempDot.append(&SendBuf[idx]);
				res = send(hSocket, szTempDot.c_str(), nLeft+1, 0);
				szTempDot.clear();
			}
			else
				res = send(hSocket, &SendBuf[idx], nLeft, 0);

			if(res == SOCKET_ERROR || res == 0)
			{
				FD_CLR(hSocket, &fdwrite);
				throw ECSmtp(ECSmtp::WSA_SEND);
			}

			nLeft -= res;
			idx += res;
		}
	}

	FD_CLR(hSocket,&fdwrite);
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: GetLocalHostName
// DESCRIPTION: Returns local host name. 
//   ARGUMENTS: none
// USES GLOBAL: m_pcLocalHostName
// MODIFIES GL: m_oError, m_pcLocalHostName 
//     RETURNS: socket of the remote service
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013
////////////////////////////////////////////////////////////////////////////////
const char* CSmtp::GetLocalHostName()
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
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013
////////////////////////////////////////////////////////////////////////////////
unsigned int CSmtp::GetRecipientCount() const
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
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013
////////////////////////////////////////////////////////////////////////////////
unsigned int CSmtp::GetBCCRecipientCount() const
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
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013
////////////////////////////////////////////////////////////////////////////////
unsigned int CSmtp::GetCCRecipientCount() const
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
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013
////////////////////////////////////////////////////////////////////////////////
const char* CSmtp::GetReplyTo() const
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
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013
////////////////////////////////////////////////////////////////////////////////
const char* CSmtp::GetMailFrom() const
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
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013
////////////////////////////////////////////////////////////////////////////////
const char* CSmtp::GetSenderName() const
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
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013
////////////////////////////////////////////////////////////////////////////////
const char* CSmtp::GetSubject() const
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
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013
////////////////////////////////////////////////////////////////////////////////
const char* CSmtp::GetXMailer() const
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
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013
////////////////////////////////////////////////////////////////////////////////
CSmptXPriority CSmtp::GetXPriority() const
{
	return m_iXPriority;
}

const char* CSmtp::GetMsgLineText(unsigned int Line) const
{
	if(Line >= MsgBody.size())
		throw ECSmtp(ECSmtp::OUT_OF_MSG_RANGE);
	return MsgBody.at(Line).c_str();
}

unsigned int CSmtp::GetMsgLines() const
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
void CSmtp::SetCharSet(const char *sCharSet)
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
void CSmtp::SetLocalHostName(const char *sLocalHostName)
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
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013
////////////////////////////////////////////////////////////////////////////////
void CSmtp::SetXPriority(CSmptXPriority priority)
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
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013
//							
////////////////////////////////////////////////////////////////////////////////
void CSmtp::SetReplyTo(const char *ReplyTo)
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
void CSmtp::SetReadReceipt(bool requestReceipt/*=true*/)
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
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013
//							
////////////////////////////////////////////////////////////////////////////////
void CSmtp::SetSenderMail(const char *EMail)
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
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013
//							
////////////////////////////////////////////////////////////////////////////////
void CSmtp::SetSenderName(const char *Name)
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
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013
//							
////////////////////////////////////////////////////////////////////////////////
void CSmtp::SetSubject(const char *Subject)
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
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013
//							
////////////////////////////////////////////////////////////////////////////////
void CSmtp::SetXMailer(const char *XMailer)
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
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013
//							
////////////////////////////////////////////////////////////////////////////////
void CSmtp::SetLogin(const char *Login)
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
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013
//							
////////////////////////////////////////////////////////////////////////////////
void CSmtp::SetPassword(const char *Password)
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
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013
//							JO 2010-0708
////////////////////////////////////////////////////////////////////////////////
void CSmtp::SetSMTPServer(const char* SrvName, const unsigned short SrvPort, bool authenticate)
{
	m_iSMTPSrvPort = SrvPort;
	m_sSMTPSrvName = SrvName;
	m_bAuthenticate = authenticate;
}

////////////////////////////////////////////////////////////////////////////////
//        NAME: GetErrorText (friend function)
// DESCRIPTION: Returns the string for specified error code.
//   ARGUMENTS: CSmtpError ErrorId - error code
// USES GLOBAL: none
// MODIFIES GL: none 
//     RETURNS: error string
//      AUTHOR: Jakub Piwowarczyk - Sebastiano Bertini
// AUTHOR/DATE: 29-03-2013
////////////////////////////////////////////////////////////////////////////////
std::string ECSmtp::GetErrorText() const
{
	switch(ErrorCode)
	{
		case ECSmtp::CSMTP_NO_ERROR:
			return "";
		case ECSmtp::WSA_STARTUP:
			return "SMTP - WSA_STARTUP - Impossibile inizializzare WinSock2";
		case ECSmtp::WSA_VER:
			return "SMTP - WSA_VER - Versione errata di WinSock2";
		case ECSmtp::WSA_SEND:
			return "SMTP - WSA_SEND - Errore funzione send()";
		case ECSmtp::WSA_RECV:
			return "SMTP - WSA_RECV - Errore funzione recv()";
		case ECSmtp::WSA_CONNECT:
			return "SMTP - WSA_CONNECT - Errore funzione connect()";
		case ECSmtp::WSA_GETHOSTBY_NAME_ADDR:
			return "SMTP - WSA_GETHOSTBY_NAME_ADDR - Impossibile determinare il server remoto";
		case ECSmtp::WSA_INVALID_SOCKET:
			return "SMTP - WSA_INVALID_SOCKET - WinSock2 non valido";
		case ECSmtp::WSA_HOSTNAME:
			return "SMTP - WSA_HOSTNAME - Errore funzione hostname()";
		case ECSmtp::WSA_IOCTLSOCKET:
			return "SMTP - WSA_IOCTLSOCKET - Errore funzione ioctlsocket()";
		case ECSmtp::WSA_SELECT:
			return "SMTP - WSA_SELECT - Errore di rete";
		case ECSmtp::BAD_IPV4_ADDR:
			return "SMTP - BAD_IPV4_ADDR - Indirizzo IPv4 errato";
		case ECSmtp::UNDEF_MSG_HEADER:
			return "SMTP - UNDEF_MSG_HEADER - Header messaggio non definito";
		case ECSmtp::UNDEF_MAIL_FROM:
			return "SMTP - UNDEF_MAIL_FROM - Mittente non definito";
		case ECSmtp::UNDEF_SUBJECT:
			return "SMTP - UNDEF_SUBJECT - Soggetto non definito";
		case ECSmtp::UNDEF_RECIPIENTS:
			return "SMTP - UNDEF_RECIPIENTS - Definire almento un destinatario";
		case ECSmtp::UNDEF_LOGIN:
			return "SMTP - UNDEF_LOGIN - User non definito";
		case ECSmtp::UNDEF_PASSWORD:
			return "SMTP - UNDEF_PASSWORD - Password non definita";
		case  ECSmtp::BAD_DECODE_CHALLENGE:
			return "SMTP - BAD_DECODE_CHALLENGE - Decodifica challenge fallita";
		case ECSmtp::BAD_LOGIN_PASSWORD:
			return "SMTP - BAD_LOGIN_PASSWORD - Utente o password non valida";
		case ECSmtp::BAD_DIGEST_RESPONSE:
			return "SMTP - BAD_DIGEST_RESPONSE - Risposta MD5 errata da server";
		case ECSmtp::BAD_SERVER_NAME:
			return "SMTP - BAD_SERVER_NAME - Impossibile determinare il nome del server dalla risposta MD5";
		case ECSmtp::UNDEF_RECIPIENT_MAIL:
			return "SMTP - UNDEF_RECIPIENT_MAIL - Destinatario non definito";
		case ECSmtp::COMMAND_MAIL_FROM:
			return "SMTP - COMMAND_MAIL_FROM - Errore comando FROM";
		case ECSmtp::COMMAND_EHLO:
			return "SMTP - COMMAND_EHLO - Errore comando EHLO";
		case ECSmtp::COMMAND_AUTH_PLAIN:
			return "SMTP - COMMAND_AUTH_PLAIN - Errore comando AUTH PLAIN";
		case ECSmtp::COMMAND_AUTH_LOGIN:
			return "SMTP - COMMAND_AUTH_LOGIN - Errore comando AUTH LOGIN";
		case ECSmtp::COMMAND_AUTH_CRAMMD5:
			return "SMTP - COMMAND_AUTH_CRAMMD5 - Errore comando AUTH CRAM-MD5";
		case ECSmtp::COMMAND_AUTH_DIGESTMD5:
			return "SMTP - COMMAND_AUTH_DIGESTMD5 - Errore comando AUTH DIGEST-MD5";
		case ECSmtp::COMMAND_DIGESTMD5:
			return "SMTP - COMMAND_DIGESTMD5 - Errore comando MD5 DIGEST";
		case ECSmtp::COMMAND_DATA:
			return "SMTP - COMMAND_DATA - Errore comando DATA";
		case ECSmtp::COMMAND_QUIT:
			return "SMTP - COMMAND_QUIT - Errore comando QUIT";
		case ECSmtp::COMMAND_RCPT_TO:
			return "SMTP - COMMAND_RCPT_TO - Errore comando RCPT TO";
		case ECSmtp::MSG_BODY_ERROR:
			return "SMTP - MSG_BODY_ERROR - Errore nel testo della mail";
		case ECSmtp::CONNECTION_CLOSED:
			return "SMTP - CONNECTION_CLOSED - Il server ha chiuso la connessione";
		case ECSmtp::SERVER_NOT_READY:
			return "SMTP - SERVER_NOT_READY - Il server non è pronto";
		case ECSmtp::SERVER_NOT_RESPONDING:
			return "SMTP - SERVER_NOT_RESPONDING - Il server non risponde";
		case ECSmtp::SELECT_TIMEOUT:
			return "SMTP - SELECT_TIMEOUT - Timeout";
		case ECSmtp::FILE_NOT_EXIST:
			return "SMTP - FILE_NOT_EXIST - File non trovato";
		case ECSmtp::MSG_TOO_BIG:
			return "SMTP - MSG_TOO_BIG - Il messaggio supera il limite consentito di 5MB";
		case ECSmtp::BAD_LOGIN_PASS:
			return "SMTP - BAD_LOGIN_PASS - User o password errati";
		case ECSmtp::UNDEF_XYZ_RESPONSE:
			return "SMTP - UNDEF_XYZ_RESPONSE - Risposta xyz SMTP non definita";
		case ECSmtp::LACK_OF_MEMORY:
			return "SMTP - LACK_OF_MEMORY - Errore memoria";
		case ECSmtp::TIME_ERROR:
			return "SMTP - TIME_ERROR - Errore funzione time()";
		case ECSmtp::RECVBUF_IS_EMPTY:
			return "SMTP - RECVBUF_IS_EMPTY - Il buffer RecvBuf è vuoto";
		case ECSmtp::SENDBUF_IS_EMPTY:
			return "SMTP - SENDBUF_IS_EMPTY - Il buffer SendBuf è vuoto";
		case ECSmtp::OUT_OF_MSG_RANGE:
			return "SMTP - OUT_OF_MSG_RANGE - La linea corrente è fuori dalle dimensioni del messaggio";
		case ECSmtp::COMMAND_EHLO_STARTTLS:
			return "SMTP - COMMAND_EHLO_STARTTLS - Errore comando STARTTLS";
		case ECSmtp::SSL_PROBLEM:
			return "SMTP - SSL_PROBLEM - Errore SSL";
		case ECSmtp::COMMAND_DATABLOCK:
			return "SMTP - COMMAND_DATABLOCK - Errore invio blocco dati";
		case ECSmtp::STARTTLS_NOT_SUPPORTED:
			return "SMTP - STARTTLS_NOT_SUPPORTED - STARTTLS non supportato dal serverr";
		case ECSmtp::LOGIN_NOT_SUPPORTED:
			return "SMTP - LOGIN_NOT_SUPPORTED - AUTH LOGIN non supportato dal server";
		case ECSmtp::ERRNO_EPERM:
			return "SMTP - ERRNO_EPERM - Operation not permitted";
		case ECSmtp::ERRNO_ENOENT:
			return "SMTP - ERRNO_EPERM - No such file or directory";
		case ECSmtp::ERRNO_ESRCH:
			return "SMTP - ERRNO_ESRCH - No such process";
		case ECSmtp::ERRNO_EINTR:
			return "SMTP - ERRNO_EINTR - Interrupted function";
		case ECSmtp::ERRNO_EIO:
			return "SMTP - ERRNO_EIO - I/O error";
		case ECSmtp::ERRNO_ENXIO:
			return "SMTP - ERRNO_ENXIO - No such device or address";
		case ECSmtp::ERRNO_E2BIG:
			return "SMTP - ERRNO_E2BIG - Argument list too long";
		case ECSmtp::ERRNO_ENOEXEC:
			return "SMTP - ERRNO_ENOEXEC - Exec format error";
		case ECSmtp::ERRNO_EBADF:
			return "SMTP - ERRNO_EBADF - Bad file number";
		case ECSmtp::ERRNO_ECHILD:
			return "SMTP - ERRNO_ECHILD - No spawned processes";
		case ECSmtp::ERRNO_EAGAIN:
			return "SMTP - ERRNO_EAGAIN - No more processes or not enough memory or maximum nesting level reached";
		case ECSmtp::ERRNO_ENOMEM:
			return "SMTP - ERRNO_ENOMEM - Not enough memory";
		case ECSmtp::ERRNO_EACCES:
			return "SMTP - ERRNO_EACCES - Permission denied";
		case ECSmtp::ERRNO_EFAULT:
			return "SMTP - ERRNO_EFAULT - Bad address";
		case ECSmtp::ERRNO_EBUSY:
			return "SMTP - ERRNO_EBUSY - Device or resource busy";
		case ECSmtp::ERRNO_EEXIST:
			return "SMTP - ERRNO_EEXIST - File exists";
		case ECSmtp::ERRNO_EXDEV:
			return "SMTP - ERRNO_EXDEV - Cross-device link";
		case ECSmtp::ERRNO_ENODEV:
			return "SMTP - ERRNO_ENODEV - No such device";
		case ECSmtp::ERRNO_ENOTDIR:
			return "SMTP - ERRNO_ENOTDIR - Not a directory";
		case ECSmtp::ERRNO_EISDIR:
			return "SMTP - ERRNO_EISDIR - Is a directory";
		case ECSmtp::ERRNO_EINVAL:
			return "SMTP - ERRNO_EINVAL - Invalid argument";
		case ECSmtp::ERRNO_ENFILE:
			return "SMTP - ERRNO_ENFILE - Too many files open in system";
		case ECSmtp::ERRNO_EMFILE:
			return "SMTP - ERRNO_EMFILE - Too many open files";
		case ECSmtp::ERRNO_ENOTTY:
			return "SMTP - ERRNO_ENOTTY - Inappropriate I/O control operation";
		case ECSmtp::ERRNO_EFBIG:
			return "SMTP - ERRNO_EFBIG - File too large";
		case ECSmtp::ERRNO_ENOSPC:
			return "SMTP - ERRNO_ENOSPC - No space left on device";
		case ECSmtp::ERRNO_ESPIPE:
			return "SMTP - ERRNO_ESPIPE - Invalid seek";
		case ECSmtp::ERRNO_EROFS:
			return "SMTP - ERRNO_EROFS - Read-only file system";
		case ECSmtp::ERRNO_EMLINK:
			return "SMTP - ERRNO_EMLINK - Too many links";
		case ECSmtp::ERRNO_EPIPE:
			return "SMTP - ERRNO_EPIPE - Broken pipe";
		case ECSmtp::ERRNO_EDOM:
			return "SMTP - ERRNO_EDOM - Math argument";
		case ECSmtp::ERRNO_ERANGE:
			return "SMTP - ERRNO_ERANGE - Result too large";
		case ECSmtp::ERRNO_EDEADLK:
			return "SMTP - ERRNO_EDEADLK - Resource deadlock would occur";
		case ECSmtp::ERRNO_ENAMETOOLONG:
			return "SMTP - ERRNO_ENAMETOOLONG - Filename too long";
		case ECSmtp::ERRNO_ENOLCK:
			return "SMTP - ERRNO_ENOLCK - No locks available";
		case ECSmtp::ERRNO_ENOSYS:
			return "SMTP - ERRNO_ENOSYS - Function not supported";
		case ECSmtp::ERRNO_ENOTEMPTY:
			return "SMTP - ERRNO_ENOTEMPTY - Directory not empty";
		case ECSmtp::ERRNO_EILSEQ:
			return "SMTP - ERRNO_EILSEQ - Illegal byte sequence";
		case ECSmtp::ERRNO_STRUNCATE:
			return "SMTP - ERRNO_STRUNCATE - String was truncated";
		default:
			return "SMTP - Undefined error Id";
	}
}

void CSmtp::SayHello()
{
	Command_Entry* pEntry = FindCommandEntry(command_EHLO);
	sprintf_s(SendBuf, BUFFER_SIZE, "EHLO %s\r\n", GetLocalHostName());
	SendData(pEntry);
	ReceiveResponse(pEntry);
	m_bConnected=true;
}

void CSmtp::SayQuit()
{
	// ***** CLOSING CONNECTION *****
	
	Command_Entry* pEntry = FindCommandEntry(command_QUIT);
	// QUIT <CRLF>
	strcpy_s(SendBuf, BUFFER_SIZE, "QUIT\r\n");
	m_bConnected = false;
	SendData(pEntry);
	ReceiveResponse(pEntry);
}

void CSmtp::StartTls()
{
	if(IsKeywordSupported(RecvBuf, "STARTTLS") == false)
	{
		throw ECSmtp(ECSmtp::STARTTLS_NOT_SUPPORTED);
	}

	Command_Entry* pEntry = FindCommandEntry(command_STARTTLS);
	strcpy_s(SendBuf, BUFFER_SIZE, "STARTTLS\r\n");
	SendData(pEntry);
	ReceiveResponse(pEntry);

	OpenSSLConnect();
}

void CSmtp::ReceiveData_SSL(SSL* ssl, Command_Entry* pEntry)
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
		throw ECSmtp(ECSmtp::RECVBUF_IS_EMPTY);

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
			throw ECSmtp(ECSmtp::WSA_SELECT);
		}

		if(!res)
		{
			//timeout
			FD_ZERO(&fdread);
			FD_ZERO(&fdwrite);
			throw ECSmtp(ECSmtp::SERVER_NOT_RESPONDING);
		}

		if(FD_ISSET(hSocket,&fdread) || (read_blocked_on_write && FD_ISSET(hSocket,&fdwrite)) )
		{
			while(1)
			{
				read_blocked_on_write = 0;

				const int buff_len = 1024;
				
				char* buff;

				if((buff = new  char[buff_len]) == NULL)
					throw ECSmtp(ECSmtp::LACK_OF_MEMORY);

				res = SSL_read(ssl, buff, buff_len);

				int ssl_err = SSL_get_error(ssl, res);

				if(ssl_err == SSL_ERROR_NONE)
				{
					if(offset + res > BUFFER_SIZE - 1)
					{
						FD_ZERO(&fdread);
						FD_ZERO(&fdwrite);
						throw ECSmtp(ECSmtp::LACK_OF_MEMORY);
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
					read_blocked_on_write = 1;
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
					throw ECSmtp(ECSmtp::SSL_PROBLEM);
				}
			}
		}
	}

	FD_ZERO(&fdread);
	FD_ZERO(&fdwrite);
	RecvBuf[offset] = 0;

	if(offset == 0)
	{
		throw ECSmtp(ECSmtp::CONNECTION_CLOSED);
	}
}

void CSmtp::ReceiveResponse(Command_Entry* pEntry)
{
	std::string line;
	int reply_code = 0;
	bool bFinish = false;

	while(!bFinish)
	{
		ReceiveData(pEntry);
		line.append(RecvBuf);
		size_t len = line.length();
		size_t begin = 0;
		size_t offset = 0;

		if(pEntry->command == command_INIT)
		{
			std::string::size_type bErrorFound = line.rfind("220");

			if(line.npos == bErrorFound)
			{
				line.clear();
				throw ECSmtp(pEntry->error);
			}
		}

		while(1) // loop for all lines
		{
			while(offset + 1 < len)
			{
				if(line[offset] == '\r' && line[offset+1] == '\n')
					break;
				++offset;
			}
			if(offset + 1 < len) // we found a line
			{
				// see if this is the last line
				// the last line must match the pattern: XYZ<SP>*<CRLF> or XYZ<CRLF> where XYZ is a string of 3 digits 
				offset += 2; // skip <CRLF>
				if(offset - begin >= 5)
				{
					if(isdigit(line[begin]) && isdigit(line[begin+1]) && isdigit(line[begin+2]))
					{
						// this is the last line
						if(offset - begin == 5 || line[begin+3] == ' ')
						{
							reply_code = (line[begin]-'0')*100 + (line[begin+1]-'0')*10 + line[begin+2]-'0';
							bFinish = true;
							break;
						}
					}
				}
				begin = offset;	// try to find next line
			}
			else // we haven't received the last line, so we need to receive more data 
			{
				break;
			}
		}
	}

	strcpy_s(RecvBuf, BUFFER_SIZE, line.c_str());

	std::cout << RecvBuf;

	line.clear();

	if(reply_code != pEntry->valid_reply_code)
	{
		throw ECSmtp(pEntry->error);
	}
}

void CSmtp::SendData_SSL(SSL* ssl, Command_Entry* pEntry)
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
		throw ECSmtp(ECSmtp::SENDBUF_IS_EMPTY);

	while(nLeft > 0)
	{
		FD_ZERO(&fdwrite);
		FD_ZERO(&fdread);

		FD_SET(hSocket,&fdwrite);

		if(write_blocked_on_read)
		{
			FD_SET(hSocket, &fdread);
		}

		if((res = select(0,&fdread,&fdwrite,NULL,&time)) == SOCKET_ERROR)
		{
			FD_ZERO(&fdwrite);
			FD_ZERO(&fdread);
			throw ECSmtp(ECSmtp::WSA_SELECT);
		}

		if(!res)
		{
			//timeout
			FD_ZERO(&fdwrite);
			FD_ZERO(&fdread);
			throw ECSmtp(ECSmtp::SERVER_NOT_RESPONDING);
		}

		if(FD_ISSET(hSocket,&fdwrite) || (write_blocked_on_read && FD_ISSET(hSocket, &fdread)) )
		{
			write_blocked_on_read = 0;

			/* Try to write */
			res = SSL_write(ssl, SendBuf + offset, nLeft);
	          
			switch(SSL_get_error(ssl,res))
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
				throw ECSmtp(ECSmtp::SSL_PROBLEM);
			}

		}
	}

	FD_ZERO(&fdwrite);
	FD_ZERO(&fdread);
}

void CSmtp::InitOpenSSL()
{
	SSL_library_init();
	SSL_load_error_strings();
	m_ctx = SSL_CTX_new (SSLv23_client_method());

	if(m_ctx == NULL)
		throw ECSmtp(ECSmtp::SSL_PROBLEM);
}

void CSmtp::OpenSSLConnect()
{
	if(m_ctx == NULL)
		throw ECSmtp(ECSmtp::SSL_PROBLEM);

	m_ssl = SSL_new (m_ctx);

	if(m_ssl == NULL)
		throw ECSmtp(ECSmtp::SSL_PROBLEM);

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
				throw ECSmtp(ECSmtp::WSA_SELECT);
			}

			if(!res)
			{
				//timeout
				FD_ZERO(&fdwrite);
				FD_ZERO(&fdread);
				throw ECSmtp(ECSmtp::SERVER_NOT_RESPONDING);
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
			throw ECSmtp(ECSmtp::SSL_PROBLEM);
		}
	}
}

void CSmtp::CleanupOpenSSL()
{
	if(m_ssl != NULL)
	{
		SSL_shutdown (m_ssl);  /* send SSL/TLS close_notify */
		SSL_free (m_ssl);
		sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
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
