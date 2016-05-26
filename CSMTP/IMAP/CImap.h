////////////////////////////////////////////////////////////////////////////////
// IMAP Class
////////////////////////////////////////////////////////////////////////////////

#pragma once
#ifndef __CIMAP_H__
#define __CIMAP_H__

#include <vector>
#include <string.h>
#include <assert.h>

#include <WS2tcpip.h>
#include <winsock2.h>
#include <time.h>
#pragma comment(lib, "ws2_32.lib")

#include <stdio.h>
#include <fstream>
#include <iostream>

// OpenSSL 1.0.2h
#include "openssl\ssl.h"

#define TIME_IN_SEC			3 * 60
#define BUFFER_SIZE			10240
#define BUFFER_MSGID_SIZE	200  
#define MSG_SIZE_IN_MB		10
#define IMAP_BYTE_SIZE_FILE 54

const char IMAP_BOUNDARY_ALTERNATIVE[] = "------------030003070305060005000805";
const char IMAP_BOUNDARY_MIXED[] = "------------000406070805010304010807";

enum CImapXPriority
{
	IMAP_XPRIORITY_HIGH = 2,
	IMAP_XPRIORITY_NORMAL = 3,
	IMAP_XPRIORITY_LOW = 4
};

enum IMAP_SECURITY_TYPE
{
	IMAP_NO_SECURITY,
	IMAP_USE_TLS,
	IMAP_USE_SSL,
	IMAP_DO_NOT_SET
};

class ECImap
{
public:
	enum CImapError
	{
		CIMAP_NO_ERROR = 0,
		WSA_STARTUP = 115, // WSAGetLastError()
		WSA_VER,
		WSA_SEND,
		WSA_RECV,
		WSA_CONNECT,
		WSA_GETHOSTBY_NAME_ADDR,
		WSA_INVALID_SOCKET,
		WSA_HOSTNAME,
		WSA_IOCTLSOCKET,
		WSA_SELECT,
		BAD_IPV4_ADDR,
		UNDEF_MSG_HEADER = 130,
		UNDEF_MAIL_FROM,
		UNDEF_SUBJECT,
		UNDEF_RECIPIENTS,
		UNDEF_LOGIN,
		UNDEF_PASSWORD,
		BAD_LOGIN_PASSWORD,
		BAD_DIGEST_RESPONSE,
		BAD_SERVER_NAME,
		UNDEF_RECIPIENT_MAIL,
		COMMAND_MAIL_FROM = 145,
		COMMAND_EHLO,
		COMMAND_COMPATIBILITY,
		COMMAND_APPEND,
		COMMAND_AUTH_PLAIN,
		COMMAND_AUTH_LOGIN,
		COMMAND_AUTH_CRAMMD5,
		COMMAND_AUTH_DIGESTMD5,
		COMMAND_DIGESTMD5,
		COMMAND_DATA,
		COMMAND_QUIT,
		COMMAND_RCPT_TO,
		COMMAND_LOGOUT,
		COMMAND_FAILED,
		COMMAND_SELECT,
		MSG_BODY_ERROR,
		CONNECTION_CLOSED = 165, // by server
		SERVER_NOT_READY, // remote server
		SERVER_NOT_RESPONDING,
		SELECT_TIMEOUT,
		FILE_NOT_EXIST,
		MSG_TOO_BIG,
		BAD_LOGIN_PASS,
		UNDEF_XYZ_RESPONSE,
		LACK_OF_MEMORY,
		TIME_ERROR,
		RECVBUF_IS_EMPTY,
		SENDBUF_IS_EMPTY,
		OUT_OF_MSG_RANGE,
		COMMAND_EHLO_STARTTLS,
		SSL_PROBLEM,
		COMMAND_DATABLOCK,
		STARTTLS_NOT_SUPPORTED,
		LOGIN_NOT_SUPPORTED,
		ERRNO_EPERM = 401,
		ERRNO_ENOENT,
		ERRNO_ESRCH,
		ERRNO_EINTR,
		ERRNO_EIO,
		ERRNO_ENXIO,
		ERRNO_E2BIG,
		ERRNO_ENOEXEC,
		ERRNO_EBADF,
		ERRNO_ECHILD,
		ERRNO_EAGAIN,
		ERRNO_ENOMEM,
		ERRNO_EACCES,
		ERRNO_EFAULT,
		ERRNO_EBUSY = 416,
		ERRNO_EEXIST,
		ERRNO_EXDEV,
		ERRNO_ENODEV,
		ERRNO_ENOTDIR,
		ERRNO_EISDIR,
		ERRNO_EINVAL,
		ERRNO_ENFILE,
		ERRNO_EMFILE,
		ERRNO_ENOTTY,
		ERRNO_EFBIG = 427,
		ERRNO_ENOSPC,
		ERRNO_ESPIPE,
		ERRNO_EROFS,
		ERRNO_EMLINK,
		ERRNO_EPIPE,
		ERRNO_EDOM,
		ERRNO_ERANGE,
		ERRNO_EDEADLK = 436,
		ERRNO_ENAMETOOLONG = 438,
		ERRNO_ENOLCK,
		ERRNO_ENOSYS,
		ERRNO_ENOTEMPTY,
		ERRNO_EILSEQ,
		ERRNO_STRUNCATE = 480
	};
	ECImap(CImapError err_) : ErrorCode(err_) {}
	CImapError GetErrorNum(void) const {return ErrorCode;}
	std::string GetErrorText(void) const;

private:
	CImapError ErrorCode;
};

enum IMAP_COMMAND
{
	command_INIT_IMAP,
	command_STARTTLS_IMAP,
	command_CAPABILITY,
	command_LOGIN,
	command_SELECT,
	command_APPEND,
	command_APPEND_DONE,
	command_LOGOUT
};

typedef struct Imap_tagCommand_Entry
{
	IMAP_COMMAND		command;
	int					send_timeout;	 // 0 means no send is required
	int					recv_timeout;	 // 0 means no recv is required
	char*				Token;
	char*				TokenRecv;
	bool				bSkipToken;
	ECImap::CImapError error;
}Imap_Command_Entry;

typedef struct Imap_tagContent_Type
{
	char* FileExt;
	char* FileExtContent;
}Imap_Content_Type;

class CImap  
{
public:
	CImap();
	virtual ~CImap();

	void AddRecipient(const char *email, const char *name=NULL);
	void AddBCCRecipient(const char *email, const char *name=NULL);
	void AddCCRecipient(const char *email, const char *name=NULL);    
	void AddAttachment(const char *path);
	void AddMsgLine(const char* text);
	bool ConnectRemoteServer(const char* szServer, const unsigned short nPort_=0,
							 IMAP_SECURITY_TYPE securityType=IMAP_DO_NOT_SET,
		                     bool authenticate=true, const char* login=NULL,
							 const char* password=NULL);
	void DisconnectRemoteServer();
	
	unsigned int GetBCCRecipientCount() const;    
	unsigned int GetCCRecipientCount() const;
	unsigned int GetRecipientCount() const;    
	const char* GetLocalHostName();
	const char* GetMsgLineText(unsigned int line) const;
	unsigned int GetMsgLines(void) const;
	const char* GetReplyTo() const;
	const char* GetMailFrom() const;
	const char* GetSenderName() const;
	const char* GetSubject() const;
	const char* GetXMailer() const;
	CImapXPriority GetXPriority() const;
	void SaveMessage();
	void SetCharSet(const char *sCharSet);
	void SetLocalHostName(const char *sLocalHostName);
	void SetSubject(const char*);
	void SetSenderName(const char*);
	void SetSenderMail(const char*);
	void SetReplyTo(const char*);
	void SetReadReceipt(bool requestReceipt=true);
	void SetXMailer(const char*);
	void SetLogin(const char*);
	void SetPassword(const char*);
	void SetXPriority(CImapXPriority);
	void SetIMAPServer(const char* server, const unsigned short port=0, bool authenticate=true);

	char *szMsgId;
	long long dwNumChar;
	long long dwNumCharSent;

	std::string MsgBodyHTML;
	std::string SentFolder;

private:	
	std::string m_sLocalHostName;
	std::string m_sMailFrom;
	std::string m_sNameFrom;
	std::string m_sSubject;
	std::string m_sCharSet;
	std::string m_sCharEncoding;
	std::string m_sXMailer;
	std::string m_sReplyTo;
	bool m_bReadReceipt;
	std::string m_sIPAddr;
	std::string m_sLogin;
	std::string m_sPassword;
	std::string m_sIMAPSrvName;
	unsigned short m_iIMAPSrvPort;
	bool m_bAuthenticate;
	CImapXPriority m_iXPriority;
	
	char *SendBuf;
	char *RecvBuf;
	
	SOCKET hSocket;
	bool m_bConnected;

	struct Recipient
	{
		std::string Name;
		std::string Mail;
	};

	std::vector<Recipient> Recipients;
	std::vector<Recipient> CCRecipients;
	std::vector<Recipient> BCCRecipients;
	std::vector<std::string> Attachments;
	std::vector<std::string> MsgBody;
 
	void ReceiveData(Imap_Command_Entry* pEntry);
	void SendData(Imap_Command_Entry* pEntry);
	void FormatHeader(char*);

	void SayQuit();

// TLS/SSL extension
public:
	IMAP_SECURITY_TYPE GetSecurityType() const
	{ return m_type; }
	void SetSecurityType(IMAP_SECURITY_TYPE type)
	{ m_type = type; }
	bool m_bHTML;

private:
	IMAP_SECURITY_TYPE m_type;
	SSL_CTX*      m_ctx;
	SSL*          m_ssl;

	void ReceiveResponse(Imap_Command_Entry* pEntry);
	void InitOpenSSL();
	void OpenSSLConnect();
	void CleanupOpenSSL();
	void ReceiveData_SSL(SSL* ssl, Imap_Command_Entry* pEntry);
	void SendData_SSL(SSL* ssl, Imap_Command_Entry* pEntry);
	void StartTls();
};

#endif // __CIMAP_H__