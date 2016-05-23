////////////////////////////////////////////////////////////////////////////////
// SMTP Class
////////////////////////////////////////////////////////////////////////////////

#pragma once
#ifndef __CSMTP_H__
#define __CSMTP_H__

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

#define TIME_IN_SEC			3 * 60	// how long client will wait for server response in non-blocking mode
#define BUFFER_SIZE			10240	// SendData and RecvData buffers sizes
#define BUFFER_MSGID_SIZE	200		
#define MSG_SIZE_IN_MB		10		// Maximum size of the message with all attachments
#define COUNTER_VALUE		100		// How many times program will try to receive data
#define SMTP_BYTE_SIZE_FILE 54

const char SMTP_BOUNDARY_ALTERNATIVE[] = "------------030003070305060005000805";
const char SMTP_BOUNDARY_MIXED[] = "------------000406070805010304010807";

enum CSmptXPriority
{
	XPRIORITY_HIGH = 2,
	XPRIORITY_NORMAL = 3,
	XPRIORITY_LOW = 4
};

enum SMTP_SECURITY_TYPE
{
	NO_SECURITY,
	USE_TLS,
	USE_SSL,
	DO_NOT_SET
};

class ECSmtp
{
public:
	enum CSmtpError
	{
		CSMTP_NO_ERROR = 0,
		WSA_STARTUP = 50, // WSAGetLastError()
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
		UNDEF_MSG_HEADER = 65,
		UNDEF_MAIL_FROM,
		UNDEF_SUBJECT,
		UNDEF_RECIPIENTS,
		UNDEF_LOGIN,
		UNDEF_PASSWORD,
		BAD_DECODE_CHALLENGE,
		BAD_LOGIN_PASSWORD,
		BAD_DIGEST_RESPONSE,
		BAD_SERVER_NAME,
		UNDEF_RECIPIENT_MAIL,
		COMMAND_MAIL_FROM = 76,
		COMMAND_EHLO,
		COMMAND_AUTH_PLAIN,
		COMMAND_AUTH_LOGIN,
		COMMAND_AUTH_CRAMMD5,
		COMMAND_AUTH_DIGESTMD5,
		COMMAND_DIGESTMD5,
		COMMAND_DATA,
		COMMAND_QUIT,
		COMMAND_RCPT_TO,
		MSG_BODY_ERROR,
		CONNECTION_CLOSED = 90, // by server
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
		ERRNO_EPERM = 301,
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
		ERRNO_EBUSY = 316,
		ERRNO_EEXIST,
		ERRNO_EXDEV,
		ERRNO_ENODEV,
		ERRNO_ENOTDIR,
		ERRNO_EISDIR,
		ERRNO_EINVAL,
		ERRNO_ENFILE,
		ERRNO_EMFILE,
		ERRNO_ENOTTY,
		ERRNO_EFBIG = 327,
		ERRNO_ENOSPC,
		ERRNO_ESPIPE,
		ERRNO_EROFS,
		ERRNO_EMLINK,
		ERRNO_EPIPE,
		ERRNO_EDOM,
		ERRNO_ERANGE,
		ERRNO_EDEADLK = 336,
		ERRNO_ENAMETOOLONG = 338,
		ERRNO_ENOLCK,
		ERRNO_ENOSYS,
		ERRNO_ENOTEMPTY,
		ERRNO_EILSEQ,
		ERRNO_STRUNCATE = 380
	};
	ECSmtp(CSmtpError err_) : ErrorCode(err_) {}
	CSmtpError GetErrorNum(void) const {return ErrorCode;}
	std::string GetErrorText(void) const;

private:
	CSmtpError ErrorCode;
};

enum SMTP_COMMAND
{
	command_INIT,
	command_EHLO,
	command_AUTHPLAIN,
	command_AUTHLOGIN,
	command_AUTHCRAMMD5,
	command_AUTHDIGESTMD5,
	command_DIGESTMD5,
	command_USER,
	command_PASSWORD,
	command_MAILFROM,
	command_RCPTTO,
	command_DATA,
	command_DATABLOCK,
	command_DATAEND,
	command_QUIT,
	command_STARTTLS
};

typedef struct tagCommand_Entry
{
	SMTP_COMMAND       command;
	int                send_timeout;	 // 0 means no send is required
	int                recv_timeout;	 // 0 means no recv is required
	int                valid_reply_code; // 0 means no recv is required, so no reply code
	ECSmtp::CSmtpError error;
}Command_Entry;

typedef struct Smtp_tagContent_Type
{
	char* FileExt;
	char* FileExtContent;
}Smtp_Content_Type;

class CSmtp  
{
public:
	CSmtp();
	virtual ~CSmtp();

	void AddRecipient(const char *email, const char *name=NULL);
	void AddBCCRecipient(const char *email, const char *name=NULL);
	void AddCCRecipient(const char *email, const char *name=NULL);    
	void AddAttachment(const char *path);
	void AddAttachmentName(const char *path);   
	void AddMsgLine(const char* text);
	bool ConnectRemoteServer(const char* szServer, const unsigned short nPort_=0,
							 SMTP_SECURITY_TYPE securityType=DO_NOT_SET,
		                     bool authenticate=true, const char* login=NULL,
							 const char* password=NULL);
	void DisconnectRemoteServer();
	void DelRecipients(void);
	void DelBCCRecipients(void);
	void DelCCRecipients(void);
	void DelAttachments(void);
	void DelMsgLines(void);
	void DelMsgLine(unsigned int line);
	void ModMsgLine(unsigned int line,const char* text);
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
	CSmptXPriority GetXPriority() const;
	void Send();
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
	void SetXPriority(CSmptXPriority);
	void SetSMTPServer(const char* server, const unsigned short port=0, bool authenticate=true);

	char* szMsgId;
	long long dwNumChar;

	std::string MsgBodyHTML;

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
	std::string m_sSMTPSrvName;
	unsigned short m_iSMTPSrvPort;
	bool m_bAuthenticate;
	CSmptXPriority m_iXPriority;
	
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
	std::vector<std::string> AttachmentsName;
	std::vector<std::string> MsgBody;
 
	void ReceiveData(Command_Entry* pEntry);
	void SendData(Command_Entry* pEntry);
	void FormatHeader(char*);
	int SmtpXYZdigits();
	void SayHello();
	void SayQuit();

// TLS/SSL extension
public:
	SMTP_SECURITY_TYPE GetSecurityType() const
	{ return m_type; }
	void SetSecurityType(SMTP_SECURITY_TYPE type)
	{ m_type = type; }
	bool m_bHTML;

private:
	SMTP_SECURITY_TYPE m_type;
	SSL_CTX*      m_ctx;
	SSL*          m_ssl;

	void ReceiveResponse(Command_Entry* pEntry);
	void InitOpenSSL();
	void OpenSSLConnect();
	void CleanupOpenSSL();
	void ReceiveData_SSL(SSL* ssl, Command_Entry* pEntry);
	void SendData_SSL(SSL* ssl, Command_Entry* pEntry);
	void StartTls();
};

#endif // __CSMTP_H__