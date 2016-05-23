# CSMTP

CSMTP allow you to send email via command line.

#Features
  - Support TLS/SSL ( OpenSSL v1.0.2g )
  - Support multi receiver email address with ; token
  - Support HTML body
  - Support multi attachment with ; token
  - Support authentication LOGIN - PLAIN - MD5-CRAM - DIGEST-MD5
  - Support urgent flag
  - Support read notification
  - Support password encoding for command line
  
#Supported OS
  - WinXP - Win7 x86/x64 - Win8 x86/x64 - Win8.1 x86/x64 - Win10 x64

#Command Line
	- -server <string>: SMTP server (mandatory)
  -port <number>: Port (default: 25)
  -security <number>: 0 -> Nothing / 1 -> TLS / 2 -> SSL (default: 0)
	-auth <number>: 0 -> No / 1 -> Yes (default: 0)
	-user <string>: user
	-pwd <string>: password (encoded)
	-from <string>: sender (mandatory)
	-to <string>: receiver (mandatory)
	-cc <string>: CC
	-bcc <string>: BCC
	-subject <string>: Subject (mandatory)
  -body <string>: Body
	-attachment <string>: Attachment path
	-urgent <number>: 0 -> No / 1 -> Yes
	-read <number>: read notify 0 -> No / 1 -> Yes
	
#Encode user password:
	- -encode <string>: user password (mandatory)

#Thanks to
  - Jakub Piwowarczyk
  - John_Tang
  - David Johns
