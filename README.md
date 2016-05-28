# CSMTP

CSMTP allow you to send email via command line and save message to sent folder

#Features
  - Support TLS/SSL ( OpenSSL v1.0.2h )
  - Support multi receiver email address with ; token
  - Support HTML body
  - Support multi attachment with ; token
  - Support authentication LOGIN - PLAIN - MD5-CRAM - DIGEST-MD5
  - Support urgent flag
  - Support read notification
  - Support password encoding for command line
  - Support save message to specific folder
  - Support UTF-8
  
#Supported OS
  - Win7 x86/x64 - Win8 x86/x64 - Win8.1 x86/x64 - Win10 x64

#Command Line
	1. -server <string>: SMTP server (mandatory)
	2. -port <number>: Port (default: 25)
	3. -security <number>: 0 -> Nothing / 1 -> TLS / 2 -> SSL (default: 0)
	4. -auth <number>: 0 -> No / 1 -> Yes (default: 0)
	5. -user <string>: user
	6. -pwd <string>: password (encoded)
	7. -from <string>: sender (mandatory)
	8. -to <string>: receiver (mandatory)
	9. -cc <string>: CC
	10. -bcc <string>: BCC
	11. -subject <string>: Subject (mandatory)
	12. -body <string>: Body
	13. -attachment <string>: Attachment path
	14. -urgent <number>: 0 -> No / 1 -> Yes
	15. -read <number>: read notify 0 -> No / 1 -> Yes
	16. -IMAPserver <string>: IMAP server (mandatory)
	17. -IMAPport <number>: Port (default: 143) (mandatory)
	18. -IMAPsecurity <number>: 0 -> Nothing / 1 -> TLS / 2 -> SSL (default: 0) (mandatory)
	19. -IMAPuser <string>: user (mandatory)
	20. -IMAPpwd <string>: password (encoded) (mandatory)
	21. -IMAPsentfolder <string>: sent folder tosave message (mandatory)
	
#Encode user password:
	1. -encode <string>: user password (mandatory)

#Thanks to
  - Jakub Piwowarczyk
  - John_Tang
  - David Johns
