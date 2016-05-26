#include "Main.h"

//=======================================================================
// WinMain - EntryPoint
//=======================================================================
int main(int argc, char** argv)
{
	iResult = 0;

	if ((argc - 1) > 0)
	{
		std::cout << "\n*****************************************************\n";
		std::cout << "*                      SMTP                         *\n";
		std::cout << "*****************************************************\n\n";

		iResult = HandleConsoleParam(argc, argv);
	}
	else
	{
		iResult = 1;

		std::cout << "\n[!] - " << iResult << " - Nessun parametro trovato!\n";
		std::cout << "\nUtilizzo:\n";
		std::cout << "\t-server <stringa>: indirizzo server SMTP (obbligatorio)\n";
		std::cout << "\t-port <numero>: porta comunicazione (default: 25)\n";
		std::cout << "\t-security <numero>: 0 -> Nessuna / 1 -> TLS / 2 -> SSL (default: 0)\n";
		std::cout << "\t-auth <numero>: 0 -> No / 1 -> Si (default: 0)\n";
		std::cout << "\t-user <stringa>: utente\n";
		std::cout << "\t-pwd <stringa>: password\n";
		std::cout << "\t-from <stringa>: mittente (obbligatorio)\n";
		std::cout << "\t-to <stringa>: destinatario (obbligatorio)\n";
		std::cout << "\t-cc <stringa>: copia conoscenza\n";
		std::cout << "\t-bcc <stringa>: copia conoscenza nascosta\n";
		std::cout << "\t-subject <stringa>: Oggetto mail (obbligatorio)\n";
		std::cout << "\t-body <stringa>: corpo della mail\n";
		std::cout << "\t-attachment <stringa>: allegati\n";
		std::cout << "\t-urgent <numero>: 0 -> No / 1 -> Si\n";
		std::cout << "\t-read <numero>: conferma lettura 0 -> No / 1 -> Si\n";
		std::cout << "\t-save <numero>: 0 -> No / 1 -> Si\n";
		std::cout << "\t-IMAPserver <stringa>: indirizzo server IMAP (obbligatorio)\n";
		std::cout << "\t-IMAPport <numero>: porta comunicazione (default: 143)\n";
		std::cout << "\t-IMAPsecurity <numero>: 0 -> Nessuna / 1 -> TLS / 2 -> SSL (default: 0)\n";
		std::cout << "\t-IMAPuser <stringa>: utente\n";
		std::cout << "\t-IMAPpwd <stringa>: password\n";
		std::cout << "\t-IMAPsentfolder <stringa>: Cartella destinata al salvataggio della mail\n";
		std::cout << "\nCodifica password autenticazione:\n";
		std::cout << "\t-encode <stringa>: restituisce la password criptata (obbligatorio)\n\n";
	}

	return iResult;
}
