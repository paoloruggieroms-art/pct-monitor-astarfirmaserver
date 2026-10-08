# AstarFirmaServer - Servizio locale di firma digitale CNS

Servizio locale (PowerShell), sviluppato da **Astar S.r.l.s.** per il servizio PCT Monitor ([sincpdatoscana.it](https://www.sincpdatoscana.it)), che permette di firmare digitalmente documenti PDF usando la Carta Nazionale dei Servizi (CNS) inserita nel lettore del PC dello studio, sia dal pannello web sia dall'app Android abbinata.

## Come funziona

- Il servizio ascolta **esclusivamente su `http://localhost:8765`**: non è raggiungibile dall'esterno, solo da processi in esecuzione sullo stesso PC (browser locale, estensione, app abbinata via tunnel locale).
- Dialoga con la smart card CNS tramite i driver ufficiali **PKCS#11** (OpenSC + driver Bit4id/`bit4xpki.dll`), gli stessi standard usati da Dike/Firma4NG e da ogni altro software di firma qualificata italiano.
- Il **PIN della CNS non viene mai salvato né loggato**: arriva nella richiesta di firma, viene passato direttamente al tool PKCS#11 per autenticarsi con la carta e scartato subito dopo.
- Produce firme **CAdES-BES (.p7m)** o **PAdES-BES (PDF)** standard, verificabili con qualsiasi software di firma conforme eIDAS.
- Espone anche endpoint di sola **verifica** (`/verify`) ed **estrazione del documento originale** (`/extract`) da un file firmato, utili per controllare una firma senza strumenti di terze parti.

## Cosa NON fa

- Non duplica né esporta la chiave privata della CNS: la firma avviene fisicamente sulla carta tramite il lettore.
- Non trasmette il PIN su rete esterna: tutto il traffico resta sul loopback locale del PC.
- Non effettua depositi telematici né invia atti alla cancelleria: produce solo il file firmato, da depositare con gli strumenti ufficiali.

## Installazione

Lo script `InstallFirma.bat` (da eseguire come amministratore):
1. Scarica e installa [OpenSC](https://github.com/OpenSC/OpenSC/releases) se non già presente (libreria PKCS#11 open source).
2. Aggiunge un'esclusione Windows Defender sulla cartella del servizio (necessaria perché l'antivirus talvolta blocca l'accesso ai driver PKCS#11 della smart card).
3. Configura l'avvio automatico del servizio con Windows.
4. Crea un collegamento sul Desktop per avviare/arrestare il servizio manualmente.

## Trasparenza

Questo repository viene pubblicato per consentire la verifica indipendente del funzionamento del software, in risposta a dubbi sulla sicurezza del servizio.

## Licenza

Vedi [LICENSE](LICENSE).
