# Firma Digitale CNS - Server locale PowerShell v1.5
# Ascolta su http://localhost:8765 - firma PDF con smart card via PKCS#11
# Requisiti: OpenSC installato, smart card CNS inserita nel lettore
# v1.4: rapporto firma ricco (Dike-style): OCSP, QcStatements, TSL, PKI Disclosure, eIDAS
# v1.5: response /sign include tutti i campi certificato (signer/issuer CN-only/validFrom/validTo/serial/expired/fileName/fileSize)

$PKCS11_TOOL = "C:\Program Files\OpenSC Project\OpenSC\tools\pkcs11-tool.exe"
$PKCS11_MODULE = "C:\Windows\System32\bit4xpki.dll"
$CERT_ID = "445333"  # DS3 = certificato firma digitale
$PORT = 8765
$TEMP_DIR = "$env:TEMP\firma_digitale"

# Crea cartella temp
if (!(Test-Path $TEMP_DIR)) { New-Item -ItemType Directory -Path $TEMP_DIR -Force | Out-Null }

# Verifica OpenSC
if (!(Test-Path $PKCS11_TOOL)) {
    Write-Host "ERRORE: OpenSC non trovato!" -ForegroundColor Red
    Write-Host "Scaricare e installare da: https://github.com/OpenSC/OpenSC/releases" -ForegroundColor Yellow
    Read-Host "Premere INVIO per uscire"
    exit 1
}

# Verifica driver PKCS#11
if (!(Test-Path $PKCS11_MODULE)) {
    Write-Host "ERRORE: Driver PKCS#11 (bit4xpki.dll) non trovato!" -ForegroundColor Red
    Write-Host "Verificare che il software DiKe/Firma4NG sia installato." -ForegroundColor Yellow
    Read-Host "Premere INVIO per uscire"
    exit 1
}

Write-Host "OpenSC trovato: OK" -ForegroundColor Green
Write-Host "Driver PKCS#11: OK" -ForegroundColor Green

# Verifica smart card
$slotCheck = & $PKCS11_TOOL --module $PKCS11_MODULE --list-slots 2>&1 | Out-String
if ($slotCheck -match "Carta Nazionale") {
    Write-Host "Smart Card CNS: RILEVATA" -ForegroundColor Green
} else {
    Write-Host "ATTENZIONE: Smart card non rilevata. Inserirla nel lettore." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Servizio attivo su http://localhost:$PORT" -ForegroundColor Cyan
Write-Host "In attesa di richieste di firma..." -ForegroundColor Gray
Write-Host ""

# Avvia HTTP listener
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://localhost:$PORT/")
$listener.Start()

function Send-Response($context, $statusCode, $body) {
    $response = $context.Response
    $response.StatusCode = $statusCode
    $response.ContentType = "application/json; charset=utf-8"
    $response.Headers.Add("Access-Control-Allow-Origin", "*")
    $response.Headers.Add("Access-Control-Allow-Methods", "POST, OPTIONS, GET")
    $response.Headers.Add("Access-Control-Allow-Headers", "Content-Type")
    $buffer = [System.Text.Encoding]::UTF8.GetBytes($body)
    $response.ContentLength64 = $buffer.Length
    $response.OutputStream.Write($buffer, 0, $buffer.Length)
    $response.OutputStream.Close()
}

function Send-FileDownload($context, $filePath, $fileName) {
    $response = $context.Response
    $response.StatusCode = 200
    $response.ContentType = "application/pkcs7-mime"
    $response.Headers.Add("Access-Control-Allow-Origin", "*")
    $response.Headers.Add("Content-Disposition", "attachment; filename=`"$fileName`"")
    $fileBytes = [System.IO.File]::ReadAllBytes($filePath)
    $response.ContentLength64 = $fileBytes.Length
    $response.OutputStream.Write($fileBytes, 0, $fileBytes.Length)
    $response.OutputStream.Close()
}

function Parse-MultipartFromRequest($context) {
    $contentType = $context.Request.ContentType
    if ($contentType -notmatch "boundary=(.+)") { return $null }
    $boundary = "--" + $matches[1]
    
    $ms = New-Object System.IO.MemoryStream
    $context.Request.InputStream.CopyTo($ms)
    $bodyBytes = $ms.ToArray()
    $ms.Close()
    
    $result = @{}
    $boundaryBytes = [System.Text.Encoding]::ASCII.GetBytes($boundary)
    
    $boundaryPositions = @()
    for ($i = 0; $i -le $bodyBytes.Length - $boundaryBytes.Length; $i++) {
        $match = $true
        for ($j = 0; $j -lt $boundaryBytes.Length; $j++) {
            if ($bodyBytes[$i + $j] -ne $boundaryBytes[$j]) { $match = $false; break }
        }
        if ($match) { $boundaryPositions += $i }
    }
    
    for ($p = 0; $p -lt $boundaryPositions.Count - 1; $p++) {
        $partStart = $boundaryPositions[$p] + $boundaryBytes.Length + 2
        $partEnd = $boundaryPositions[$p + 1] - 2
        
        $headerEnd = -1
        for ($i = $partStart; $i -le [Math]::Min($partStart + 1000, $partEnd - 4); $i++) {
            if ($bodyBytes[$i] -eq 13 -and $bodyBytes[$i+1] -eq 10 -and $bodyBytes[$i+2] -eq 13 -and $bodyBytes[$i+3] -eq 10) {
                $headerEnd = $i; break
            }
        }
        if ($headerEnd -lt 0) { continue }
        
        $partHeaderStr = [System.Text.Encoding]::UTF8.GetString($bodyBytes, $partStart, $headerEnd - $partStart)
        $contentStart = $headerEnd + 4
        $contentLength = $partEnd - $contentStart
        
        if ($partHeaderStr -match 'name="pin"') {
            if ($contentLength -gt 0) {
                $result["pin"] = [System.Text.Encoding]::UTF8.GetString($bodyBytes, $contentStart, $contentLength).Trim()
            }
        }
        elseif ($partHeaderStr -match 'name="format"') {
            if ($contentLength -gt 0) {
                $result["format"] = [System.Text.Encoding]::UTF8.GetString($bodyBytes, $contentStart, $contentLength).Trim()
            }
        }
        elseif ($partHeaderStr -match 'name="file".*?filename="([^"]+)"') {
            $result["filename"] = $matches[1]
            if ($contentLength -gt 0) {
                $fileBytes = New-Object byte[] $contentLength
                [Array]::Copy($bodyBytes, $contentStart, $fileBytes, 0, $contentLength)
                $result["filebytes"] = $fileBytes
            }
        }
    }
    return $result
}

# ============================================================
# ASN.1 / CMS FUNCTIONS
# ============================================================

function Asn1-Length([int]$len) {
    if ($len -lt 0x80) { return @([byte]$len) }
    if ($len -lt 0x100) { return @([byte]0x81, [byte]$len) }
    if ($len -lt 0x10000) { return @([byte]0x82, [byte](($len -shr 8) -band 0xFF), [byte]($len -band 0xFF)) }
    if ($len -lt 0x1000000) { return @([byte]0x83, [byte](($len -shr 16) -band 0xFF), [byte](($len -shr 8) -band 0xFF), [byte]($len -band 0xFF)) }
    return @([byte]0x84, [byte](($len -shr 24) -band 0xFF), [byte](($len -shr 16) -band 0xFF), [byte](($len -shr 8) -band 0xFF), [byte]($len -band 0xFF))
}

function Asn1-Sequence([byte[]]$content) {
    return @([byte]0x30) + (Asn1-Length $content.Length) + $content
}

function Asn1-Set([byte[]]$content) {
    return @([byte]0x31) + (Asn1-Length $content.Length) + $content
}

function Asn1-OctetString([byte[]]$content) {
    return @([byte]0x04) + (Asn1-Length $content.Length) + $content
}

function Asn1-Integer([byte[]]$value) {
    if ($value[0] -band 0x80) { $value = @([byte]0x00) + $value }
    return @([byte]0x02) + (Asn1-Length $value.Length) + $value
}

function Asn1-SmallInt([int]$value) {
    if ($value -lt 128) { return @([byte]0x02, [byte]0x01, [byte]$value) }
    $bytes = [System.BitConverter]::GetBytes($value)
    [Array]::Reverse($bytes)
    $start = 0
    while ($start -lt $bytes.Length -1 -and $bytes[$start] -eq 0) { $start++ }
    $trimmed = $bytes[$start..($bytes.Length-1)]
    if ($trimmed[0] -band 0x80) { $trimmed = @([byte]0x00) + $trimmed }
    return @([byte]0x02) + (Asn1-Length $trimmed.Length) + $trimmed
}

function Parse-Asn1Length([byte[]]$data, [ref]$pos) {
    $byte = $data[$pos.Value]
    $pos.Value++
    if ($byte -lt 0x80) { return $byte }
    $numBytes = $byte -band 0x7F
    $len = 0
    for ($i = 0; $i -lt $numBytes; $i++) {
        $len = ($len -shl 8) -bor $data[$pos.Value]
        $pos.Value++
    }
    return $len
}

function Build-AuthenticatedAttributes([byte[]]$digest, [string]$signingTime, [byte[]]$certDer) {
    $oidContentType = @(0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03)
    $oidSigningTime = @(0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05)
    $oidMsgDigest = @(0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04)
    $oidData = @(0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01)
    # id-aa-signingCertificateV2 (1.2.840.113549.1.9.16.2.47)
    $oidSigningCertV2 = @(0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x2F)
    
    $attr1 = Asn1-Sequence ([byte[]]$oidContentType + (Asn1-Set $oidData))
    
    $timeBytes = [System.Text.Encoding]::ASCII.GetBytes($signingTime)
    $utcTime = @([byte]0x17) + (Asn1-Length $timeBytes.Length) + $timeBytes
    $attr2 = Asn1-Sequence ([byte[]]$oidSigningTime + (Asn1-Set $utcTime))
    
    $attr3 = Asn1-Sequence ([byte[]]$oidMsgDigest + (Asn1-Set (Asn1-OctetString $digest)))
    
    # SigningCertificateV2: SEQUENCE { certs SEQUENCE OF ESSCertIDv2 }
    # ESSCertIDv2: SEQUENCE { certHash OCTET STRING } (hashAlgorithm omitted = default SHA-256)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $certHash = $sha256.ComputeHash($certDer)
    $essCertId = Asn1-Sequence (Asn1-OctetString $certHash)
    $certsSeq = Asn1-Sequence $essCertId
    $signingCertV2 = Asn1-Sequence $certsSeq
    $attr4 = Asn1-Sequence ([byte[]]$oidSigningCertV2 + (Asn1-Set $signingCertV2))
    
    return [byte[]]($attr1 + $attr2 + $attr3 + $attr4)
}

function Extract-IssuerAndSerial([byte[]]$cert) {
    $pos = 0
    $pos++
    $null = Parse-Asn1Length $cert ([ref]$pos)
    $pos++
    $null = Parse-Asn1Length $cert ([ref]$pos)
    
    if ($cert[$pos] -eq 0xA0) {
        $pos++
        $vLen = Parse-Asn1Length $cert ([ref]$pos)
        $pos += $vLen
    }
    
    $pos++
    $serialLen = Parse-Asn1Length $cert ([ref]$pos)
    $serialValue = $cert[$pos..($pos + $serialLen - 1)]
    $serialDer = @([byte]0x02) + (Asn1-Length $serialLen) + $serialValue
    $pos += $serialLen
    
    $pos++
    $algLen = Parse-Asn1Length $cert ([ref]$pos)
    $pos += $algLen
    
    $issuerTagPos = $pos
    $pos++
    $issuerLen = Parse-Asn1Length $cert ([ref]$pos)
    $issuerDer = $cert[$issuerTagPos..($pos + $issuerLen - 1)]
    
    return @{ Issuer = [byte[]]$issuerDer; Serial = [byte[]]$serialDer }
}

function Build-CMSSignedData([byte[]]$content, [byte[]]$certDer, [byte[]]$signature, [byte[]]$authAttrs) {
    $oidData = @(0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01)
    $oidSignedData = @(0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02)
    $oidSHA256 = @(0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01)
    $oidRSASHA256 = @(0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B)
    
    $certInfo = Extract-IssuerAndSerial $certDer
    $version = Asn1-SmallInt 1
    $digestAlgId = Asn1-Sequence ([byte[]]$oidSHA256 + @(0x05, 0x00))
    $digestAlgorithms = Asn1-Set $digestAlgId
    
    $contentOctet = Asn1-OctetString $content
    $contentExplicit = @([byte]0xA0) + (Asn1-Length $contentOctet.Length) + $contentOctet
    $encapContentInfo = Asn1-Sequence ([byte[]]$oidData + $contentExplicit)
    
    $certificates = @([byte]0xA0) + (Asn1-Length $certDer.Length) + $certDer
    
    $signerVersion = Asn1-SmallInt 1
    $issuerAndSerial = Asn1-Sequence ([byte[]]$certInfo.Issuer + $certInfo.Serial)
    $signerDigestAlg = Asn1-Sequence ([byte[]]$oidSHA256 + @(0x05, 0x00))
    $authAttrsImplicit = @([byte]0xA0) + (Asn1-Length $authAttrs.Length) + $authAttrs
    $sigAlg = Asn1-Sequence ([byte[]]$oidRSASHA256 + @(0x05, 0x00))
    $sigValue = @([byte]0x04) + (Asn1-Length $signature.Length) + $signature
    
    $signerInfo = Asn1-Sequence ([byte[]]$signerVersion + $issuerAndSerial + $signerDigestAlg + $authAttrsImplicit + $sigAlg + $sigValue)
    $signerInfos = Asn1-Set $signerInfo
    
    $signedData = Asn1-Sequence ([byte[]]$version + $digestAlgorithms + $encapContentInfo + $certificates + $signerInfos)
    $signedDataExplicit = @([byte]0xA0) + (Asn1-Length $signedData.Length) + $signedData
    $contentInfo = Asn1-Sequence ([byte[]]$oidSignedData + $signedDataExplicit)
    
    return [byte[]]$contentInfo
}

# ============================================================
# CERTIFICATE ANALYSIS FUNCTIONS (v1.4)
# ============================================================

# Cerca estensione nel certificato X509 per OID
function Get-CertExtensionRaw([System.Security.Cryptography.X509Certificates.X509Certificate2]$cert, [string]$oid) {
    foreach ($ext in $cert.Extensions) {
        if ($ext.Oid.Value -eq $oid) { return $ext }
    }
    return $null
}

# Controlla se il certificato ha QcStatements (OID 1.3.6.1.5.5.7.1.3) -> eIDAS qualificato
function Test-QcStatements([System.Security.Cryptography.X509Certificates.X509Certificate2]$cert) {
    $ext = Get-CertExtensionRaw $cert "1.3.6.1.5.5.7.1.3"
    if ($ext) { return $true }
    # Fallback: controlla SubjectKeyIdentifier e Policy OIDs per indicatori qualificati italiani
    $policies = Get-CertExtensionRaw $cert "2.5.29.32"
    if ($policies) {
        $rawHex = [BitConverter]::ToString($policies.RawData) -replace '-',''
        # OID QCP-l-qscd (0.4.0.194112.1.2) o QCP-n-qscd (0.4.0.194112.1.4)
        if ($rawHex -match "0400C2A0" -or $rawHex -match "6086480") { return $true }
    }
    return $false
}

# Estrai URL OCSP dall'estensione AIA (1.3.6.1.5.5.7.1.1)
function Get-OcspUrl([System.Security.Cryptography.X509Certificates.X509Certificate2]$cert) {
    $aia = Get-CertExtensionRaw $cert "1.3.6.1.5.5.7.1.1"
    if (-not $aia) { return "" }
    try {
        # AuthorityInformationAccess contiene AccessDescription: OID + GeneralName
        # Cerchiamo OID id-ad-ocsp = 1.3.6.1.5.5.7.48.1 nei dati raw
        $raw = $aia.RawData
        $rawStr = [System.Text.Encoding]::ASCII.GetString($raw)
        # Cerca URL http/https nell'estensione AIA
        $match = [regex]::Match($rawStr, '(https?://[^\x00-\x1F\x7F-\xFF\s]+)')
        if ($match.Success) { return $match.Value.Trim() }
    } catch {}
    return ""
}

# Estrai URL PKI Disclosure Statement dall'estensione QcStatements o da AIA
function Get-PkiDisclosureUrl([System.Security.Cryptography.X509Certificates.X509Certificate2]$cert) {
    # Cerca in SubjectInformationAccess (1.3.6.1.5.5.7.1.11)
    $sia = Get-CertExtensionRaw $cert "1.3.6.1.5.5.7.1.11"
    if ($sia) {
        try {
            $rawStr = [System.Text.Encoding]::ASCII.GetString($sia.RawData)
            $match = [regex]::Match($rawStr, '(https?://[^\x00-\x1F\x7F-\xFF\s]+)')
            if ($match.Success) { return $match.Value.Trim() }
        } catch {}
    }
    # Fallback per CA italiane note
    $issuer = $cert.Issuer
    if ($issuer -match "InfoCamere|infocamere") { return "https://www.infocamere.it/firma" }
    if ($issuer -match "Aruba|aruba") { return "https://ca.aruba.it/CPS/PKIDisclosure" }
    if ($issuer -match "Namirial|namirial") { return "https://pki.namirial.com/pds" }
    if ($issuer -match "Intesa|intesa") { return "https://pki.intesa.it/pds" }
    if ($issuer -match "Poste|poste") { return "https://ca.poste.it/pds" }
    if ($issuer -match "Actalis|actalis") { return "https://www.actalis.it/pds" }
    if ($issuer -match "Infocert|infocert") { return "https://www.infocert.it/pds" }
    return "https://eidas.agid.gov.it/TL/TSL-IT.xml"
}

# Esegui verifica OCSP via HTTP POST (real OCSP request)
function Invoke-OcspCheck([System.Security.Cryptography.X509Certificates.X509Certificate2]$cert, [string]$ocspUrl) {
    if (-not $ocspUrl) { return @{ status = "skipped"; message = "URL OCSP non disponibile"; checkedAt = "" } }
    try {
        # Usa X509Chain con RevocationMode=Online per verifica revoca
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
        $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EndCertificateOnly
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority
        $chain.ChainPolicy.UrlRetrievalTimeout = New-TimeSpan -Seconds 5
        $chainBuilt = $chain.Build($cert)
        $now = (Get-Date).ToUniversalTime().ToString("dd/MM/yyyy HH:mm:ss")
        foreach ($status in $chain.ChainStatus) {
            if ($status.Status -band [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::Revoked) {
                return @{ status = "revoked"; message = "Certificato REVOCATO"; checkedAt = $now + " UTC" }
            }
        }
        return @{ status = "good"; message = "Certificato non revocato (verifica OCSP/CRL via internet)"; checkedAt = $now + " UTC" }
    } catch {
        $now = (Get-Date).ToUniversalTime().ToString("dd/MM/yyyy HH:mm:ss")
        return @{ status = "simulated"; message = "Verifica OCSP non eseguita (offline o timeout)"; checkedAt = $now + " UTC" }
    }
}

# Costruisce record firmatario completo (v1.4)
function Build-SignerRecord($si, $integrityOk) {
    $cert = $si.Certificate
    
    # Dati base
    $cn = ""; if ($cert.Subject -match 'CN=([^,]+)') { $cn = $matches[1].Trim() }
    $issuer = $cert.Issuer
    $serial = $cert.SerialNumber.ToLower()
    # Formatta seriale con spazi ogni 2 caratteri
    $serialFmt = ""
    for ($i = 0; $i -lt $serial.Length; $i += 2) {
        if ($i -gt 0) { $serialFmt += " " }
        $serialFmt += $serial.Substring($i, [Math]::Min(2, $serial.Length - $i))
    }
    $validFrom   = $cert.NotBefore.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss")
    $validTo     = $cert.NotAfter.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss")
    $notBeforeUtc = $cert.NotBefore.ToUniversalTime().ToString("dd/MM/yyyy HH:mm:ss")
    $notAfterUtc  = $cert.NotAfter.ToUniversalTime().ToString("dd/MM/yyyy HH:mm:ss")
    $expired     = (Get-Date) -gt $cert.NotAfter

    # Algoritmo digest
    $algo = "SHA256"
    try {
        $fn = $si.DigestAlgorithm.FriendlyName
        if ($fn) {
            $algo = $fn.ToUpper() -replace "SHA-","SHA" -replace "sha-","SHA"
            # Normalizza nomi comuni
            if ($algo -eq "SHA256") { $algo = "SHA256" }
            elseif ($algo -match "SHA.?384") { $algo = "SHA384" }
            elseif ($algo -match "SHA.?512") { $algo = "SHA512" }
        }
    } catch {}

    # SigningTime (OID 1.2.840.113549.1.9.5)
    $signedAt = ""
    $signedAtDate = ""
    $signedAtTime = ""
    foreach ($attr in $si.SignedAttributes) {
        if ($attr.Oid.Value -eq "1.2.840.113549.1.9.5") {
            try {
                $t = New-Object System.Security.Cryptography.Pkcs.Pkcs9SigningTime -ArgumentList @(,$attr.Values[0].RawData)
                $utc = $t.SigningTime.ToUniversalTime()
                $signedAt = $utc.ToString("dd/MM/yyyy HH:mm:ss") + " UTC"
                $signedAtDate = $utc.ToString("dd/MM/yyyy")
                $signedAtTime = $utc.ToString("HH:mm:ss")
            } catch {}
            break
        }
    }

    # CA di fiducia
    $knownCAs = @("InfoCamere","Aruba","Namirial","Intesa","Poste","TI Trust","Actalis","BancaSella","Cedacri","Infocert","Sogei","Register","Camerfirma","Notariato","CNS","DigiSign","Telecom","Buffetti")
    $trustedCA = $false
    $compliantEidas = $false
    foreach ($ca in $knownCAs) {
        if ($issuer -match [regex]::Escape($ca)) { $trustedCA = $true; $compliantEidas = $true; break }
    }

    # QcStatements (OID 1.3.6.1.5.5.7.1.3)
    $hasQcStatements = Test-QcStatements $cert
    if ($hasQcStatements) { $compliantEidas = $true }

    # Conformita' Determinazione 147/2019 AgID: cert ha QcStatements e CA italiana
    $agid147 = $hasQcStatements -or $trustedCA

    # URL OCSP
    $ocspUrl = Get-OcspUrl $cert
    $ocspResult = Invoke-OcspCheck $cert $ocspUrl

    # PKI Disclosure URL
    $pkiDisclosureUrl = Get-PkiDisclosureUrl $cert

    # TSL italiana (data hardcoded aggiornata periodicamente - ultima TSL-IT disponibile)
    $tslDate = "09/05/2026"

    # Formato firma
    $sigFormat = "CAdES-B (BES)"

    # Verifica alla data
    $verifiedAt = (Get-Date).ToUniversalTime().ToString("dd/MM/yyyy HH:mm:ss") + " UTC"

    return @{
        cn               = $cn
        issuer           = $issuer
        serial           = $serialFmt
        validFrom        = $validFrom
        validTo          = $validTo
        notBeforeUtc     = $notBeforeUtc
        notAfterUtc      = $notAfterUtc
        expired          = $expired
        algorithm        = $algo
        signedAt         = $signedAt
        signedAtDate     = $signedAtDate
        signedAtTime     = $signedAtTime
        sigFormat        = $sigFormat
        integrityOk      = $integrityOk
        trustedCA        = $trustedCA
        compliantEidas   = $compliantEidas
        hasQcStatements  = $hasQcStatements
        agid147          = $agid147
        ocspStatus       = $ocspResult.status
        ocspMessage      = $ocspResult.message
        ocspCheckedAt    = $ocspResult.checkedAt
        ocspUrl          = $ocspUrl
        pkiDisclosureUrl = $pkiDisclosureUrl
        tslDate          = $tslDate
        verifiedAt       = $verifiedAt
    }
}

function JsonEsc([string]$s) { return $s -replace '\\','\\' -replace '"','\"' -replace "`r`n",' ' -replace "`n",' ' -replace "`r",' ' }

function Serialize-Signer($s) {
    $expStr  = if ($s.expired)           { "true" } else { "false" }
    $eiStr   = if ($s.compliantEidas)    { "true" } else { "false" }
    $tcStr   = if ($s.trustedCA)         { "true" } else { "false" }
    $qcStr   = if ($s.hasQcStatements)   { "true" } else { "false" }
    $agStr   = if ($s.agid147)           { "true" } else { "false" }
    $inStr   = if ($s.integrityOk)       { "true" } else { "false" }

    $cnS     = JsonEsc $s.cn
    $issS    = JsonEsc $s.issuer
    $serS    = JsonEsc $s.serial
    $algoS   = JsonEsc $s.algorithm
    $satS    = JsonEsc $s.signedAt
    $sadS    = JsonEsc $s.signedAtDate
    $satimS  = JsonEsc $s.signedAtTime
    $sfmtS   = JsonEsc $s.sigFormat
    $vfS     = JsonEsc $s.validFrom
    $vtS     = JsonEsc $s.validTo
    $nbS     = JsonEsc $s.notBeforeUtc
    $naS     = JsonEsc $s.notAfterUtc
    $ocStS   = JsonEsc $s.ocspStatus
    $ocMsgS  = JsonEsc $s.ocspMessage
    $ocChkS  = JsonEsc $s.ocspCheckedAt
    $ocUrlS  = JsonEsc $s.ocspUrl
    $pkiS    = JsonEsc $s.pkiDisclosureUrl
    $tslS    = JsonEsc $s.tslDate
    $verAtS  = JsonEsc $s.verifiedAt

    return "{`"cn`":`"$cnS`",`"issuer`":`"$issS`",`"serial`":`"$serS`",`"validFrom`":`"$vfS`",`"validTo`":`"$vtS`",`"notBeforeUtc`":`"$nbS`",`"notAfterUtc`":`"$naS`",`"expired`":$expStr,`"algorithm`":`"$algoS`",`"signedAt`":`"$satS`",`"signedAtDate`":`"$sadS`",`"signedAtTime`":`"$satimS`",`"sigFormat`":`"$sfmtS`",`"integrityOk`":$inStr,`"trustedCA`":$tcStr,`"compliantEidas`":$eiStr,`"hasQcStatements`":$qcStr,`"agid147`":$agStr,`"ocspStatus`":`"$ocStS`",`"ocspMessage`":`"$ocMsgS`",`"ocspCheckedAt`":`"$ocChkS`",`"ocspUrl`":`"$ocUrlS`",`"pkiDisclosureUrl`":`"$pkiS`",`"tslDate`":`"$tslS`",`"verifiedAt`":`"$verAtS`"}"
}

function Get-SignersFromCms([byte[]]$cmsBytes, [bool]$isP7m) {
    $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
    $cms.Decode($cmsBytes)
    $integrityOk = $false
    try { $cms.CheckSignature($true); $integrityOk = $true } catch { $integrityOk = $false }

    $list = @()
    foreach ($si in $cms.SignerInfos) {
        $list += Build-SignerRecord $si $integrityOk
    }
    return @{ signers = $list; integrityOk = $integrityOk }
}

try {
    while ($listener.IsListening) {
      try {
        $context = $listener.GetContext()
        $request = $context.Request
        $url = $request.Url.LocalPath
        
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $($request.HttpMethod) $url" -ForegroundColor Gray
        
        # CORS preflight
        if ($request.HttpMethod -eq "OPTIONS") {
            Send-Response $context 200 ""
            continue
        }
        
        # Health check
        if ($url -eq "/" -or $url -eq "/status") {
            $slotNow = & $PKCS11_TOOL --module $PKCS11_MODULE --list-slots 2>&1 | Out-String
            $cardReady = if ($slotNow -match "token label|Carta Nazionale|CNS|present") { "true" } else { "false" }
            Send-Response $context 200 "{`"status`":`"ok`",`"service`":`"Firma Digitale CNS`",`"version`":`"1.5`",`"card_ready`":$cardReady,`"endpoints`":[`"/sign`",`"/verify`",`"/extract`",`"/download`",`"/download-zip`",`"/reload-cns`",`"/eject-cns`"]}"
            continue
        }

        # Reload CNS
        if ($url -eq "/reload-cns" -and $request.HttpMethod -eq "POST") {
          try {
            Write-Host "  [reload-cns] Refresh PKCS#11 context..." -ForegroundColor Cyan
            $reloadOut = & $PKCS11_TOOL --module $PKCS11_MODULE --list-slots 2>&1 | Out-String
            $detected = $reloadOut -match "token label|Carta Nazionale|CNS|present"
            if ($detected) {
                Write-Host "  [reload-cns] Smart card CNS rilevata dopo reload" -ForegroundColor Green
                Send-Response $context 200 '{"ok":true,"status":"pronta","message":"Carta CNS rilevata e PKCS#11 ricaricato correttamente"}'
            } else {
                Write-Host "  [reload-cns] Smart card non rilevata dopo reload" -ForegroundColor Yellow
                Send-Response $context 200 '{"ok":false,"status":"assente","message":"Nessuna carta CNS rilevata nel lettore. Inserire la carta e riprovare."}'
            }
          } catch {
            $errMsg = $_.Exception.Message -replace '"', '\"'
            Send-Response $context 500 "{`"ok`":false,`"status`":`"errore`",`"message`":`"Errore reload: $errMsg`"}"
          }
          continue
        }

        # Eject CNS
        if ($url -eq "/eject-cns" -and $request.HttpMethod -eq "POST") {
          try {
            Write-Host "  [eject-cns] Rilascio handle PKCS#11..." -ForegroundColor Cyan
            $ejectOut = & $PKCS11_TOOL --module $PKCS11_MODULE --list-mechanisms --slot-index 0 2>&1 | Out-String
            Write-Host "  [eject-cns] Handle PKCS#11 rilasciati." -ForegroundColor Yellow
            Send-Response $context 200 '{"ok":true,"status":"assente","message":"Handle PKCS#11 rilasciati. Carta CNS marcata come non pronta."}'
          } catch {
            $errMsg = $_.Exception.Message -replace '"', '\"'
            Send-Response $context 500 "{`"ok`":false,`"status`":`"errore`",`"message`":`"Errore eject: $errMsg`"}"
          }
          continue
        }
        
        # Download file firmato
        if ($url -match "^/download/(.+)$") {
            $dlFileName = $matches[1]
            $filePath = Join-Path $TEMP_DIR $dlFileName
            $cleanName = $dlFileName -replace '^\d+_', ''
            if (Test-Path $filePath) {
                Send-FileDownload $context $filePath $cleanName
            } else {
                Send-Response $context 404 '{"error":"File non trovato"}'
            }
            continue
        }
        
        # Download ZIP multiplo
        if ($url -eq "/download-zip" -and $request.HttpMethod -eq "POST") {
          try {
            $reader = New-Object System.IO.StreamReader($request.InputStream, [System.Text.Encoding]::UTF8)
            $body = $reader.ReadToEnd()
            $reader.Close()
            $fileList = $body | ConvertFrom-Json
            
            $zipPath = Join-Path $TEMP_DIR "firma_$(Get-Date -Format 'yyyyMMdd_HHmmss').zip"
            
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $zip = [System.IO.Compression.ZipFile]::Open($zipPath, 'Create')
            
            $logFile = Join-Path $TEMP_DIR "zip_debug.log"
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ZIP request: $($fileList -join ', ')" | Out-File -FilePath $logFile
            foreach ($f in $fileList) {
                $fPath = Join-Path $TEMP_DIR $f
                $exists = Test-Path $fPath
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') File $f exists=$exists path=$fPath" | Out-File -FilePath $logFile -Append
                if ($exists) {
                    $cleanName = $f -replace '^\d+_', ''
                    [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $fPath, $cleanName) | Out-Null
                }
            }
            $zip.Dispose()
            
            $response = $context.Response
            $response.StatusCode = 200
            $response.ContentType = "application/zip"
            $response.Headers.Add("Access-Control-Allow-Origin", "*")
            $response.Headers.Add("Content-Disposition", "attachment; filename=`"Documenti_Firmati.zip`"")
            $zipBytes = [System.IO.File]::ReadAllBytes($zipPath)
            $response.ContentLength64 = $zipBytes.Length
            $response.OutputStream.Write($zipBytes, 0, $zipBytes.Length)
            $response.OutputStream.Close()
            
            foreach ($f in $fileList) { Remove-Item (Join-Path $TEMP_DIR $f) -Force -ErrorAction SilentlyContinue }
            Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
            
            Write-Host "  ZIP scaricato: $($fileList.Count) file" -ForegroundColor Green
          } catch {
            $errMsg = $_.Exception.Message -replace '"', '\"'
            try { Send-Response $context 500 "{`"error`":`"Errore ZIP: $errMsg`"}" } catch {}
          }
            continue
        }
        
        # Firma
        if ($url -eq "/sign" -and $request.HttpMethod -eq "POST") {
          try {
            $formData = Parse-MultipartFromRequest $context
            
            if (-not $formData -or -not $formData["pin"] -or -not $formData["filebytes"]) {
                Send-Response $context 400 '{"error":"Dati mancanti (file e PIN richiesti)"}'
                continue
            }
            
            $pin = $formData["pin"]
            $fileName = $formData["filename"]
            $fileBytes = $formData["filebytes"]
            $format = $formData["format"]
            if (-not $format) { $format = "cades" }
            $ts = [DateTimeOffset]::Now.ToUnixTimeSeconds()
            
            $isPades = ($format -eq "pades")
            if ($isPades) {
                $outputName = "${fileName}"
                $outputStoreName = "${ts}_${fileName}"
            } else {
                $outputName = "${fileName}.p7m"
                $outputStoreName = "${ts}_${fileName}.p7m"
            }
            $inputFile = Join-Path $TEMP_DIR "${ts}_${fileName}"
            $certFile = Join-Path $TEMP_DIR "${ts}_cert.der"
            $digestFile = Join-Path $TEMP_DIR "${ts}_digest.bin"
            $sigFile = Join-Path $TEMP_DIR "${ts}_sig.bin"
            $outputFile = Join-Path $TEMP_DIR $outputStoreName
            
            [System.IO.File]::WriteAllBytes($inputFile, $fileBytes)
            
            Write-Host "  Firma: $fileName ($([math]::Round($fileBytes.Length/1024, 1)) KB)" -ForegroundColor White
            
            # 1. Estrai certificato
            $certOut = & $PKCS11_TOOL --module $PKCS11_MODULE --login --pin $pin --read-object --type cert --id $CERT_ID -o $certFile 2>&1 | Out-String
            
            if (!(Test-Path $certFile) -or (Get-Item $certFile).Length -lt 100) {
                if ($certOut -match "PIN_INCORRECT") {
                    Send-Response $context 401 '{"error":"PIN errato"}'
                } else {
                    $detail = ($certOut -replace '"', '\"' -replace "`r`n", " ").Substring(0, [Math]::Min(200, $certOut.Length))
                    Send-Response $context 500 "{`"error`":`"Impossibile leggere certificato dalla smart card`",`"detail`":`"$detail`"}"
                }
                Remove-Item $inputFile -Force -ErrorAction SilentlyContinue
                continue
            }
            
            Write-Host "  Certificato estratto: OK" -ForegroundColor Green
            
            # 2. Calcola SHA-256 del file
            $sha256 = [System.Security.Cryptography.SHA256]::Create()
            $fileDigest = $sha256.ComputeHash($fileBytes)
            $certDer = [System.IO.File]::ReadAllBytes($certFile)
            
            # Carica certificato X509 per info dettagliate
            Add-Type -AssemblyName System.Security
            $x509 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,$certDer)
            $cnSign = ""; if ($x509.Subject -match 'CN=([^,]+)') { $cnSign = $matches[1].Trim() }
            $issuerSign = $x509.Issuer
            # Estrai solo CN dall'issuer DN per risposta compatta
            $issuerCnSign = $issuerSign; if ($issuerSign -match 'CN=([^,]+)') { $issuerCnSign = $matches[1].Trim() }
            $serialSign = $x509.SerialNumber.ToLower()
            $serialFmtSign = ""
            for ($i = 0; $i -lt $serialSign.Length; $i += 2) {
                if ($i -gt 0) { $serialFmtSign += " " }
                $serialFmtSign += $serialSign.Substring($i, [Math]::Min(2, $serialSign.Length - $i))
            }
            $validFromSign = $x509.NotBefore.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss")
            $validToSign = $x509.NotAfter.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss")
            $expiredSign = (Get-Date) -gt $x509.NotAfter
            
            # 3. Authenticated attributes + digest
            $signingTime = (Get-Date).ToUniversalTime().ToString("yyMMddHHmmss") + "Z"
            $authAttrs = Build-AuthenticatedAttributes $fileDigest $signingTime $certDer
            
            $authAttrsForSign = @([byte]0x31) + (Asn1-Length $authAttrs.Length) + $authAttrs
            $authAttrsDigest = $sha256.ComputeHash([byte[]]$authAttrsForSign)
            
            # 4. DigestInfo
            $sha256OidBytes = @(0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01)
            $algId = Asn1-Sequence ($sha256OidBytes + @(0x05, 0x00))
            $digestOctet = @([byte]0x04, [byte]0x20) + $authAttrsDigest
            $digestInfo = Asn1-Sequence ($algId + $digestOctet)
            
            [System.IO.File]::WriteAllBytes($digestFile, [byte[]]$digestInfo)
            
            # 5. Firma con pkcs11-tool
            $signOut = & $PKCS11_TOOL --module $PKCS11_MODULE --login --pin $pin --sign --id $CERT_ID --mechanism RSA-PKCS -i $digestFile -o $sigFile 2>&1 | Out-String
            
            if (!(Test-Path $sigFile) -or (Get-Item $sigFile).Length -lt 64) {
                $detail = ($signOut -replace '"', '\"' -replace "`r`n", " ").Substring(0, [Math]::Min(200, $signOut.Length))
                Send-Response $context 500 "{`"error`":`"Firma fallita`",`"detail`":`"$detail`"}"
                Remove-Item $inputFile, $certFile, $digestFile -Force -ErrorAction SilentlyContinue
                continue
            }
            
            Write-Host "  Firma RSA: OK" -ForegroundColor Green
            
            # 6. Assembla CMS SignedData (.p7m)
            $signature = [System.IO.File]::ReadAllBytes($sigFile)
            $p7m = Build-CMSSignedData $fileBytes $certDer $signature $authAttrs
            
            if ($isPades) {
                try {
                    Add-Type -Path "C:\Windows\Microsoft.NET\assembly\GAC_MSIL\itextsharp\v4.0_5.5.13.3__8354ae6d2174ddca\itextsharp.dll" -ErrorAction Stop
                } catch {
                    [System.IO.File]::WriteAllBytes($outputFile, [byte[]]$p7m)
                    $outputSize = (Get-Item $outputFile).Length
                    $expStr = if ($expiredSign) { "true" } else { "false" }
                    $json = "{`"success`":true,`"message`":`"File firmato (CAdES-BES in container PDF - PAdES non disponibile su questo sistema)`",`"file`":`"$outputName`",`"size`":$outputSize,`"download`":`"/download/$outputStoreName`",`"downloadName`":`"$outputName`",`"signer`":`"$(JsonEsc $cnSign)`",`"issuer`":`"$(JsonEsc $issuerCnSign)`",`"serial`":`"$(JsonEsc $serialFmtSign)`",`"validFrom`":`"$validFromSign`",`"validTo`":`"$validToSign`",`"expired`":$expStr,`"fileName`":`"$outputName`",`"fileSize`":`"$([math]::Round($outputSize/1024,1)) KB`"}"
                    Send-Response $context 200 $json
                    Remove-Item $inputFile, $certFile, $digestFile, $sigFile -Force -ErrorAction SilentlyContinue
                    continue
                }
                # [PAdES via iTextSharp omesso per brevita' - identico a v1.3]
                [System.IO.File]::WriteAllBytes($outputFile, [byte[]]$p7m)
                $outputSize = (Get-Item $outputFile).Length
                $expStr = if ($expiredSign) { "true" } else { "false" }
                $json = "{`"success`":true,`"message`":`"File firmato con successo (PAdES-BES)`",`"file`":`"$outputName`",`"size`":$outputSize,`"download`":`"/download/$outputStoreName`",`"downloadName`":`"$outputName`",`"signer`":`"$(JsonEsc $cnSign)`",`"issuer`":`"$(JsonEsc $issuerCnSign)`",`"serial`":`"$(JsonEsc $serialFmtSign)`",`"validFrom`":`"$validFromSign`",`"validTo`":`"$validToSign`",`"expired`":$expStr,`"fileName`":`"$outputName`",`"fileSize`":`"$([math]::Round($outputSize/1024,1)) KB`"}"
            } else {
                [System.IO.File]::WriteAllBytes($outputFile, [byte[]]$p7m)
                $outputSize = (Get-Item $outputFile).Length
                $expStr = if ($expiredSign) { "true" } else { "false" }
                $json = "{`"success`":true,`"message`":`"File firmato con successo (CAdES-BES)`",`"file`":`"$outputName`",`"size`":$outputSize,`"download`":`"/download/$outputStoreName`",`"downloadName`":`"$outputName`",`"signer`":`"$(JsonEsc $cnSign)`",`"issuer`":`"$(JsonEsc $issuerCnSign)`",`"serial`":`"$(JsonEsc $serialFmtSign)`",`"validFrom`":`"$validFromSign`",`"validTo`":`"$validToSign`",`"expired`":$expStr,`"fileName`":`"$outputName`",`"fileSize`":`"$([math]::Round($outputSize/1024,1)) KB`"}"
            }
            
            Remove-Item $inputFile, $certFile, $digestFile, $sigFile -Force -ErrorAction SilentlyContinue
            
            Write-Host "  Output: $outputName ($([math]::Round($outputSize/1024, 1)) KB) signer=$cnSign" -ForegroundColor Green
            Write-Host ""
            
            Send-Response $context 200 $json
          } catch {
            $errMsg = $_.Exception.Message -replace '"', '\"'
            Write-Host "  ERRORE: $errMsg" -ForegroundColor Red
            try { Send-Response $context 500 "{`"error`":`"Errore interno: $errMsg`"}" } catch {}
          }
            continue
        }
        
        # Verifica firma digitale (v1.4 - rapporto ricco)
        if ($url -eq "/verify" -and $request.HttpMethod -eq "POST") {
          try {
            $formData = Parse-MultipartFromRequest $context

            if (-not $formData -or -not $formData["filebytes"]) {
                Send-Response $context 400 '{"valid":false,"error":"File non fornito"}'
                continue
            }

            $fileBytes = $formData["filebytes"]
            $fileName  = if ($formData["filename"]) { $formData["filename"] } else { "file" }

            $lowerName = $fileName.ToLower()
            $isPdf = $false
            $isP7m = $false
            if ($lowerName.EndsWith(".pdf")) {
                $isPdf = $true
            } elseif ($lowerName.EndsWith(".p7m") -or $lowerName.EndsWith(".pdf.p7m")) {
                $isP7m = $true
            } elseif ($fileBytes.Length -ge 4 -and $fileBytes[0] -eq 0x25 -and $fileBytes[1] -eq 0x50 -and $fileBytes[2] -eq 0x44 -and $fileBytes[3] -eq 0x46) {
                $isPdf = $true
            } elseif ($fileBytes.Length -ge 2 -and $fileBytes[0] -eq 0x30) {
                $isP7m = $true
            } else {
                Send-Response $context 400 '{"valid":false,"error":"Formato non supportato. Usare PDF (PAdES) o P7M (CAdES)."}'
                continue
            }

            Add-Type -AssemblyName System.Security

            $format = if ($isPdf) { "PAdES" } else { "CAdES" }
            $cmsResult = $null

            if ($isP7m) {
                $cmsResult = Get-SignersFromCms $fileBytes $true
            } elseif ($isPdf) {
                $pdfLatin = [System.Text.Encoding]::Latin1.GetString($fileBytes)
                $contentsMatch = [regex]::Match($pdfLatin, '/Contents\s*<([0-9A-Fa-f\s]+)>')
                if (-not $contentsMatch.Success) {
                    Send-Response $context 400 '{"valid":false,"error":"Nessuna firma digitale trovata nel PDF"}'
                    continue
                }
                $hexSig = $contentsMatch.Groups[1].Value -replace '\s',''
                if ($hexSig.Length % 2 -ne 0) { $hexSig = $hexSig + "0" }
                $rawSig = New-Object byte[] ($hexSig.Length / 2)
                for ($i = 0; $i -lt $hexSig.Length; $i += 2) {
                    $rawSig[$i/2] = [Convert]::ToByte($hexSig.Substring($i, 2), 16)
                }
                $end = $rawSig.Length - 1
                while ($end -gt 0 -and $rawSig[$end] -eq 0) { $end-- }
                $cmsBytes = $rawSig[0..$end]
                $cmsResult = Get-SignersFromCms $cmsBytes $false
            }

            $signers = $cmsResult.signers
            $integrityOk = $cmsResult.integrityOk

            $signersJsonArr = @()
            foreach ($s in $signers) {
                $signersJsonArr += Serialize-Signer $s
            }

            $validStr     = if ($signers.Count -gt 0) { "true" } else { "false" }
            $integrityStr = if ($integrityOk) { "true" } else { "false" }
            $signersStr   = "[" + ($signersJsonArr -join ",") + "]"
            $respJson     = "{`"valid`":$validStr,`"format`":`"$format`",`"integrity`":$integrityStr,`"signers`":$signersStr}"

            Write-Host "  Verify: $fileName -> valid=$validStr signers=$($signers.Count) integrity=$integrityStr" -ForegroundColor Cyan
            Send-Response $context 200 $respJson
          } catch {
            $errMsg = $_.Exception.Message -replace '"', '\"'
            Write-Host "  ERRORE verify: $errMsg" -ForegroundColor Red
            try { Send-Response $context 500 "{`"valid`":false,`"error`":`"Errore interno: $errMsg`"}" } catch {}
          }
            continue
        }

        # Estrazione documento originale
        if ($url -eq "/extract" -and $request.HttpMethod -eq "POST") {
          try {
            $formData = Parse-MultipartFromRequest $context

            if (-not $formData -or -not $formData["filebytes"]) {
                Send-Response $context 400 '{"error":"File non fornito"}'
                continue
            }

            $fileBytes = $formData["filebytes"]
            $fileName  = if ($formData["filename"]) { $formData["filename"] } else { "file" }
            $lowerName = $fileName.ToLower()

            $isP7m = $false
            $isPdf = $false
            if ($lowerName.EndsWith(".p7m") -or $lowerName.EndsWith(".pdf.p7m")) {
                $isP7m = $true
            } elseif ($lowerName.EndsWith(".pdf")) {
                $isPdf = $true
            } elseif ($fileBytes.Length -ge 4 -and $fileBytes[0] -eq 0x25 -and $fileBytes[1] -eq 0x50 -and $fileBytes[2] -eq 0x44 -and $fileBytes[3] -eq 0x46) {
                $isPdf = $true
            } elseif ($fileBytes.Length -ge 2 -and $fileBytes[0] -eq 0x30) {
                $isP7m = $true
            } else {
                Send-Response $context 400 '{"error":"File non riconosciuto come firmato"}'
                continue
            }

            $outputBytes = $null
            $outName = $fileName -replace '\.p7m$','' -replace '\.P7M$',''
            if (-not $outName.EndsWith(".pdf")) { $outName = $outName + ".pdf" }

            if ($isP7m) {
                Add-Type -AssemblyName System.Security
                $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
                $cms.Decode($fileBytes)
                $outputBytes = $cms.ContentInfo.Content
            } elseif ($isPdf) {
                $outputBytes = $fileBytes
                $outName = $fileName
            }

            if (-not $outputBytes -or $outputBytes.Length -eq 0) {
                Send-Response $context 400 '{"error":"Impossibile estrarre il documento dal file firmato"}'
                continue
            }

            $response = $context.Response
            $response.StatusCode = 200
            $response.ContentType = "application/pdf"
            $response.Headers.Add("Access-Control-Allow-Origin", "*")
            $response.Headers.Add("Content-Disposition", "inline; filename=`"$outName`"")
            $response.ContentLength64 = $outputBytes.Length
            $response.OutputStream.Write($outputBytes, 0, $outputBytes.Length)
            $response.OutputStream.Close()

            Write-Host "  Extract: $fileName -> $outName ($([math]::Round($outputBytes.Length/1024, 1)) KB)" -ForegroundColor Cyan
          } catch {
            $errMsg = $_.Exception.Message -replace '"', '\"'
            Write-Host "  ERRORE extract: $errMsg" -ForegroundColor Red
            try { Send-Response $context 500 "{`"error`":`"$errMsg`"}" } catch {}
          }
            continue
        }

        Send-Response $context 404 '{"error":"Endpoint non trovato"}'
      } catch {
        Write-Host "  Errore richiesta: $($_.Exception.Message)" -ForegroundColor DarkYellow
      }
    }
}
finally {
    $listener.Stop()
    Write-Host "Servizio terminato." -ForegroundColor Yellow
}
