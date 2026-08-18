<#
.SYNOPSIS
    Generate mTLS certificates for the EDR platform.
.DESCRIPTION
    Creates a self-signed CA and issues certificates for:
    - server (backend)
    - agent (endpoint)
    - scanner
    - gui (management console)
.NOTES
    Requires OpenSSL installed or uses Rust's rcgen if available.
    For development only. Production should use a proper PKI.
#>

$ErrorActionPreference = "Stop"
$certsDir = Join-Path $PWD "certs"
if (-not (Test-Path $certsDir)) { New-Item -ItemType Directory -Path $certsDir -Force | Out-Null }

$days = 3650
$bits = 4096

Write-Host "Generating mTLS certificates in $certsDir" -ForegroundColor Cyan

# Try to use OpenSSL
$openssl = Get-Command "openssl" -ErrorAction SilentlyContinue

if ($openssl) {
    # CA key and certificate
    & openssl genrsa -out "$certsDir/ca.key" $bits
    & openssl req -x509 -new -nodes -key "$certsDir/ca.key" -sha256 -days $days `
        -out "$certsDir/ca.pem" `
        -subj "/C=US/O=EDR Development/CN=EDR Root CA"

    function New-Cert {
        param([string]$Name, [string]$CN)
        & openssl genrsa -out "$certsDir/$Name.key" $bits
        & openssl req -new -key "$certsDir/$Name.key" -out "$certsDir/$Name.csr" `
            -subj "/C=US/O=EDR Development/CN=$CN"
        $sanCfg = "$certsDir/${Name}_san.cfg"
        Set-Content -Path $sanCfg -Value "subjectAltName=DNS:$CN,DNS:localhost,IP:127.0.0.1" -Encoding ASCII
        & openssl x509 -req -in "$certsDir/$Name.csr" -CA "$certsDir/ca.pem" -CAkey "$certsDir/ca.key" `
            -CAcreateserial -out "$certsDir/$Name.pem" -days $days -sha256 `
            -extfile $sanCfg
        Remove-Item "$certsDir/$Name.csr" -Force
        Remove-Item $sanCfg -Force
    }

    New-Cert "server" "edr-server"
    New-Cert "agent" "edr-agent"
    New-Cert "scanner" "edr-scanner"
    New-Cert "gui" "edr-gui"
} else {
    Write-Host "OpenSSL not found. Generating self-signed certs with .NET..." -ForegroundColor Yellow

    # C# helper to export RSA private key as PKCS#1 PEM (works on .NET Framework 4.8)
    $pkcs1Helper = @"
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

public static class Pkcs1Writer
{
    public static string ExportPrivateKeyPem(RSAParameters parameters)
    {
        byte[] der = ExportPrivateKeyDer(parameters);
        StringBuilder sb = new StringBuilder();
        sb.AppendLine("-----BEGIN RSA PRIVATE KEY-----");
        sb.AppendLine(Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks));
        sb.AppendLine("-----END RSA PRIVATE KEY-----");
        return sb.ToString();
    }

    static byte[] ExportPrivateKeyDer(RSAParameters parameters)
    {
        var items = new List<byte[]>();
        items.Add(EncodeInteger(new byte[] { 0 })); // version = 0
        items.Add(EncodeInteger(StripLeadingZeros(parameters.Modulus)));
        items.Add(EncodeInteger(StripLeadingZeros(parameters.Exponent)));
        items.Add(EncodeInteger(StripLeadingZeros(parameters.D)));
        items.Add(EncodeInteger(StripLeadingZeros(parameters.P)));
        items.Add(EncodeInteger(StripLeadingZeros(parameters.Q)));
        items.Add(EncodeInteger(StripLeadingZeros(parameters.DP)));
        items.Add(EncodeInteger(StripLeadingZeros(parameters.DQ)));
        items.Add(EncodeInteger(StripLeadingZeros(parameters.InverseQ)));
        return EncodeSequence(items);
    }

    static byte[] StripLeadingZeros(byte[] value)
    {
        if (value == null || value.Length == 0) return new byte[] { 0 };
        int start = 0;
        while (start < value.Length - 1 && value[start] == 0) start++;
        byte[] trimmed = new byte[value.Length - start];
        Array.Copy(value, start, trimmed, 0, trimmed.Length);
        return trimmed;
    }

    static byte[] EncodeInteger(byte[] rawValue)
    {
        if (rawValue[0] >= 0x80)
        {
            byte[] prefixed = new byte[rawValue.Length + 1];
            prefixed[0] = 0x00;
            Array.Copy(rawValue, 0, prefixed, 1, rawValue.Length);
            return EncodeTag(0x02, prefixed);
        }
        return EncodeTag(0x02, rawValue);
    }

    static byte[] EncodeSequence(List<byte[]> items)
    {
        var content = new List<byte>();
        foreach (var item in items) content.AddRange(item);
        return EncodeTag(0x30, content.ToArray());
    }

    static byte[] EncodeTag(byte tag, byte[] content)
    {
        var result = new List<byte> { tag };
        if (content.Length < 128)
        {
            result.Add((byte)content.Length);
        }
        else
        {
            byte[] lenBytes = BitConverter.GetBytes(content.Length);
            if (BitConverter.IsLittleEndian) Array.Reverse(lenBytes);
            int start = 0;
            while (start < lenBytes.Length - 1 && lenBytes[start] == 0) start++;
            int numLenBytes = lenBytes.Length - start;
            result.Add((byte)(0x80 | numLenBytes));
            for (int i = start; i < lenBytes.Length; i++) result.Add(lenBytes[i]);
        }
        result.AddRange(content);
        return result.ToArray();
    }
}
"@

    Add-Type -TypeDefinition $pkcs1Helper -Language CSharp

    # Precompute validity bounds so all certs share consistent timestamps
    $notBefore = [System.DateTimeOffset]::Now.AddDays(-1)
    $notAfter  = [System.DateTimeOffset]::Now.AddDays(3650)

    # .NET helper to create a cert + key pair as PEM files
    function New-CertDotNet {
        param(
            [string]$Name,
            [string]$CN,
            [string]$DnsNames = "",
            [string]$IpAddresses = "",
            [bool]$IsCA = $false,
            [System.Security.Cryptography.X509Certificates.X509Certificate2]$SigningCert = $null
        )

        $rsa = [System.Security.Cryptography.RSA]::Create(4096)
        $subject = "CN=$CN, O=EDR Development, C=US"
        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            $subject, $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )

        if ($IsCA) {
            $request.CertificateExtensions.Add(
                [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true)
            ) | Out-Null
            $request.CertificateExtensions.Add(
                [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
                    [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor
                    [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign,
                    $true
                )
            ) | Out-Null
            $cert = $request.CreateSelfSigned($notBefore, $notAfter.AddDays(1))
        } else {
            $eku = [System.Security.Cryptography.OidCollection]::new()
            $eku.Add([System.Security.Cryptography.Oid]::new("1.3.6.1.5.5.7.3.1")) | Out-Null
            $eku.Add([System.Security.Cryptography.Oid]::new("1.3.6.1.5.5.7.3.2")) | Out-Null
            $request.CertificateExtensions.Add(
                [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($eku, $true)
            ) | Out-Null

            $request.CertificateExtensions.Add(
                [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
                    [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor
                    [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment,
                    $true
                )
            ) | Out-Null

            $san = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
            if ($DnsNames) { $DnsNames -split ',' | ForEach-Object { $san.AddDnsName($_.Trim()) } }
            if ($IpAddresses) { $IpAddresses -split ',' | ForEach-Object { $san.AddIpAddress([System.Net.IPAddress]::Parse($_.Trim())) } }
            $request.CertificateExtensions.Add($san.Build()) | Out-Null

            $serial = [Guid]::NewGuid().ToByteArray()
            $cert = $request.Create($SigningCert, $notBefore, $notAfter, $serial)
        }

        # Export certificate as PEM
        $certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
        $certPem = "-----BEGIN CERTIFICATE-----`n"
        $certPem += [Convert]::ToBase64String($certBytes, [System.Base64FormattingOptions]::InsertLineBreaks)
        $certPem += "`n-----END CERTIFICATE-----`n"

        # Export private key as PKCS#1 PEM (works on .NET Framework 4.8)
        $params = $rsa.ExportParameters($true)
        $keyPem = [Pkcs1Writer]::ExportPrivateKeyPem($params)

        Set-Content -Path "$certsDir/$Name.pem" -Value $certPem -Encoding ASCII
        Set-Content -Path "$certsDir/$Name.key" -Value $keyPem -Encoding ASCII

        Write-Host "  $Name.pem + $Name.key" -ForegroundColor Gray
        return $cert
    }

    # CA
    $caCert = New-CertDotNet -Name "ca" -CN "EDR Root CA" -IsCA $true

    # Server (backend)
    New-CertDotNet -Name "server" -CN "edr-server" -DnsNames "localhost,edr-server" -IpAddresses "127.0.0.1" -SigningCert $caCert | Out-Null

    # Agent
    New-CertDotNet -Name "agent" -CN "edr-agent" -DnsNames "localhost" -IpAddresses "127.0.0.1" -SigningCert $caCert | Out-Null

    # Scanner
    New-CertDotNet -Name "scanner" -CN "edr-scanner" -DnsNames "localhost" -IpAddresses "127.0.0.1" -SigningCert $caCert | Out-Null

    # GUI (optional, not actively used)
    New-CertDotNet -Name "gui" -CN "edr-gui" -DnsNames "localhost" -SigningCert $caCert | Out-Null
}

Write-Host "Certificates generated in $certsDir" -ForegroundColor Green
Write-Host "  CA:       $certsDir\ca.pem" -ForegroundColor Gray
Write-Host "  Server:   $certsDir\server.pem" -ForegroundColor Gray
Write-Host "  Agent:    $certsDir\agent.pem" -ForegroundColor Gray
Write-Host "  Scanner:  $certsDir\scanner.pem" -ForegroundColor Gray
Write-Host "  GUI:      $certsDir\gui.pem" -ForegroundColor Gray
