<?php

namespace OCA\DKMunicipalOrganisation\Service\Serviceplatformen;

use DOMDocument;
use DOMXPath;
use Exception;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use RobRichards\XMLSecLibs\XMLSecEnc;

/**
 * TokenFetcher - WS-Trust SAML Token Issuer
 *
 * This implementation handles WS-Trust security token issuance with WS-Security message signing.
 * It uses the robrichards/xmlseclibs library for XML digital signatures.
 *
 * Requirements:
 * - PHP 7.4 or higher
 * - OpenSSL extension
 * - cURL extension
 * - SOAP extension (optional, for metadata only)
 * - composer require robrichards/xmlseclibs
 */
class TokenIssuer
{
    private const SAML_TOKEN_TYPE = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";
    private const CLAIMS_DIALECT = "http://docs.oasis-open.org/wsfed/authorization/200706/authclaims";
    private const CVR_CLAIM_TYPE = "dk:gov:saml:attribute:CvrNumberIdentifier";

    public static function issueToken(
        string $entityId,
        string $clientCertificatePath,
        string $clientCertificatePassword,
        string $cvr,
        string $tokenIssuerBaseUrl,
        string $serverCertificatePath
    ) {
        if (!extension_loaded('soap')) {
            throw new Exception('PHP SOAP extension is required but not installed. Please install it using: apt-get install php-soap');
        }

        $clientCertificate = self::loadCertificate($clientCertificatePath, $clientCertificatePassword);
        $serverCertificate = self::loadCertificate($serverCertificatePath, null);

        $serverCertificateDnsName = self::getCertificateDnsName($serverCertificate);
        $absoluteUri = self::getAbsoluteUri($entityId);

        $tokenIssuerUrl = $tokenIssuerBaseUrl . 'runtime/services/kombittrust/14/certificatemixed';

        $requestSecurityToken = self::buildRequestSecurityToken(
            $absoluteUri,
            $tokenIssuerBaseUrl,
            $cvr,
            $clientCertificate,
            $clientCertificatePath,
            $clientCertificatePassword
        );

        $token = self::sendWsTrustRequest(
            $tokenIssuerUrl,
            $requestSecurityToken,
            $clientCertificatePath,
            $clientCertificatePassword,
            $serverCertificatePath
        );

        return $token;
    }

    private static function loadCertificate(string $path, ?string $password): array
    {
        if (!file_exists($path)) {
            throw new Exception("Certificate file not found: {$path}");
        }

        if ($password !== null) {
            $certContent = file_get_contents($path);
            $certData = [];
            if (!openssl_pkcs12_read($certContent, $certData, $password)) {
                throw new Exception("Failed to load certificate from: {$path}");
            }
            return $certData;
        } else {
            $certContent = file_get_contents($path);
            $certData = openssl_x509_parse($certContent);
            if ($certData === false) {
                throw new Exception("Failed to parse certificate from: {$path}");
            }
            return ['cert' => $certContent, 'parsed' => $certData];
        }
    }

    private static function getCertificateDnsName(array $certificate): string
    {
        if (isset($certificate['parsed']['subject']['CN'])) {
            return $certificate['parsed']['subject']['CN'];
        }

        if (isset($certificate['parsed']['extensions']['subjectAltName'])) {
            $altNames = $certificate['parsed']['extensions']['subjectAltName'];
            if (preg_match('/DNS:([^,]+)/', $altNames, $matches)) {
                return $matches[1];
            }
        }

        throw new Exception("Could not extract DNS name from certificate");
    }

    private static function getAbsoluteUri(string $entityId): string
    {
        $url = parse_url($entityId);
        if ($url === false || !isset($url['scheme'])) {
            throw new Exception("Invalid entity ID URI: {$entityId}");
        }
        return $entityId;
    }

    private static function buildRequestSecurityToken(
        string $appliesTo,
        string $issuer,
        string $cvr,
        array $clientCertificate,
        string $clientCertPath,
        string $clientCertPassword
    ): string {
        $tokenType = self::SAML_TOKEN_TYPE;
        $dialect = self::CLAIMS_DIALECT;
        $claimType = self::CVR_CLAIM_TYPE;

        // Load certificate for UseKey
        $certData = self::loadCertificateForSigning($clientCertPath, $clientCertPassword);
        $certContent = str_replace(['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----', "\n", "\r", ' '], '', $certData['cert']);

        $bstId = 'uuid-' . self::generateUuid() . '-1';

        $rst = <<<XML
<trust:RequestSecurityToken xmlns:trust="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
    <wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">
        <wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing">
            <wsa:Address>{$appliesTo}</wsa:Address>
        </wsa:EndpointReference>
    </wsp:AppliesTo>
    <trust:Claims xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706" Dialect="{$dialect}">
        <auth:ClaimType Uri="{$claimType}" Optional="false">
            <auth:Value>{$cvr}</auth:Value>
        </auth:ClaimType>
    </trust:Claims>
    <trust:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/PublicKey</trust:KeyType>
    <trust:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</trust:RequestType>
    <trust:TokenType>{$tokenType}</trust:TokenType>
    <trust:UseKey>
        <BinarySecurityToken d5p1:Id="{$bstId}" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" xmlns:d5p1="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">{$certContent}</BinarySecurityToken>
    </trust:UseKey>
    <trust:Issuer>
        <wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing">
            <wsa:Address>{$issuer}</wsa:Address>
        </wsa:EndpointReference>
    </trust:Issuer>
</trust:RequestSecurityToken>
XML;

        return strtr($rst, [
            '{$tokenType}' => htmlspecialchars($tokenType, ENT_XML1),
            '{$dialect}' => htmlspecialchars($dialect, ENT_XML1),
            '{$claimType}' => htmlspecialchars($claimType, ENT_XML1),
            '{$appliesTo}' => htmlspecialchars($appliesTo, ENT_XML1),
            '{$cvr}' => htmlspecialchars($cvr, ENT_XML1),
            '{$issuer}' => htmlspecialchars($issuer, ENT_XML1),
            '{$certContent}' => $certContent,
            '{$bstId}' => $bstId
        ]);
    }

    private static function sendWsTrustRequest(
        string $tokenIssuerUrl,
        string $requestXml,
        string $clientCertPath,
        string $clientCertPassword,
        string $serverCertPath
    ) {
        try {
            // Create SOAP envelope (NO WS-Security signing - using transport security only)
            $soapEnvelope = self::wrapInSoapEnvelope($requestXml, $tokenIssuerUrl);

            // Debug: Save the SOAP request for inspection
            $debugFile = sys_get_temp_dir() . '/soap_request_debug_' . date('Y-m-d_H-i-s') . '.xml';
            file_put_contents($debugFile, $soapEnvelope);
            error_log("SOAP request saved to: " . $debugFile);

            // Convert PKCS#12 to PEM format for cURL
            $pemFiles = self::convertP12ToPem($clientCertPath, $clientCertPassword);

            // Use cURL for the HTTPS request with certificate authentication
            $ch = curl_init($tokenIssuerUrl);

            // Enable verbose curl output for debugging
            $verboseFile = sys_get_temp_dir() . '/curl_verbose_' . date('Y-m-d_H-i-s') . '.log';
            $verbose = fopen($verboseFile, 'w+');

            curl_setopt_array($ch, [
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => $soapEnvelope,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_SSL_VERIFYHOST => false,
                // Remove client certificate options since server doesn't use TLS client auth
                CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,  // Force HTTP/1.1
                CURLOPT_SSLVERSION => CURL_SSLVERSION_TLSv1_2,  // Force TLS 1.2
                CURLOPT_VERBOSE => true,
                CURLOPT_STDERR => $verbose,
                CURLOPT_HTTPHEADER => [
                    'Content-Type: application/soap+xml; charset=utf-8',
                    'SOAPAction: http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue'
                ]
            ]);

            $response = curl_exec($ch);
            $curlError = curl_error($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            // Close and log verbose output
            if ($verbose) {
                fclose($verbose);
                error_log("cURL verbose log saved to: " . $verboseFile);
            }

            // Debug: Save the SOAP response for inspection
            if ($response) {
                $responseFile = sys_get_temp_dir() . '/soap_response_debug_' . date('Y-m-d_H-i-s') . '.xml';
                file_put_contents($responseFile, $response);
                error_log("SOAP response saved to: " . $responseFile);
            }

            // Clean up temporary files
            // DEBUGGING: Keep files for inspection
            // if (file_exists($pemFiles['cert'])) {
            //     unlink($pemFiles['cert']);
            // }
            // if (file_exists($pemFiles['key'])) {
            //     unlink($pemFiles['key']);
            // }
            error_log("Certificate kept for debugging at: " . $pemFiles['cert']);
            error_log("Private key kept for debugging at: " . $pemFiles['key']);

            if ($response === false || $curlError) {
                throw new Exception("SOAP request failed: " . $curlError);
            }

            if ($httpCode !== 200) {
                throw new Exception("SOAP request returned HTTP {$httpCode}. Response: " . substr($response, 0, 1000));
            }

            return self::extractSecurityToken($response);
        } catch (Exception $e) {
            throw new Exception("WS-Trust request failed: " . $e->getMessage());
        }
    }

    private static function loadCertificateForSigning(string $p12Path, string $password): array
    {
        $p12Content = file_get_contents($p12Path);
        $certData = [];

        if (!openssl_pkcs12_read($p12Content, $certData, $password)) {
            throw new Exception("Failed to read PKCS#12 certificate for signing: " . openssl_error_string());
        }

        return $certData;
    }

    private static function signSoapMessage(string $soapEnvelope, array $certData): string
    {
        $doc = new DOMDocument();
        $doc->preserveWhiteSpace = false;
        $doc->formatOutput = false;
        $doc->loadXML($soapEnvelope);

        // Find the Body and Timestamp elements to sign
        $xpath = new DOMXPath($doc);
        $xpath->registerNamespace('soap', 'http://www.w3.org/2003/05/soap-envelope');
        $xpath->registerNamespace('wsu', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd');
        $xpath->registerNamespace('wsse', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd');

        $bodyNode = $xpath->query('//soap:Body')->item(0);
        $timestampNode = $xpath->query('//wsu:Timestamp')->item(0);
        $securityNode = $xpath->query('//wsse:Security')->item(0);

        if (!$bodyNode || !$timestampNode || !$securityNode) {
            throw new Exception("Required SOAP elements not found for signing");
        }

        // Get the IDs
        $timestampId = $timestampNode->getAttributeNS('http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd', 'Id');
        $bodyId = $bodyNode->getAttributeNS('http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd', 'Id');

        // Create XMLSecurityDSig object
        $objDSig = new XMLSecurityDSig();
        $objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);

        // Add references to sign (Timestamp first, then Body - order matters!)
        $objDSig->addReference(
            $timestampNode,
            XMLSecurityDSig::SHA256,
            ['http://www.w3.org/2001/10/xml-exc-c14n#'],
            ['id_name' => 'Id', 'overwrite' => false]
        );

        $objDSig->addReference(
            $bodyNode,
            XMLSecurityDSig::SHA256,
            ['http://www.w3.org/2001/10/xml-exc-c14n#'],
            ['id_name' => 'Id', 'overwrite' => false]
        );

        // Create new XMLSecurityKey using RSA-SHA256
        $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'private']);
        $objKey->loadKey($certData['pkey']);

        // Sign the XML
        $objDSig->sign($objKey);

        // Add BinarySecurityToken with the certificate
        $binarySecurityToken = $doc->createElementNS(
            'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
            'wsse:BinarySecurityToken'
        );
        $binarySecurityToken->setAttribute('EncodingType', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary');
        $binarySecurityToken->setAttribute('ValueType', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3');
        $tokenId = 'X509-' . uniqid();
        $binarySecurityToken->setAttributeNS(
            'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
            'wsu:Id',
            $tokenId
        );

        // Extract certificate without headers/footers and base64 encode
        $certContent = $certData['cert'];
        $certContent = str_replace(['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----', "\n", "\r"], '', $certContent);
        $binarySecurityToken->nodeValue = $certContent;

        // Insert BinarySecurityToken before Timestamp
        $securityNode->insertBefore($binarySecurityToken, $timestampNode);

        // Add the certificate reference to signature using SecurityTokenReference
        $objDSig->add509Cert($certData['cert'], true);

        // Insert signature into Security header (after Timestamp)
        $objDSig->insertSignature($securityNode, $timestampNode->nextSibling);

        return $doc->saveXML();
    }

    private static function convertP12ToPem(string $p12Path, string $password): array
    {
        $p12Content = file_get_contents($p12Path);
        $certData = [];

        if (!openssl_pkcs12_read($p12Content, $certData, $password)) {
            throw new Exception("Failed to read PKCS#12 certificate: " . openssl_error_string());
        }

        // Create separate files for certificate and private key
        $uniqueId = uniqid();
        $certPath = sys_get_temp_dir() . '/client_cert_' . $uniqueId . '.crt';
        $keyPath = sys_get_temp_dir() . '/client_key_' . $uniqueId . '.key';

        // Write certificate file
        if (file_put_contents($certPath, $certData['cert']) === false) {
            throw new Exception("Failed to write certificate file");
        }

        // Write private key file
        if (file_put_contents($keyPath, $certData['pkey']) === false) {
            throw new Exception("Failed to write private key file");
        }

        error_log("Certificate written to: " . $certPath);
        error_log("Private key written to: " . $keyPath);

        return [
            'cert' => $certPath,
            'key' => $keyPath
        ];
    }

    private static function wrapInSoapEnvelope(string $body, string $toUrl): string
    {
        $messageId = self::generateUuid();

        return <<<XML
<s:Envelope xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:s="http://www.w3.org/2003/05/soap-envelope">
  <s:Header>
    <a:Action s:mustUnderstand="1">http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue</a:Action>
    <a:MessageID>urn:uuid:{$messageId}</a:MessageID>
    <a:ReplyTo>
      <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
    </a:ReplyTo>
  </s:Header>
  <s:Body>
    {$body}
  </s:Body>
</s:Envelope>
XML;
    }

    private static function extractSecurityToken(string $soapResponse)
    {
        $dom = new DOMDocument();
        if (!@$dom->loadXML($soapResponse)) {
            throw new Exception("Invalid SOAP response received");
        }

        $xpath = new DOMXPath($dom);
        $xpath->registerNamespace('wst', 'http://docs.oasis-open.org/ws-sx/ws-trust/200512');
        $xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');

        $tokenNodes = $xpath->query('//wst:RequestedSecurityToken');

        if ($tokenNodes->length === 0) {
            throw new Exception("No security token found in response");
        }

        return $dom->saveXML($tokenNodes->item(0));
    }

    private static function generateUuid(): string
    {
        $data = random_bytes(16);
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }
}
