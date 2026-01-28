<?php

namespace OCA\DkMunicipalOrganisation\Service\Serviceplatformen;
use OCA\DkMunicipalOrganisation\Service\Certificate;
use Exception;
use DOMDocument;
use DOMXPath;

/**
 * OrganisationWrapper - Wrapper for the Organisation SOAP service
 *
 * This class handles communication with the Organisation service using
 * a SAML token for authentication with holder-of-key confirmation.
 * The SOAP message is signed according to WS-Security requirements.
 */
class OrganisationWrapper
{
    private const SOAP12_NAMESPACE = 'http://www.w3.org/2003/05/soap-envelope';
    private const WSA_NAMESPACE = 'http://www.w3.org/2005/08/addressing';
    private const WSSE_NAMESPACE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    private const WSSE11_NAMESPACE = 'http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd';
    private const WSU_NAMESPACE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
    private const DS_NAMESPACE = 'http://www.w3.org/2000/09/xmldsig#';
    private const SOAP_ACTION = 'http://kombit.dk/sts/organisation/organisationssystem/fremsoegobjekthierarki';
    private const STR_TRANSFORM = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#STR-Transform';

    private OrganisationConfiguration $configuration;
    private SAMLToken $samlToken;

    public function __construct(OrganisationConfiguration $configuration, SAMLToken $token)
    {
        $this->configuration = $configuration;
        $this->samlToken = $token;
    }

    public function fremsoeg(int $limit, int $offset): string
    {
        $transactionUUID = $this->generateUUID();
        $messageId = 'urn:uuid:' . $this->generateUUID();

        $pemFiles = self::storeTempPemFiles($this->configuration->getClientCertificate());

        try {
            $soapEnvelope = $this->buildSignedSoapEnvelope($transactionUUID, $messageId, $limit, $offset, $pemFiles);
            $response = $this->sendRequest($soapEnvelope, $pemFiles);
            return $this->extractFremsoegOutput($response);
        } finally {
            $this->cleanupPemFiles($pemFiles);
        }
    }

    private function extractFremsoegOutput(string $soapResponse): string
    {
        $doc = new DOMDocument();
        $doc->loadXML($soapResponse);

        $xpath = new DOMXPath($doc);
        $xpath->registerNamespace('soap', 'http://www.w3.org/2003/05/soap-envelope');
        $xpath->registerNamespace('ns6', 'http://stoettesystemerne.dk/organisation/organisationsystem/6/');

        $outputNodes = $xpath->query('//ns6:FremsoegObjekthierarkiOutput');
        if ($outputNodes->length === 0) {
            throw new Exception("FremsoegObjekthierarkiOutput not found in response");
        }

        return $doc->saveXML($outputNodes->item(0));
    }

    private function buildSignedSoapEnvelope(string $transactionUUID, string $messageId, int $limit, int $offset, array $pemFiles): string
    {
        $endpoint = $this->configuration->getEndpoint();
        $samlAssertion = $this->samlToken->getAssertion();

        // Get the assertion ID
        $assertionId = $this->extractAssertionId($samlAssertion);

        // Generate IDs matching WCF format
        $bodyId = '_1';
        $actionId = '_2';
        $messageIdId = '_3';
        $replyToId = '_4';
        $toId = '_5';
        $timestampId = 'uuid-' . $this->generateUUID() . '-3';
        // WCF format: _str followed by assertion ID (which starts with _)
        $strId = '_str' . $assertionId;

        $now = new \DateTime('now', new \DateTimeZone('UTC'));
        $expires = clone $now;
        $expires->modify('+5 minutes');
        $created = $now->format('Y-m-d\TH:i:s.v\Z');
        $expiresStr = $expires->format('Y-m-d\TH:i:s.v\Z');

        // Build the envelope matching WCF structure (no BinarySecurityToken needed)
        $envelope = <<<XML
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
<s:Header>
<a:Action s:mustUnderstand="1" u:Id="{$actionId}">{$this->escapeXml(self::SOAP_ACTION)}</a:Action>
<h:RequestHeader xmlns:h="http://kombit.dk/xml/schemas/RequestHeader/1/" xmlns="http://kombit.dk/xml/schemas/RequestHeader/1/"><TransactionUUID>{$this->escapeXml($transactionUUID)}</TransactionUUID></h:RequestHeader>
<a:MessageID u:Id="{$messageIdId}">{$this->escapeXml($messageId)}</a:MessageID>
<a:ReplyTo u:Id="{$replyToId}"><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>
<a:To s:mustUnderstand="1" u:Id="{$toId}">{$this->escapeXml($endpoint)}</a:To>
<o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
<u:Timestamp u:Id="{$timestampId}">
<u:Created>{$created}</u:Created>
<u:Expires>{$expiresStr}</u:Expires>
</u:Timestamp>
{$samlAssertion}
<o:SecurityTokenReference b:TokenType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0" u:Id="{$strId}" xmlns:b="http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd">
<o:KeyIdentifier ValueType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID">{$assertionId}</o:KeyIdentifier>
</o:SecurityTokenReference>
</o:Security>
</s:Header>
<s:Body u:Id="{$bodyId}">
<FremsoegObjekthierarkiInput xmlns="http://stoettesystemerne.dk/organisation/organisationsystem/6/">
<FoersteResultatReference xmlns="urn:oio:sagdok:3.0.0">{$offset}</FoersteResultatReference>
<MaksimalAntalKvantitet xmlns="urn:oio:sagdok:3.0.0">{$limit}</MaksimalAntalKvantitet>
</FremsoegObjekthierarkiInput>
</s:Body>
</s:Envelope>
XML;

        return $this->signSoapEnvelope($envelope, $pemFiles, [
            'bodyId' => $bodyId,
            'actionId' => $actionId,
            'messageIdId' => $messageIdId,
            'replyToId' => $replyToId,
            'toId' => $toId,
            'timestampId' => $timestampId,
            'strId' => $strId,
            'assertionId' => $assertionId
        ]);
    }

    private function extractAssertionId(string $assertion): string
    {
        if (preg_match('/ID="([^"]+)"/', $assertion, $matches)) {
            return $matches[1];
        }
        throw new Exception("Could not extract assertion ID from SAML token");
    }

    private function signSoapEnvelope(string $envelope, array $pemFiles, array $ids): string
    {
        $doc = new DOMDocument();
        $doc->preserveWhiteSpace = true;
        $doc->loadXML($envelope);

        $xpath = new DOMXPath($doc);
        $xpath->registerNamespace('s', self::SOAP12_NAMESPACE);
        $xpath->registerNamespace('o', self::WSSE_NAMESPACE);
        $xpath->registerNamespace('u', self::WSU_NAMESPACE);
        $xpath->registerNamespace('a', self::WSA_NAMESPACE);

        $securityNodes = $xpath->query('//o:Security');
        if ($securityNodes->length === 0) {
            throw new Exception("Security element not found");
        }
        $securityElement = $securityNodes->item(0);

        $privateKey = openssl_pkey_get_private(file_get_contents($pemFiles['key']));
        if (!$privateKey) {
            throw new Exception("Failed to load private key: " . openssl_error_string());
        }

        // Build references in the same order as WCF
        $references = [];

        // Body
        $bodyElement = $xpath->query("//s:Body[@u:Id='{$ids['bodyId']}']")->item(0);
        if ($bodyElement) {
            $references[] = ['uri' => '#' . $ids['bodyId'], 'digest' => $this->computeDigest($bodyElement)];
        }

        // Action
        $actionElement = $xpath->query("//a:Action[@u:Id='{$ids['actionId']}']")->item(0);
        if ($actionElement) {
            $references[] = ['uri' => '#' . $ids['actionId'], 'digest' => $this->computeDigest($actionElement)];
        }

        // MessageID
        $messageIdElement = $xpath->query("//a:MessageID[@u:Id='{$ids['messageIdId']}']")->item(0);
        if ($messageIdElement) {
            $references[] = ['uri' => '#' . $ids['messageIdId'], 'digest' => $this->computeDigest($messageIdElement)];
        }

        // ReplyTo
        $replyToElement = $xpath->query("//a:ReplyTo[@u:Id='{$ids['replyToId']}']")->item(0);
        if ($replyToElement) {
            $references[] = ['uri' => '#' . $ids['replyToId'], 'digest' => $this->computeDigest($replyToElement)];
        }

        // To
        $toElement = $xpath->query("//a:To[@u:Id='{$ids['toId']}']")->item(0);
        if ($toElement) {
            $references[] = ['uri' => '#' . $ids['toId'], 'digest' => $this->computeDigest($toElement)];
        }

        // Timestamp
        $timestampElement = $xpath->query("//u:Timestamp[@u:Id='{$ids['timestampId']}']")->item(0);
        if ($timestampElement) {
            $references[] = ['uri' => '#' . $ids['timestampId'], 'digest' => $this->computeDigest($timestampElement)];
        }

        // STR-Transform reference for the SecurityTokenReference (proves holder-of-key)
        $assertionElement = $xpath->query("//*[@ID='{$ids['assertionId']}']")->item(0);
        if ($assertionElement) {
            $references[] = [
                'uri' => '#' . $ids['strId'],
                'digest' => $this->computeDigest($assertionElement),
                'strTransform' => true
            ];
        }

        // Build SignedInfo (without namespace - will be added during signature building)
        $signedInfoContent = $this->buildSignedInfoForSignature($references);

        // KeyInfo references the SAML assertion via KeyIdentifier (matching WCF format)
        $keyInfoXml = '<KeyInfo>' .
            '<o:SecurityTokenReference b:TokenType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:b="http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd">' .
            '<o:KeyIdentifier ValueType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID">' . $ids['assertionId'] . '</o:KeyIdentifier>' .
            '</o:SecurityTokenReference>' .
            '</KeyInfo>';

        // Build Signature element first (without signature value) to get proper namespace inheritance
        $signatureTemplate = '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">' .
            $signedInfoContent .
            '<SignatureValue></SignatureValue>' .
            $keyInfoXml .
            '</Signature>';

        // Parse the template and canonicalize SignedInfo with inherited namespace
        $sigTempDoc = new DOMDocument();
        $sigTempDoc->loadXML($signatureTemplate);
        $signedInfoNode = $sigTempDoc->getElementsByTagName('SignedInfo')->item(0);
        $canonicalSignedInfo = $signedInfoNode->C14N(true);

        $signature = '';
        if (!openssl_sign($canonicalSignedInfo, $signature, $privateKey, OPENSSL_ALGO_SHA256)) {
            throw new Exception("Failed to sign: " . openssl_error_string());
        }
        $signatureValue = base64_encode($signature);

        // Build final Signature element with actual signature value
        $signatureXml = '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">' .
            $signedInfoContent .
            '<SignatureValue>' . $signatureValue . '</SignatureValue>' .
            $keyInfoXml .
            '</Signature>';

        // Insert signature at the end of Security header
        $signatureDoc = new DOMDocument();
        $signatureDoc->loadXML($signatureXml);
        $signatureElement = $doc->importNode($signatureDoc->documentElement, true);
        $securityElement->appendChild($signatureElement);

        return $doc->saveXML();
    }

    private function computeDigest(\DOMElement $element): string
    {
        $canonical = $element->C14N(true);
        return base64_encode(hash('sha256', $canonical, true));
    }

    private function buildSignedInfoForSignature(array $references): string
    {
        $refsXml = '';
        foreach ($references as $ref) {
            // Note: CanonicalizationMethod inside TransformationParameters needs explicit namespace
            // because it's inside o: namespace context
            $transformXml = isset($ref['strTransform'])
                ? '<Transform Algorithm="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#STR-Transform">' .
                  '<o:TransformationParameters xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">' .
                  '<CanonicalizationMethod xmlns="http://www.w3.org/2000/09/xmldsig#" Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></CanonicalizationMethod>' .
                  '</o:TransformationParameters>' .
                  '</Transform>'
                : '<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></Transform>';

            $refsXml .= '<Reference URI="' . $ref['uri'] . '">' .
                '<Transforms>' . $transformXml . '</Transforms>' .
                '<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></DigestMethod>' .
                '<DigestValue>' . $ref['digest'] . '</DigestValue>' .
                '</Reference>';
        }

        // No namespace here - it will inherit from parent Signature element
        return '<SignedInfo>' .
            '<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></CanonicalizationMethod>' .
            '<SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></SignatureMethod>' .
            $refsXml .
            '</SignedInfo>';
    }

    private function escapeXml(string $value): string
    {
        return htmlspecialchars($value, ENT_XML1 | ENT_QUOTES, 'UTF-8');
    }

    private function sendRequest(string $soapEnvelope, array $pemFiles): string
    {
        $endpoint = $this->configuration->getEndpoint();

        $ch = curl_init();

        curl_setopt_array($ch, [
            CURLOPT_URL => $endpoint,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $soapEnvelope,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/soap+xml; charset=utf-8; action="' . self::SOAP_ACTION . '";',
            ],
            CURLOPT_TIMEOUT => 30,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_SSLCERT => $pemFiles['cert'],
            CURLOPT_SSLCERTTYPE => 'PEM',
            CURLOPT_SSLKEY => $pemFiles['key'],
            CURLOPT_SSLKEYTYPE => 'PEM',
        ]);

        /*
        $serviceCertPath = $this->configuration->getOrganisationServiceCertificatePath();
        if (!empty($serviceCertPath) && file_exists($serviceCertPath)) {
            curl_setopt($ch, CURLOPT_CAINFO, $serviceCertPath);
        }
        */

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        $errno = curl_errno($ch);

        curl_close($ch);

        if ($errno !== 0) {
            throw new Exception("cURL error ({$errno}): {$error}");
        }

        if ($httpCode >= 400) {
            throw new Exception("HTTP error {$httpCode}: {$response}");
        }

        return $response;
    }

    /**
     * Convert PKCS#12 certificate to PEM format
     */
    private static function storeTempPemFiles(Certificate $certificate): array
    {
        // Create separate files for certificate and private key
        $uniqueId = uniqid();
        $certPath = sys_get_temp_dir() . '/org_client_cert_' . $uniqueId . '.pem';
        $keyPath = sys_get_temp_dir() . '/org_client_key_' . $uniqueId . '.pem';

        // Write certificate file
        if (file_put_contents($certPath, $certificate->getPublicKey()) === false) {
            throw new Exception("Failed to write certificate file");
        }

        // Write private key file
        if (file_put_contents($keyPath, $certificate->getPrivateKey()) === false) {
            throw new Exception("Failed to write private key file");
        }

        return [
            'cert' => $certPath,
            'key' => $keyPath
        ];
    }


    private function cleanupPemFiles(array $pemFiles): void
    {
        if (isset($pemFiles['cert']) && file_exists($pemFiles['cert'])) {
            unlink($pemFiles['cert']);
        }
        if (isset($pemFiles['key']) && file_exists($pemFiles['key'])) {
            unlink($pemFiles['key']);
        }
    }

    private function generateUUID(): string
    {
        $data = random_bytes(16);
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }
}
