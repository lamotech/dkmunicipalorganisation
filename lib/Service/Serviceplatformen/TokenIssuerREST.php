<?php

namespace OCA\DKMunicipalOrganisation\Service\Serviceplatformen;

use Exception;

/**
 * TokenIssuerREST - WS-Trust SAML Token Issuer via REST API
 *
 * This implementation uses the REST API endpoint for token issuance with
 * client certificate authentication via TLS.
 *
 * Requirements:
 * - PHP 7.4 or higher
 * - OpenSSL extension
 * - cURL extension
 */
class TokenIssuerREST
{
    private const SAML_TOKEN_TYPE = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";
    private const REQUEST_TYPE = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue";
    private const KEY_TYPE = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/PublicKey";

    /**
     * Issue a SAML token using the REST API
     *
     * @param string $entityId The service entity ID (AppliesTo)
     * @param string $clientCertificatePath Path to PKCS#12 certificate file
     * @param string $clientCertificatePassword Certificate password
     * @param string $cvr CVR number
     * @param string $tokenIssuerBaseUrl Base URL of the STS service
     * @return SAMLToken The issued SAML token
     * @throws Exception
     */
    public static function issueToken(
        string $entityId,
        string $clientCertificatePath,
        string $clientCertificatePassword,
        string $cvr,
        string $tokenIssuerBaseUrl
    ): SAMLToken {
        // Build the REST API URL
        $apiUrl = rtrim($tokenIssuerBaseUrl, '/') . '/runtime/api/rest/wstrust/v1/issue';

        // Convert PKCS#12 to PEM format for cURL
        $pemFiles = self::convertP12ToPem($clientCertificatePath, $clientCertificatePassword);

        try {
            // Build the request payload (needs pemFiles to extract certificate)
            $requestPayload = self::buildRequestPayload($entityId, $cvr, $pemFiles);

            // Send the REST request with client certificate authentication
            $response = self::sendRestRequest($apiUrl, $requestPayload, $pemFiles);

            // Return a SAMLToken instance
            return new SAMLToken($response);
        } finally {
            // Clean up temporary PEM files
            if (isset($pemFiles['cert']) && file_exists($pemFiles['cert'])) {
                unlink($pemFiles['cert']);
            }
            if (isset($pemFiles['key']) && file_exists($pemFiles['key'])) {
                unlink($pemFiles['key']);
            }
        }
    }

    /**
     * Build the request payload according to the API specification
     */
    private static function buildRequestPayload(string $appliesTo, string $cvr, array $pemFiles): array
    {
        // Load the certificate to extract the public key
        $certContent = file_get_contents($pemFiles['cert']);

        // Remove PEM headers and newlines to get base64 content
        $certBase64 = str_replace(
            ['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----', "\n", "\r", ' '],
            '',
            $certContent
        );

        return [
            'AppliesTo' => [
                'EndpointReference' => [
                    'Address' => $appliesTo
                ]
            ],
            'KeyType' => self::KEY_TYPE,
            'RequestType' => self::REQUEST_TYPE,
            'TokenType' => self::SAML_TOKEN_TYPE,
            'Anvenderkontekst' => [
                'Cvr' => $cvr
            ],
            'UseKey' => $certBase64
        ];
    }

    /**
     * Send the REST request with client certificate authentication
     */
    private static function sendRestRequest(string $url, array $payload, array $pemFiles): array
    {
        $ch = curl_init($url);

        // Encode payload as JSON
        $jsonPayload = json_encode($payload, JSON_UNESCAPED_SLASHES);

        // Enable verbose curl output for debugging
        $verboseFile = sys_get_temp_dir() . '/curl_rest_verbose_' . date('Y-m-d_H-i-s') . '.log';
        $verbose = fopen($verboseFile, 'w+');

        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $jsonPayload,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_SSLCERT => $pemFiles['cert'],
            CURLOPT_SSLCERTTYPE => 'PEM',
            CURLOPT_SSLKEY => $pemFiles['key'],
            CURLOPT_SSLKEYTYPE => 'PEM',
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_SSLVERSION => CURL_SSLVERSION_TLSv1_2,
            CURLOPT_VERBOSE => true,
            CURLOPT_STDERR => $verbose,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                'Accept: application/json',
                'Content-Length: ' . strlen($jsonPayload)
            ]
        ]);

        // Debug: Save the request payload
        $requestFile = sys_get_temp_dir() . '/rest_request_' . date('Y-m-d_H-i-s') . '.json';
        file_put_contents($requestFile, $jsonPayload);
        error_log("REST request saved to: " . $requestFile);

        $response = curl_exec($ch);
        $curlError = curl_error($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        // Close and log verbose output
        if ($verbose) {
            fclose($verbose);
            error_log("cURL verbose log saved to: " . $verboseFile);
        }

        // Debug: Save the response
        if ($response) {
            $responseFile = sys_get_temp_dir() . '/rest_response_' . date('Y-m-d_H-i-s') . '.json';
            file_put_contents($responseFile, $response);
            error_log("REST response saved to: " . $responseFile);
        }

        if ($response === false || $curlError) {
            throw new Exception("REST request failed: " . $curlError);
        }

        if ($httpCode !== 200) {
            $errorMessage = "REST request returned HTTP {$httpCode}";
            if ($response) {
                $errorData = json_decode($response, true);
                if (isset($errorData['message'])) {
                    $errorMessage .= ": " . $errorData['message'];
                } else {
                    $errorMessage .= ". Response: " . substr($response, 0, 500);
                }
            }
            throw new Exception($errorMessage);
        }

        // Parse JSON response
        $responseData = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception("Failed to parse JSON response: " . json_last_error_msg());
        }

        return $responseData;
    }

    /**
     * Convert PKCS#12 certificate to PEM format
     */
    private static function convertP12ToPem(string $p12Path, string $password): array
    {
        if (!file_exists($p12Path)) {
            throw new Exception("Certificate file not found: {$p12Path}");
        }

        $p12Content = file_get_contents($p12Path);
        $certData = [];

        if (!openssl_pkcs12_read($p12Content, $certData, $password)) {
            throw new Exception("Failed to read PKCS#12 certificate: " . openssl_error_string());
        }

        // Create separate files for certificate and private key
        $uniqueId = uniqid();
        $certPath = sys_get_temp_dir() . '/rest_client_cert_' . $uniqueId . '.crt';
        $keyPath = sys_get_temp_dir() . '/rest_client_key_' . $uniqueId . '.key';

        // Write certificate file
        if (file_put_contents($certPath, $certData['cert']) === false) {
            throw new Exception("Failed to write certificate file");
        }

        // Write private key file
        if (file_put_contents($keyPath, $certData['pkey']) === false) {
            throw new Exception("Failed to write private key file");
        }

        error_log("REST: Certificate written to: " . $certPath);
        error_log("REST: Private key written to: " . $keyPath);

        return [
            'cert' => $certPath,
            'key' => $keyPath
        ];
    }
}
