<?php
declare(strict_types=1);

namespace OCA\DKMunicipalOrganisation\Service;
use OneLogin\Saml2\Settings;
use OneLogin\Saml2\IdPMetadataParser;
use OneLogin\Saml2\Metadata;
use OneLogin\Saml2\Constants;
use OneLogin\Saml2\Error;
use OneLogin\Saml2\Error\ValidationError;
use OneLogin\Saml2\Error\MissingAttributeError;
use OneLogin\Saml2\Error\SettingNotFound;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use DOMDocument;
use DOMXPath;
use DOMNode;
use DOMElement;

class SAMLService {
	public function createSAMLMetadata(): string {

		// ---- SP config (edit these) ----
		$entityId = 'https://korsbaek.lamotech.dk/dkmunicipalorganisation';
		$acsUrl   = 'https://korsbaek.lamotech.dk/dkmunicipalorganisation/saml/acs';
		$slsUrl   = 'https://korsbaek.lamotech.dk/dkmunicipalorganisation/saml/sls';
		$slsResponseUrl   = 'https://korsbaek.lamotech.dk/dkmunicipalorganisation/saml/loggedout';

		// Your SP keys/certs (PEM)
		//$spPublicCert  = 'MIIDEDCCAfigAwIBAgIQGYyGXXPjCI5Gy/WWhKC6GTANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQDDBBNeVNlbGZTaWduZWRDZXJ0MB4XDTI2MDExMTA4MjgxNFoXDTI3MDExMTA4NDgxNFowGzEZMBcGA1UEAwwQTXlTZWxmU2lnbmVkQ2VydDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANhYJ5E00wBzlNY1ASOUF59F9GDA3M8SrQ/3nNIJE7Ydynkrj4y4TrzjNyKPGjv1ujLc65vWxD2pnaDM32aJBveUEGCMoKyhwwC646m6pFycC2wr2r0IZ0yBFzt2h77iD1CUKCb+p3NlnhFxvAFzeLYXZqTRPoNoPNSndvwFEiENYa6CYbCi03W7gs+2s8iTxJfFzjBuCryCAMcR3gUJfBHYLB58s9brUEleirTNQEAO1goK8FiebMCqZ2bzncISa79yHkYSthFelPnrYYhB0Cpq4A7vC1Ws3KhSv/0KpXWdsCsrnZep3c4bcLyQKRUbUzMk1tjegDB9F5iz9BY0euUCAwEAAaNQME4wDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAdBgNVHQ4EFgQUpOcQNcRAfubgtn5+K87LgKKx9YAwDQYJKoZIhvcNAQELBQADggEBAABX7WTTEG9/Oe0dqLY2ArMyeYaDkEqUolr9tr+A17hrZ6s/uXfIEJii84Nl5v5ySczewiHpKmMJkLwnElfz6x+k8xEG9E1PrVw+pq/6p6Igxb8e+Ty/QxOBSZdD5FpS/XbrVa8try6PhhuXaPgfbHOcVAt2IZk4Q1zrnG6OGskU3/cc4UOjqScBy/s2u0rtcMgYcLEq0adLnIAWWRaJWZJrGnuEQ1G9BNAVZF0nObbsW+WRxVibrFyJPdBmX9dwwb5mUQx6d6eFhj9q1MBPsLeYMbFHGCeTXdS411p53WhY2p1C8YXSFAdTFWPD+YglgAE6bvr55fVJ1okx8lCN9pE='; // public cert PEM
		//$spPrivateKey  = 'MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDYWCeRNNMAc5TWNQEjlBefRfRgwNzPEq0P95zSCRO2Hcp5K4+MuE684zcijxo79boy3Oub1sQ9qZ2gzN9miQb3lBBgjKCsocMAuuOpuqRcnAtsK9q9CGdMgRc7doe+4g9QlCgm/qdzZZ4RcbwBc3i2F2ak0T6DaDzUp3b8BRIhDWGugmGwotN1u4LPtrPIk8SXxc4wbgq8ggDHEd4FCXwR2CwefLPW61BJXoq0zUBADtYKCvBYnmzAqmdm853CEmu/ch5GErYRXpT562GIQdAqauAO7wtVrNyoUr/9CqV1nbArK52Xqd3OG3C8kCkVG1MzJNbY3oAwfReYs/QWNHrlAgMBAAECggEAX3fHPhSJaBGZBE2vivu20NoV1PxGdDpRlFI4KZdH032h84Z9eiN622+IzP9JHFx7JibG8aX8QxmuLV861gxxvp7f+zsTTBq16oSOIj/yd8uEXt+bTv9+VgxBLERJ8rne+Dfo4AxP6GRXNGt0A0/pXLFG4kRTybkd3tlncB7suRhW5tz1+0pcd3pSgveIFHvGh/hg0t8OfN/xnwrkx0Iufv2qfhbvad3d427cdNM/HrrcOTXGjJghuO4gzUKL8iYUp/4izunJMTRibsNYzZ1p4VceJWc+h7j6TGkEWSo9V/fBj4vxpfg8pAyyHhtcjJx/1cpXS1PFqFgvWTjf9nWMoQKBgQDrNLiU9XJjygQOh7KEbviMp+BlAYq5Kpbk/OkvLi9sLXD/nJr+UMdVOMgsk3OPRMQcs5QlBj42B23WzcEcVyMmb0ew5+MH4Yx/VnFEAj+Dj5wWNUruEfuFw4ybdxVluDechObxPjGRUL8zQlrmN18BglokF0uUsEwoXuPhIkXHdwKBgQDreIza5Gau9srXF/wn4Pjzx2YlvM3rj2IFohuedjJ1219e90gztglJBZGfvn5o8bbVfIudxB46ZYiI/bn3SOzNgmufvoa2X/87o5FGqLmBO2jjhDBv2FcH9PYmNBtumbuuCN3EVtVB1E+CbWmkPQtzu5t9YaluQvRRk60mt2gfgwKBgQCI5+gk9HV/9j/EQWI8yecs4C6yPGKGA29PnJMSnlyGKDEk6AAj1dshFOsXX0CdfRZ16mVp46dkhZB+vscP+vx/y7g8Fc3FcZj5KdTGFFTp/DaLiruxtY/lPXzjpT40NjVQit9uPphVkF2qtY35gPNxCnHzngelZbT+rrUP/4YEYwKBgFQVBecb6/bKNYA9FlN/KCaUq0sKclWNK6lrS4V4G2iuXw3gKy4b8JDcpjVupmD+/xSYlppNb6XWn7ybLY65waVYzumJ9TymZtN7AuNCWItnFXs4trsZe2ph9IuLy8fgqX3puJblkt0g3Qtr2m9FRROciFdrSj8PNYLzwr6ye0HVAoGBANrxu0I76RYpL4QjUMZXfusm/oew5cgwCw3t7UOUfMC7D81wtssYqV9vxaY45IyTpp5ZXy0E+bUi8WyHgeyHoLHnTOBvn54f9OlW2fPdA9i/9ylB41KpzZ6wF2QSbgpbhxAOPkkB3BFMqdogQzo+1bGKxW0ypXLkOa/l0cqKwnlA'; // private key PEM

		$spPublicCert  = 'MIIGZjCCBJqgAwIBAgIUGkzYGF4g6Du8cUnCFeK/5E86V4YwQQYJKoZIhvcNAQEKMDSgDzANBglghkgBZQMEAgEFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgEFAKIDAgEgMFYxLTArBgNVBAMMJERlbiBEYW5za2UgU3RhdCBPQ0VTIHVkc3RlZGVuZGUtQ0EgMTEYMBYGA1UECgwPRGVuIERhbnNrZSBTdGF0MQswCQYDVQQGEwJESzAeFw0yNjAxMDcwNjM5NDlaFw0yOTAxMDYwNjM5NDhaMIGcMRowGAYDVQQDDBFTZXJ2aWNlcGxhdGZvcm1lbjE3MDUGA1UEBRMuVUk6REstTzpHOjQxZjYwYmNkLTUyNjYtNDRkNi1hMTBmLWYzMDMzMDE5YjNhNzEfMB0GA1UECgwWTGFtb3RlY2ggU29sdXRpb25zIEFwUzEXMBUGA1UEYQwOTlRSREstNDQ0NDc2MjIxCzAJBgNVBAYTAkRLMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA1WFXhqR6zvHcZaqg7UkWTZCyxj2ncM27kQIcs/u9VnXDOBva9H8D6k1WsCdo2wUmhd+Yf5pkD/fD2w7ERpj95Me4/3bpIvUFUmkbuJ8fWxem8J/Yh2f1Xpoq1GogEhhwJ/vs6FQVs8+aT1Bm0z9/j0NICz2mKYEVgbJ61afGzGmUVacAHGmKPUnRZMgeNK8Nguf7C+21RFfdwAN95L5hokYkqURaUYqto9FFno9Y6CXy4Wx3p2jnEWso9etWtmdoE63SXtz/khPlvlQNxzvLIIuegp3RJGtOOPkPGvIph/S7KlOFd7OTRK8WliQxbJ5EB66vrqSSTGS+BPzGwJrsgC07D2uMBm4J/xIeMLDjr1/YfFwslZdFuy/pbzNpnkXsKlMjocUU9mOBfS5ZyTLPI03ORWiVxbs1cljIF57adnC0QM+/FRNcQZPhfo7LcvjacNGn0m/HW90J/aUU6e7bG45QieGxezCi811I7fCpQsPAzwz2aB32hd2YbWLCOtzBAgMBAAGjggF7MIIBdzAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFEwB4spzvMO+OAo4PTawXHSce5e5MHMGCCsGAQUFBwEBBGcwZTA/BggrBgEFBQcwAoYzaHR0cDovL2NhMS5nb3YuZGsvb2Nlcy9pc3N1aW5nLzEvY2FjZXJ0L2lzc3VpbmcuY2VyMCIGCCsGAQUFBzABhhZodHRwOi8vY2ExLmdvdi5kay9vY3NwMCIGA1UdIAQbMBkwCAYGBACPegEBMA0GCyqBUIEpAQEBAwcBMDsGCCsGAQUFBwEDBC8wLTArBggrBgEFBQcLAjAfBgcEAIvsSQECMBSGEmh0dHBzOi8vdWlkLmdvdi5kazBBBgNVHR8EOjA4MDagNKAyhjBodHRwOi8vY2ExLmdvdi5kay9vY2VzL2lzc3VpbmcvMS9jcmwvaXNzdWluZy5jcmwwHQYDVR0OBBYEFA9uGWDmLV6OCbfRyoYHvbBFI+MCMA4GA1UdDwEB/wQEAwIFoDBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAQUAoRwwGgYJKoZIhvcNAQEIMA0GCWCGSAFlAwQCAQUAogMCASADggGBAKRiie7UrZzJehh///fK32dDNSSIE4PVgmfotXb56LEaz4Dvge1AgetwxxLZYtmhVz1NhO9S8Hh+eR2LhufKHUfrKOoCPxzd5gXquSpb+08DCuKx2kOothkGsRNhrQm3OeWbPGrhMGsO6IxMENWUZJP9uABay4mmT1xA6Oa51shi6GfBz3Xn+nIqqCJjMOcTtpPF6o1GKTppZllfnO2d9Xz3UrD4D/kfANgpn/p5yG2+mbATbNtmFbMjLUJT+VUqZNlejIMBzlklpB3aHtN1WUZ+iGq4RI02sncnvw+EgBydd35/Cgx2XVpyvkT1JzgHl2cML3rfKcJ3uEcbB1fvJrow1Ib/Erxm9rUMh44FjiyfYECjdxLVcCYajkfOqq1rjVBoGcVgImjZP/e309rMZ3ZwG2W/OPNrGDKI4fj8gIKElXfw+Tri65/9AJ1Fnds7GMYa7VQUwzBE9lClmevaa67RzsBFmA9jVS0RP21Yog5HyT89DwzP23RD7OF3MK1AuQ=='; // public cert PEM
		$spPrivateKey  = 'MIIG/gIBADANBgkqhkiG9w0BAQEFAASCBugwggbkAgEAAoIBgQDVYVeGpHrO8dxlqqDtSRZNkLLGPadwzbuRAhyz+71WdcM4G9r0fwPqTVawJ2jbBSaF35h/mmQP98PbDsRGmP3kx7j/duki9QVSaRu4nx9bF6bwn9iHZ/VemirUaiASGHAn++zoVBWzz5pPUGbTP3+PQ0gLPaYpgRWBsnrVp8bMaZRVpwAcaYo9SdFkyB40rw2C5/sL7bVEV93AA33kvmGiRiSpRFpRiq2j0UWej1joJfLhbHenaOcRayj161a2Z2gTrdJe3P+SE+W+VA3HO8sgi56CndEka044+Q8a8imH9LsqU4V3s5NErxaWJDFsnkQHrq+upJJMZL4E/MbAmuyALTsPa4wGbgn/Eh4wsOOvX9h8XCyVl0W7L+lvM2meRewqUyOhxRT2Y4F9LlnJMs8jTc5FaJXFuzVyWMgXntp2cLRAz78VE1xBk+F+jsty+Npw0afSb8db3Qn9pRTp7tsbjlCJ4bF7MKLzXUjt8KlCw8DPDPZoHfaF3ZhtYsI63MECAwEAAQKCAYAjdeYZDOAQ4K5XIfRVArqnYMbo/YmETFhhuJdjDNCyG+d5vV1VmP8iUsB3jVEWZuR4RoieGh8LbUo57xoMvnOhL9TNdao4Yj5EbA3MkHsiRQu7/OB73jmvg1DfVJSoVTHcXzhHguPJalSTXkH8VNbizNRd89yXlKlpkKrrs1JtGZWqZ1K0JhDwbwJSrJQifr3w1ZMJsDMZ3L1QIfRrzXzFvkDs9VxKJVEGgqp+d4WXrOjQcBlxc5RE94lK1xWlwgjC0rY0cX5u9/dSxryumq+prxhWlV/GKYHBsszGO7yijUl06sHQNLYn0KBm3A8y7uJNe4kZ4XA3B7uGv8Gccl0Zlwg4ZFY1JpR6I+0tatr6cWwwhxlF5rxiJ/m6lVEmoynos1vmkP/7gWJhKADlCbGboATiwT6bPtu60bHvxOyiLEiKj4k6uW2nzjPmvkOt3qgiZ+Cm/70XpvoMhCxE9gSEe+ZprmPwbJlwrvAx2HFwiUr8YhDgT9h0qtq2eyG6K/0CgcEA8k89pceUbmT+6LtmUN8E3be92TrsM67DJri9iNOjZBnTs8qh7ZkS9QTtw5dxR8XgfDRB6sH78fmlTFKnTMQXKayJyZciMD3xkKAV8ICZD3Uv6V2I7BHg7WdqtSJICfAbLy+FGtJ7Es3/9S2wYQgw/IqfJ7+XuzBDC/Gdh/M8pRvNfshWwR+9WMp9M8NKmFW3nmpwDh7InjRj/n08SkqO9DZXzyguDrg4/ZdE6sNmG29CWJCDMHU83PA26rnzEzq9AoHBAOFvqyMoVM32YrfcZZfQMiWLxO7lza/lnUzxMfknUujmdmwTZ6aaVkWNBRDN0rUPFGaArFx6tcrBoRkxgPnuOEciFT9mVi/LWXuFvVr6UgKQY8+pFFuAZGmkmv2Ghx3fs7tqly170qLWIU5n9Ch1rYuvO9xmqIejRPUgtaXMPm0CB3OJpfzKftlG0mizh6rZbsb0t5uwvDBPJ2R5np8hMsAg91i4B5vqHf8kpOv01mVfSEYHdYSWCcta3tlwI62MVQKBwQCVrIDmAEwdjOEwnWFsHvaAhlkM8CqrGg6NwpvBAwnwcUulyUsQ2vcsxmif4tIkhYRO9HCrNDwOkiia5otVDeNI6L0L+wExT3IB5gDnWGgzdi2sNwy21axcuP7e+FgLW3dPREkx8kX3raunpRtINKkdtfrtsJlnFT61CABI0+ToEC51XAbKsHJjgGCqMr3HL1uGzTR+ZGGD59TEhFNTiI6ZJ2BCJA2fJgh+DIyTfzN5StZuooWGz0RTLUae41HU1PkCgcEA2wnCMaXVSE12O4kEmQ4sOzjjvu8//AFQ5lqQILLppuuN8pKkKkdZPbi4TEx/x3aAbtvlHPIJwpiCa9UiqTSiL9NY68IGSef96LvYcRY5Ks6afEGfSwykA9Vw1paooAkkPBxkCUh/L8J4mBL/M3Sri8ZWll6Urz2fGcGPXSnnGclX7hW3Vrh1qa1bcWnGjuU28k8CO17sas/tyX019w2tnuopCmW81uwR+z7ik3TP/60lrw0+TPXvTEvdrU19DPoFAoHANgxvNmiyxR361bBpAsvFSHg8fL22mvDCYAR6j2ggmIGFRKSA4j+Pl95uXzRt843GNClLsxgjS4aQEndENgr7Vq4vmU0oNfaIvi6L6wuJQ2f5tgOzTQKo647DiEi5YciQhTAk6ZWPTBt/UavIipWDq/oTIUPI+RMIj48Ohi5MUVyynpkfIe7KfQoeuoUM0xVwWmcu9kt5grY1uXrmnLhUbOtRts6kqbiLuGlqdo2kSyVxu3C8NAeLnlqI2G79g5RA'; // private key PEM

		// Minimal example settings for an SP
		$settingsInfo = [
			'strict' => true,
			'debug'  => false,
		
			'sp' => [
				'entityId' => $entityId,
				'assertionConsumerService' => [
				  'url'     => $acsUrl,
				  'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
				],
				'singleLogoutService' => [
				  'url'     => $slsUrl,
				  'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
				],
				'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName',
			
				// published in metadata:
				'x509cert'   => $spPublicCert,
			
				// used at runtime for signing requests etc (not exported in metadata):
				'privateKey' => $spPrivateKey,
			  ],
		
			// IdP section can be empty for generating SP metadata,
			// but the library still expects the key to exist in many configs
			'idp' => [
				'entityId' => 'https://saml.n2adgangsstyring.eksterntest-stoettesystemerne.dk/runtime',
				'singleSignOnService' => ['url' => 'https://n2adgangsstyring.eksterntest-stoettesystemerne.dk/runtime/saml2/issue.idp', 'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'],
				'singleLogoutService' => ['url' => 'https://n2adgangsstyring.eksterntest-stoettesystemerne.dk/runtime/saml2/logout.idp', 'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'],
				'x509cert' => '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',
			],
		
			// security flags that show up in SPSSODescriptor as in your sample
			'security' => [
				'authnRequestsSigned' => true,
				'wantAssertionsSigned' => true,
				'wantAssertionsEncrypted' => true,
				'signatureAlgorithm' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
				'digestAlgorithm'    => 'http://www.w3.org/2001/04/xmlenc#sha256',
			],
		];
		
		$settings = new Settings($settingsInfo);
		
		// Generate metadata XML
		$metadata = $settings->getSPMetadata();
		
		// Validate metadata against schema rules
		$errors = $settings->validateMetadata($metadata);
			

		// ---- 2) Load DOM and ensure EntityDescriptor has an ID to reference ----
		$doc = new DOMDocument();
		$doc->preserveWhiteSpace = false;
		$doc->formatOutput = true;
		$doc->loadXML($metadata);

		$xpath = new \DOMXPath($doc);

		// Find SLS node
		$sls = $xpath->query('//*[local-name()="SingleLogoutService" and namespace-uri()="urn:oasis:names:tc:SAML:2.0:metadata"]')->item(0);
		if ($sls instanceof \DOMElement) {
			// Add ResponseLocation (optional but you want it)
			$sls->setAttribute('ResponseLocation', $slsResponseUrl);
		}
		
		// Find ACS nodes
		$acsNodes = $xpath->query('//*[local-name()="AssertionConsumerService" and namespace-uri()="urn:oasis:names:tc:SAML:2.0:metadata"]');
		if ($acsNodes && $acsNodes->length > 0) {
		
			// If you only have one ACS, make it index 0 and default
			/** @var \DOMElement $acs */
			$acs = $acsNodes->item(0);
		
			$acs->setAttribute('index', '0');
			$acs->setAttribute('isDefault', 'true');
		
			// (Optional) if your generator produced multiple ACS entries, ensure only one is default:
			for ($i = 1; $i < $acsNodes->length; $i++) {
				$acsNodes->item($i)->removeAttribute('isDefault');
			}
		}
		

		$doc->preserveWhiteSpace = true;   // keep exactly what is there
		$doc->formatOutput = false;        // IMPORTANT: do not re-indent

		/*
		$entityDescriptor = $doc->documentElement; // <EntityDescriptor ...>
		if (!$entityDescriptor->hasAttribute('ID')) {
		// Create an ID similar to your example: _uuid
		$id = $this->uuidv4();
		$entityDescriptor->setAttribute('ID', $id);
		} else {
		$id = $entityDescriptor->getAttribute('ID');
		}
		*/

		$entityDescriptor = $doc->documentElement;
		// Remove accidental "Id" attribute (case-sensitive!)
		/*
		if ($entityDescriptor->hasAttribute('Id')) {
		  $entityDescriptor->removeAttribute('Id');
		}
		
		// Ensure we have a single ID
		if (!$entityDescriptor->hasAttribute('ID')) {
		  $entityDescriptor->setAttribute('ID', '_' . $this->uuidv4());
		}
		*/
		// Tell DOM / xmlsec this attribute is of type ID
		/*
		$entityDescriptor->setAttribute('Id', '_' . $this->uuidv4());
		$entityDescriptor->setIdAttribute('Id', true);
		$id = $entityDescriptor->getAttribute('Id');
*/

/*
		$this->removeBlankTextNodes($entityDescriptor);
		$entityDescriptor->removeAttribute('validUntil');
		$entityDescriptor->removeAttribute('cacheDuration');

		$entityDescriptor->setAttribute('ID', $id);
		$entityDescriptor->setIdAttribute('ID', true);
		// ---- 4) Sign (enveloped) with xmlseclibs: exc-c14n, rsa-sha256, sha256 digest ----
		$dsig = new XMLSecurityDSig();
		$dsig->idKeys = ['ID'];
		$dsig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
*/

		$id = '_' . $this->uuidv4();
		$this->removeBlankTextNodes($entityDescriptor);            // before signing
		$entityDescriptor->removeAttribute('Id');
		$entityDescriptor->setAttribute('ID', $id);
		$entityDescriptor->setIdAttribute('ID', true);

		$dsig = new XMLSecurityDSig();
		$dsig->idKeys = ['ID'];
		$dsig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);

		// Reference the EntityDescriptor by its ID
		$dsig->addReference(
			$entityDescriptor,
			XMLSecurityDSig::SHA256,
			[
				'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
				'http://www.w3.org/2001/10/xml-exc-c14n#',
			],
			[
				'id_name'   => 'ID',         // use ID attribute name
				'force_uri' => true,         // do not auto-generate pfx... URIs
				'uri'       => '#' . $id,    // the URI you want
			]
		);

			/*
		//$this->removeBlankTextNodes($entityDescriptor);
		$id = $entityDescriptor->getAttribute('Id');
		$entityDescriptor->removeAttribute('Id');
		$entityDescriptor->setAttribute('ID', $id);
		$entityDescriptor->setIdAttribute('ID', true);  // also important
*/

		//$entityDescriptor->removeAttribute('validUntil');
		//$entityDescriptor->removeAttribute('cacheDuration');


		// Format certificates to proper PEM format
		$spPrivateKeyPem = $this->formatAsPem($spPrivateKey, 'PRIVATE KEY');
		$spPublicCertPem = $this->formatAsPem($spPublicCert, 'CERTIFICATE');

		$key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'private']);
		$key->loadKey($spPrivateKeyPem, false, false);

		/*
		if ($entityDescriptor->hasAttribute('Id')) {
			$entityDescriptor->removeAttribute('Id');
		  }
*/
		
		
		// Create signature and insert it right under EntityDescriptor (like your sample)
		$dsig->sign($key);
		$dsig->add509Cert($spPublicCertPem, true, false, ['issuerSerial' => false]);
		$dsig->insertSignature($entityDescriptor, $entityDescriptor->firstChild);

		// Save XML without the XML declaration
		$metadata = $doc->saveXML($doc->documentElement);
		file_put_contents('/var/www/html/apps-extra/dkmunicipalorganisation/sp-metadata.xml', $metadata);

		if (!empty($errors)) {
			$metadata =  "Metadata validation errors:\n" . implode("\n", $errors) . "Metadata:\n" . $metadata;
		}

		return $metadata;
	}

	// ---------------- helpers ----------------

	function removeBlankTextNodes(DOMElement $node): void {
		if (!$node->hasChildNodes()) return;
	  
		// iterate backwards because we may remove nodes
		for ($i = $node->childNodes->length - 1; $i >= 0; $i--) {
		  $child = $node->childNodes->item($i);
	  
		  if ($child->nodeType === XML_TEXT_NODE && trim($child->nodeValue) === '') {
			$node->removeChild($child);
			continue;
		  }
		  if ($child instanceof DOMElement && $child->hasChildNodes()) {
			$this->removeBlankTextNodes($child);
		  }
		}
	  }

	  
	/**
	 * Format a base64 string as PEM (with proper headers and line breaks)
	 */
	private function formatAsPem(string $base64String, string $type): string {
		// Remove any existing whitespace
		$base64String = preg_replace('/\s+/', '', $base64String);
		
		// Add line breaks every 64 characters
		$formatted = chunk_split($base64String, 64, "\n");
		
		// Remove trailing newline
		$formatted = rtrim($formatted, "\n");
		
		// Add PEM headers
		return "-----BEGIN {$type}-----\n{$formatted}\n-----END {$type}-----\n";
	}

	function uuidv4(): string {
		$data = random_bytes(16);
		$data[6] = chr((ord($data[6]) & 0x0f) | 0x40);
		$data[8] = chr((ord($data[8]) & 0x3f) | 0x80);
		$hex = bin2hex($data);
		return sprintf('%s-%s-%s-%s-%s',
		substr($hex, 0, 8),
		substr($hex, 8, 4),
		substr($hex, 12, 4),
		substr($hex, 16, 4),
		substr($hex, 20, 12)
		);
	}
  
	/**
	 * Force a particular prefix for a namespace throughout the document.
	 * This is ONLY needed if someone hard-requires "m:" rather than "md:".
	 */
	function forcePrefix(DOMDocument $doc, string $ns, string $prefix): void {
		$xpath = new DOMXPath($doc);
		// Find all elements in the namespace (XPath doesn't need a prefix if we use local-name + namespace-uri)
		$nodes = $xpath->query('//*[namespace-uri()="'.$ns.'"]');
		if (!$nodes) return;
	
		/** @var DOMElement $el */
		foreach ($nodes as $el) {
		// Rename node with desired prefix
		$doc->renameNode($el, $ns, $prefix . ':' . $el->localName);
		}
	
		// Ensure root has xmlns:prefix mapping
		$root = $doc->documentElement;
		if ($root && !$root->hasAttribute('xmlns:' . $prefix)) {
		$root->setAttribute('xmlns:' . $prefix, $ns);
		}
    }	
}

