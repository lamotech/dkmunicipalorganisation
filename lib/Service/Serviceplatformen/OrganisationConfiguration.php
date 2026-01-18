<?php
    
    namespace OCA\DKMunicipalOrganisation\Service\Serviceplatformen;

/**
 * OrganisationConfiguration - Configuration for the Organisation service
 *
 * This class holds the configuration settings needed to connect
 * to the Organisation SOAP service.
 */
class OrganisationConfiguration
{
    private string $endpoint;
    private string $clientCertificatePath;
    private string $clientCertificatePassword;
    private string $organisationServiceCertificatePath;

    public function getEndpoint(): string
    {
        return $this->endpoint;
    }

    public function setEndpoint(string $endpoint): self
    {
        $this->endpoint = $endpoint;
        return $this;
    }

    public function getClientCertificatePath(): string
    {
        return $this->clientCertificatePath;
    }

    public function setClientCertificatePath(string $clientCertificatePath): self
    {
        $this->clientCertificatePath = $clientCertificatePath;
        return $this;
    }

    public function getClientCertificatePassword(): string
    {
        return $this->clientCertificatePassword;
    }

    public function setClientCertificatePassword(string $clientCertificatePassword): self
    {
        $this->clientCertificatePassword = $clientCertificatePassword;
        return $this;
    }

    public function getOrganisationServiceCertificatePath(): string
    {
        return $this->organisationServiceCertificatePath;
    }

    public function setOrganisationServiceCertificatePath(string $organisationServiceCertificatePath): self
    {
        $this->organisationServiceCertificatePath = $organisationServiceCertificatePath;
        return $this;
    }
}
