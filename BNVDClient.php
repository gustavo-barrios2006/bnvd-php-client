<?php

/**
 * BNVD API Client - PHP
 * Cliente oficial para a API do Banco Nacional de Vulnerabilidades Cibernéticas
 * @version 1.0.0
 */

namespace BNVD;

/**
 * Níveis de severidade CVSS
 */
class Severity
{
    const LOW = 'LOW';
    const MEDIUM = 'MEDIUM';
    const HIGH = 'HIGH';
    const CRITICAL = 'CRITICAL';
}

/**
 * Configuração do cliente
 */
class Config
{
    public string $baseUrl;
    public int $timeout;
    public array $headers;

    public function __construct(string $baseUrl, int $timeout = 30, array $headers = [])
    {
        $this->baseUrl = $baseUrl;
        $this->timeout = $timeout;
        $this->headers = array_merge([
            'Content-Type' => 'application/json',
        ], $headers);
    }
}

/**
 * Parâmetros de paginação
 */
class PaginationParams
{
    public ?int $page = null;
    public ?int $perPage = null;

    public function __construct(?int $page = null, ?int $perPage = null)
    {
        $this->page = $page;
        $this->perPage = $perPage;
    }

    public function toQueryParams(): array
    {
        $params = [];
        if ($this->page !== null) {
            $params['page'] = $this->page;
        }
        if ($this->perPage !== null) {
            $params['per_page'] = $this->perPage;
        }
        return $params;
    }
}

/**
 * Parâmetros de busca
 */
class SearchParams extends PaginationParams
{
    public ?int $year = null;
    public ?string $severity = null;
    public ?string $vendor = null;
    public ?bool $includePt = true;

    public function __construct(
        ?int $page = null,
        ?int $perPage = null,
        ?int $year = null,
        ?string $severity = null,
        ?string $vendor = null,
        ?bool $includePt = true
    ) {
        parent::__construct($page, $perPage);
        $this->year = $year;
        $this->severity = $severity;
        $this->vendor = $vendor;
        $this->includePt = $includePt;
    }

    public function toQueryParams(): array
    {
        $params = parent::toQueryParams();
        if ($this->year !== null) {
            $params['year'] = $this->year;
        }
        if ($this->severity !== null) {
            $params['severity'] = $this->severity;
        }
        if ($this->vendor !== null) {
            $params['vendor'] = $this->vendor;
        }
        if ($this->includePt !== null) {
            $params['include_pt'] = $this->includePt ? 'true' : 'false';
        }
        return $params;
    }
}

/**
 * Parâmetros de busca recente
 */
class RecentSearchParams extends PaginationParams
{
    public ?int $days = null;
    public ?bool $includePt = true;

    public function __construct(
        ?int $page = null,
        ?int $perPage = null,
        ?int $days = null,
        ?bool $includePt = true
    ) {
        parent::__construct($page, $perPage);
        $this->days = $days;
        $this->includePt = $includePt;
    }

    public function toQueryParams(): array
    {
        $params = parent::toQueryParams();
        if ($this->days !== null) {
            $params['days'] = $this->days;
        }
        if ($this->includePt !== null) {
            $params['include_pt'] = $this->includePt ? 'true' : 'false';
        }
        return $params;
    }
}

/**
 * Resposta da API
 */
class APIResponse
{
    public string $status;
    public mixed $data;
    public ?string $message;
    public ?array $pagination;

    public function __construct(array $json)
    {
        $this->status = $json['status'] ?? 'error';
        $this->data = $json['data'] ?? null;
        $this->message = $json['message'] ?? null;
        $this->pagination = $json['pagination'] ?? null;
    }

    public function isSuccess(): bool
    {
        return $this->status === 'success';
    }

    public function isError(): bool
    {
        return $this->status === 'error';
    }
}

/**
 * Cliente da API BNVD
 */
class Client
{
    private Config $config;

    public function __construct(Config $config)
    {
        $this->config = $config;
    }

    /**
     * Faz requisição HTTP para a API
     */
    private function request(string $endpoint, array $params = []): APIResponse
    {
        $url = $this->config->baseUrl . $endpoint;

        if (!empty($params)) {
            $url .= '?' . http_build_query($params);
        }

        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'header' => $this->buildHeaders(),
                'timeout' => $this->config->timeout,
                'ignore_errors' => true,
            ],
        ]);

        $response = @file_get_contents($url, false, $context);

        if ($response === false) {
            throw new \Exception('HTTP request failed');
        }
        $json = json_decode($response, true);

        if($endpoint == "/api/v1/")
        {
            $json["data"] = $json;
            $json["status"] = "success";
        }

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \Exception('JSON decode error: ' . json_last_error_msg());
        }

        return new APIResponse($json);
    }

    private function buildHeaders(): string
    {
        $headers = [];
        foreach ($this->config->headers as $key => $value) {
            $headers[] = "$key: $value";
        }
        return implode("\r\n", $headers);
    }

    /**
     * Retorna informações sobre a API
     */
    public function getAPIInfo(): APIResponse
    {
        return $this->request('/api/v1/');
    }

    /**
     * Lista todas as vulnerabilidades com suporte a paginação e filtros
     */
    public function listVulnerabilities(?SearchParams $params = null): APIResponse
    {
        $queryParams = $params ? $params->toQueryParams() : [];
        return $this->request('/api/v1/vulnerabilities', $queryParams);
    }

    /**
     * Busca uma vulnerabilidade específica pelo CVE ID
     */
    public function getVulnerability(string $cveId, bool $includePt = true): APIResponse
    {
        return $this->request("/api/v1/vulnerabilities/$cveId", [
            'include_pt' => $includePt ? 'true' : 'false',
        ]);
    }

    /**
     * Busca vulnerabilidades recentes
     */
    public function getRecentVulnerabilities(?RecentSearchParams $params = null): APIResponse
    {
        $queryParams = $params ? $params->toQueryParams() : [];
        return $this->request('/api/v1/search/recent', $queryParams);
    }

    /**
     * Retorna as 5 vulnerabilidades mais recentes
     */
    public function getTop5Recent(bool $includePt = true): APIResponse
    {
        return $this->request('/api/v1/search/recent/5', [
            'include_pt' => $includePt ? 'true' : 'false',
        ]);
    }

    /**
     * Busca vulnerabilidades por ano
     */
    public function searchByYear(int $year, ?PaginationParams $params = null): APIResponse
    {
        $queryParams = $params ? $params->toQueryParams() : [];
        return $this->request("/api/v1/search/year/$year", $queryParams);
    }

    /**
     * Busca vulnerabilidades por severidade
     */
    public function searchBySeverity(string $severity, ?PaginationParams $params = null): APIResponse
    {
        $queryParams = $params ? $params->toQueryParams() : [];
        return $this->request("/api/v1/search/severity/$severity", $queryParams);
    }

    /**
     * Busca vulnerabilidades por vendor/fabricante
     */
    public function searchByVendor(string $vendor, ?PaginationParams $params = null): APIResponse
    {
        $queryParams = $params ? $params->toQueryParams() : [];
        return $this->request("/api/v1/search/vendor/$vendor", $queryParams);
    }

    /**
     * Retorna estatísticas gerais
     */
    public function getStats(): APIResponse
    {
        return $this->request('/api/v1/stats');
    }

    /**
     * Retorna estatísticas por ano
     */
    public function getYearStats(): APIResponse
    {
        return $this->request('/api/v1/stats/years');
    }
}
