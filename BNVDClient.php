<?php

/**
 * BNVD API Client - PHP
 *
 * Cliente oficial para a API do Banco Nacional de Vulnerabilidades Cibernéticas (BNVD).
 * Este cliente fornece métodos convenientes para consumir os endpoints REST da API,
 * permitindo buscar vulnerabilidades, estatísticas e informações gerais.
 *
 * @package BNVD
 * @version 1.0.0
 * @license MIT
 */

namespace BNVD;

/**
 * Representa os níveis de severidade CVSS utilizados pelo BNVD.
 *
 * @see https://nvd.nist.gov/vuln-metrics/cvss
 */
class Severity
{
    const LOW = 'LOW';
    const MEDIUM = 'MEDIUM';
    const HIGH = 'HIGH';
    const CRITICAL = 'CRITICAL';
}

/**
 * Representa a configuração do cliente BNVD.
 *
 * Inclui URL base, timeout e cabeçalhos HTTP personalizados.
 */
class Config
{
    /**
     * URL base da API BNVD.
     *
     * @var string
     */
    public string $baseUrl;

    /**
     * Tempo limite em segundos para as requisições HTTP.
     *
     * @var int
     */
    public int $timeout;

    /**
     * Cabeçalhos HTTP adicionais a serem incluídos em cada requisição.
     *
     * @var array<string, string>
     */
    public array $headers;

    /**
     * @param string $baseUrl URL base da API (ex: "https://bnvd-api.gov.br")
     * @param int $timeout Tempo limite da requisição em segundos
     * @param array<string, string> $headers Cabeçalhos personalizados
     */
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
 * Define parâmetros de paginação para consultas à API.
 */
class PaginationParams
{
    /**
     * Número da página atual.
     *
     * @var int|null
     */
    public ?int $page = null;

    /**
     * Número de resultados por página.
     *
     * @var int|null
     */
    public ?int $perPage = null;

    /**
     * @param int|null $page Número da página
     * @param int|null $perPage Itens por página
     */
    public function __construct(?int $page = null, ?int $perPage = null)
    {
        $this->page = $page;
        $this->perPage = $perPage;
    }

    /**
     * Converte os parâmetros em formato de query string.
     *
     * @return array<string, int>
     */
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
 * Define parâmetros para busca de vulnerabilidades na API (estende {@see PaginationParams}).
 */
class SearchParams extends PaginationParams
{
    /**
     * Ano de publicação da vulnerabilidade.
     *
     * @var int|null
     */
    public ?int $year = null;

    /**
     * Severidade da vulnerabilidade (LOW, MEDIUM, HIGH, CRITICAL).
     *
     * @var string|null
     */
    public ?string $severity = null;

    /**
     * Fabricante ou fornecedor associado à vulnerabilidade.
     *
     * @var string|null
     */
    public ?string $vendor = null;

    /**
     * Indica se deve incluir traduções em português.
     *
     * @var bool|null
     */
    public ?bool $includePt = true;

    /**
     * @param int|null $page Página de resultados
     * @param int|null $perPage Itens por página
     * @param int|null $year Ano da vulnerabilidade
     * @param string|null $severity Severidade (ver {@see Severity})
     * @param string|null $vendor Fabricante
     * @param bool|null $includePt Incluir tradução PT-BR
     */
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

    /**
     * @inheritDoc
     */
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
 * Parâmetros para busca de vulnerabilidades recentes (estende {@see PaginationParams}).
 */
class RecentSearchParams extends PaginationParams
{
    /**
     * Número de dias desde hoje para considerar vulnerabilidades recentes.
     *
     * @var int|null
     */
    public ?int $days = null;

    /**
     * Incluir tradução em português.
     *
     * @var bool|null
     */
    public ?bool $includePt = true;

    /**
     * @param int|null $page Página de resultados
     * @param int|null $perPage Itens por página
     * @param int|null $days Intervalo em dias
     * @param bool|null $includePt Incluir tradução PT-BR
     */
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

    /**
     * @inheritDoc
     */
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
 * Representa a resposta da API BNVD.
 */
class APIResponse
{
    /**
     * Status da resposta (success|error).
     *
     * @var string
     */
    public string $status;

    /**
     * Dados retornados pela API.
     *
     * @var mixed
     */
    public mixed $data;

    /**
     * Mensagem de erro, caso aplicável.
     *
     * @var string|null
     */
    public ?string $message;

    /**
     * Dados de paginação, se existirem.
     *
     * @var array|null
     */
    public ?array $pagination;

    /**
     * @param array<string, mixed> $json Dados decodificados do JSON retornado
     */
    public function __construct(array $json)
    {
        $this->status = $json['status'] ?? 'error';
        $this->data = $json['data'] ?? null;
        $this->message = $json['message'] ?? null;
        $this->pagination = $json['pagination'] ?? null;
    }

    /**
     * Verifica se a resposta foi bem-sucedida.
     *
     * @return bool
     */
    public function isSuccess(): bool
    {
        return $this->status === 'success';
    }
    public function isSuccess(): bool
    {
        return $this->status === 'success';
    }

    /**
     * Verifica se a resposta contém erro.
     *
     * @return bool
     */
    public function isError(): bool
    {
        return $this->status === 'error';
    }
}

/**
 * Cliente principal para comunicação com a API BNVD.
 *
 * Esta classe fornece métodos de alto nível para acessar os principais endpoints
 * do Banco Nacional de Vulnerabilidades Cibernéticas.
 */
class Client
{
    /**
     * Configuração do cliente HTTP.
     *
     * @var Config
     */
    private Config $config;

    /**
     * @param Config $config Instância de configuração do cliente
     */
    public function __construct(Config $config)
    {
        $this->config = $config;
    }

    /**
     * Executa uma requisição GET à API.
     *
     * @param string $endpoint Caminho do endpoint (ex: "/api/v1/vulnerabilities")
     * @param array<string, string|int|bool> $params Parâmetros de query
     * @return APIResponse
     *
     * @throws \Exception Se houver erro de rede ou JSON inválido
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

    /**
     * Gera os cabeçalhos HTTP formatados.
     *
     * @return string
     */
    private function buildHeaders(): string
    {
        $headers = [];
        foreach ($this->config->headers as $key => $value) {
            $headers[] = "$key: $value";
        }
        return implode("\r\n", $headers);
    }

    /**
     * Retorna informações gerais sobre a API (metadados).
     *
     * Consulta o endpoint raiz da versão da API para obter metadados descritivos
     * — por exemplo: name, version, endpoints disponíveis e parâmetros suportados.
     *
     * @return APIResponse Objeto APIResponse com os metadados da API (campo `data`).
     *
     * @throws \Exception Se a requisição falhar ou a resposta JSON for inválida.
     */
    public function getAPIInfo(): APIResponse
    {
        return $this->request('/api/v1/');
    }

    /**
     * Lista todas as vulnerabilidades com suporte a paginação e filtros
     *     *
     * @param SearchParams|null $params Parâmetros opcionais de busca e paginação.
     * @return APIResponse Resposta com lista de vulnerabilidades e, se houver, dados de paginação.
     *
     * @throws \Exception Se a requisição falhar ou a resposta JSON for inválida.
     */
    public function listVulnerabilities(?SearchParams $params = null): APIResponse
    {
        $queryParams = $params ? $params->toQueryParams() : [];
        return $this->request('/api/v1/vulnerabilities', $queryParams);
    }

    /**
     * Busca uma vulnerabilidade específica pelo CVE ID
     *
     * @param string $cveId Identificador CVE (ex: "CVE-2025-12345").
     * @param bool $includePt Indica se deve incluir traduções em português (padrão: true).
     * @return APIResponse Objeto contendo os detalhes da vulnerabilidade.
     *
     * @throws \Exception Se a requisição falhar ou a resposta JSON for inválida.
     */
    public function getVulnerability(string $cveId, bool $includePt = true): APIResponse
    {
        return $this->request("/api/v1/vulnerabilities/$cveId", [
            'include_pt' => $includePt ? 'true' : 'false',
        ]);
    }

    /**
     * Busca vulnerabilidades recentes
     *
     * @param RecentSearchParams|null $params Parâmetros de busca recente (page, perPage, days, includePt).
     * @return APIResponse Lista de vulnerabilidades recentes e paginação.
     *
     * @throws \Exception Se a requisição falhar ou a resposta JSON for inválida.
     */
    public function getRecentVulnerabilities(?RecentSearchParams $params = null): APIResponse
    {
        $queryParams = $params ? $params->toQueryParams() : [];
        return $this->request('/api/v1/search/recent', $queryParams);
    }

    /**
     * Retorna as 5 vulnerabilidades mais recentes
     *
     * @param bool $includePt Incluir tradução em português (padrão: true).
     * @return APIResponse Resposta com até 5 vulnerabilidades mais recentes.
     *
     * @throws \Exception Se a requisição falhar ou a resposta JSON for inválida.
     */
    public function getTop5Recent(bool $includePt = true): APIResponse
    {
        return $this->request('/api/v1/search/recent/5', [
            'include_pt' => $includePt ? 'true' : 'false',
        ]);
    }

    /**
     * Busca vulnerabilidades por ano
     *
     * @param int $year Ano desejado (ex: 2024).
     * @param PaginationParams|null $params Parâmetros de paginação (page, perPage).
     * @return APIResponse Lista de vulnerabilidades do ano solicitado com paginação.
     *
     * @throws \Exception Se a requisição falhar ou a resposta JSON for inválida.
     */
    public function searchByYear(int $year, ?PaginationParams $params = null): APIResponse
    {
        $queryParams = $params ? $params->toQueryParams() : [];
        return $this->request("/api/v1/search/year/$year", $queryParams);
    }

    /**
     * Busca vulnerabilidades por severidade CVSS.
     *
     * @param string $severity Severidade desejada (ex: Severity::CRITICAL).
     * @param PaginationParams|null $params Parâmetros de paginação (opcional).
     * @return APIResponse Lista de vulnerabilidades filtradas por severidade.
     *
     * @throws \Exception Se a requisição falhar ou a resposta JSON for inválida.
     */
    public function searchBySeverity(string $severity, ?PaginationParams $params = null): APIResponse
    {
        $queryParams = $params ? $params->toQueryParams() : [];
        return $this->request("/api/v1/search/severity/$severity", $queryParams);
    }

    /**
     * Busca vulnerabilidades por vendor/fabricante
     *
     * @param string $vendor Nome do fabricante (ex: "Microsoft", "Cisco").
     * @param PaginationParams|null $params Parâmetros de paginação (opcional).
     * @return APIResponse Lista de vulnerabilidades relacionadas ao vendor.
     *
     * @throws \Exception Se a requisição falhar ou a resposta JSON for inválida.
     */
    public function searchByVendor(string $vendor, ?PaginationParams $params = null): APIResponse
    {
        $queryParams = $params ? $params->toQueryParams() : [];
        return $this->request("/api/v1/search/vendor/$vendor", $queryParams);
    }

    /**
     * Retorna estatísticas gerais
     *
     * @return APIResponse Estatísticas gerais (campo `data`).
     *
     * @throws \Exception Se a requisição falhar ou a resposta JSON for inválida.
     */
    public function getStats(): APIResponse
    {
        return $this->request('/api/v1/stats');
    }

    /**
     * Retorna estatísticas por ano
     *
     * @return APIResponse Estatísticas por ano (array no campo `data`).
     *
     * @throws \Exception Se a requisição falhar ou a resposta JSON for inválida.
     */
    public function getYearStats(): APIResponse
    {
        return $this->request('/api/v1/stats/years');
    }

    /**
     * Lista todas as notícias cadastradas na base do BNVD.
     *
     * Permite o uso de parâmetros de paginação para controlar
     * o número de resultados retornados por requisição.
     *
     * @param PaginationParams|null $params Parâmetros opcionais de paginação (página e quantidade por página).
     *
     * @return APIResponse Objeto contendo a resposta da API com a lista de notícias.
     *
     * @throws \Exception Caso a requisição HTTP falhe ou o JSON retornado seja inválido.
     */
    public function listNoticias(?PaginationParams $params = null): APIResponse
    {
        $queryParams = $params ? $params->toQueryParams() : [];
        return $this->request('/api/v1/noticias', $queryParams);
    }

    /**
     * Retorna as notícias mais recentes indexadas pelo BNVD.
     *
     * O número de notícias retornadas pode ser controlado pelo parâmetro `$limit`.
     *
     * @param int $limit Quantidade de notícias recentes a serem retornadas (padrão: 5).
     *
     * @return APIResponse Objeto contendo a lista das notícias mais recentes.
     *
     * @throws \Exception Caso a requisição HTTP falhe ou o JSON retornado seja inválido.
     */
    public function getRecentNoticias(int $limit = 5): APIResponse
    {
        return $this->request("/api/v1/noticias/recentes/$limit");
    }

    /**
     * Busca uma notícia específica utilizando seu slug.
     *
     * O slug é o identificador textual único de cada notícia no sistema.
     *
     * @param string $slug Slug único da notícia desejada.
     *
     * @return APIResponse Objeto contendo os detalhes completos da notícia.
     *
     * @throws \Exception Caso a requisição HTTP falhe ou o JSON retornado seja inválido.
     */
    public function getNoticiaBySlug(string $slug): APIResponse
    {
        return $this->request("/api/v1/noticias/$slug");
    }

    /**
     * Retorna informações gerais sobre os endpoints do BNVD para consultas relacionadas ao sistema MITRE ATT&CK.
     *
     * @return APIResponse Objeto contendo informações sobre o MITRE ATT&CK.
     *
     * @throws \Exception Caso a requisição HTTP falhe ou o JSON retornado seja inválido.
     */    public function getMitreInfo(): APIResponse
    {
        return $this->request('/api/v1/mitre');
    }

    /**
     * Lista todas as matrizes MITRE ATT&CK disponíveis na base de dados.
     *
     * Cada matriz contém uma taxonomia de técnicas, táticas e relacionamentos
     * utilizadas por grupos de ameaças conhecidas.
     *
     * @return APIResponse Objeto contendo a lista de matrizes MITRE ATT&CK.
     *
     * @throws \Exception Caso a requisição HTTP falhe ou o JSON retornado seja inválido.
     */
     */    public function listMitreMatrices(): APIResponse
    {
        return $this->request('/api/v1/mitre/matrices');
    }

    /**
     * Retorna detalhes de uma matriz MITRE ATT&CK específica.
     *
     * É possível incluir traduções para o português definindo `$includePt` como true.
     *
     * @param string $matrixName Nome da matriz a ser consultada.
     * @param bool   $includePt  Indica se a resposta deve incluir traduções em português (padrão: true).
     *
     * @return APIResponse Objeto contendo os dados detalhados da matriz solicitada.
     *
     * @throws \Exception Caso a requisição HTTP falhe ou o JSON retornado seja inválido.
     */
    public function getMitreMatrix(string $matrixName, bool $includePt = true): APIResponse
    {
        return $this->request("/api/v1/mitre/matrix/$matrixName", [
            'include_pt' => $includePt ? 'true' : 'false',
        ]);
    }

    /**
     * Lista todas as técnicas do sistema MITRE ATT&CK.
     *
     * Pode receber parâmetros opcionais para filtragem e paginação.
     *
     * @param array $params Parâmetros opcionais de filtragem e paginação.
     *
     * @return APIResponse Objeto contendo a lista de técnicas MITRE ATT&CK.
     *
     * @throws \Exception Caso a requisição HTTP falhe ou o JSON retornado seja inválido.
     */
    public function listMitreTechniques(array $params = []): APIResponse
    {
        return $this->request('/api/v1/mitre/techniques', $params);
    }

    /**
     * Retorna detalhes de uma técnica MITRE ATT&CK específica.
     *
     * É possível incluir traduções em português utilizando `$includePt = true`.
     *
     * @param string $techniqueId Identificador único da técnica.
     * @param bool   $includePt   Indica se a resposta deve incluir traduções em português (padrão: true).
     *
     * @return APIResponse Objeto contendo os detalhes da técnica especificada.
     *
     * @throws \Exception Caso a requisição HTTP falhe ou o JSON retornado seja inválido.
     */
    public function getMitreTechnique(string $techniqueId, bool $includePt = true): APIResponse
    {
        return $this->request("/api/v1/mitre/technique/$techniqueId", [
            'include_pt' => $includePt ? 'true' : 'false',
        ]);
    }

    /**
     * Lista todas as subtécnicas MITRE ATT&CK.
     *
     * Cada subtécnica está associada a uma técnica principal e pode
     * conter parâmetros opcionais de filtragem.
     *
     * @param array $params Parâmetros opcionais de filtragem e paginação.
     *
     * @return APIResponse Objeto contendo a lista de subtécnicas.
     *
     * @throws \Exception Caso a requisição HTTP falhe ou o JSON retornado seja inválido.
     */
    public function listMitreSubtechniques(array $params = []): APIResponse
    {
        return $this->request('/api/v1/mitre/subtechniques', $params);
    }

    /**
     * Lista todos os grupos de ameaças MITRE ATT&CK.
     *
     * Cada grupo representa uma entidade conhecida que utiliza táticas
     * e técnicas específicas para realizar ataques.
     *
     * @param array $params Parâmetros opcionais de filtragem e paginação.
     *
     * @return APIResponse Objeto contendo a lista de grupos MITRE ATT&CK.
     *
     * @throws \Exception Caso a requisição HTTP falhe ou o JSON retornado seja inválido.
     */
    public function listMitreGroups(array $params = []): APIResponse
    {
        return $this->request('/api/v1/mitre/groups', $params);
    }

    /**
     * Retorna detalhes de um grupo de ameaças específico do MITRE ATT&CK.
     *
     * É possível incluir traduções em português ajustando o parâmetro `$includePt`.
     *
     * @param string $groupId   Identificador único do grupo.
     * @param bool   $includePt Indica se a resposta deve incluir traduções em português (padrão: true).
     *
     * @return APIResponse Objeto contendo os detalhes completos do grupo.
     *
     * @throws \Exception Caso a requisição HTTP falhe ou o JSON retornado seja inválido.
     */
    public function getMitreGroup(string $groupId, bool $includePt = true): APIResponse
    {
        return $this->request("/api/v1/mitre/group/$groupId", [
            'include_pt' => $includePt ? 'true' : 'false',
        ]);
    }

    /**
     * Lista todas as mitigações MITRE ATT&CK.
     *
     * As mitigações descrevem contramedidas ou estratégias para reduzir
     * a eficácia das técnicas de ataque conhecidas.
     *
     * @param array $params Parâmetros opcionais de filtragem e paginação.
     *
     * @return APIResponse Objeto contendo a lista de mitigações.
     *
     * @throws \Exception Caso a requisição HTTP falhe ou o JSON retornado seja inválido.
     */
    public function listMitreMitigations(array $params = []): APIResponse
    {
        return $this->request('/api/v1/mitre/mitigations', $params);
    }

    /**
     * Retorna detalhes de uma mitigação específica.
     *
     * É possível incluir traduções em português ajustando o parâmetro `$includePt`.
     *
     * @param string $mitigationId Identificador único da mitigação.
     * @param bool   $includePt    Indica se a resposta deve incluir traduções em português (padrão: true).
     *
     * @return APIResponse Objeto contendo os detalhes da mitigação solicitada.
     *
     * @throws \Exception Caso a requisição HTTP falhe ou o JSON retornado seja inválido.
     */
    public function getMitreMitigation(string $mitigationId, bool $includePt = true): APIResponse
    {
        return $this->request("/api/v1/mitre/mitigation/$mitigationId", [
            'include_pt' => $includePt ? 'true' : 'false',
        ]);
    }
}
}