# BNVD API Client - PHP

Cliente oficial em PHP para a API do Banco Nacional de Vulnerabilidades Cibernéticas (BNVD).

## Requisitos

- PHP 8.0 ou superior
- Extensão JSON habilitada

## Instalação

Via Composer:

```bash
composer require bnvd/bnvd-client
```

## Uso

```php
<?php

require_once 'vendor/autoload.php';

use BNVD\Client;
use BNVD\Config;
use BNVD\SearchParams;
use BNVD\Severity;

// Configurar cliente
$config = new Config(
    baseUrl: 'https://bnvd.org',
    timeout: 30
);

$client = new Client($config);

// Listar vulnerabilidades
$params = new SearchParams(
    page: 1,
    perPage: 20,
    includePt: true
);

$result = $client->listVulnerabilities($params);

if ($result->isSuccess()) {
    echo "Total: " . $result->pagination['total'] . "\n";
    foreach ($result->data as $vuln) {
        echo $vuln['cve']['id'] . "\n";
    }
}

// Buscar vulnerabilidade específica
$vuln = $client->getVulnerability('CVE-2024-12345');

// Buscar por ano
$vulns2024 = $client->searchByYear(2024);

// Buscar por severidade
$critical = $client->searchBySeverity(Severity::CRITICAL);

// Buscar vulnerabilidades recentes
$recentParams = new \BNVD\RecentSearchParams(
    days: 7,
    perPage: 20
);
$recent = $client->getRecentVulnerabilities($recentParams);

// Obter estatísticas
$stats = $client->getStats();
echo "Total de vulnerabilidades: " . $stats->data['total_vulnerabilities'] . "\n";
```

## Métodos Disponíveis

### Informações da API
- `getAPIInfo()` - Retorna informações sobre a API

### Vulnerabilidades
- `listVulnerabilities($params)` - Lista todas as vulnerabilidades
- `getVulnerability($cveId, $includePt)` - Busca vulnerabilidade específica
- `getRecentVulnerabilities($params)` - Vulnerabilidades recentes
- `getTop5Recent($includePt)` - Top 5 mais recentes
- `searchByYear($year, $params)` - Busca por ano
- `searchBySeverity($severity, $params)` - Busca por severidade
- `searchByVendor($vendor, $params)` - Busca por fabricante

### Estatísticas
- `getStats()` - Estatísticas gerais
- `getYearStats()` - Estatísticas por ano

## Níveis de Severidade

```php
use BNVD\Severity;

Severity::LOW       // Baixa
Severity::MEDIUM    // Média
Severity::HIGH      // Alta
Severity::CRITICAL  // Crítica
```

## Tratamento de Erros

```php
try {
    $result = $client->getVulnerability('CVE-INVALID');
    if ($result->isError()) {
        echo "Erro: " . $result->message . "\n";
    }
} catch (\Exception $e) {
    echo "Erro de requisição: " . $e->getMessage() . "\n";
}
```

## Exemplos Avançados

### Busca com Múltiplos Filtros

```php
$params = new SearchParams(
    page: 1,
    perPage: 50,
    year: 2024,
    severity: Severity::CRITICAL,
    includePt: true
);

$result = $client->listVulnerabilities($params);
```

### Paginação

```php
$page = 1;
$perPage = 20;

do {
    $params = new SearchParams(page: $page, perPage: $perPage);
    $result = $client->listVulnerabilities($params);
    
    // Processar resultados
    foreach ($result->data as $vuln) {
        // ...
    }
    
    $page++;
} while ($page <= $result->pagination['total_pages']);
```

## Licença

MIT
