# Restaurars API

## Descrição
O projeto **Restaurars API** é uma aplicação para gerenciamento e exposição de dados relacionados ao projeto Restaura Rural RS. 
Foi desenvolvida em C e utiliza bibliotecas como `pq`, `microhttpd` e `cjson` para conectar-se ao banco de dados PostgreSQL 
e expor APIs HTTP.

## Dependências
- `gcc` ou outro compilador compatível
- `libpq-dev` para integração com PostgreSQL
- `libmicrohttpd-dev` para servidor HTTP
- `libcjson-dev` para manipulação de JSON
- CMake 3.10 ou superior

## Compilação e Execução
### Etapas
1. Clone o repositório:
    ```bash
    git clone <URL_DO_REPOSITORIO>
    cd <NOME_DO_REPOSITORIO>
    ```
2. Configure o build com CMake:
    ```bash
    cmake .
    ```
3. Compile o projeto:
    ```bash
    make
    ```
4. Instale o binário (opcional):
    ```bash
    make install
    ```

O binário será instalado em `/home/$USER/bin` por padrão.

## Licença
Este projeto é licenciado sob a GNU General Public License v3.0. Veja o arquivo `LICENSE` para mais detalhes.
