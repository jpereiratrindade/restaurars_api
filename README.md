
# Restaurars API

## Descrição
O projeto **Restaurars API** é uma aplicação em C projetada para o gerenciamento e exposição de dados relacionados ao projeto Restaura Rural RS. Ele utiliza bibliotecas modernas para conectar-se a bancos de dados PostgreSQL, manipular dados JSON e fornecer serviços HTTP por meio de APIs RESTful.

## Funcionalidades
- Conexão com banco de dados PostgreSQL utilizando `libpq`.
- Servidor HTTP integrado com `libmicrohttpd`.
- Manipulação e formatação de dados JSON com `libcjson`.

## Estrutura do Projeto
- **main.c**: Ponto de entrada do aplicativo.
- **funcoes.c** e **funcoes.h**: Implementações de funções auxiliares.
- **CMakeLists.txt**: Configuração do projeto para CMake.
- **LICENSE**: Detalhes da licença do projeto.

## Dependências
Certifique-se de ter as seguintes dependências instaladas no sistema:
- `gcc` ou outro compilador C compatível.
- `libpq-dev`: Para integração com PostgreSQL.
- `libmicrohttpd-dev`: Para fornecer serviços HTTP.
- `libcjson-dev`: Para manipulação de JSON.
- CMake 3.10 ou superior: Para gerenciamento de builds.

No Fedora, você pode instalar as dependências com:
```bash
sudo dnf install gcc cmake libpq-devel libmicrohttpd-devel cjson-devel
```

No Ubuntu, use:
```bash
sudo apt update
sudo apt install gcc cmake libpq-dev libmicrohttpd-dev libcjson-dev
```

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

4. Execute o binário:
    ```bash
    ./bin/restaurars_api
    ```

5. (Opcional) Instale o binário no sistema:
    ```bash
    make install
    ```

   O binário será instalado no diretório `/home/$USER/bin` por padrão.

## Estrutura do Código
- `main.c`: Contém a função principal e a inicialização da API.
- `funcoes.c` e `funcoes.h`: Implementam funções auxiliares para lidar com conexões ao banco de dados, formatação JSON e endpoints HTTP.

## Testes
Verifique a funcionalidade enviando requisições para o servidor:
```bash
curl http://localhost:8080/api/example
```

## Licença
Este projeto é licenciado sob a GNU General Public License v3.0. Veja o arquivo `LICENSE` para mais detalhes.
