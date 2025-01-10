/**
 * @file funcoes.c
 * @brief Implementação das funções auxiliares utilizadas na aplicação.
 *
 * Este arquivo contém funções para manipulação de dados e interação com APIs
 * e bibliotecas externas.
 */

#include "funcoes.h"

// Chave secreta utilizada para assinar tokens JWT
const char *KEY = "secretKEY"; // Chave secreta para assinar os tokens    

/**
 * @brief Manipulador para sinal de interrupção (SIGINT).
 * @param sig Código do sinal recebido.
 *
 * Define a variável global `running` como falsa, permitindo
 * que a aplicação encerre seu loop principal de execução.
 */
void handle_sigint(int sig) {
    running = false;
}

/**
 * @brief Estabelece conexão com o banco de dados.
 *
 * A conexão é configurada com base em variáveis globais para host, porta, nome
 * do banco, usuário e senha. Caso a conexão falhe, a aplicação será encerrada.
 */
 void init_db_connection() {
    char conninfo[256];
    snprintf(conninfo, sizeof(conninfo), 
             "host=%s port=%s dbname=%s user=%s password=%s", 
             DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASS);

    conn = PQconnectdb(conninfo);
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "Erro ao conectar ao banco de dados: %s\n", PQerrorMessage(conn));
        exit(EXIT_FAILURE);
    }
    printf("Conexão com o banco de dados estabelecida.\n");
}

/**
 * @brief Fecha a conexão com o banco de dados, se existir.
 */
void close_db_connection() {
    if (conn) {
        PQfinish(conn);
    }
}

/**
 * @brief Executa uma consulta SQL genérica e retorna os resultados como JSON.
 * @param query Consulta SQL a ser executada.
 * @param fields Array com os nomes dos campos esperados no resultado.
 * @param field_count Número de campos esperados.
 * @return String JSON com os resultados ou uma mensagem de erro.
 */
 char *handle_get_query(const char *query, const char **fields, int field_count) {
    PGresult *res = PQexec(conn, query);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Erro na consulta SQL: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return strdup("{\"error\": \"Erro ao buscar dados.\"}");
    }

    cJSON *json_array = cJSON_CreateArray();
    for (int i = 0; i < PQntuples(res); i++) {
        cJSON *item = cJSON_CreateObject();
        for (int j = 0; j < field_count; j++) {
            cJSON_AddStringToObject(item, fields[j], PQgetvalue(res, i, j));
        }
        cJSON_AddItemToArray(json_array, item);
    }

    char *response_str = cJSON_PrintUnformatted(json_array);
    cJSON_Delete(json_array);
    PQclear(res);

    return response_str;
}

/**
 * @brief Roteamento de requisições HTTP.
 * @param method Método HTTP (GET, POST etc.).
 * @param url Endpoint solicitado.
 * @param post_buffer Dados enviados no corpo da requisição (para POST).
 * @param conn Conexão com o banco de dados.
 * @param connection Estrutura de conexão HTTP.
 * @return Resposta JSON como string.
 */
 char *route_request(const char *method, const char *url, const char *post_buffer, PGconn *conn, struct MHD_Connection *connection)
{
    const char *auth_header = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Authorization");

    // Rotas públicas: não requerem autenticação
    if ((strcmp(url, "/register") == 0 && strcmp(method, "POST") == 0) ||
        (strcmp(url, "/login") == 0 && strcmp(method, "POST") == 0)) {
        // Processar registro ou login sem validação de token
        if (strcmp(url, "/register") == 0) {
            cJSON *json = cJSON_Parse(post_buffer);
            if (!json) {
                return strdup("{\"error\": \"Invalid JSON\"}");
            }

            const cJSON *username = cJSON_GetObjectItemCaseSensitive(json, "username");
            const cJSON *senha = cJSON_GetObjectItemCaseSensitive(json, "senha");
            const cJSON *cpf = cJSON_GetObjectItemCaseSensitive(json, "cpf");
            const cJSON *email = cJSON_GetObjectItemCaseSensitive(json, "email");

            if (!username || !username->valuestring || 
                !senha || !senha->valuestring || 
                !cpf || !cpf->valuestring || 
                !email || !email->valuestring) {
                cJSON_Delete(json);
                return strdup("{\"error\": \"Username, password, CPF, and email are required\"}");
            }

            char *response = register_user(username->valuestring, senha->valuestring, cpf->valuestring, email->valuestring, KEY);
            cJSON_Delete(json);
            return response;
        } else if (strcmp(url, "/login") == 0) {
            cJSON *json = cJSON_Parse(post_buffer);
            if (!json) {
                return strdup("{\"error\": \"Invalid JSON\"}");
            }

            const cJSON *username = cJSON_GetObjectItemCaseSensitive(json, "username");
            const cJSON *senha = cJSON_GetObjectItemCaseSensitive(json, "senha");

            if (!username || !username->valuestring || !senha || !senha->valuestring) {
                cJSON_Delete(json);
                return strdup("{\"error\": \"Username and password are required\"}");
            }

            char *response = login_user(username->valuestring, senha->valuestring, KEY);
            cJSON_Delete(json);
            return response;
        }
    }

    // Rotas protegidas: requerem autenticação
    // Verificar token JWT    
    if (!auth_header || strncmp(auth_header, "Bearer ", 7) != 0) {
        return strdup("{\"error\": \"Unauthorized\"}");
    }

    const char *token = auth_header ? auth_header + 7 : NULL; // Ignora "Bearer "
    if (token && !validate_token(token, KEY)) {
        return strdup("{\"error\": \"Invalid or expired token\"}");
    }

    // Identificar nível de acesso do usuário
    int user_role = get_role_id_from_token(token); // Implementação que retorna o role_id a partir do token.
    if (user_role < 0) {
        return strdup("{\"error\": \"Invalid or expired token\"}");
    }

    // Processar requisições por método
    if (strcmp(method, "GET") == 0) {
        if (user_role < 1) {
            return strdup("{\"error\": \"Access denied: Role 1 or higher required\"}");
        }
        if(strcmp(url, "/tables") == 0){
            char query[256];
            snprintf(query, sizeof(query),
                    "SELECT table_name FROM information_schema.tables "
                    "WHERE table_schema = 'public' AND table_name LIKE '%s%%';",
                    "uso_da_terra_");

            PGresult* res = PQexec(conn, query);

            if (PQresultStatus(res) != PGRES_TUPLES_OK) {
                fprintf(stderr, "Query failed: %s\n", PQerrorMessage(conn));
                PQclear(res);
                return NULL;
            }

            cJSON* json_array = cJSON_CreateArray();
            int rows = PQntuples(res);
            for (int i = 0; i < rows; i++) {
                const char* table_name = PQgetvalue(res, i, 0);
                cJSON_AddItemToArray(json_array, cJSON_CreateString(table_name));
            }
            char *json_response = cJSON_Print(json_array);
            cJSON_Delete(json_array);
            PQclear(res);

            if (!json_response) {
                fprintf(stderr, "Failed to serialize JSON.\n");
                return strdup("{\"error\": \"Failed to serialize JSON\"}");
            }

            // Retorna o JSON como string
            return json_response;
        }
        if (strncmp(url, "/uso_da_terra_", 14) == 0) {
            char* response = process_request_auto(url, conn);
            return response ? response : strdup("{\"error\": \"Unknown error\"}");
        }
    }
    if (strcmp(method, "POST") == 0) {
        if (user_role < 3) {
            return strdup("{\"error\": \"Access denied: Role 3 or higher required\"}");
        }
        // Rotas POST
        // Adicionar rotas POST conforme necessário
    }

    // Resposta padrão para rotas desconhecidas
    return strdup("{\"error\": \"Endpoint not found\"}");
}

/**
 * @brief Manipula requisições HTTP recebidas pela aplicação.
 * @param cls Contexto do aplicativo (não utilizado aqui).
 * @param connection Estrutura de conexão HTTP.
 * @param url Endpoint solicitado.
 * @param method Método HTTP (e.g., GET, POST).
 * @param version Versão do protocolo HTTP.
 * @param upload_data Dados enviados no corpo da requisição (POST/PUT).
 * @param upload_data_size Tamanho dos dados no corpo da requisição.
 * @param con_cls Ponteiro para dados de conexão persistente entre chamadas.
 * @return Resultado do processamento da requisição (MHD_Result).
 *
 * Esta função inicializa buffers para dados de upload, processa o corpo da requisição,
 * chama o roteador de requisições e envia a resposta HTTP.
 */
enum MHD_Result handle_request(void *cls, struct MHD_Connection *connection, 
                               const char *url, const char *method, const char *version, 
                               const char *upload_data, size_t *upload_data_size, void **con_cls) {
    if (*con_cls == NULL) {
        char *buffer = calloc(1024, sizeof(char));
        if (!buffer) return MHD_NO;
        *con_cls = buffer;
        return MHD_YES;
    }

    char *post_buffer = *con_cls;

    if (*upload_data_size > 0) {
        strncat(post_buffer, upload_data, *upload_data_size);
        *upload_data_size = 0;
        return MHD_YES;
    }

    char *response_str = route_request(method, url, post_buffer, conn, connection);


    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(response_str),
                                                                    (void *)response_str,
                                                                    MHD_RESPMEM_MUST_FREE);
    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);

    free(*con_cls);
    *con_cls = NULL;

    return ret;
}

/**
 * @brief Verifica os privilégios do usuário no banco de dados.
 * @param conn Conexão com o banco de dados.
 * @param username Nome do usuário a ser verificado.
 * @return 1 se o usuário tiver privilégios, 0 caso contrário.
 */
int check_user_privileges(PGconn *conn, const char *username) {
    const char *query = "SELECT can_post FROM users WHERE username = $1";
    const char *paramValues[1] = {username};

    PGresult *res = PQexecParams(conn, query, 1, NULL, paramValues, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return 0;  // Não autorizado
    }

    // Verificar privilégio
    int can_post = atoi(PQgetvalue(res, 0, 0));
    PQclear(res);
    return can_post;  // Retorna 1 se autorizado, 0 caso contrário
}
/**
 * @brief Registra um novo usuário no sistema.
 * @param username Nome do usuário.
 * @param senha Senha do usuário.
 * @param cpf CPF do usuário.
 * @param email E-mail do usuário.
 * @param key Chave secreta para gerar tokens JWT.
 * @return Resposta JSON indicando sucesso ou erro no registro.
 */
char *register_user(const char *username, const char *senha, const char *cpf, const char *email, const char *key)
{
    char password_hash[65];
    char query[512];
    PGresult *res;

    // Validação de CPF
    if (!validar_cpf(cpf)) {
        return strdup("{\"error\": \"CPF inválido\"}");
    }

    // Gerar hash da senha
    gerar_hash_sha256(senha, password_hash);

    // Converter o role_id para string
    char role_id_str[12];
    snprintf(role_id_str, sizeof(role_id_str), "%d", 1); // role_id fixo como "1"

    // Montar a query SQL para inserir o usuário
    snprintf(query, sizeof(query),
             "INSERT INTO users_register (username, password_hash, cpf, email, role_id) VALUES ($1, $2, $3, $4, $5)");

    const char *paramValues[5] = {username, password_hash, cpf, email, role_id_str};
    res = PQexecParams(conn, query, 5, NULL, paramValues, NULL, NULL, 0);
    
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        // Verificar se o erro é relacionado a duplicidade de chave
        if (strstr(PQerrorMessage(conn), "duplicate key value")) {
            if (strstr(PQerrorMessage(conn), "users_register_username_key")) {
                PQclear(res);
                // Gerar novo token para o usuário existente
                int role = 1; // Recuperar do banco, se necessário
                char *token = generate_token(username, cpf, role, key);
                cJSON *response = cJSON_CreateObject();
                cJSON_AddStringToObject(response, "message", "Usuário já existe");
                cJSON_AddStringToObject(response, "token", token);
                char *response_str = cJSON_PrintUnformatted(response);
                cJSON_Delete(response);
                free(token);
                return response_str;            }
            if (strstr(PQerrorMessage(conn), "users_register_cpf_key")) {
                PQclear(res);
                return strdup("{\"error\": \"CPF já registrado\"}");
            }
        }
        // Erro genérico
        char error_message[256];
        snprintf(error_message, sizeof(error_message), "{\"error\": \"Erro ao registrar usuário: %s\"}", PQerrorMessage(conn));
        PQclear(res);
        return strdup(error_message);        
    }

    PQclear(res);

    // Gerar o token JWT
    jwt_t *jwt = NULL;
    char *token = NULL;

    if (jwt_new(&jwt) != 0) {
        return strdup("{\"error\": \"Failed to create token\"}");
    }

    jwt_add_grant(jwt, "username", username);
    jwt_add_grant(jwt, "cpf", cpf);

    // Configurar expiração para 24 horas
    time_t exp_time = time(NULL) + 86400;
    jwt_add_grant_int(jwt, "exp", exp_time);

    // Definir algoritmo e chave de assinatura
    jwt_set_alg(jwt, JWT_ALG_HS256, (unsigned char *)key, strlen(key));

    // Gerar o token como string
    token = jwt_encode_str(jwt);
    if (!token) {
        jwt_free(jwt);
        return strdup("{\"error\": \"Failed to encode token\"}");
    }

    jwt_free(jwt);

    // Retornar o token como resposta JSON
    cJSON *response = cJSON_CreateObject();
    cJSON_AddStringToObject(response, "token", token);
    char *response_str = cJSON_PrintUnformatted(response);

    free(token);
    cJSON_Delete(response);
    return response_str;
}
/**
 * @brief Valida um token JWT.
 * @param token Token JWT a ser validado.
 * @param key Chave secreta para validação do token.
 * @return 1 se o token for válido, 0 caso contrário.
 */
int validate_token(const char *token, const char *key) {
    jwt_t *jwt = NULL;

    if (jwt_decode(&jwt, token, (unsigned char *)key, strlen(key)) != 0) {
        return 0; // Token inválido
    }

    // Verificar expiração
    time_t now = time(NULL);
    time_t exp = jwt_get_grant_int(jwt, "exp");
    if (now > exp) {
        jwt_free(jwt);
        return 0; // Token expirado
    }

    // Verificar campos obrigatórios
    const char *username = jwt_get_grant(jwt, "username");
    const char *cpf = jwt_get_grant(jwt, "cpf");
    int role = jwt_get_grant_int(jwt, "role");

    if (!username || !cpf || role < 0) {
        jwt_free(jwt);
        return 0; // Token inválido
    }

    jwt_free(jwt);
    return 1; // Token válido
}
/**
 * @brief Valida um número de CPF.
 * 
 * Verifica se o CPF fornecido é válido com base no formato e nos dígitos verificadores.
 * 
 * @param cpf String contendo o CPF a ser validado.
 * @return true se o CPF for válido, false caso contrário.
 */
bool validar_cpf(const char *cpf)
{
    if (strlen(cpf) != 11) {
        return false;
    }
    for (int i = 0; i < 11; i++) {
        if (!isdigit(cpf[i])) {
            return false;
        }
    }
    // Validação dos dígitos verificadores
    int soma = 0, resto;
    for (int i = 0; i < 9; i++) {
        soma += (cpf[i] - '0') * (10 - i);
    }
    resto = (soma * 10) % 11;
    if (resto == 10) resto = 0;
    if (resto != (cpf[9] - '0')) return false;

    soma = 0;
    for (int i = 0; i < 10; i++) {
        soma += (cpf[i] - '0') * (11 - i);
    }
    resto = (soma * 10) % 11;
    if (resto == 10) resto = 0;
    return resto == (cpf[10] - '0');
}
/**
 * @brief Gera o hash SHA-256 para uma string de entrada.
 * 
 * Calcula o hash da entrada fornecida e armazena o resultado em formato hexadecimal no buffer de saída.
 * 
 * @param input String de entrada a ser hashada.
 * @param output Buffer onde o hash gerado será armazenado.
 */
void gerar_hash_sha256(const char *input, char *output) {
    EVP_MD_CTX *mdctx;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    // Criar o contexto de digest
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "Erro ao criar contexto de digest\n");
        return;
    }

    // Inicializar o contexto com SHA-256
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        fprintf(stderr, "Erro ao inicializar digest SHA-256\n");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    // Atualizar o digest com os dados de entrada
    if (EVP_DigestUpdate(mdctx, input, strlen(input)) != 1) {
        fprintf(stderr, "Erro ao atualizar digest SHA-256\n");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    // Finalizar o digest e obter o hash
    if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
        fprintf(stderr, "Erro ao finalizar digest SHA-256\n");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    // Converter o hash em uma string hexadecimal
    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[hash_len * 2] = '\0';

    // Liberar o contexto
    EVP_MD_CTX_free(mdctx);
}
/**
 * @brief Realiza login de um usuário.
 * 
 * Verifica as credenciais do usuário no banco de dados, valida a senha fornecida e retorna um token JWT se bem-sucedido.
 * 
 * @param username Nome do usuário.
 * @param senha Senha do usuário.
 * @param key Chave secreta para assinatura do token JWT.
 * @return String JSON contendo o token JWT ou mensagem de erro.
 */
char *login_user(const char *username, const char *senha, const char *key)
{
    char query[256];
    PGresult *res;

    // Consultar o banco para verificar se o usuário existe
    snprintf(query, sizeof(query),
             "SELECT password_hash, cpf FROM users_register WHERE username = $1");
    const char *paramValues[1] = {username};
    res = PQexecParams(conn, query, 1, NULL, paramValues, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return strdup("{\"error\": \"Usuário não encontrado\"}");
    }

    // Obter o hash da senha e o CPF do banco
    const char *stored_hash = PQgetvalue(res, 0, 0);
    const char *cpf = PQgetvalue(res, 0, 1);

    // Verificar a senha
    char password_hash[65];
    gerar_hash_sha256(senha, password_hash);
    if (strcmp(stored_hash, password_hash) != 0) {
        PQclear(res);
        return strdup("{\"error\": \"Senha incorreta\"}");
    }

    PQclear(res);

    // Gerar um novo token JWT
    jwt_t *jwt = NULL;
    char *token = NULL;

    if (jwt_new(&jwt) != 0) {
        return strdup("{\"error\": \"Falha ao criar token\"}");
    }

    jwt_add_grant(jwt, "username", username);
    jwt_add_grant(jwt, "cpf", cpf);

    // Configurar expiração para 24 horas
    time_t exp_time = time(NULL) + 86400;
    jwt_add_grant_int(jwt, "exp", exp_time);

    // Definir algoritmo e chave de assinatura
    jwt_set_alg(jwt, JWT_ALG_HS256, (unsigned char *)key, strlen(key));

    // Gerar o token como string
    token = jwt_encode_str(jwt);
    if (!token) {
        jwt_free(jwt);
        return strdup("{\"error\": \"Falha ao codificar token\"}");
    }

    jwt_free(jwt);

    // Retornar o token como resposta JSON
    cJSON *response = cJSON_CreateObject();
    cJSON_AddStringToObject(response, "token", token);
    char *response_str = cJSON_PrintUnformatted(response);

    free(token);
    cJSON_Delete(response);
    return response_str;
}
/**
 * @brief Obtém o ID do papel de um usuário a partir de um token JWT.
 * 
 * Decodifica o token JWT e extrai o campo "role", que indica o nível de acesso do usuário.
 * 
 * @param token Token JWT codificado.
 * @return ID do papel (role) se válido, -1 em caso de erro.
 */
int get_role_id_from_token(const char *token) {
    jwt_t *jwt = NULL;

    if (jwt_decode(&jwt, token, (unsigned char *)KEY, strlen(KEY)) != 0) {
        return -1; // Token inválido ou expirado
    }

    int role_id = jwt_get_grant_int(jwt, "role");
    jwt_free(jwt);

    return role_id >= 0 ? role_id : -1;
}
/**
 * @brief Recupera o token existente de um usuário.
 * 
 * Consulta o banco de dados para verificar se já existe um token associado ao nome de usuário fornecido.
 * 
 * @param username Nome do usuário.
 * @return String contendo o token JWT ou NULL se não encontrado.
 */
char *get_existing_token(const char *username)
{
    const char *query = "SELECT token FROM users_register WHERE username = $1";
    const char *paramValues[1] = {username};
    PGresult *res = PQexecParams(conn, query, 1, NULL, paramValues, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return NULL; // Token não encontrado
    }

    char *token = strdup(PQgetvalue(res, 0, 0));
    PQclear(res);
    return token;
}
/**
 * @brief Gera um token JWT para um usuário.
 * 
 * Cria um token JWT assinado com informações do usuário, como nome, CPF e nível de acesso (role).
 * 
 * @param username Nome do usuário.
 * @param cpf CPF do usuário.
 * @param role ID do papel (role) do usuário.
 * @param key Chave secreta usada para assinar o token.
 * @return String contendo o token JWT gerado.
 */
char *generate_token(const char *username, const char *cpf, int role, const char *key) {
    jwt_t *jwt = NULL;
    char *token = NULL;

    if (jwt_new(&jwt) != 0) {
        return strdup("{\"error\": \"Failed to create token\"}");
    }

    jwt_add_grant(jwt, "username", username);
    jwt_add_grant(jwt, "cpf", cpf);
    jwt_add_grant_int(jwt, "role", role);

    // Configurar expiração para 24 horas
    time_t exp_time = time(NULL) + 86400;
    jwt_add_grant_int(jwt, "exp", exp_time);

    // Definir algoritmo e chave de assinatura
    jwt_set_alg(jwt, JWT_ALG_HS256, (unsigned char *)key, strlen(key));

    // Gerar o token como string
    token = jwt_encode_str(jwt);
    if (!token) {
        jwt_free(jwt);
        return strdup("{\"error\": \"Failed to encode token\"}");
    }

    jwt_free(jwt);

    // Retornar o token
    return token;
}

/**
 * @brief Retorna o conteúdo de uma tabela do banco de dados em formato JSON.
 * 
 * Consulta todos os registros de uma tabela específica e organiza os dados em um array JSON.
 * 
 * @param conn Conexão ativa com o banco de dados.
 * @param table_name Nome da tabela a ser consultada.
 * @return Objeto JSON contendo os dados da tabela ou NULL em caso de erro.
 */
cJSON* get_table_content_as_json(PGconn* conn, const char* table_name) {
    char query[256];
    snprintf(query, sizeof(query), "SELECT * FROM %s;", table_name);

    PGresult* res = PQexec(conn, query);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Query failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return NULL;
    }

    cJSON* json_array = cJSON_CreateArray();
    int rows = PQntuples(res);
    int cols = PQnfields(res);

    for (int i = 0; i < rows; i++) {
        cJSON* row = cJSON_CreateObject();
        for (int j = 0; j < cols; j++) {
            const char* col_name = PQfname(res, j);
            const char* col_value = PQgetvalue(res, i, j);
            cJSON_AddStringToObject(row, col_name, col_value);
        }
        cJSON_AddItemToArray(json_array, row);
    }

    PQclear(res);
    return json_array;
}
/**
 * @brief Lista tabelas do banco de dados com um prefixo específico.
 * 
 * Consulta as tabelas do banco de dados cujo nome começa com o prefixo fornecido.
 * 
 * @param conn Conexão ativa com o banco de dados.
 * @param prefix Prefixo a ser usado para filtrar as tabelas.
 * @return Array JSON contendo os nomes das tabelas ou NULL em caso de erro.
 */
cJSON* get_tables_as_json(PGconn* conn, const char* prefix) {
    char query[256];
    snprintf(query, sizeof(query),
             "SELECT table_name FROM information_schema.tables "
             "WHERE table_schema = 'public' AND table_name LIKE '%s%%';",
             prefix);

    PGresult* res = PQexec(conn, query);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Query failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return NULL;
    }

    cJSON* json_array = cJSON_CreateArray();
    int rows = PQntuples(res);
    for (int i = 0; i < rows; i++) {
        const char* table_name = PQgetvalue(res, i, 0);
        cJSON_AddItemToArray(json_array, cJSON_CreateString(table_name));
    }

    PQclear(res);
    return json_array;
}
/**
 * @brief Processa requisições para tabelas com prefixo "uso_da_terra".
 * 
 * Extrai o sufixo da URL, identifica a tabela correspondente e retorna seu conteúdo em formato JSON.
 * 
 * @param url URL da requisição.
 * @param conn Conexão ativa com o banco de dados.
 * @return String JSON contendo os dados da tabela ou mensagem de erro.
 */
char* process_request_auto(const char* url, PGconn* conn) {
    if (strncmp(url, "/uso_da_terra_", 14) != 0) {
        return NULL; // Indica que a rota não corresponde.
    }

    const char* table_name_suffix = url + 14;
    char full_table_name[256];
    snprintf(full_table_name, sizeof(full_table_name), "uso_da_terra_%s", table_name_suffix);

    cJSON* table_json = get_table_content_as_json(conn, full_table_name);
    if (!table_json) {
        return strdup("{\"error\": \"Table not found or query failed\"}");
    }

    char* json_response = cJSON_Print(table_json);
    cJSON_Delete(table_json);
    return json_response;
}
