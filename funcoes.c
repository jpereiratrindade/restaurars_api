/**
 * @file funcoes.c
 * @brief Implementação das funções auxiliares utilizadas na aplicação.
 *
 * Este arquivo contém funções para manipulação de dados e interação com APIs
 * e bibliotecas externas.
 */

#include "funcoes.h"

void handle_sigint(int sig) {
    running = false;
}

// Funções de inicialização e finalização do banco
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

void close_db_connection() {
    if (conn) {
        PQfinish(conn);
    }
}

// Função genérica para lidar com GET usando queries SQL
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

// Função específica para /uso_da_terra_municipio
char *handle_get_uso_da_terra_municipio() {
    const char *fields[] = {"id", "nome", "codigo_ibge"};
    const char *query = "SELECT id, nome, codigo_ibge FROM uso_da_terra_municipio";
    return handle_get_query(query, fields, 3);
}

// Função específica para /uso_da_terra_corede
char *handle_get_uso_da_terra_corede() {
    const char *fields[] = {"id", "nome", "descricao", "regiao_funcional_id"};
    const char *query = "SELECT id, nome, descricao, regiao_funcional_id FROM uso_da_terra_corede";
    return handle_get_query(query, fields, 3);
}

// Função específica para /uso_da_terra_bioma
char *handle_get_uso_da_terra_bioma() {
    const char *fields[] = {"id", "nome", "descricao", "area_total"};
    const char *query = "SELECT id, nome, descricao, area_total FROM uso_da_terra_bioma";
    return handle_get_query(query, fields, 3);
}

// Função específica para /uso_da_terra_regiaofuncional
char *handle_get_uso_da_terra_regiaofuncional() {
    const char *fields[] = {"id", "name", "description"};
    const char *query = "SELECT id, name, description FROM uso_da_terra_regiaofuncional";
    return handle_get_query(query, fields, 3);
}

// Função específica para /uso_da_terra_classeusoterra
char *handle_get_uso_da_terra_classeusoterra() {
    const char *fields[] = {"id", "label", "description"};
    const char *query = "SELECT id, label, description FROM uso_da_terra_classeusoterra";
    return handle_get_query(query, fields, 3);
}

// Função específica para /uso_da_terra_tipocampo
char *handle_get_uso_da_terra_tipocampo() {
    const char *fields[] = {"id", "nome", "descricao"};
    const char *query = "SELECT id, nome, descricao FROM uso_da_terra_tipocampo";
    return handle_get_query(query, fields, 3);
}

// Função específica para /uso_da_terra_registrousoterra
char *handle_get_uso_da_terra_registrousoterra() {
    const char *fields[] = {"id", "classe_uso_terra_id", "tipo_campo_id", "cobertura"};
    const char *query = "SELECT id, classe_uso_terra_id, tipo_campo_id, cobertura FROM uso_da_terra_registrousoterra";
    return handle_get_query(query, fields, 3);
}

// Função específica para /uso_da_terra_metadadosniveisotto
char *handle_get_uso_da_terra_metadadosniveisotto() {
    const char *fields[] = {"id", "level", "source", "description"};
    const char *query = "SELECT id, level, source, description FROM uso_da_terra_metadadosniveisotto";
    return handle_get_query(query, fields, 3);
}

// Função específica para /uso_da_terra_colecaomapbiomas
char *handle_get_uso_da_terra_colecaomapbiomas() {
    const char *fields[] = {"id", "name", "description"};
    const char *query = "SELECT id, name, description FROM uso_da_terra_colecaomapbiomas";
    return handle_get_query(query, fields, 3);
}

// Roteamento de requisições
char *route_request(const char *method, const char *url, const char *post_buffer) {
    if (strcmp(method, "GET") == 0) {
        if (strcmp(url, "/uso_da_terra_municipio") == 0) {
            return handle_get_uso_da_terra_municipio();
        } else if (strcmp(url, "/uso_da_terra_corede") == 0) {
            return handle_get_uso_da_terra_corede();
        } else if (strcmp(url, "/uso_da_terra_bioma") == 0) {
            return handle_get_uso_da_terra_bioma();
        } else if (strcmp(url, "/uso_da_terra_regiaofuncional") == 0) {
            return handle_get_uso_da_terra_regiaofuncional();
        } else if (strcmp(url, "/uso_da_terra_classeusoterra") == 0) {
            return handle_get_uso_da_terra_classeusoterra();
        } else if (strcmp(url, "/uso_da_terra_tipocampo") == 0) {
            return handle_get_uso_da_terra_tipocampo();
        } else if (strcmp(url, "/uso_da_terra_registrousoterra") == 0) {
            return handle_get_uso_da_terra_registrousoterra();
        } else if (strcmp(url, "/uso_da_terra_metadadosniveisotto") == 0) {
            return handle_get_uso_da_terra_metadadosniveisotto();
        } else if (strcmp(url, "/uso_da_terra_colecaomapbiomas") == 0) {
            return handle_get_uso_da_terra_colecaomapbiomas();
        }
    }
    return strdup("{\"error\": \"Endpoint não encontrado ou método não permitido.\"}");
}

// Lida com requisições HTTP
enum MHD_Result handle_request(void *cls, struct MHD_Connection *connection, 
                                      const char *url, const char *method, const char *version, 
                                      const char *upload_data, size_t *upload_data_size, void **con_cls) {
    if (*con_cls == NULL) {
        char *buffer = calloc(1024, sizeof(char));
        if (buffer == NULL) {
            return MHD_NO;
        }
        *con_cls = buffer;
        return MHD_YES;
    }

    char *post_buffer = *con_cls;

    if (*upload_data_size > 0) {
        strncat(post_buffer, upload_data, *upload_data_size);
        *upload_data_size = 0;
        return MHD_YES;
    }

    char *response_str = route_request(method, url, post_buffer);

    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(response_str), 
                                                                    (void *)response_str, 
                                                                    MHD_RESPMEM_MUST_FREE);
    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);

    free(*con_cls);
    *con_cls = NULL;

    return ret;
}
