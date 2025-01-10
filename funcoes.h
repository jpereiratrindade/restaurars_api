/**
 * @file funcoes.h
 * @brief Cabeçalhos das funções auxiliares utilizadas na aplicação.
 *
 * Declarações de funções e definições de macros para uso na API.
 */

#ifndef FUNCOES_H
#define FUNCOES_H

#include <microhttpd.h>
#include <libpq-fe.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <cjson/cJSON.h>

#include <signal.h>
#include <stdbool.h>

#define PORT 8081
// Variável global para controle de execução
extern volatile bool running;

// Configuração do banco de dados PostgreSQL
#define DB_HOST "host"
#define DB_PORT "5432"
#define DB_NAME "database"
#define DB_USER "user"
#define DB_PASS "password"

// Declaração do ponteiro de conexão com o banco de dados
extern PGconn *conn;

// Prototipação das funções
void handle_sigint(int sig);
void init_db_connection();
void close_db_connection();
static char *handle_get_query(const char *query, const char **fields, int field_count);
void init_db_connection();
void close_db_connection();
char *handle_get_query(const char *query, const char **fields, int field_count);
char *handle_get_uso_da_terra_municipio();
char *handle_get_uso_da_terra_corede();
char *handle_get_uso_da_terra_bioma();
char *handle_get_uso_da_terra_regiaofuncional();
char *handle_get_uso_da_terra_classeusoterra();
char *handle_get_uso_da_terra_tipocampo();
char *handle_get_uso_da_terra_registrousoterra();
char *handle_get_uso_da_terra_metadadosniveisotto();
char *handle_get_uso_da_terra_colecaomapbiomas();
char *handle_post_data(const char *post_buffer);
char *route_request(const char *method, const char *url, const char *post_buffer);
enum MHD_Result handle_request(void *cls, struct MHD_Connection *connection, 
                                      const char *url, const char *method, const char *version, 
                                      const char *upload_data, size_t *upload_data_size, void **con_cls);

#endif