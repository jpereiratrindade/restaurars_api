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

#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include <jwt.h>

#include <ctype.h>

#define PORT 8081
// Variável global para controle de execução
extern volatile bool running;

// Configuração do banco de dados PostgreSQL
#define DB_HOST "localhost"
#define DB_PORT "5432"
#define DB_NAME "devdb"
#define DB_USER "jpereiratrindade"
#define DB_PASS "adraude2607"

// Configuração de autenticação básica
extern const char *USERNAME;
extern const char *PASSWORD;

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
enum MHD_Result handle_request(void *cls, struct MHD_Connection *connection, 
                                      const char *url, const char *method, const char *version, 
                                      const char *upload_data, size_t *upload_data_size, void **con_cls);
char *generate_sha512_hash(const char *password, const char *salt);
char *register_user(const char *username, const char *senha, const char *cpf, const char *email, const char *key);
int validate_token(const char *token, const char *key);
char *route_request(const char *method, const char *url, const char *post_buffer, PGconn *conn, struct MHD_Connection *connection);
bool validar_cpf(const char *cpf);
void gerar_hash_sha256(const char *input, char *output);
char *login_user(const char *username, const char *senha, const char *key);
int get_role_id_from_token(const char *token);
char *generate_token(const char *username, const char *cpf, int role, const char *key);
cJSON* get_table_content_as_json(PGconn* conn, const char* table_name);
cJSON* get_tables_as_json(PGconn* conn, const char* prefix);
char* process_request_auto(const char* url, PGconn* conn);

#endif
