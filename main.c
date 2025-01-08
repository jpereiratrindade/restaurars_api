/**
 * @file main.c
 * @brief Arquivo principal da aplicação Restaurars API.
 *
 * Este arquivo contém a função principal (main) e inicializa os componentes necessários
 * para a execução da API.
 */

#include "funcoes.h"

// Definição da variável global
PGconn *conn;

volatile bool running = true; // Definição da variável global

int main() {
    struct MHD_Daemon *daemon;

    // Configurar sinal para interrupção (Ctrl+C)
    signal(SIGINT, handle_sigint);

    // Inicializar conexão com o banco de dados
    init_db_connection();

    // Iniciar o servidor
    daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, PORT, NULL, NULL, &handle_request, NULL, MHD_OPTION_END);
    if (daemon == NULL) {
        fprintf(stderr, "Falha ao iniciar o servidor.\n");
        close_db_connection();
        return EXIT_FAILURE;
    }

    printf("Servidor rodando em http://localhost:%d\n", PORT);

    // Manter o processo ativo até receber SIGINT
    while (running) {
        sleep(1);
    }

    // Finalizar servidor e conexão com o banco de dados
    MHD_stop_daemon(daemon);
    close_db_connection();
    return EXIT_SUCCESS;
}