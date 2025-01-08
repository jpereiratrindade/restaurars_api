cmake_minimum_required(VERSION 3.10)
project(API C)

# Definir o diretório de saída para o binário
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Diretório de inclusão para os cabeçalhos
include_directories(${CMAKE_SOURCE_DIR})

# Adicionar os arquivos-fonte
set(SOURCES
    main.c
    funcoes.c
)

# Adicionar o executável
add_executable(restaurars_api ${SOURCES})

# Linkar bibliotecas necessárias
target_link_libraries(restaurars_api pq microhttpd cjson)

# Instalação do binário no diretório /home/$USER/bin
install(TARGETS restaurars_api DESTINATION /home/$ENV{USER}/bin)

# Mensagem para ajudar o usuário
message(STATUS "Para instalar, use: make install")
