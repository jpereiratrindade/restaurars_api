cmake_minimum_required(VERSION 3.10)
project(API C)

# Configuração do diretório de saída para os binários
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Diretório de inclusão para cabeçalhos
include_directories(${CMAKE_SOURCE_DIR})

# Adicionar os arquivos de cabeçalhos e fontes
set(SOURCES
    main.c
    funcoes.c
)
set(HEADERS
    funcoes.h
)

# Adicionar o executável
add_executable(restaurars_api ${SOURCES} ${HEADERS})

# Linkar bibliotecas necessárias
target_link_libraries(restaurars_api pq microhttpd cjson)

# Instalar o binário no diretório /home/$USER/bin
install(TARGETS restaurars_api DESTINATION /home/$ENV{USER}/bin)

# Mensagem de ajuda para instalação
message(STATUS "Para instalar, use: make install")
