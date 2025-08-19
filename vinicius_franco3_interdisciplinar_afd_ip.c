#include <stdio.h>
#include <stdlib.h>

#define TAM_MAX_ESTADO 10
#define TAM_MAX_LINHA 100
#define MAX_FINAIS 20

typedef struct {
    unsigned int ip[4];
    unsigned int mascara[4];
    unsigned int rede[4];
    unsigned int broadcast[4];
    unsigned int wildcard[4];
    unsigned int hostMin[4];
    unsigned int hostMax[4];
    int cidr;
    long quantidadeIPs;
} InfoRede;

int compararString(const char* a, const char* b) {
    int i = 0;
    while (a[i] != '\0' && b[i] != '\0') {
        if (a[i] != b[i])
            return a[i] - b[i];
        i++;
    }
    return a[i] - b[i];
}

void copiarString(char* dest, const char* src) {
    int i = 0;
    while (src[i] != '\0') {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
}

void copiarStringLimite(char* dest, const char* src, int limite) {
    int i = 0;
    while (i < limite - 1 && src[i] != '\0') {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
}

typedef struct Transicao {
    char estadoOrigem[TAM_MAX_ESTADO];
    char simbolo;
    char estadoDestino[TAM_MAX_ESTADO];
    struct Transicao* prox;
} Transicao;

typedef struct {
    Transicao* inicio;
    char estadoInicial[TAM_MAX_ESTADO];
    char estadosFinais[MAX_FINAIS][TAM_MAX_ESTADO];
    int qtdFinais;
} ListaTransicoes;

ListaTransicoes* criarLista() {
    ListaTransicoes* lista = malloc(sizeof(ListaTransicoes));
    if (!lista) { perror("malloc"); exit(1); }
    lista->inicio = NULL;
    lista->qtdFinais = 0;
    lista->estadoInicial[0] = '\0';
    return lista;
}

void adicionarTransicao(ListaTransicoes* lista, const char* origem, char simbolo, const char* destino) {
    Transicao* t = malloc(sizeof(Transicao));
    if (!t) { perror("malloc"); exit(1); }
    copiarStringLimite(t->estadoOrigem, origem, TAM_MAX_ESTADO);
    t->simbolo = simbolo;
    copiarStringLimite(t->estadoDestino, destino, TAM_MAX_ESTADO);
    t->prox = lista->inicio;
    lista->inicio = t;
}

char* transicionar(ListaTransicoes* lista, const char* estadoAtual, char simbolo) {
    Transicao* t = lista->inicio;
    while (t != NULL) {
        if (t->simbolo == simbolo && compararString(t->estadoOrigem, estadoAtual) == 0) {
            return t->estadoDestino;
        }
        t = t->prox;
    }
    return NULL;
}

int eEstadoFinal(ListaTransicoes* lista, const char* estado) {
    for (int i = 0; i < lista->qtdFinais; i++) {
        if (compararString(lista->estadosFinais[i], estado) == 0) {
            return 1;
        }
    }
    return 0;
}

ListaTransicoes* carregarAFD(const char* arquivo) {
    FILE* f = fopen(arquivo, "r");
    if (!f) { perror("Erro ao abrir arquivo AFD"); exit(1); }
    ListaTransicoes* lista = criarLista();
    char linha[TAM_MAX_LINHA];
    while (fgets(linha, sizeof(linha), f)) {
        if (linha[0] == '\n' || linha[0] == '#' || linha[0] == '\0') continue;
        int len = 0;
        while (linha[len] != '\0' && linha[len] != '\n' && linha[len] != '\r') len++;
        linha[len] = '\0';
        if (linha[0] == '-' && linha[1] == '>') {
            char origem[TAM_MAX_ESTADO], destino[TAM_MAX_ESTADO];
            char simbolo;
            if (sscanf(linha + 2, "%[^,],%c,%s", origem, &simbolo, destino) == 3) {
                if (lista->estadoInicial[0] == '\0') {
                    copiarStringLimite(lista->estadoInicial, origem, TAM_MAX_ESTADO);
                }
                adicionarTransicao(lista, origem, simbolo, destino);
            }
        } else if (linha[0] == '*') {
            char estadoFinal[TAM_MAX_ESTADO];
            if (sscanf(linha + 1, "%s", estadoFinal) == 1) {
                if (lista->qtdFinais < MAX_FINAIS) {
                    copiarStringLimite(lista->estadosFinais[lista->qtdFinais], estadoFinal, TAM_MAX_ESTADO);
                    lista->qtdFinais++;
                }
            }
        } else {
            char origem[TAM_MAX_ESTADO], destino[TAM_MAX_ESTADO];
            char simbolo;
            if (sscanf(linha, "%[^,],%c,%s", origem, &simbolo, destino) == 3) {
                adicionarTransicao(lista, origem, simbolo, destino);
            }
        }
    }
    fclose(f);
    return lista;
}

int validarPorAFD(ListaTransicoes* afd, const char* entrada) {
    char estadoAtual[TAM_MAX_ESTADO];
    copiarStringLimite(estadoAtual, afd->estadoInicial, TAM_MAX_ESTADO);
    for (int i = 0; entrada[i] != '\0'; i++) {
        char* proxEstado = transicionar(afd, estadoAtual, entrada[i]);
        if (proxEstado == NULL) return 0;
        copiarStringLimite(estadoAtual, proxEstado, TAM_MAX_ESTADO);
    }
    return eEstadoFinal(afd, estadoAtual);
}

int isPrivado(unsigned int ip[4]) {
    if (ip[0] == 10) return 1;
    if (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) return 1;
    if (ip[0] == 192 && ip[1] == 168) return 1;
    return 0;
}

const char* classificarIP(unsigned int ip[4]) {
    if (ip[0] == 0) return "corrente";
    if (ip[0] == 10) return "privada";
    if (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) return "privada";
    if (ip[0] == 192 && ip[1] == 168) return "privada";
    if (ip[0] == 127) return "localhost";
    if (ip[0] == 39) return "reservado";
    if (ip[0] == 128 && ip[1] == 0) return "reservado";
    if (ip[0] == 191 && ip[1] == 255) return "reservado";
    if (ip[0] == 223 && ip[1] == 255 && ip[2] == 255) return "reservado";
    if (ip[0] >= 240 && ip[0] <= 254) return "reservado";
    if (ip[0] == 192 && ip[1] == 0 && ip[2] == 2) return "documentacao";
    if (ip[0] == 192 && ip[1] == 88 && ip[2] == 99) return "ipv6toipv4";
    if (ip[0] == 169 && ip[1] == 254) return "zeroconf";
    if (ip[0] == 198 && (ip[1] == 18 || ip[1] == 19)) return "benchmark";
    if (ip[0] >= 224 && ip[0] <= 239) return "multicast";
    if (ip[0] == 255 && ip[1] == 255 && ip[2] == 255 && ip[3] == 255) return "broadcast";
    return "publica";
}

InfoRede calcularRede(unsigned int ip[4]) {
    InfoRede info;
    if (ip[0] == 10) {
        info.mascara[0] = 255; info.mascara[1] = 0; info.mascara[2] = 0; info.mascara[3] = 0;
        info.cidr = 8;
    } else if (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) {
        info.mascara[0] = 255; info.mascara[1] = 255; info.mascara[2] = 0; info.mascara[3] = 0;
        info.cidr = 16;
    } else if (ip[0] == 192 && ip[1] == 168) {
        info.mascara[0] = 255; info.mascara[1] = 255; info.mascara[2] = 255; info.mascara[3] = 0;
        info.cidr = 24;
    } else {
        info.mascara[0] = 255; info.mascara[1] = 255; info.mascara[2] = 255; info.mascara[3] = 0;
        info.cidr = 24;
    }
    for (int i = 0; i < 4; i++) {
        info.wildcard[i] = 255 - info.mascara[i];
    }
    for (int i = 0; i < 4; i++) {
        info.rede[i] = ip[i] & info.mascara[i];
    }
    for (int i = 0; i < 4; i++) {
        info.broadcast[i] = info.rede[i] | info.wildcard[i];
    }
    info.hostMin[0] = info.rede[0];
    info.hostMin[1] = info.rede[1];
    info.hostMin[2] = info.rede[2];
    info.hostMin[3] = info.rede[3] + 1;
    info.hostMax[0] = info.broadcast[0];
    info.hostMax[1] = info.broadcast[1];
    info.hostMax[2] = info.broadcast[2];
    info.hostMax[3] = info.broadcast[3] - 1;
    info.quantidadeIPs = (1L << (32 - info.cidr)) - 2;
    return info;
}

void gerarArquivoRede(unsigned int ip[4], const char* ip_str) {
    char nome_arquivo[100];
    snprintf(nome_arquivo, sizeof(nome_arquivo), "vinicius_franco3_interdisciplinar_afd_ip_%s.saida", ip_str);
    FILE* f = fopen(nome_arquivo, "w");
    if (!f) {
        perror("Erro ao criar arquivo de rede");
        return;
    }
    InfoRede info = calcularRede(ip);
    fprintf(f, "Endereço de IP: %s\n", ip_str);
    fprintf(f, "Máscara de Rede: %d.%d.%d.%d\n", info.mascara[0], info.mascara[1], info.mascara[2], info.mascara[3]);
    fprintf(f, "CIDR: %d\n", info.cidr);
    fprintf(f, "Wildcard: %d.%d.%d.%d\n", info.wildcard[0], info.wildcard[1], info.wildcard[2], info.wildcard[3]);
    fprintf(f, "IP de Rede: %d.%d.%d.%d\n", info.rede[0], info.rede[1], info.rede[2], info.rede[3]);
    fprintf(f, "Broadcast: %d.%d.%d.%d\n", info.broadcast[0], info.broadcast[1], info.broadcast[2], info.broadcast[3]);
    fprintf(f, "Host Minimo: %d.%d.%d.%d\n", info.hostMin[0], info.hostMin[1], info.hostMin[2], info.hostMin[3]);
    fprintf(f, "Host Máximo: %d.%d.%d.%d\n", info.hostMax[0], info.hostMax[1], info.hostMax[2], info.hostMax[3]);
    fprintf(f, "Quantidade IPs: %ld\n", info.quantidadeIPs);
    fclose(f);
}

void escrever_jff(ListaTransicoes* afd, const char* nomeArquivo) {
    FILE* f = fopen(nomeArquivo, "w");
    if (!f) {
        perror("Erro ao criar .jff");
        return;
    }
    fprintf(f, "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n");
    fprintf(f, "<structure>\n");
    fprintf(f, "\t<type>fa</type>\n");
    fprintf(f, "\t<automaton>\n");
    char estados[100][TAM_MAX_ESTADO];
    int num_estados = 0;
    Transicao* t = afd->inicio;
    while (t != NULL) {
        int encontrado = 0;
        for (int i = 0; i < num_estados; i++) {
            if (compararString(estados[i], t->estadoOrigem) == 0) {
                encontrado = 1;
                break;
            }
        }
        if (!encontrado) {
            copiarStringLimite(estados[num_estados], t->estadoOrigem, TAM_MAX_ESTADO);
            num_estados++;
        }
        encontrado = 0;
        for (int i = 0; i < num_estados; i++) {
            if (compararString(estados[i], t->estadoDestino) == 0) {
                encontrado = 1;
                break;
            }
        }
        if (!encontrado) {
            copiarStringLimite(estados[num_estados], t->estadoDestino, TAM_MAX_ESTADO);
            num_estados++;
        }
        t = t->prox;
    }
    for (int i = 0; i < num_estados; i++) {
        fprintf(f, "\t\t<state id=\"%d\" name=\"%s\">\n", i, estados[i]);
        if (compararString(estados[i], afd->estadoInicial) == 0) {
            fprintf(f, "\t\t\t<initial/>\n");
        }
        for (int j = 0; j < afd->qtdFinais; j++) {
            if (compararString(estados[i], afd->estadosFinais[j]) == 0) {
                fprintf(f, "\t\t\t<final/>\n");
                break;
            }
        }
        fprintf(f, "\t\t</state>\n");
    }
    t = afd->inicio;
    while (t != NULL) {
        int from_id = -1, to_id = -1;
        for (int i = 0; i < num_estados; i++) {
            if (compararString(estados[i], t->estadoOrigem) == 0) from_id = i;
            if (compararString(estados[i], t->estadoDestino) == 0) to_id = i;
        }
        if (from_id != -1 && to_id != -1) {
            fprintf(f, "\t\t<transition>\n");
            fprintf(f, "\t\t\t<from>%d</from>\n", from_id);
            fprintf(f, "\t\t\t<to>%d</to>\n", to_id);
            fprintf(f, "\t\t\t<read>%c</read>\n", t->simbolo);
            fprintf(f, "\t\t</transition>\n");
        }
        t = t->prox;
    }
    fprintf(f, "\t</automaton>\n");
    fprintf(f, "</structure>\n");
    fclose(f);
}

int main() {
    ListaTransicoes* afd = carregarAFD("vinicius_franco3_interdisciplinar_afd_ip.csv");
    FILE* entrada = fopen("t3_b1_interdisciplinar_afd_ip.entrada", "r");
    FILE* saida = fopen("vinicius_franco3_interdisciplinar_afd_ip.saida", "w");
    if (!entrada || !saida) {
        perror("Erro ao abrir arquivos");
        return 1;
    }
    char linha[TAM_MAX_LINHA];
    while (fgets(linha, sizeof(linha), entrada)) {
        int len = 0;
        while (linha[len] != '\0' && linha[len] != '\n' && linha[len] != '\r') len++;
        linha[len] = '\0';
        int valido = validarPorAFD(afd, linha);
        if (valido) {
            unsigned int ip[4];
            int campos = sscanf(linha, "%u.%u.%u.%u", &ip[0], &ip[1], &ip[2], &ip[3]);
            if (campos == 4) {
                int octetoValido = 1;
                for (int i = 0; i < 4; i++) {
                    if (ip[i] > 255) {
                        octetoValido = 0;
                        break;
                    }
                }
                if (!octetoValido) {
                    fprintf(saida, "%s,nao,-\n", linha);
                } else {
                    const char* tipo = classificarIP(ip);
                    fprintf(saida, "%s,sim,%s\n", linha, tipo);
                    if (isPrivado(ip)) {
                        gerarArquivoRede(ip, linha);
                    }
                }
            } else {
                fprintf(saida, "%s,nao,-\n", linha);
            }
        } else {
            fprintf(saida, "%s,nao,-\n", linha);
        }
    }
    fclose(entrada);
    fclose(saida);
    escrever_jff(afd, "vinicius_franco3_interdisciplinar_afd_ip.jff");
    return 0;
}
