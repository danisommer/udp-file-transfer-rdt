# Transferência confiável de arquivos sobre UDP

Cliente e servidor em Python que transferem arquivos sobre UDP com a confiabilidade implementada na aplicação: segmentação, CRC32 por segmento, retransmissão seletiva por NACK e CRC32 do arquivo inteiro. O cliente simula perda de pacotes para mostrar a recuperação funcionando. Só biblioteca padrão.

## Como rodar

Python 3.8 ou mais novo (testado no 3.12), sem dependências. Os comandos rodam de dentro de `udp_rdt/`.

Servidor, que serve a pasta `data/`:

```bash
cd udp_rdt
python3 server.py
```

Cliente, em outro terminal:

```bash
cd udp_rdt
python3 client.py --server 127.0.0.1:9000 --file hello.txt
python3 client.py --server 127.0.0.1:9000 --file bigfile.bin --drop seq:1,5-9
python3 client.py --server 127.0.0.1:9000 --file bigfile.bin --drop-prob 0.05
```

O arquivo é salvo em `downloads/`, ou no caminho de `--out`. O cliente sai com código 0 quando o arquivo chega íntegro e 2 quando não.

| Opção do servidor | Padrão | Para que serve |
|---|---|---|
| `--host` | `0.0.0.0` | endereço de escuta |
| `--port` | `9000` | porta |
| `--data-dir` | `data` | pasta com os arquivos servidos |
| `--segment-size` | `1200` | bytes de dados por segmento (máximo 1300) |

| Opção do cliente | Padrão | Para que serve |
|---|---|---|
| `--server` | obrigatória | `ip:porta` do servidor |
| `--file` | obrigatória | nome do arquivo no servidor |
| `--out` | `downloads/<nome>` | onde salvar |
| `--timeout` | `5` | segundos sem pacotes antes de pedir retransmissão |
| `--drop` | — | descarta uma vez os segmentos da lista, ex.: `seq:1,5-9`; pode repetir |
| `--drop-prob` | `0` | probabilidade de descartar cada segmento recebido |

## Protocolo

Todo datagrama começa com o tipo (1 byte) e a versão do protocolo (1 byte).

| Tipo | Código | Sentido | Conteúdo |
|---|---|---|---|
| `GET` | `0x01` | cliente → servidor | nome do arquivo |
| `DATA` | `0x02` | servidor → cliente | número de sequência, tamanho total, offset, tamanho do payload, CRC32 do segmento e os dados |
| `END` | `0x03` | servidor → cliente | total de segmentos e CRC32 do arquivo inteiro |
| `NACK` | `0x11` | cliente → servidor | números de sequência que faltam |
| `OK` | `0x12` | cliente → servidor | recebeu tudo; o servidor libera o estado daquele cliente |
| `ERR` | `0x7F` | servidor → cliente | código e mensagem: arquivo não encontrado ou caminho fora de `data/` |

O cabeçalho do `DATA` tem 30 bytes. Com 1200 bytes de dados, o datagrama cabe nos 1472 bytes de payload UDP de um quadro Ethernet, sem fragmentação IP.

## Fluxo de uma transferência

1. O cliente envia `GET`. Se o servidor não responder em 2 segundos, o cliente desiste.
2. O servidor divide o arquivo em segmentos, guarda os pacotes prontos para aquele cliente, envia todos em sequência e fecha com `END`.
3. O cliente confere o CRC32 de cada segmento, descarta os corrompidos e guarda os bons pelo número de sequência. A ordem de chegada não importa.
4. Ao receber `END`, o cliente manda `NACK` com a lista do que falta, e o servidor reenvia só esses segmentos.
5. Com todos os segmentos, o cliente envia `OK`, confere o tamanho e o CRC32 do arquivo inteiro e grava.
6. Se passar `--timeout` segundos sem pacotes, o cliente manda `NACK` do que falta, ou repete o `GET` se nada chegou. Três timeouts seguidos encerram a transferência com erro.

## Perda de pacotes

`--drop seq:1,5-9` descarta cada segmento da lista uma única vez, então a retransmissão passa. `--drop-prob` descarta ao acaso, inclusive retransmissões.

A perda também acontece sem simulação: o servidor envia o arquivo inteiro de uma vez, e o sistema operacional descarta datagramas quando o buffer de recepção do cliente enche. Num teste local com o `bigfile.bin` (12 MB) e 6 perdas simuladas, faltaram mais de 150 segmentos ao fim do envio; os NACKs recuperaram todos e o arquivo chegou idêntico.

## Estrutura

| Arquivo | Papel |
|---|---|
| `udp_rdt/server.py` | servidor: segmentação, envio, reenvio por NACK |
| `udp_rdt/client.py` | cliente: montagem do arquivo, NACK, timeouts e simulação de perda |
| `udp_rdt/protocol.py` | formato de cada tipo de pacote (`struct`) e CRC32 |
| `udp_rdt/utils.py` | leitura da opção `--drop` |
| `udp_rdt/data/` | arquivos de exemplo: `hello.txt` (16 KB) e `bigfile.bin` (12 MB) |

## Limitações

- Sem controle de fluxo nem de congestionamento: o servidor não espera confirmação entre segmentos, e a recuperação depende dos NACKs.
- O servidor monta todos os segmentos do arquivo na memória antes de enviar.
- O estado da transferência fica indexado pelo endereço do cliente, então duas transferências simultâneas do mesmo `ip:porta` se sobrescrevem.
- Se o último segmento completar o arquivo antes de o `END` chegar, o cliente encerra sem o CRC32 do arquivo inteiro e confia no CRC de cada segmento e no tamanho total.
