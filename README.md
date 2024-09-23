
# LNXHardening - Script de Automação para Hardening de Servidores Linux

![Segmento](https://img.shields.io/badge/Segmento_:-Segurança_da_Informação-blue?style=flat-square) 
![Fase](https://img.shields.io/badge/Fase_:-Experimental-orange?style=flat-square) 
![Tecnologias](https://img.shields.io/badge/Tecnologias_:-Shell_Scripting,_Linux,_Hardening-lightyellow?style=flat-square) 
![Versão](https://img.shields.io/badge/versão_:-1.0-darkyellow?style=flat-square)

Este script Bash automatiza a aplicação de medidas de endurecimento (hardening) em servidores Linux, com foco nas distribuições CentOS/RHEL e Ubuntu/Debian. O objetivo é aumentar a segurança do sistema, seguindo as recomendações do CIS Benchmark.

## O que é o CIS Benchmark?
O **CIS Benchmark** (_Center for Internet Security Benchmark_) é um conjunto de boas práticas e configurações de segurança recomendadas para diversos sistemas operacionais e softwares. Ele fornece um guia abrangente para proteger sistemas contra ameaças cibernéticas, ajudando a reduzir a superfície de ataque e minimizar o risco de vulnerabilidades.

## Uso
1. **Clone o repositório**
   ```bash
   git clone https://github.com/euandros/lnxhardening.git
   cd vansor-forensic-collector
   ```

2. **Acesse o diretório**
   ```bash
   cd lnxhardening
   ```

3. **Execute o script**
   ```bash
   ./lnxhardening.sh
   ```

4. **Siga as instruções do menu**
* Escolha a opção correspondente à sua distribuição (CentOS/RHEL ou Ubuntu/Debian).
* O script irá executar as etapas de hardening automaticamente.
* Aguarde a conclusão do processo.

## Recursos do script
* Automatiza a aplicação de diversas medidas de segurança.
* Suporta CentOS/RHEL e Ubuntu/Debian.
* Baseado nas recomendações do CIS Benchmark.
* Menu interativo para facilitar o uso.
* Inclui comentários explicativos no código.

## Considerações importantes
* **Privilégios**: O script requer privilégios de **root** (ou `sudo`) para executar as alterações necessárias no sistema.
* **Responsabilidade**: Utilize o script com cuidado e revise o código antes de executá-lo em um ambiente de produção.

## Contribuições
Contribuições são bem-vindas! Sinta-se à vontade para abrir issues ou pull requests para melhorias ou correções.   

**Aviso**: Este script é fornecido "_tal como está_", sem garantias de qualquer tipo. O uso é por sua conta e risco.
