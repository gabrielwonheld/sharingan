![Logo do Sharingan](images/Mangekyou_Sharingan.png)
# Sharingan
Sharingan é uma ferramenta de monitoramento de rede desenvolvida em Python, capaz de verificar a conectividade de serviços via TCP, e que está em evolução para suportar novas funcionalidades como parsing de HTML, fuzzing e escaneamento de portas.


Índice
- [Sobre](#sobre)
- [Funcionalidades](#funcionalidades)
- [Funcionalidades futuras](#funcionalidades-futuras)
- [Instalação](#instalação)
- [Como Usar](#como-usar)
- [Monitorar Serviços](#monitorar-serviços)
- [Contribuição](#contribuição)
- [Licença](#licença)

## Sobre

O Sharingan foi desenvolvido inicialmente para monitorar câmeras IP em um ambiente de trabalho, verificando a conectividade dos serviços via TCP. O objetivo é futuramente aumentar as funcionalidades na ferramenta. 

## Funcionalidades
- **Monitoramento de Serviços** : Verifica a disponibilidade de serviços em hosts na rede através de uma conexão TCP.

### Funcionalidades Futuras
- **HTML Parser**: Analisa o conteúdo de páginas web e extrai dados importantes.
- **Fuzzing de Arquivos e Diretórios**: Realiza fuzzing para descobrir diretórios ou arquivos ocultos.
- **Scanning de Portas**: Verifica as portas abertas de um host para identificar serviços ativos.
- **Monitoramento de Recursos**: Função planejada para monitorar consumo de CPU, memória e mais.

## Instalação
### Clone o repositório:

```
git clone https://github.com/seu-usuario/sharingan.git
cd sharingan

```

Certifique-se de que o Python esteja instalado corretamente na sua máquina. O projeto foi desenvolvido em Python versão 3.12.7

## Como Usar
A ferramenta pode ser usada diretamente via linha de comando com vários parâmetros opcionais:

### Monitorar Serviços
**Para listar hosts ativos**
```
python sharingan --monitor -f inventory.yaml --active
```
**Para listar hosts inativos**

```
python sharingan --monitor -f inventory.yaml --inactive
```
**Ex:**
``` 
⠿⠿⠿⠿⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⠟⠛⠛⠛⠛⠛
⣶⣦⣤⣤⣤⣤⣤⣤⣬⣭⣭⣍⣉⡙⠛⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠛⣋⣩⣭⣥⣤⣴⣶⣶⣶⣶⣶⣶⣶⣶⣶
⣆⠀⠀⠀⢡⠁⠀⡀⠀⢸⠟⠻⣯⠙⠛⠷⣶⣬⡙⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⢉⣥⣶⡟⠻⣙⡉⠀⢰⡆⠀⠀⣡⠀⣧⠀⠀⠀⢨
⠻⣦⠀⠀⠈⣇⣀⣧⣴⣿⣶⣶⣿⣷⠀⢀⡇⠉⠻⢶⣌⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣡⡶⠟⠉⠀⢣⠀⣿⠷⠀⠀⠀⠀⣿⡷⢀⠇⠀⠀⢠⣿
⣦⡈⢧⡀⠀⠘⢮⡙⠛⠉⠀⠄⠙⢿⣀⠞⠀⠀⠀⠀⠙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠈⠳⣄⠉⠓⠒⠚⠋⢀⡠⠋⠀⢀⣴⣏⣿
⣿⣿⣿⣛⣦⣀⠀⠙⠓⠦⠤⣤⠔⠛⠁⠀⠀⠀⠀⠀⢀⣀⣹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣤⣤⣤⣤⣤⣀⣀⣀⣀⢙⢓⣒⡒⠚⠋⢠⣤⢶⣟⣽⣿⣿
⣿⣿⣿⣿⣿⣿⣷⣦⠀⠀⣴⣿⣷⣶⣶⣶⣾⡖⢰⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣶⣾⣿⣿⣶⣾⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿

----------------- Sharingan - Hosts Ativos -----------------     
gateway---------------------------------[22]
gateway---------------------------------[80]
google ---------------------------------[80]
google ---------------------------------[443]
Total de Hosts:6
Total de Hosts Ativos:2

```

### Onde:

- `--monitor` ou `-m`: Ativa o modo de monitoramento.
- `--active` ou `-a`: Lista os hosts ativos.
- `--inactive` ou `-i`: Lista os hosts inativos.
- `--inventory` ou `-f`: Fornece o caminho para o arquivo YAML de inventário de hosts.

### Exemplo de inventory.yaml

**Uma porta para vários hosts**
``` 
hosts:
  intranet:
    addr: 10.37.0.3
  gateway:
    addr: 192.168.1.1
  google:
    addr: google.com
    
common_port: 80

```

**Uma porta para cada host**

``` 
hosts:
  intranet:
    addr: 10.37.0.3
    ports:
      - 80a
      - 443
  gateway:
    addr: 192.168.1.1
    ports:
      - 22
      - 80
  google:
    addr: google.com
    ports:
      - 443
      - 80

```


### Para mais opções, use o comando de ajuda:

```
python sharingan.py --help

```
## Contribuição
Sinta-se à vontade para contribuir com o Sharingan. As sugestões e melhorias são sempre bem-vindas. Se você quiser contribuir, siga os passos abaixo:

### Checklist

- [x] Monitoramento de serviços em porta TCP
- [ ] Refatoração/Reorganização (aberto a ideias)
- [x] Parser HTML
- [ ] scanning de portas
- [ ] Versão do README.md em inglês
- [ ] Monitoramento de Recursos

### Como fazer
1. Faça um fork do projeto.
2. Crie um branch para sua feature (git checkout -b minha-feature).
3. Faça commit das suas alterações (git commit -m 'Minha nova feature').
4. Envie para o branch (git push origin minha-feature).
5. Abra um Pull Request.
Se precisar de ajuda, confira o [guia de contribuição do GitHub](https://docs.github.com/en/get-started/quickstart/contributing-to-projects)
## Licença
Este projeto está licenciado sob a licença MIT - veja o arquivo LICENSE para mais detalhes.
