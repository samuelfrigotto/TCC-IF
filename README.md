# Detecção de Anomalias em Tráfego de Rede com Isolation Forest

Detector de anomalias de rede baseado no algoritmo *Isolation Forest*, treinado
sobre o CIC-IDS2017 e validado em tráfego gerado ao vivo num ambiente de máquinas
virtuais. Trabalho de Conclusão de Curso, Engenharia de Computação, UTFPR.

O modelo é treinado em modo *novelty detection*: aprende apenas o perfil do
tráfego benigno e trata como anomalia tudo que se afasta desse padrão.

Repositório: <https://github.com/samuelfrigotto/TCC-IF>

## Modelos

Dois pipelines treinados ficam em `modelos/`:

- `pipeline_m0_geral.joblib` — 78 características (`main.py`).
- `pipeline_m1_sem_artefato.joblib` — 64 características (`main_sem_artefato.py`), sem
  14 características que versões diferentes do *CICFlowMeter* calculam de forma
  divergente. É o modelo usado na validação ao vivo.

## Apoio de ferramenta de IA

Os geradores de tráfego e os utilitários do ambiente de validação em `VMs/`
(`benign_gen.py`, `hulk.py`, `slowloris.py`, `cenario_misto.sh`,
`cenario_misto_slow.sh`, `detector_rt.py`, `_setup_detector.sh`), além de `scripts/comparar.py`,
`scripts/align_features.py` e `scripts/avaliar.py`, foram construídos com o apoio
do assistente Claude (Anthropic, modelos Opus 4.7 e 4.8), por causa do prazo do
trabalho e da pouca experiência prévia com a área de máquinas virtuais. Cada um
foi revisado, executado e validado antes do uso, e cada arquivo apoiado traz essa
indicação no cabeçalho.

## Estrutura

```
.
├── main.py                      treina e avalia o modelo (78 características)
├── main_sem_artefato.py         igual ao main, sem as 14 características-artefato (64)
├── config/                      hiperparâmetros e lista de características-artefato
├── src/
│   ├── data_loader.py           leitura e rotulagem do CIC-IDS2017
│   ├── preprocessing.py         filtro benigno, StandardScaler, PCA
│   ├── model.py                 Isolation Forest, treino, inferência, persistência
│   └── evaluation.py            métricas, ROC, análise por categoria
├── scripts/
│   ├── balanced_dataset.py      monta o subconjunto balanceado do CIC-IDS2017
│   ├── align_features.py        alinha as colunas do CICFlowMeter atual
│   ├── avaliar.py               rotula por tempo/porta e mede recall por categoria (números)
│   └── comparar.py              cruza a detecção ao vivo com a verdade e gera o painel
├── modelos/                     pipelines treinados (model + scaler + PCA + features)
├── data/
│   └── feature_columns.csv      ordem canônica das características (cabeçalho de treino)
└── VMs/                         ambiente de validação ao vivo (Capítulo 5)
    ├── benign_gen.py            gerador de tráfego benigno
    ├── hulk.py                  DoS de volume (HULK)
    ├── slowloris.py             DoS lento
    ├── cenario_misto.sh         orquestra captura + janelas de ataque
    ├── cenario_misto_slow.sh    variante com slowloris
    ├── detector_rt.py           detecção em tempo quase real no sensor
    ├── _setup_detector.sh       prepara o sensor sem Internet (a partir da pasta compartilhada)
    ├── deteccao.json            saída de exemplo do detector (ver "Saídas")
    ├── marcadores.txt           janelas de ataque do experimento de exemplo
    └── painel.png               painel de exemplo do experimento
```

## Pré-requisitos

- **Host:** Windows com Python 3 (o desenvolvimento usou o Anaconda) e
  [VirtualBox 7.2](https://www.virtualbox.org/) instalado. Para extrair a imagem
  do Kali, [7-Zip](https://www.7-zip.org/).
- **Dependências Python do host:** `pip install -r requirements.txt`.
- **CICFlowMeter:** o repositório já traz um *build* da ferramenta em
  `VMs/CICFlowMeter/` e a biblioteca nativa em `VMs/jnetpcap-1.4.r1425/`. A
  ferramenta original é de terceiros \[[Lashkari et al.,
  2017](https://www.unb.ca/cic/research/applications.html)\] e roda sobre o JDK 8.

---

# Parte 1 — Treinamento e avaliação sobre o *dataset*

O CIC-IDS2017 não é redistribuído aqui. Baixe o *dataset* original, coloque os
CSV em `data/cicids2017/` e gere o subconjunto balanceado:

```bash
pip install -r requirements.txt
python scripts/balanced_dataset.py     # monta data/cicids2017/cicids2017_balanced.csv
python main.py                         # treina o modelo de 78 características (m0)
python main_sem_artefato.py            # treina o modelo de 64 características (m1)
```

Os pipelines treinados são salvos em `modelos/`.

---

# Parte 2 — Validação ao vivo (três máquinas virtuais)

A validação roda numa rede isolada (modo *host-only*, faixa 192.168.56.0/24, sem
rota para a Internet) com três máquinas virtuais:

- **Atacante** (Kali Linux) — gera o tráfego benigno e os ataques.
- **Vítima** (Metasploitable2) — alvo, com serviços abertos, entre eles um
  servidor web na porta 80 com a página `phpinfo.php`.
- **Sensor** — escuta o segmento em modo promíscuo, captura o tráfego e roda o
  modelo. É um clone do Kali.

Uma captura única reúne tráfego benigno dominante, com PortScan e DoS injetados
em janelas de tempo marcadas. Cada fluxo é rotulado por **tempo e porta de
destino**, sem usar nenhuma característica que o modelo enxerga, o que mantém o
*ground truth* independente da decisão do modelo.

> Os comandos `VBoxManage.exe` abaixo estão escritos para o PowerShell. Na execução de testes o executável ficou em `B:\Vbox\VBoxManage.exe` em vez de
> `C:\Program Files\Oracle\VirtualBox\VBoxManage.exe` — ajuste o caminho. Para
> encurtar, defina `$vb = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"`.

## 2.1 — Rede isolada (host-only)

```powershell
$vb = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"

# cria o adaptador host-only
& $vb hostonlyif create                       # cria "VirtualBox Host-Only Ethernet Adapter"
$ifn = "VirtualBox Host-Only Ethernet Adapter"
& $vb hostonlyif ipconfig $ifn --ip 192.168.56.1 --netmask 255.255.255.0

# servidor DHCP da rede isolada (faixa dinâmica .150-.254; os endereços .101/.102/.104
# ficam reservados por VM mais adiante, então cada máquina recebe sempre o mesmo IP)
& $vb dhcpserver add --interface=$ifn --server-ip 192.168.56.100 `
  --netmask 255.255.255.0 --lower-ip 192.168.56.150 --upper-ip 192.168.56.254 --enable
```

> No Windows o IP do adaptador às vezes não é aplicado na primeira chamada.
> Confira com `& $vb list hostonlyifs` e repita o `hostonlyif ipconfig` se preciso.

## 2.2 — Vítima (Metasploitable2)

Baixe a [imagem oficial do Metasploitable2](https://sourceforge.net/projects/metasploitable/)
(arquivo `.zip` com o disco `Metasploitable.vmdk`, já bootável) e extraia em
`D:\VMs\meta`.

```powershell
$vmdk = "D:\VMs\meta\Metasploitable2-Linux\Metasploitable.vmdk"

& $vb internalcommands sethduuid $vmdk        # novo UUID, evita colisão de disco
& $vb createvm --name meta --ostype Ubuntu --register --basefolder "D:\VMs"
& $vb modifyvm meta --memory 512 --nic1 hostonly --hostonlyadapter1 $ifn `
  --nicpromisc1 allow-all --boot1 disk
& $vb storagectl meta --name IDE --add ide
& $vb storageattach meta --storagectl IDE --port 0 --device 0 --type hdd --medium $vmdk
```

`--nicpromisc1 allow-all` (com hífen) é obrigatório — sem o modo promíscuo o
sensor não enxerga o tráfego entre as outras VMs. A VM **não é ligada agora** (ver
a etapa "Subir as VMs" adiante). Quando ligada, recebe o IP fixo `192.168.56.101`,
reservado naquela etapa. Login `msfadmin` / `msfadmin`.

## 2.3 — Atacante (Kali)

Baixe a [imagem do Kali para VirtualBox](https://www.kali.org/get-kali/#kali-virtual-machines)
(arquivo `.7z`), extraia o `.vbox` e o `.vdi` para `D:\VMs\kali` e crie a VM:

```powershell
$vdi = "D:\VMs\kali\kali-linux-2026.1-virtualbox-amd64\kali-linux-2026.1-virtualbox-amd64.vdi"

& $vb internalcommands sethduuid $vdi
& $vb createvm --name kali --ostype Debian_64 --register --basefolder "D:\VMs"
& $vb modifyvm kali --memory 2048 --cpus 2 --ioapic on --nic1 hostonly `
  --hostonlyadapter1 $ifn --nicpromisc1 allow-all --boot1 disk
& $vb storagectl kali --name SATA --add sata --controller IntelAHCI --portcount 2
& $vb storageattach kali --storagectl SATA --port 0 --device 0 --type hdd --medium $vdi
```

A VM ainda **não é ligada aqui** (ver a etapa "Subir as VMs" adiante). Quando
ligada, recebe o IP fixo `192.168.56.102`, reservado naquela etapa. Login `kali` / `kali`.

## 2.4 — Sensor (clone do Kali)

O sensor é um clone *linked* do Kali (compartilha o disco base, ocupa pouco
espaço):

```powershell
& $vb snapshot kali take base
& $vb clonevm kali --snapshot base --options link --name sensor --register --basefolder "D:\VMs"
& $vb modifyvm sensor --memory 1536
```

## 2.5 — Pasta compartilhada e *payloads* offline

O sensor recebe tudo pela pasta compartilhada `vmshare`, sem precisar de Internet.
Como os binários grandes não cabem no repositório, prepare-os uma vez no host (que
tem Internet) dentro de `VMs/`:

```powershell
$py = "python"     # ou o caminho do seu Python, ex.: D:\anaconda\python.exe

# wheels Linux do scikit-learn para o Python 3.13 do Kali
& $py -m pip download scikit-learn scipy joblib threadpoolctl `
  --only-binary=:all: --platform manylinux2014_x86_64 --platform manylinux_2_28_x86_64 `
  --python-version 313 --implementation cp --abi cp313 -d VMs\wheels

# JDK 8 para Linux (Temurin)
Invoke-WebRequest -UseBasicParsing `
  -Uri "https://api.adoptium.net/v3/binary/latest/8/ga/linux/x64/jdk/hotspot/normal/eclipse" `
  -OutFile VMs\jdk8-linux-x64.tar.gz
```

Registre a pasta compartilhada nas duas VMs (Kali e sensor) — elas precisam estar
**desligadas** para aceitar a configuração permanente:

```powershell
& $vb sharedfolder add kali   --name vmshare --hostpath "CAMINHO_DO_REPO\VMs"
& $vb sharedfolder add sensor --name vmshare --hostpath "CAMINHO_DO_REPO\VMs"
```

Reserve um IP fixo para cada VM no servidor DHCP, assim elas recebem sempre os
mesmos endereços (vítima em `.101`, Kali em `.102` e sensor em `.104`). As VMs já
precisam estar criadas para isto:

```powershell
& $vb dhcpserver modify --interface=$ifn --vm=meta   --nic=1 --fixed-address=192.168.56.101
& $vb dhcpserver modify --interface=$ifn --vm=kali   --nic=1 --fixed-address=192.168.56.102
& $vb dhcpserver modify --interface=$ifn --vm=sensor --nic=1 --fixed-address=192.168.56.104
```

Suba as três VMs:

```powershell
& $vb startvm meta   --type headless
& $vb startvm kali   --type headless
& $vb startvm sensor --type headless
```

Confirme, a partir do Kali, que a vítima está no ar:

```bash
nmap -sV 192.168.56.101    # deve listar as portas 21/22/80/3306
```

No Kali e no sensor, crie o ponto de montagem e monte a `vmshare`:

```bash
sudo mkdir -p /mnt/vmshare
sudo mount -t vboxsf vmshare /mnt/vmshare
```

## 2.6 — Preparar o sensor (sem Internet)

No **sensor**, com a `vmshare` montada, rode o script de preparação. Ele cria o
ambiente Python a partir das *wheels*, instala o JDK 8, copia o CICFlowMeter, o
modelo e o cabeçalho de características, e cria o *link* da `libpcap` — tudo a
partir de `/mnt/vmshare`, sem Internet:

```bash
sh /mnt/vmshare/_setup_detector.sh
```

Ao final ele confirma `sklearn`, o `java -version` e o carregamento do modelo de
64 características.

## 2.7 — Rodar o experimento

Com as três VMs no ar, **primeiro** inicie o detector no sensor:

```bash
sudo mount -t vboxsf vmshare /mnt/vmshare 2>/dev/null
~/detenv/bin/python ~/detector_rt.py --iface eth0 --dur 340 --janela 20
```

Ele captura por 340 segundos e atualiza o placar a cada 20 segundos. **Logo em
seguida**, dispare o cenário no atacante (você tem até 20 segundos pra disparar o kali atacante):

```bash
sudo mkdir -p /mnt/vmshare
sudo mount -t vboxsf vmshare /mnt/vmshare 2>/dev/null
sudo sh /mnt/vmshare/cenario_misto.sh 192.168.56.101
```

O cenário roda por cerca de cinco minutos (benigno → PortScan → DoS HULK) e grava
`marcadores.txt` na pasta compartilhada. Quando o detector terminar, copie a
detecção para a pasta compartilhada:

```bash
cp /tmp/deteccao.json /mnt/vmshare/
```

No **host**, gere o painel cruzando a detecção com a verdade:

```powershell
python scripts\comparar.py --deteccao VMs\deteccao.json --marcadores VMs\marcadores.txt --png VMs\painel.png
```

O painel sai em `VMs\painel.png`, com a taxa de detecção por categoria, a matriz
de confusão e a distribuição de *scores*. Esperado: DoS por volta de 75% a 83%,
PortScan próximo de 2%, benigno acima de 90% de acerto.

---

## Saídas

- **`VMs/painel.png`** — figura do experimento, com os quatro quadrantes. É a
  forma legível de ler o resultado.
- **`VMs/marcadores.txt`** — os instantes em que cada janela de ataque começou e
  terminou, escritos pelo `cenario_misto.sh`. É a base do *ground truth* por tempo.
- **`VMs/deteccao.json`** — a saída crua do detector, com um registro por fluxo
  (`src`, `dst`, `sport`, `dport`, `proto`, `ts`, `pred`, `score`) mais os totais
  `n` e `anomalias`. O arquivo é gravado em **uma única linha** para ocupar menos
  espaço e memória, então não é fácil de ler direto; ele existe para o
  `comparar.py`, que o interpreta e cruza com os marcadores. A leitura do
  experimento é feita pelo `painel.png`.

## Licença

Ver [LICENSE](LICENSE).
