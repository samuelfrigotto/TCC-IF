#!/bin/sh
# Apoio do assistente Claude (Anthropic, Opus 4.7/4.8) na construcao; revisado e validado pelo autor.
# Setup do sensor/detector SEM INTERNET. Tudo vem de /mnt/vmshare (a pasta compartilhada).
SHARE=/mnt/vmshare                                   # caminho da pasta compartilhada com o host

echo "=== 0. montar vmshare ==="                     # etapa 0: garantir a pasta compartilhada montada
echo kali | sudo -S mkdir -p $SHARE 2>/dev/null      # cria o ponto de montagem (senha do sudo via stdin)
echo kali | sudo -S mount -t vboxsf vmshare $SHARE 2>/dev/null  # monta a pasta compartilhada VirtualBox
ls $SHARE/wheels >/dev/null 2>&1 && echo "  wheels visiveis" || echo "  ERRO: wheels nao visiveis"  # confere se os payloads estão acessíveis

echo "=== 1. venv + sklearn (offline, das wheels) ==="  # etapa 1: ambiente Python a partir das wheels locais
python3 -m venv --system-site-packages ~/detenv      # cria um venv reaproveitando os pacotes do sistema (numpy/pandas)
~/detenv/bin/pip install --no-index --find-links $SHARE/wheels scikit-learn joblib threadpoolctl scipy 2>&1 | tail -3  # instala do diretório local, sem rede

echo "=== 2. JDK8 Linux ==="                          # etapa 2: instalar o Java 8 exigido pelo CICFlowMeter
mkdir -p ~/jdk8                                       # cria a pasta de destino do JDK
tar -xzf $SHARE/jdk8-linux-x64.tar.gz -C ~/jdk8 --strip-components=1  # extrai o JDK direto em ~/jdk8 (sem a pasta-raiz do tar)
~/jdk8/bin/java -version 2>&1 | head -1               # confirma a versão do Java instalado

echo "=== 3. CICFlowMeter + jnetpcap ==="             # etapa 3: copiar o extrator de características e as libs nativas
mkdir -p ~/cfm                                       # cria a pasta do extrator
cp -r $SHARE/CICFlowMeter ~/cfm/                     # copia o CICFlowMeter (jars + launcher)
cp -r $SHARE/jnetpcap-1.4.r1425 ~/cfm/              # copia as bibliotecas nativas (.so) do jnetpcap
chmod +x ~/cfm/CICFlowMeter/bin/cfm                  # garante permissão de execução no launcher cfm
echo "  cfm: $(ls ~/cfm/CICFlowMeter/bin/cfm)"       # confirma que o launcher está no lugar

echo "=== 4. modelo + train_header ==="               # etapa 4: copiar o modelo e o cabeçalho de features
mkdir -p ~/det                                       # cria a pasta do detector
cp $SHARE/pipeline_m1_sem_artefato.joblib ~/det/    # copia o modelo de 64 features
cp $SHARE/feature_columns.csv ~/det/train_header.csv  # copia o cabeçalho de features com o nome esperado pelo detector
echo "  det: $(ls ~/det)"                            # lista o conteúdo da pasta do detector

echo "=== 5. detector_rt.py pro home ==="             # etapa 5: deixar o script do detector no home
cp $SHARE/detector_rt.py ~/detector_rt.py            # copia o detector para o diretório do usuário
echo "  $(ls -la ~/detector_rt.py | awk '{print $NF}')"  # confirma o caminho do arquivo copiado

echo "=== 6. symlink libpcap (jnetpcap procura libpcap.so sem versao) ==="  # etapa 6: criar o link da libpcap
echo kali | sudo -S ln -sf /usr/lib/x86_64-linux-gnu/libpcap.so.0.8 /usr/lib/x86_64-linux-gnu/libpcap.so  # aponta libpcap.so para a versão instalada
ls -la /usr/lib/x86_64-linux-gnu/libpcap.so          # confirma o link criado

echo "=== 7. tcpdump presente? ==="                   # etapa 7: checar a ferramenta de captura
which tcpdump || echo "  AVISO: tcpdump ausente (Kali normalmente tem)"  # avisa se o tcpdump não estiver instalado

echo "=== VERIFICACAO FINAL ==="                      # verificação final do ambiente montado
~/detenv/bin/python -c 'import sklearn,joblib,numpy,pandas; print("libs OK - sklearn", sklearn.__version__, "numpy", numpy.__version__)'  # confere as bibliotecas Python
~/detenv/bin/python -c 'import joblib; b=joblib.load("/home/kali/det/pipeline_m1_sem_artefato.joblib"); print("modelo OK -", len(b["features"]), "features")' 2>&1 | tail -1  # confere o carregamento do modelo
echo "=== SETUP DONE ==="                            # marca o fim do setup
