#!/bin/bash
 
# Nome: LNXHardening
# Descrição: Script de automação para aplicação de hardening de servidores linux
# seja para as distribuições da família RHEL ou distribuições baseadas em Debian.
# Referência: CIS Benchmark
# Sistemas suportados/testados: CentOS 8, RHEL 8, Ubuntu 22.04 e Debian 11.
# Autor: Evandro Santos
# Contato: evandro.santos@tutanota.com
# Data: Segunda-feira, 22 de setemnbro de 2024, São Paulo.
# Versão: 1.0
 
# Função para o script de hardening CentOS
harden_centos_rhel() {
  echo "Aplicando o Hardening ao Sistema Linux CentOS/RHEL..."
 
  # Passo 1: Documentar as informações do host
  echo -e "\e[33mDocumentando informações do host...\e[0m"
  echo "Hostname: $(hostname)" >> Informacoes_Gerais.txt
  echo "Endereço IP: $(hostname -I)" >> Informacoes_Gerais.txt
  echo "Sistema Operacional: $(cat /etc/redhat-release)" >> Informacoes_Gerais.txt
  echo
 
  # Passo 2: Proteção do BIOS
  echo -e "\e[33mHabilitando proteção do BIOS...\e[0m"
  dmidecode -t 0 | grep -i "status de segurança: habilitado" || echo "Proteção do BIOS não habilitada"
  echo
 
  # Passo 3: Criptografia do disco rígido
  echo -e "\e[33mCriptografando disco rígido...\e[0m"
  read -s -p "Por favor, insira a frase de criptografia: " passphrase
  if [ -z "$passphrase" ]; then
    echo "Frase de criptografia não pode estar vazia. Saindo..."
    exit 1
  fi
 
  yum install -y cryptsetup
  modprobe dm-crypt
  dd if=/dev/zero of=/root/crypt.img bs=1M count=512
  echo -n "$passphrase" | cryptsetup -q luksFormat /root/crypt.img
  echo -n "$passphrase" | cryptsetup luksOpen /root/crypt.img crypt
  mkfs.ext4 /dev/mapper/crypt
  mount /dev/mapper/crypt /mnt
  echo "/dev/mapper/crypt /mnt ext4 defaults 0 0" >> /etc/fstab
  echo
 
  # Passo 4: Particionamento do disco
  echo -e "\e[33mParticionando disco...\e[0m"
  parted /dev/sda mklabel msdos
  parted -a opt /dev/sda mkpart primary ext4 0% 100%
  mkfs.ext4 /dev/sda1
  echo "/dev/sda1 /mnt ext4 defaults 0 0" >> /etc/fstab
  echo
 
  # Passo 5: Bloquear o diretório de inicialização
  echo -e "\e[33mBloqueando diretório de inicialização...\e[0m"
  chattr +i /boot/grub2/grub.cfg
  chattr +i /boot/grub2/user.cfg
  chattr +i /boot/grub2/device.map
  echo
 
  # Passo 6: Desativar o uso de USB
  echo -e "\e[33mDesativando o uso de USB...\e[0m"
  echo "install usb-storage /bin/true" > /etc/modprobe.d/usb-storage.conf
  echo
 
  # Passo 7: Atualizar o sistema
  echo -e "\e[33mAtualizando o sistema...\e[0m"
  yum update -y
  echo
 
  # Passo 8: Verificar os pacotes instalados
  echo -e "\e[33mVerificando os pacotes instalados...\e[0m"
  yum list installed
  echo
 
  # Passo 9: Verificar as portas abertas
  echo -e "\e[33mVerificando as portas abertas...\e[0m"
  netstat -tulnp
  echo
 
  # Passo 10: Segurança do SSH
  echo -e "\e[33mFortalecendo o SSH...\e[0m"
  sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
  sed -i 's/^PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
  systemctl restart sshd
  echo
 
  # Passo 11: Habilitar o SELinux
  echo -e "\e[33mHabilitando o SELinux...\e[0m"
  yum install -y selinux-policy-targeted
  sed -i 's/SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config
  setenforce 1
  echo
 
  # Passo 12: Configurar parâmetros de rede
  echo -e "\e[33mConfigurando parâmetros de rede...\e[0m"
  sysctl -w net.ipv4.ip_forward=0
  sysctl -w net.ipv4.conf.all.send_redirects=0
  sysctl -w net.ipv4.conf.default.send_redirects=0
  sysctl -w net.ipv4.tcp_syncookies=1
  echo "NETWORKING_IPV6=no" >> /etc/sysconfig/network
  echo "IPV6INIT=no" >> /etc/sysconfig/network
  echo
 
  # Passo 13: Gerenciar políticas de senha
  echo -e "\e[33mGerenciando políticas de senha...\e[0m"
  sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/g' /etc/login.defs
  sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/g' /etc/login.defs
  sed -i 's/sha512/sha512 rounds=65536/g' /etc/pam.d/system-auth-ac
  echo
 
  # Passo 14: Permissões e verificações
  echo -e "\e[33mRealizando permissões e verificações...\e[0m"
  chmod 644 /etc/passwd /etc/group /etc/shadow /etc/gshadow
  chown root:root /etc/passwd /etc/shadow
  chown root:shadow /etc/shadow
  chown root:root /etc/group /etc/gshadow
  chown root:shadow /etc/gshadow
  chown root:root /boot/grub2/grub.cfg
  chmod og-rwx /boot/grub2/grub.cfg
  chmod 700 /root
  echo
 
  # Passo 15: Reforçar processos adicionais da distribuição
  echo -e "\e[33mReforçando processos adicionais da distribuição...\e[0m"
  echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
  echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
  echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
  sysctl -p
  echo
 
  # Passo 16: Remover serviços desnecessários
  echo -e "\e[33mRemovendo serviços desnecessários...\e[0m"
  systemctl disable avahi-daemon.service
  systemctl disable cups.service
  systemctl disable dhcpd.service
  systemctl disable slapd.service
  systemctl disable named.service
  systemctl disable xinetd.service
  systemctl disable avahi-daemon.service
  echo
 
  # Passo 17: Verificar segurança nos arquivos-chave
  echo -e "\e[33mVerificando segurança nos arquivos-chave...\e[0m"
  chmod 600 /root/.ssh/authorized_keys
  chmod 700 /root/.ssh/
  chown root:root /root/.ssh/
  ls -al /root/.ssh
  echo
 
  # Passo 18: Limitar acesso root usando SUDO
  echo -e "\e[33mLimitando acesso root usando SUDO...\e[0m"
  echo "root ALL=(ALL) ALL" >> /etc/sudoers.d/root
  echo
 
  # Passo 19: Permitir apenas root acessar o CRON
  echo -e "\e[33mLimitando acesso ao CRON apenas para root...\e[0m"
  touch /etc/cron.allow
  echo "root" > /etc/cron.allow
  chmod 400 /etc/cron.allow
  chown root:root /etc/cron.allow
  echo
 
  # Passo 20: Configurar acesso remoto e configurações básicas do SSH
  echo -e "\e[33mConfigurando acesso remoto e configurações básicas do SSH...\e[0m"
  sed -i 's/^#LogLevel.*/LogLevel VERBOSE/g' /etc/ssh/sshd_config
  sed -i 's/^#MaxAuthTries.*/MaxAuthTries 4/g' /etc/ssh/sshd_config
  systemctl restart sshd
  echo
 
  # Passo 21: Desativar o Xwindow
  echo -e "\e[33mDesativando o Xwindow...\e[0m"
  systemctl set-default multi-user.target
  systemctl isolate multi-user.target
  echo
 
  # Passo 22: Minimizar a instalação de pacotes
  echo -e "\e[33mMinimizando a instalação de pacotes...\e[0m"
  yum install -y yum-utils
  yum-config-manager --disable \* &> /dev/null
  yum-config-manager --enable base &> /dev/null
  yum-config-manager --enable updates &> /dev/null
  yum-config-manager --enable extras &> /dev/null
  yum-config-manager --enable epel &> /dev/null
  echo
 
  # Passo 23: Verificar contas com senhas vazias
  echo -e "\e[33mVerificando contas com senhas vazias...\e[0m"
  awk -F: '($2 == "" ) {print $1}' /etc/shadow
  echo
 
  # Passo 24: Monitorar atividades do usuário
  echo -e "\e[33mMonitorando atividades do usuário...\e[0m"
  yum install -y audit
  sed -i 's/^active.*/active = yes/' /etc/audit/auditd.conf
  systemctl enable auditd.service
  systemctl start auditd.service
  echo
 
  # Passo 25: Instalar e configurar o fail2ban
  echo -e "\e[33mInstalando e configurando o fail2ban...\e[0m"
  yum install epel-release -y
  yum install fail2ban -y
  cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
  sed -i 's/^# bantime =.*/bantime = 3600/g' /etc/fail2ban/jail.local
  sed -i 's/^# maxretry =.*/maxretry = 3/g' /etc/fail2ban/jail.local
  systemctl enable fail2ban
  systemctl start fail2ban
  echo
 
  # Passo 26: Detecção de rootkits
  echo -e "\e[33mDetectando rootkits...\e[0m"
  yum install rkhunter -y
  rkhunter --update
  rkhunter --propupd
  rkhunter --check
  echo
 
  # Passo 27: Monitorar logs do sistema
  echo -e "\e[33mMonitorando logs do sistema...\e[0m"
  echo "auth,user.* /var/log/user.log" >> /etc/rsyslog.conf
  echo "*.emerg /var/log/emergency.log" >> /etc/rsyslog.conf
  systemctl restart rsyslog
  echo
 
  # Passo 28: Habilitar autenticação de 2 fatores
  echo -e "\e[33mHabilitando autenticação de 2 fatores...\e[0m"
  yum install -y google-authenticator
  google-authenticator
  sed -i 's/^ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config
  systemctl restart sshd.service
  echo
 
  echo -e "\e[32mFortalecimento completo!\e[0m"
 
}
 
# Função para o script de hardening Ubuntu/Debian
harden_ubuntu_debian() {
    echo "Aplicando o Hardening ao Sistema Linux Ubuntu/Debian..."
  # Passo 1: Documentar as informações do host
    echo -e "\e[33mPasso 1: Documentando as informações do host\e[0m"
    echo "Hostname: $(hostname)"
    echo "Versão do Kernel: $(uname -r)"
    echo "Distribuição: $(lsb_release -d | cut -f2)"
    echo "Informações da CPU: $(lscpu | grep 'Modelo')"
    echo "Informações de memória: $(free -h | awk '/Mem/{print $2}')"
    echo "Informações do disco: $(lsblk | grep disco)"
    echo
 
    # Passo 2: Proteção do BIOS
    echo -e "\e[33mPasso 2: Proteção do BIOS\e[0m"
    echo "Verificando se a proteção do BIOS está ativada..."
    if [ -f /sys/devices/system/cpu/microcode/reload ]; then
      echo "A proteção do BIOS está ativada"
    else
      echo "A proteção do BIOS não está ativada"
    fi
    echo ""
 
    # Passo 3: Criptografia do disco rígido
    echo -e "\e[33mPasso 3: Criptografia do disco rígido\e[0m"
    echo "Verificando se a criptografia do disco rígido está ativada..."
    if [ -d /etc/luks ]; then
      echo "A criptografia do disco rígido está ativada"
    else
      echo "A criptografia do disco rígido não está ativada"
    fi
    echo ""
 
    # Passo 4: Particionamento do disco
    echo -e "\e[33mPasso 4: Particionamento do disco\e[0m"
    echo "Verificando se o particionamento do disco já foi feito..."
    if [ -d /home -a -d /var -a -d /usr ]; then
      echo "O particionamento do disco já foi feito"
    else
      echo "O particionamento do disco não foi feito ou está incompleto"
    fi
    sudo fdisk /dev/sda
    sudo mkfs.ext4 /dev/sda1
    sudo mkswap /dev/sda2
    sudo swapon /dev/sda2
    sudo mount /dev/sda1 /mnt
    echo
 
    # Passo 5: Bloquear o diretório de boot
    echo -e "\e[33mPasso 5: Bloquear o diretório de boot\e[0m"
    echo "Bloqueando o diretório de boot..."
    sudo chmod 700 /boot
    echo ""
 
    # Passo 6: Desativar o uso de USB
    echo -e "\e[33mPasso 6: Desativar o uso de USB\e[0m"
    echo "Desativando o uso de USB..."
    echo 'blacklist usb-storage' | sudo tee /etc/modprobe.d/blacklist-usbstorage.conf
    echo ""
 
    # Passo 7: Atualizar o sistema
    echo -e "\e[33mPasso 7: Atualizar o sistema\e[0m"
    sudo apt-get update && sudo apt-get upgrade -y
    echo ""
 
    # Passo 8: Verificar os pacotes instalados
    echo -e "\e[33mPasso 8: Verificar os pacotes instalados\e[0m"
    dpkg --get-selections | grep -v deinstall
    echo ""
 
    # Passo 9: Verificar as portas abertas
    echo -e "\e[33mPasso 9: Verificar as portas abertas\e[0m"
    sudo netstat -tulpn
    echo ""
 
    # Passo 10: Segurança do SSH
    echo -e "\e[33mPasso 10: Reforçar a segurança do SSH\e[0m"
    sudo sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/g' /etc/ssh/sshd_config
    sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
    sudo systemctl restart sshd
    echo
 
    # Passo 11: Ativar o SELinux
    echo -e "\e[33mPasso 11: Ativar o SELinux\e[0m"
    echo "Verificando se o SELinux está instalado..."
    if [ -f /etc/selinux/config ]; then
      echo "O SELinux já está instalado"
    else
      echo "O SELinux não está instalado, instalando agora..."
      sudo apt-get install selinux-utils selinux-basics -y
    fi
    echo "Ativando o SELinux..."
    sudo selinux-activate
    echo ""
 
    # Passo 12: Configurar parâmetros de rede
    echo -e "\e[33mPasso 12: Configurar parâmetros de rede\e[0m"
    echo "Configurando parâmetros de rede..."
    sudo sysctl -p
    echo ""
 
    # Passo 13: Gerenciar políticas de senha
    echo -e "\e[33mPasso 13: Gerenciar políticas de senha\e[0m"
    echo "Modificando as políticas de senha..."
    sudo sed -i 's/PASS_MAX_DAYS\t99999/PASS_MAX_DAYS\t90/g' /etc/login.defs
    sudo sed -i 's/PASS_MIN_DAYS\t0/PASS_MIN_DAYS\t7/g' /etc/login.defs
    sudo sed -i 's/PASS_WARN_AGE\t7/PASS_WARN_AGE\t14/g' /etc/login.defs
    echo ""
 
    # Passo 14: Permissões e verificações
    echo -e "\e[33mPasso 14: Permissões e verificações\e[0m"
    echo "Configurando as permissões corretas em arquivos sensíveis..."
    sudo chmod 700 /etc/shadow /etc/gshadow /etc/passwd /etc/group
    sudo chmod 600 /boot/grub/grub.cfg
    sudo chmod 644 /etc/fstab /etc/hosts /etc/hostname /etc/timezone /etc/bash.bashrc
    echo "Verificando a integridade dos arquivos do sistema..."
    sudo debsums -c
    echo ""
 
    # Passo 15: Reforço adicional do processo de distribuição
    echo -e "\e[33mPasso 15: Reforço adicional do processo de distribuição\e[0m"
    echo "Desabilitando despejos de núcleo..."
    sudo echo '* hard core 0' | sudo tee /etc/security/limits.d/core.conf
    echo "Restringindo o acesso aos logs do kernel..."
    sudo chmod 640 /var/log/kern.log
    echo "Configurando as permissões corretas nos scripts de inicialização..."
    sudo chmod 700 /etc/init.d/*
    echo ""
 
    # Passo 16: Remover serviços desnecessários
    echo -e "\e[33mPasso 16: Remover serviços desnecessários\e[0m"
    echo "Removendo serviços desnecessários..."
    sudo apt-get purge rpcbind rpcbind-* -y
    sudo apt-get purge nis -y
    echo ""
 
    # Passo 17: Verificar a segurança dos arquivos-chave
    echo -e "\e[33mPasso 17: Verificar a segurança dos arquivos-chave\e[0m"
    echo "Verificando a segurança dos arquivos-chave..."
    sudo find /etc/ssh -type f -name 'ssh_host_*_key' -exec chmod 600 {} \;
    echo ""
 
    # Passo 18: Limitar o acesso root usando o SUDO
    echo -e "\e[33mPasso 18: Limitar o acesso root usando o SUDO\e[0m"
    echo "Limitando o acesso root usando o SUDO..."
    sudo apt-get install sudo -y
    sudo groupadd admin
    sudo usermod -a -G admin "$(whoami)"
    sudo sed -i 's/%sudo\tALL=(ALL:ALL) ALL/%admin\tALL=(ALL:ALL) ALL/g' /etc/sudoers
    echo ""
 
    # Passo 19: Permitir apenas root para acessar o CRON
    echo -e "\e[33mPasso 19: Restringir o acesso ao CRON\e[0m"
    echo "Permitindo apenas root para acessar o CRON..."
    sudo chmod 600 /etc/crontab
    sudo chown root:root /etc/crontab
    sudo chmod 600 /etc/cron.hourly/*
    sudo chmod 600 /etc/cron.daily/*
    sudo chmod 600 /etc/cron.weekly/*
    sudo chmod 600 /etc/cron.monthly/*
    sudo chmod 600 /etc/cron.d/*
    echo ""
 
    # Passo 20: Configurações básicas de acesso remoto e SSH
    echo -e "\e[33mPasso 20: Configurações básicas de acesso remoto e SSH\e[0m"
    echo "Desabilitando o login root via SSH..."
    sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
    echo "Desabilitando autenticação por senha via SSH..."
    sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
    echo "Desabilitando o encaminhamento X11 via SSH..."
    sudo sed -i 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config
    echo "Recarregando o serviço SSH..."
    sudo systemctl reload sshd
    echo ""
 
    # Passo 21: Desabilitar o Xwindow
    echo -e "\e[33mPasso 21: Desabilitar o Xwindow\e[0m"
    echo "Desabilitando o Xwindow..."
    sudo systemctl set-default multi-user.target
    echo ""
 
    # Passo 22: Minimizar a instalação de pacotes
    echo -e "\e[33mPasso 22: Minimizar a instalação de pacotes\e[0m"
    echo "Instalando apenas pacotes essenciais..."
    sudo apt-get install --no-install-recommends -y systemd-sysv apt-utils
    sudo apt-get --purge autoremove -y
    echo ""
 
    # Passo 23: Verificar contas com senhas vazias
    echo -e "\e[33mPasso 23: Verificar contas com senhas vazias\e[0m"
    echo "Verificando contas com senhas vazias..."
    sudo awk -F: '($2 == "" ) {print}' /etc/shadow
    echo ""
 
    # Passo 24: Monitorar atividades do usuário
    echo -e "\e[33mPasso 24: Monitorar atividades do usuário\e[0m"
    echo "Instalando auditd para monitoramento de atividades do usuário..."
    sudo apt-get install auditd -y
    echo "Configurando o auditd..."
    sudo echo "-w /var/log/auth.log -p wa -k authentication" | sudo tee -a /etc/audit/rules.d/audit.rules
    sudo echo "-w /etc/passwd -p wa -k password-file" | sudo tee -a /etc/audit/rules.d/audit.rules
    sudo echo "-w /etc/group -p wa -k group-file" | sudo tee -a /etc/audit/rules.d/audit.rules
    sudo systemctl restart auditd
    echo ""
 
    # Passo 25: Instalar e configurar fail2ban
    echo -e "\e[33mPasso 25: Instalar e configurar fail2ban\e[0m"
    echo "Instalando fail2ban..."
    sudo apt-get install fail2ban -y
    echo "Configurando fail2ban..."
    sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    sudo sed -i 's/bantime  = 10m/bantime  = 1h/g' /etc/fail2ban/jail.local
    sudo sed -i 's/maxretry = 5/maxretry = 3/g' /etc/fail2ban/jail.local
    sudo systemctl enable fail2ban
    sudo systemctl start fail2ban
    echo ""
 
    # Passo 26: Detecção de rootkits
    echo -e "\e[33mPasso 26: Instalando e executando a detecção de rootkits...\e[0m"
    sudo apt-get install rkhunter
    sudo rkhunter --update
    sudo rkhunter --propupd
    sudo rkhunter --check
    echo
 
    # Passo 27: Monitorar logs do sistema
    echo -e "\e[33mPasso 27: Monitorar logs do sistema\e[0m"
    echo "Instalando logwatch para monitoramento de logs do sistema..."
    sudo apt-get install logwatch -y
    echo ""
 
    # Passo 28: Ativar autenticação de dois fatores
    echo -e "\e[33mPasso 28: Ativar autenticação de dois fatores\e[0m"
    echo "Instalando o Google Authenticator para autenticação de dois fatores..."
    sudo apt-get install libpam-google-authenticator -y
    echo "Ativando autenticação de dois fatores..."
    sudo google-authenticator
    echo "Editando as configurações do PAM para autenticação de dois fatores..."
    sudo sed -i 's/ChallengeResponseAuthentication no/ChallengeResponseAuthentication yes/g' /etc/ssh/sshd_config
    sudo sed -i 's/UsePAM no/UsePAM yes/g' /etc/ssh/sshd_config
    sudo sed -i 's/#auth required pam_google_authenticator.so/auth required pam_google_authenticator.so/g' /etc/pam.d/sshd
    sudo systemctl reload sshd
    echo ""
 
    echo -e "\e[32mFortificação concluída!\e[0m"
 
  }
 
# Função para exibir o menu
show_menu() {
  echo "Escolha uma opção:"
  echo "1. Hardening CentOS/RHEL"
  echo "2. Hardening Ubuntu/Debian"
  echo "3. Sair"
}
 
# Loop principal do menu
while true; do
  show_menu
  read -p "Digite sua escolha (1/2/3): " choice
 
  case $choice in
    1)
      harden_centos_rhel
      ;;
    2)
      harden_ubuntu_debian
      ;;
    3)
      echo "Saindo..."
      exit 0
      ;;
    *)
      echo "Escolha inválida. Por favor, digite 1, 2 ou 3."
      ;;
  esac
done
