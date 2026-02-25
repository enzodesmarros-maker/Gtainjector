# 💉 Injector .dll — v1 Beta

Ferramenta educacional para estudo de injeção de DLL em Windows.

---

## 💾 Download

Acesse a aba **Releases** e baixe o arquivo mais recente.

Execute sempre como **Administrador**.

---

## 🔧 Como usar

1. Abra o programa como Administrador
2. Clique em **Selecionar Processo** e escolha o processo alvo
3. Clique em **Procurar** e selecione a DLL
4. Clique em **INJETAR**

---

## 📄 O que e uma DLL?

DLL e um arquivo de extensao `.dll` que contem codigo que pode ser carregado dentro de um processo em execucao. E amplamente estudado em seguranca de software e desenvolvimento de sistemas.

---

## 🖥️ Como achar o processo alvo?

Abra o processo primeiro, depois abra o Injector. Clique em **Selecionar Processo** e vai aparecer uma lista com todos os programas rodando no momento.

---

## 📂 Como selecionar a DLL?

Clique em **Procurar** e navegue ate a pasta onde esta o arquivo `.dll`. Selecione o arquivo e clique em Abrir.

---

## ⚠️ O que fazer se o processo fechar?

Isso pode acontecer por alguns motivos: 1) A DLL nao e compativel com o processo alvo. 2) A arquitetura da DLL (x86/x64) nao corresponde ao processo. 3) O processo nao estava totalmente carregado no momento da injecao. 4) A DLL possui dependencias que nao estao presentes no processo. Espere o processo carregar completamente antes de injetar e verifique se a DLL e do tipo correto para o processo.

---

## 🗑️ Como remover a DLL?

Na lista **Modulos Carregados** a DLL aparece com destaque. Clique em **Remover** ao lado dela. Ou clique em **DESSINJ. TODAS** para remover tudo de uma vez.

---

## 🔑 Por que precisa de Administrador?

Sem permissao de Administrador o programa nao consegue acessar a memoria de outros processos. Clique com botao direito no `.exe` e selecione **Executar como administrador**.

---

## 🛡️ Por que o antivirus apita?

Ferramentas de injecao de DLL sao detectadas por antivirus porque utilizam tecnicas de acesso a memoria de processos externos. O codigo fonte esta disponivel aqui no GitHub para verificacao. Adicione uma excecao ou desative temporariamente se necessario. O autor nao se responsabiliza por qualquer problema causado pela desativacao do antivirus.

---

## ❌ Aviso

Este projeto e disponibilizado exclusivamente para fins **educacionais** e de **pesquisa em seguranca de software**.

O autor nao se responsabiliza por qualquer uso indevido desta ferramenta. O usuario e o unico responsavel pelo uso que fizer dela.

---

## 🏆 Creditos

- xitzinho — Black rock
- auralobo — clean da pista

---
---

# 💉 Injector .dll — v1 Beta

Educational tool for studying DLL injection on Windows.

---

## 💾 Download

Go to the **Releases** tab and download the latest file.

Always run as **Administrator**.

---

## 🔧 How to use

1. Open as Administrator
2. Click **Selecionar Processo** and choose the target process
3. Click **Procurar** and select the DLL
4. Click **INJETAR**

---

## 📄 What is a DLL?

A DLL is a file with the `.dll` extension that contains code which can be loaded into a running process. It is widely studied in software security and systems development.

---

## 🖥️ How to find the target process?

Open the process first, then open the Injector. Click **Selecionar Processo** and a list of all running programs will appear.

---

## 📂 How to select the DLL?

Click **Procurar** and navigate to the folder where your `.dll` file is located. Select the file and click Open.

---

## ⚠️ What to do if the process closes?

This can happen for a few reasons: 1) The DLL is not compatible with the target process. 2) The DLL architecture (x86/x64) does not match the process. 3) The process was not fully loaded at the time of injection. 4) The DLL has dependencies that are not present in the process. Wait for the process to fully load before injecting and make sure the DLL is the correct type for the process.

---

## 🗑️ How to remove the DLL?

In the **Modulos Carregados** list the DLL appears highlighted. Click **Remover** next to it. Or click **DESSINJ. TODAS** to remove everything at once.

---

## 🔑 Why does it need Administrator?

Without Administrator permission the program cannot access the memory of other processes. Right click the `.exe` and select **Run as administrator**.

---

## 🛡️ Why does the antivirus flag it?

DLL injection tools are flagged by antivirus software because they use memory access techniques on external processes. Source code is available on GitHub for verification. Add an exception or temporarily disable it if needed. The author is not responsible for any issues caused by disabling your antivirus.

---

## ❌ Warning

This project is provided exclusively for **educational** and **software security research** purposes.

The author is not responsible for any misuse of this tool. The user is solely responsible for how they use it.

---

## 🏆 Credits

- xitzinho — Black rock
- auralobo — clean da pista
