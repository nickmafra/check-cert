package com.nickmafra;

import com.nickmafra.util.X509Utils;

import java.io.*;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;

public class CheckCertApplication {

    public static void main(String[] args) {
        Deque<String> argStack = new ArrayDeque<>();
        Arrays.stream(args).forEach(argStack::push);

        X509Certificate certificate = carregarCertificado(argStack);
        escrever("Principal do certificado: " + certificate.getSubjectDN().getName());

        List<Comando> comandoList = Arrays.stream(Comando.values()).collect(Collectors.toList());
        comandoList.forEach(cmd -> escrever("Comando disponível: " + cmd));
        String comando = ler("Digite o comando desejado: ", argStack);
        comandoList.stream()
                .filter(cmd -> comando.equalsIgnoreCase(cmd.name()))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Comando '" + comando + "' é inválido."))
                .consumer.accept(certificate);
    }

    // carregamento do certificado

    private static X509Certificate carregarCertificado(Deque<String> argStack) {
        String path = ler("Digite o caminho do certificado: ", argStack);
        try (InputStream in = new FileInputStream(new File(path))) {
            String tipo = ler("Digite o tipo do certificado (PEM/JKS): ", argStack);
            if ("PEM".equalsIgnoreCase(tipo)) {
                return carregarPem(in);
            } else if ("JKS".equalsIgnoreCase(tipo)) {
                return carregarJks(argStack, in);
            } else {
                throw new IllegalArgumentException("Tipo '" + tipo + "' é inválido.");
            }
        } catch (FileNotFoundException e) {
            throw new IllegalArgumentException("Arquivo não encontrado.", e);
        } catch (IOException e) {
            throw new IllegalArgumentException("Erro ao carregar arquivo.", e);
        }
    }

    private static X509Certificate carregarPem(InputStream in) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        } catch (CertificateException e) {
            throw new IllegalArgumentException("Erro ao ler certificado X509 PEM.", e);
        }
    }

    private static X509Certificate carregarJks(Deque<String> argStack, InputStream in) {
        String senha = ler("Digite a senha do keystore jks: ", argStack);
        KeyStore ks;
        try {
            ks = KeyStore.getInstance("JKS");
            ks.load(in, senha.toCharArray());

            Enumeration<String> aliases = ks.aliases();
            String ultimoAlias;
            int qtAlias = 0;
            do {
                String alias = aliases.nextElement();
                escrever("Alias encontrado: " + alias);
                ultimoAlias = alias;
                qtAlias++;
            } while (aliases.hasMoreElements());
            String alias;
            if (qtAlias == 1) {
                alias = ultimoAlias;
            } else {
                alias = ler("Digite o nome do alias desejado: ", argStack);
                if (!ks.containsAlias(alias)) {
                    throw new IllegalArgumentException("O alias é inválido.");
                }
            }
            Certificate certificate = ks.getCertificate(alias);
            if (!(certificate instanceof X509Certificate)) {
                throw new RuntimeException("O certificado não é X509.");
            } else {
                return (X509Certificate) certificate;
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("Erro ao ler keystore.", e);
        }
    }

    // comandos

    private enum Comando {
        CHAVE64(CheckCertApplication::mostrarChavePublicaBase64),
        CHAVE16(CheckCertApplication::mostrarChavePublicaHex);

        Consumer<X509Certificate> consumer;

        Comando(Consumer<X509Certificate> consumer) {
            this.consumer = consumer;
        }
    }

    private static void mostrarChavePublicaBase64(X509Certificate certificate) {
        String chave = X509Utils.getBase64PublicKey(certificate);
        escrever("Chave pública em base64: " + chave);
    }

    private static void mostrarChavePublicaHex(X509Certificate certificate) {
        String chave = X509Utils.getHexPublicKey(certificate);
        escrever("Chave pública em hexadecimal: " + chave);
    }

    // funções úteis

    private static void escrever(String message) {
        System.out.println(message);
    }

    private static Scanner scanner = new Scanner(System.in);

    private static String ler(String message, Deque<String> argStack) {
        if (!argStack.isEmpty()) {
            System.out.println(message + argStack.peek());
            return argStack.pop();
        }
        System.out.print(message);
        return scanner.nextLine();
    }
}
