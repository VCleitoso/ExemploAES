import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.util.Base64;

public class Usuario {
    private Long id;
    private String nome;
    private String password;
    private String dados;

    public String getDados() {
        String a = this.dados;
        a = CriptografiaAES.decriptografar(a, this.nome);
        return a;
    }

    public void setDados(String dados) {
        String a = CriptografiaAES.criptografar(dados, this.nome);
        this.dados = a;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getId() {
        return this.id;
    }

    public String getNome() {
        return this.nome;
    }

    public void setNome(String nome) {
        this.nome = nome;
    }

    public String getPassword() {
        String a = this.password;
        a = CriptografiaAES.decriptografar(a, this.nome);
        return a;
    }

    public void setPassword(String password) {
        String a = CriptografiaAES.criptografar(password, this.nome);
        this.password = a;
    }

    public static class CriptografiaAES {
        private static final String ALGORITHM = "AES";
        private static final String CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";
        private static final int ITERATIONS = 10000;
        private static final int KEY_LENGTH = 128; // 128 bits = 16 bytes

        public static String criptografar(String plaintext, String nome) {
            try {
                SecretKeySpec secretKey = gerarChave(nome);
                Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
                byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
                return Base64.getEncoder().encodeToString(encryptedBytes);
            } catch (Exception e) {
                e.printStackTrace();
            }
            return null;
        }

        public static String decriptografar(String ciphertext, String nome) {
            try {
                SecretKeySpec secretKey = gerarChave(nome);
                Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
                cipher.init(Cipher.DECRYPT_MODE, secretKey);
                byte[] encryptedBytes = Base64.getDecoder().decode(ciphertext);
                byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
                return new String(decryptedBytes, StandardCharsets.UTF_8);
            } catch (Exception e) {
                e.printStackTrace();
            }
            return null;
        }

        private static SecretKeySpec gerarChave(String nome) {
            try {
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                KeySpec spec = new PBEKeySpec(nome.toCharArray(), nome.getBytes(StandardCharsets.UTF_8), ITERATIONS, KEY_LENGTH);
                SecretKeySpec secretKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), ALGORITHM);
                return secretKey;
            } catch (Exception e) {
                e.printStackTrace();
            }
            return null;
        }
    }

    public static void aguardarTempo(long milissegundos) {
        try {
            Thread.sleep(milissegundos);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        Usuario user = new Usuario();
        user.setId(3L);
        user.setNome("Eduardo Morias");
        System.out.println("Criptografando...");
        aguardarTempo(1000);
        user.setDados("Eu_gosto_de_todos");
        System.out.println("Criptografou dado");
        aguardarTempo(1000);
        user.setPassword("debsbdgvurhcujxhcuieh@424e5u39xjenhA");
        System.out.println("Criptografando senha");
        aguardarTempo(1000);
        System.out.print("Nome (chave): ");
        System.out.println(user.getNome());
        System.out.print("Senha criptografada: ");
        System.out.println(CriptografiaAES.criptografar(user.getPassword(), user.getNome()));
        System.out.print("Dados criptografados: ");
        System.out.println(CriptografiaAES.criptografar(user.getDados(), user.getNome()));
        System.out.print("Senha descriptografada: ");
        System.out.println(user.getPassword());
        System.out.print("Dados descriptografados: ");
        System.out.println(user.getDados());
    }
}
/*    Importações:
        javax.crypto.Cipher: fornece as funcionalidades de criptografia e descriptografia.
        javax.crypto.SecretKeyFactory: usado para gerar chaves secretas a partir de informações fornecidas.
        javax.crypto.spec.PBEKeySpec: fornece uma representação de chave secreta baseada em senha.
        javax.crypto.spec.SecretKeySpec: especifica uma chave secreta em formato de byte array.
        java.nio.charset.StandardCharsets: fornece constantes para conjuntos de caracteres suportados.

    Classe Usuario:
        Essa classe representa um usuário e possui os seguintes atributos:
            id: um identificador numérico para o usuário.
            nome: o nome do usuário.
            password: a senha do usuário (criptografada).
            dados: algum dado associado ao usuário (criptografado).
        Os métodos getDados e setDados são usados para obter e definir os dados do usuário, respectivamente. Esses métodos fazem uso da classe CriptografiaAES para descriptografar e criptografar os dados, usando o nome do usuário como parâmetro.
        Os métodos getId, getNome, setNome, getPassword e setPassword são usados para obter e definir os outros atributos do usuário. Os métodos getPassword e setPassword também fazem uso da classe CriptografiaAES para descriptografar e criptografar a senha.

    Classe CriptografiaAES:
        Essa classe está aninhada dentro da classe Usuario e contém métodos estáticos para criptografar e descriptografar strings usando o algoritmo AES.
        A constante ALGORITHM define o algoritmo de criptografia como AES.
        A constante CIPHER_ALGORITHM define o algoritmo de criptografia usado pelo objeto Cipher como AES/ECB/PKCS5Padding. Esse algoritmo de modo eletrônico em bloco usa o modo ECB para criptografia e o padding PKCS5.
        A constante ITERATIONS define o número de iterações usado na geração da chave secreta.
        A constante KEY_LENGTH define o comprimento da chave secreta em bits.
        O método criptografar recebe uma string plaintext e o nome do usuário como parâmetros. Ele gera uma chave secreta a partir do nome do usuário usando o algoritmo PBKDF2 com HMAC-SHA1. Em seguida, cria um objeto Cipher com o algoritmo definido e o modo de criptografia definido como Cipher.ENCRYPT_MODE. A chave secreta é usada para inicializar o objeto Cipher e, em seguida, a string plaintext é criptografada e retornada como uma string codificada em Base64.
        O método decriptografar recebe uma string ciphertext e o nome do usuário como parâmetros. Ele gera uma chave secreta da mesma forma que o método criptografar. Em seguida, cria um objeto Cipher com o algoritmo definido e o modo de criptografia definido como Cipher.DECRYPT_MODE. A chave secreta é usada para inicializar o objeto Cipher e, em seguida, a string ciphertext é decodificada de Base64 e descriptografada, retornando a string original.
        O método gerarChave recebe o nome do usuário como parâmetro. Ele usa o algoritmo PBKDF2 com HMAC-SHA1 para gerar uma chave secreta a partir do nome do usuário. A chave secreta é retornada como um objeto SecretKeySpec.

    Método aguardarTempo:
        Esse método estático é usado para pausar a execução do programa por um determinado número de milissegundos.

    Método main:
        Esse é o ponto de entrada do programa.
        Ele cria uma instância da classe Usuario chamada user.
        Define o ID, nome e outros atributos do usuário.
        Em seguida, criptografa os dados e a senha do usuário usando a classe CriptografiaAES.
        Por fim, imprime o nome, senha e dados descriptografados do usuário.

Em resumo, esse código implementa uma classe de usuário que armazena informações como ID, nome, senha e dados criptografados. Ele utiliza o algoritmo AES para criptografar e descriptografar os dados e a senha do usuário, usando o nome do usuário como parte da chave de criptografia.*/
