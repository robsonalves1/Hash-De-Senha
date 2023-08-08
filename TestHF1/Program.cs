using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;

class Program
{
    private static RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();

    static void Main(string[] args)
    {
        byte[] salt = new byte[16];
        rngCsp.GetBytes(salt);

        Console.WriteLine("Informe a senha");
        string senha = Console.ReadLine();

        Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(senha, salt);

        byte[] hash = pbkdf2.GetBytes(20);
        byte[] hashBytes = new byte[36];

        Array.Copy(salt, 0, hashBytes, 0, 16);
        Array.Copy(hash, 0, hashBytes, 16, 20);

        string hashSenha = Convert.ToBase64String(hashBytes);

        Console.WriteLine($"\nHash da senha gerado : {hashSenha}");

        // Simulating storing the hashSenha and salt somewhere (e.g., in a database)

        Console.WriteLine("\nInforme a senha para verificar:");
        var senhaVerificacao = Console.ReadLine();

        // Convert the stored hashSenha back to bytes
        byte[] storedHashBytes = Convert.FromBase64String(hashSenha);

        // Extract the salt from the stored hash
        byte[] storedSalt = new byte[16];
        Array.Copy(storedHashBytes, 0, storedSalt, 0, 16);

        // Generate a new hash using the user-provided password and the extracted salt
        var pbkdf2Verificacao = new Rfc2898DeriveBytes(senhaVerificacao, storedSalt, 1000);
        byte[] newHash = pbkdf2Verificacao.GetBytes(20);

        // Compare the newly generated hash with the stored hash
        bool passwordsMatch = true;
        for (int i = 0; i < 20; i++)
        {
            if (storedHashBytes[i + 16] != newHash[i])
            {
                passwordsMatch = false;
                break;
            }
        }

        if (passwordsMatch)
        {
            Console.WriteLine("\nAs senhas coincidem!");
        }
        else
        {
            Console.WriteLine("\nAs senhas não coincidem!");
        }

        Console.ReadKey();
    }
}
