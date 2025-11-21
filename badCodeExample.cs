public class VulnerableCSharpExample
{
    // Exposed secret key
    private static string ApiSecret = "topsecret_api_key_123";

    static void Main(string[] args)
    {
        string userPath = args.Length > 0 ? args[0] : "../etc/passwd";

        // Path traversal
        string fileContents = File.ReadAllText(userPath);
        Console.WriteLine(fileContents);

        // Broken crypto – ECB mode
        using (var aes = Aes.Create())
        {
            aes.Mode = CipherMode.ECB;
            byte[] encrypted = aes.CreateEncryptor().TransformFinalBlock(
                System.Text.Encoding.UTF8.GetBytes("SensitiveData"), 0, 14);
        }

        // Unrestricted thread spawning (DoS)
        for (int i = 0; i < 5000; i++)
        {
            new Thread(() => {
                Thread.Sleep(1000000);
            }).Start();
        }

        // XXE injection
        var xml = new XmlDocument
        {
            XmlResolver = new XmlUrlResolver()
        };
        xml.LoadXml(@"<!DOCTYPE foo [ <!ENTITY xxe SYSTEM 'file:///c:/windows/win.ini'> ]>
                      <root>&xxe;</root>");

        // Writing to protected system directory
        File.WriteAllText("C:\\Windows\\System32\\bad.txt", "oops");

        // Insecure randomness
        Random rng = new Random();
        Console.WriteLine(rng.Next());
    }
}
