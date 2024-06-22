// Copyright (c) 2024 Roger Brown.
// Licensed under the MIT License.

using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Mime;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using System.Web;
using System.Xml;

namespace signtool
{
    class Program
    {
        readonly string[] args;
        readonly Dictionary<string, string> arguments = new Dictionary<string, string>();
        readonly List<string> options = new List<string>();
        readonly string endpoint;
        readonly string authorization;

        Program(string[] args)
        {
            this.args = args;

            string path = String.Join(Path.DirectorySeparatorChar, new string[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                (string)AppContext.GetData("configDirectory"),
                (string)AppContext.GetData("configFile")
            });

            XmlDocument doc = new XmlDocument();
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read);
            doc.Load(stream);

            endpoint = doc.SelectSingleNode("/SignTool/Endpoint").InnerText;
            authorization = doc.SelectSingleNode("/SignTool/Authorization").InnerText;
        }

        static Task<int> Main(string[] args)
        {
            return new Program(args).Main();
        }

        async Task<int> Main()
        {
            int i = 0;
            int rc = 2;

            while (i < args.Length)
            {
                string arg = args[i++];

                if (ArgMatches(arg, "a") || ArgMatches(arg, "as") || ArgMatches(arg, "q") || ArgMatches(arg, "v") || ArgMatches(arg, "r") || ArgMatches(arg, "u") || ArgMatches(arg, "ph") || ArgMatches(arg, "uw") || ArgMatches(arg, "v") || ArgMatches(arg, "debug"))
                {
                    options.Add(arg.Substring(1));
                }
                else if (ArgMatches(arg, "sha1") || ArgMatches(arg, "fd") || ArgMatches(arg, "td") || ArgMatches(arg, "t") || ArgMatches(arg, "tr"))
                {
                    arguments[arg.Substring(1)] = args[i++];
                }
                else if (String.Equals(arg, "sign", StringComparison.OrdinalIgnoreCase) || String.Equals(arg, "verify", StringComparison.OrdinalIgnoreCase))
                {
                    arguments["command"] = arg;
                }
                else
                {
                    rc = await SignFile(arg);

                    if (rc != 0)
                    {
                        break;
                    }
                }
            }

            return rc;
        }

        private bool ArgMatches(string arg, string v)
        {
            char[] a = arg.ToCharArray();

            if (a[0] == '/' || a[0] == '-')
            {
                return String.Equals(v, new string(a, 1, a.Length - 1), StringComparison.OrdinalIgnoreCase);
            }

            return false;
        }

        async Task<int> SignFile(string filePath)
        {
            int rc = 3;
            using var form = new MultipartFormDataContent();
            using var fileContent = new ByteArrayContent(await File.ReadAllBytesAsync(filePath));
            string fileNameOnly = Path.GetFileName(filePath);
            fileContent.Headers.ContentType = MediaTypeHeaderValue.Parse("multipart/form-data");
            form.Add(fileContent, "formFile", fileNameOnly);
            var httpClient = new HttpClient();
            int schemaLength = authorization.IndexOf(' ');
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(authorization.Substring(0, schemaLength), authorization.Substring(schemaLength + 1));
            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.Append(endpoint);
            bool and = false;

            if (options.Count > 0)
            {
                arguments["options"] = String.Join(",", options);
            }

            foreach (var e in arguments)
            {
                stringBuilder.Append(and ? '&' : '?').Append(HttpUtility.UrlEncode(e.Key)).Append('=').Append(HttpUtility.UrlEncode(e.Value));
                and = true;
            }

            string url = stringBuilder.ToString();

            var response = await httpClient.PostAsync(url, form);

            if (response.IsSuccessStatusCode)
            {
                List<KeyValuePair<string, string>> output = new List<KeyValuePair<string, string>>();
                string fileName = null;
                var contentDisposition = response.Content.Headers.ContentDisposition;

                if (contentDisposition != null)
                {
                    if ("attachment".Equals(contentDisposition.DispositionType))
                    {
                        fileName = contentDisposition.FileName;
                    }
                }

                string contentType = response.Content.Headers.ContentType.MediaType;

                if (fileName == null)
                {
                    if ("application/json".Equals(contentType))
                    {
                        Dictionary<string, JsonElement> json;

                        using (var stream = response.Content.ReadAsStream())
                        {
                            json = await JsonSerializer.DeserializeAsync<Dictionary<string, JsonElement>>(stream);
                        }

                        foreach (string name in new string[] { "SignerCertificate", "Status", "StatusMessage", "Path" })
                        {
                            string value = null;

                            if (json.TryGetValue(name, out JsonElement element))
                            {
                                value = element.GetString();

                                switch (name)
                                {
                                    case "SignerCertificate":
                                        {
                                            X509Certificate2 cert = X509Certificate2.CreateFromPem(value);

                                            value = cert.Thumbprint;
                                        }
                                        break;
                                    case "Status":
                                        rc = "Valid".Equals(value) ? 0 : 1;
                                        break;
                                }
                            }

                            output.Add(new KeyValuePair<string, string>(name, value));
                        }
                    }
                    else
                    {
                        using (var stream = Console.OpenStandardOutput())
                        {
                            await response.Content.CopyToAsync(stream);
                        }
                    }
                }
                else
                {
                    string certificate = arguments["sha1"];

                    output.Add(new KeyValuePair<string, string>("SignerCertificate", certificate));
                    output.Add(new KeyValuePair<string, string>("Status", "Valid"));
                    output.Add(new KeyValuePair<string, string>("StatusMessage", "Signature verified."));
                    output.Add(new KeyValuePair<string, string>("Path", fileName));

                    if (!contentType.Equals(MediaTypeNames.Application.Octet))
                    {
                        throw new Exception($"wrong content response - {contentType}");
                    }

                    if (!fileName.Equals(fileNameOnly))
                    {
                        throw new Exception($"wrong file - {fileName}");
                    }

                    using (var stream = File.OpenWrite(filePath))
                    {
                        await response.Content.CopyToAsync(stream);
                    }

                    rc = 0;
                }

                if (output.Count > 0)
                {
                    int[] lengths = new int[output.Count];
                    int totalLength = lengths.Length - 1;
                    int i = 0;

                    while (i < lengths.Length)
                    {
                        var kp = output[i];
                        int len = kp.Key.Length;

                        if (kp.Value != null && kp.Value.Length > len)
                        {
                            len = kp.Value.Length;
                        }

                        lengths[i] = len;
                        totalLength += len;
                        i++;
                    }

                    char[] buf = new char[totalLength];

                    for (int k = 0; k < 3; k++)
                    {
                        i = 0;
                        int j = 0;

                        while (i < lengths.Length)
                        {
                            var kp = output[i];

                            if (j != 0)
                            {
                                buf[j++] = ' ';
                            }

                            switch (k)
                            {
                                case 0:
                                    Array.Fill(buf, ' ', j, lengths[i]);
                                    Array.Copy(kp.Key.ToCharArray(), 0, buf, j, kp.Key.Length);
                                    break;
                                case 1:
                                    Array.Fill(buf, ' ', j, lengths[i]);
                                    Array.Fill(buf, '-', j, kp.Key.Length);
                                    break;
                                case 2:
                                    Array.Fill(buf, ' ', j, lengths[i]);
                                    if (kp.Value != null && kp.Value.Length > 0)
                                    {
                                        Array.Copy(kp.Value.ToCharArray(), 0, buf, j, kp.Value.Length);
                                    }
                                    break;
                            }

                            j += lengths[i];
                            i++;
                        }

                        Console.WriteLine(buf);
                    }
                }
            }
            else
            {
                using (var stream = Console.OpenStandardError())
                {
                    await response.Content.CopyToAsync(stream);
                }
            }

            return rc;
        }
    }
}
