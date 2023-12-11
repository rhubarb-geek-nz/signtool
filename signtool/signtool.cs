/**************************************************************************
 *
 *  Copyright 2022, Roger Brown
 *
 *  This file is part of Roger Brown's Toolkit.
 *
 *  This program is free software: you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by the
 *  Free Software Foundation, either version 3 of the License, or (at your
 *  option) any later version.
 * 
 *  This program is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 *  more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Mime;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Xml;

namespace signtool
{
    class Program
    {
        readonly string [] args;
        readonly Dictionary<string, string> arguments= new Dictionary<string, string>();
        readonly List<string> options = new List<string>();
        readonly string endpoint;
        readonly string authorization;

        Program(string [] args)
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

                if (ArgMatches(arg,"a") || ArgMatches(arg, "as") || ArgMatches(arg, "q") || ArgMatches(arg, "v") || ArgMatches(arg, "r") || ArgMatches(arg, "u") || ArgMatches(arg, "ph") || ArgMatches(arg, "uw") || ArgMatches(arg, "v") || ArgMatches(arg, "debug"))
                {
                    options.Add(arg.Substring(1));
                }
                else if (ArgMatches(arg, "sha1") || ArgMatches(arg, "fd") || ArgMatches(arg, "td") || ArgMatches(arg, "t") || ArgMatches(arg, "tr"))
                {
                    arguments[arg.Substring(1)] = args[i++];
                }
                else if (String.Equals(arg, "sign", StringComparison.OrdinalIgnoreCase) || String.Equals(arg,"verify", StringComparison.OrdinalIgnoreCase))
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
            form.Add(fileContent,"formFile",fileNameOnly);
            var httpClient = new HttpClient();
            int schemaLength = authorization.IndexOf(' ');
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(authorization.Substring(0, schemaLength), authorization.Substring(schemaLength+1));
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
            Console.WriteLine($"{url} {filePath}");
            var response = await httpClient.PostAsync(url, form);

            if (response.IsSuccessStatusCode)
            {
                string fileName = null;
                var contentDisposition = response.Content.Headers.ContentDisposition;

                if (contentDisposition != null)
                {
                    if ("attachment".Equals(contentDisposition.DispositionType))
                    {
                        fileName = contentDisposition.FileName;
                    }
                }

                if (fileName == null)
                {
                    using (var stream = Console.OpenStandardOutput())
                    {
                        await response.Content.CopyToAsync(stream);
                    }
                }
                else
                {
                    string contentType = response.Content.Headers.ContentType.MediaType;

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
                }
                rc = 0;
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
