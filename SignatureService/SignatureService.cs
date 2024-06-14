// Copyright (c) 2024 Roger Brown.
// Licensed under the MIT License.

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Net;
using System.Net.Mime;
#if NET7_0_OR_GREATER
#else
using System.Security.Cryptography;
#endif
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading.Tasks;

namespace SignatureService
{
    internal class SignatureService
    {
        private readonly ILogger<SignatureService> logger;
        private readonly IWebHostEnvironment env;
        private readonly IConfiguration config;
        private readonly string wwwAuthenticate;
        private readonly List<string> authorization;
        private readonly static string
            CMD_SetAuthenticodeSignature = "Set-AuthenticodeSignature",
            CMD_GetAuthenticodeSignature = "Get-AuthenticodeSignature";
        private readonly static string
            ARG_Certificate = "Certificate",
            ARG_TimestampServer = "TimestampServer",
            ARG_HashAlgorithm = "HashAlgorithm",
            ARG_FilePath = "FilePath";

        public SignatureService(IConfiguration config, IWebHostEnvironment env, ILogger<SignatureService> logger)
        {
            this.env = env;
            this.logger = logger;
            this.config = config;

            logger.LogInformation($"WebRootPath {env.WebRootPath}");

            var signtool = config.GetSection("Signtool");

            authorization = signtool.GetSection(HeaderNames.Authorization).Get<List<string>>();
            wwwAuthenticate = signtool.GetValue<string>(HeaderNames.WWWAuthenticate);
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var request = context.Request;

            string auth = request.Headers.Authorization;

            if (!authorization.Contains(auth))
            {
                context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                context.Response.Headers.WWWAuthenticate = wwwAuthenticate;
                return;
            }

            string guid = Guid.NewGuid().ToString();

            string dir = Path.Combine(env.WebRootPath, guid);

            Directory.CreateDirectory(dir);

            try
            {
                string fileName = null, filePath = null;
                bool bDelete = false;

                try
                {
                    if (request.HasFormContentType)
                    {
                        IFormCollection form = await request.ReadFormAsync();
                        IFormFileCollection formFiles = form.Files;

                        foreach (IFormFile formFile in formFiles)
                        {
                            if (bDelete)
                            {
                                throw new Exception($"{fileName} already being processed");
                            }

                            fileName = formFile.FileName;

                            if (fileName.Contains("/") || fileName.Contains("\\"))
                            {
                                throw new ArgumentException(fileName, "fileName");
                            }

                            filePath = Path.Combine(dir, fileName);

                            using (var file = File.Open(filePath, FileMode.Create))
                            {
                                bDelete = true;

                                await formFile.CopyToAsync(file);
                            }
                        }
                    }
                    else
                    {
                        if (!System.Net.Mime.MediaTypeNames.Application.Octet.Equals(request.ContentType))
                        {
                            throw new Exception($"{request.ContentType} should be {MediaTypeNames.Application.Octet}");
                        }

                        fileName = new ContentDisposition(request.Headers.ContentDisposition).FileName;

                        if (fileName.Contains("/") || fileName.Contains("\\"))
                        {
                            throw new ArgumentException(fileName, "fileName");
                        }

                        filePath = Path.Combine(dir, fileName);

                        using (var file = File.Open(filePath, FileMode.Create))
                        {
                            bDelete = true;

                            await request.Body.CopyToAsync(file);
                        }
                    }

                    string command = request.Query["command"];

                    switch (command)
                    {
                        case "sign":
                            {
                                string sha1 = request.Query["sha1"];
                                string fd = request.Query["fd"];
                                string t = request.Query["t"];

                                X509Store keyStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                                keyStore.Open(OpenFlags.ReadOnly);

                                X509Certificate2 cert = keyStore.Certificates.Find(X509FindType.FindByThumbprint, sha1, true).Single();

                                logger.LogInformation($"{CMD_SetAuthenticodeSignature} -{ARG_Certificate} {cert.Thumbprint} -{ARG_TimestampServer} {t} -{ARG_HashAlgorithm} {fd} -{ARG_FilePath} {filePath}");

                                using (PowerShell powerShell = PowerShell.Create())
                                {
                                    powerShell
                                        .AddCommand(CMD_SetAuthenticodeSignature)
                                        .AddParameter(ARG_Certificate, cert)
                                        .AddParameter(ARG_TimestampServer, t)
                                        .AddParameter(ARG_HashAlgorithm, fd)
                                        .AddParameter(ARG_FilePath, filePath);

                                    await powerShell.InvokeAsync();
                                }

                                var response = context.Response;

                                response.StatusCode = 200;

                                response.ContentType = MediaTypeNames.Application.Octet;

                                ContentDisposition contentDisposition = new ContentDisposition("attachment");

                                contentDisposition.FileName = Path.GetFileName(filePath);

                                response.Headers.ContentDisposition = contentDisposition.ToString();

                                using (var outfile = File.Open(filePath, FileMode.Open))
                                {
                                    await outfile.CopyToAsync(response.Body);
                                }
                            }
                            break;
                        case "verify":
                            {
                                logger.LogInformation($"{CMD_GetAuthenticodeSignature} -{ARG_FilePath} {filePath}");

                                Dictionary<string, object> body = new Dictionary<string, object>();

                                using (PowerShell powerShell = PowerShell.Create())
                                {
                                    powerShell
                                        .AddCommand(CMD_GetAuthenticodeSignature)
                                        .AddParameter(ARG_FilePath, filePath);

                                    var result = await powerShell.InvokeAsync();

                                    foreach (PSObject item in result)
                                    {
                                        foreach (var propertyInfo in item.Properties)
                                        {
                                            if (propertyInfo.Value != null)
                                            {
                                                object value;

                                                if (propertyInfo.Value is X509Certificate2 certificate)
                                                {
                                                    value = ExportCertificatePem(certificate);
                                                }
                                                else
                                                {
                                                    if (propertyInfo.Value.GetType().IsEnum)
                                                    {
                                                        value = propertyInfo.Value.ToString();
                                                    }
                                                    else
                                                    {
                                                        if (propertyInfo.Value is string str)
                                                        {
                                                            switch (propertyInfo.Name)
                                                            {
                                                                case "Path":
                                                                    str = fileName;
                                                                    break;
                                                                case "StatusMessage":
                                                                    str = str.Replace(filePath, fileName);
                                                                    break;
                                                            }

                                                            value = str;
                                                        }
                                                        else
                                                        {
                                                            if (propertyInfo.Value is bool)
                                                            {
                                                                value = propertyInfo.Value;
                                                            }
                                                            else
                                                            {
                                                                value = null;
                                                            }
                                                        }
                                                    }
                                                }

                                                if (value != null)
                                                {
                                                    body.Add(propertyInfo.Name, value);
                                                }
                                            }
                                        }
                                    }
                                }

                                var response = context.Response;

                                response.StatusCode = 200;

                                response.ContentType = MediaTypeNames.Application.Json;

                                string json = JsonSerializer.Serialize(body);

                                await response.Body.WriteAsync(System.Text.Encoding.UTF8.GetBytes(json));
                            }
                            break;
                        default:
                            throw new ArgumentException(command, "command");
                    }

                }
                finally
                {
                    if (bDelete)
                    {
                        File.Delete(filePath);
                    }
                }
            }
            finally
            {
                Directory.Delete(dir, false);
            }
        }

        private string ExportCertificatePem(X509Certificate2 cert)
        {
#if NET7_0_OR_GREATER
            return cert.ExportCertificatePem();
#else
            byte[] certificateBytes = cert.RawData;
            char[] certificatePem = PemEncoding.Write("CERTIFICATE", certificateBytes);
            return new string(certificatePem);
#endif
        }
    }
}
