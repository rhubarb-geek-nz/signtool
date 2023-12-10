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

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Mime;
using System.Text;
using System.Threading.Tasks;

namespace SignatureService
{
	internal class SignatureService
	{
        private readonly ILogger<SignatureService> logger;
        private readonly IWebHostEnvironment env;
        private readonly IConfiguration config;
        private readonly List<string> validOptions = new List<string>(new string[] { "q", "a"});
        private readonly string authorization, realm;

        public SignatureService(IConfiguration config, IWebHostEnvironment env,ILogger<SignatureService> logger)
        {
            this.env = env;
            this.logger = logger;
            this.config = config;

            logger.LogInformation($"WebRootPath {env.WebRootPath}");

			var signtool = config.GetSection("Signtool");

            authorization = signtool.GetValue<string>("Authorization");
            realm = signtool.GetValue<string>("Realm");
        }

        public async Task InvokeAsync(HttpContext context)
        {
			var request = context.Request;

            string auth = request.Headers.Authorization;

            if (!authorization.Equals(auth))
            {
                context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
	            context.Response.Headers.Add("WWW-Authenticate", $"Basic realm=\"{realm}\"");
                return;
            }

            string guid = Guid.NewGuid().ToString();

            string dir = env.WebRootPath + "\\" + guid;

            Directory.CreateDirectory(dir);

            try
            {
                string filename = null;

                if (request.HasFormContentType)
                {
                    IFormCollection form = await request.ReadFormAsync();
                    IFormFileCollection formFiles = form.Files;

                    foreach (IFormFile formFile in formFiles)
                    {
                        filename = formFile.FileName;

                        if (filename.Contains("/") || filename.Contains("\\"))
                        {
                            throw new ArgumentException(filename, "filename");
                        }

                        filename = dir + "\\" + filename;

                        using (var file = File.Open(filename, FileMode.Create))
                        {
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

                    ContentDisposition contentDisposition = new ContentDisposition(request.Headers.ContentDisposition);

                    filename = contentDisposition.FileName;

                    if (filename.Contains("/") || filename.Contains("\\"))
                    {
                        throw new ArgumentException(filename, "filename");
                    }

                    filename = dir + System.IO.Path.DirectorySeparatorChar + filename;

                    using (var file = File.Open(filename, FileMode.Create))
                    {
                        await request.Body.CopyToAsync(file);
                    }
                }

                StringBuilder stringBuilder = new StringBuilder();

                string command = request.Query["command"];

                stringBuilder.Append(command);
                stringBuilder.Append(" ");

                if (request.Query.TryGetValue("options", out var options))
                {
                    foreach (var optionHeader in options)
                    {
                        foreach (var opt in optionHeader.Split(","))
                        {
                            if (!validOptions.Contains(opt))
                            {
                                throw new Exception($"invalid option {opt}");
                            }

                            stringBuilder.Append("/");
                            stringBuilder.Append(opt);
                            stringBuilder.Append(" ");
                        }
                    }
                }

                foreach (string argName in new string[] { "td", "sha1", "fd", "t", "tr"})
                {
                    if (request.Query.TryGetValue(argName, out var args))
                    {
                        foreach (var arg in args)
                        {
                            if (arg.Contains(" ")||arg.Contains("\\") || arg.Contains("\"") || arg.Contains("\'"))
                            {
                                throw new Exception($"invalid argument {arg}");
                            }

                            foreach (char c in arg.ToCharArray())
                            {
                                if (c < ' ')
                                {
                                    throw new Exception($"invalid argument {arg}");
                                }
                            }

                            if (argName.Equals("sha1"))
                            {
                                Convert.FromHexString(arg);
                            }

                            if (argName.Equals("t")||argName.Equals("tr"))
                            {
                                new Uri(arg);
                            }

                            stringBuilder.Append("/");
                            stringBuilder.Append(argName);
                            stringBuilder.Append(" ");
                            stringBuilder.Append(arg);
                            stringBuilder.Append(" ");
                        }
                    }
                }

                stringBuilder.Append("\"");
                stringBuilder.Append(filename);
                stringBuilder.Append("\"");

                ProcessStartInfo startInfo = new()
                {
                    FileName = "signtool.exe",
                    Arguments = stringBuilder.ToString(),
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                };

                logger.LogInformation($"{startInfo.FileName} {startInfo.Arguments}");

                var proc = Process.Start(startInfo);

                ArgumentNullException.ThrowIfNull(proc);

                await proc.WaitForExitAsync();

                string output = await proc.StandardOutput.ReadToEndAsync();
                string error = await proc.StandardError.ReadToEndAsync();

                if (output.Length > 0)
                {
                    logger.LogInformation(output);
                }

                if (error.Length > 0)
                {
                    logger.LogInformation(error);
                }

                int exitCode = proc.ExitCode;

                var response = context.Response;

                response.StatusCode = exitCode == 0 ? 200 : 500;

                if (exitCode == 0 && String.Equals(command, "sign", StringComparison.OrdinalIgnoreCase))
                {
                    response.ContentType = MediaTypeNames.Application.Octet;

                    ContentDisposition contentDisposition = new ContentDisposition("attachment");

                    contentDisposition.FileName = Path.GetFileName(filename);

                    response.Headers.ContentDisposition = contentDisposition.ToString();

                    using (var outfile = File.Open(filename, FileMode.Open))
                    {
                        await outfile.CopyToAsync(response.Body);
                    }
                }
                else
                {
                    response.ContentType = "text/plain";

                    await response.Body.WriteAsync(Encoding.ASCII.GetBytes(output));
                    await response.Body.WriteAsync(Encoding.ASCII.GetBytes(error));
                }
            }
            finally
            {
                Directory.Delete(dir, true);
            }
        }
	}
}
