// Copyright (c) 2024 Roger Brown.
// Licensed under the MIT License.

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

var builder = WebApplication.CreateBuilder(args);

var app = builder.Build();

var config = app.Services.GetRequiredService<IConfiguration>();
var webenv = app.Services.GetRequiredService<IWebHostEnvironment>();
var logger = app.Services.GetRequiredService<ILogger<SignatureService.SignatureService>>();
string endpoint = config.GetSection("Signtool").GetValue<string>("Endpoint");

app.MapPost(endpoint, new SignatureService.SignatureService(config, webenv, logger).InvokeAsync);

app.Run();
