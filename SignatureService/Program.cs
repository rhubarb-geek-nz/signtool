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
