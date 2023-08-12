using AuthAndRefreshTokenDemo.Middleware;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Server;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    // Refresh token
    .AddJwtBearer(/*"Refresh Token", */options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = TokenUtil.Issuer,
            ValidAudience = TokenUtil.Issuer,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(TokenUtil.RefreshTokenSecret))
        };
    });
// Access token
//.AddJwtBearer("Access Token", options =>
//{
//    options.TokenValidationParameters = new TokenValidationParameters
//    {
//        ValidateIssuer = true,
//        ValidateAudience = true,
//        ValidateLifetime = true,
//        ValidateIssuerSigningKey = true,
//        ValidIssuer = TokenUtil.Issuer,
//        ValidAudience = TokenUtil.Issuer,
//        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(TokenUtil.AccessTokenSecret))
//    };
//});
builder.Services.AddAuthorization();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.UseMiddleware<RequestLoggingMiddleware>();

app.MapControllers();

app.Run();
