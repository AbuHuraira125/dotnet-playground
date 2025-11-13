using System.Text;
using IdentityUserImplementation.Domain.UserEntities; // AppUser, Role
using IdentityUserImplementation.Models;
using IdentityUserImplementation.PolicyHandler;
using IdentityUserImplementation.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AppDbContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
});

// Identity (provides UserManager<>, SignInManager<>, RoleManager<>)
builder.Services.AddIdentity<AppUser, Role>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();

// ===== JWT authentication =====
var jwtIssuer = builder.Configuration["JWT:ValidIssuer"];
var jwtAudience = builder.Configuration["JWT:ValidAudience"];
var jwtSecret = builder.Configuration["JWT:Secret"];

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtIssuer,
        ValidAudience = jwtAudience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret!))
    };
});

// custom handler (checks user claims against the policy name)
builder.Services.AddScoped<IAuthorizationHandler, AuthorizePolicyHandler>();

// Authorization:
// 1) Fallback: require an authenticated user everywhere (unless [AllowAnonymous])
// 2) For each Module×Action policy, allow EITHER the specific policy OR "AllAll"
builder.Services.AddAuthorization(options =>
{
    options.FallbackPolicy = new AuthorizationPolicyBuilder()
        .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme)
        .RequireAuthenticatedUser()
        .Build();

    foreach (var module in StaticAuthValues.GetModules())
        foreach (var action in StaticAuthValues.GetActions())
        {
            var name = $"{module}{action}";
            options.AddPolicy(name, p =>
                p.Requirements.Add(new AuthorizePolicyRequirement(new[] { name, "AllAll" })));
            //                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
            // OR semantics: passing policy 'name' OR 'AllAll' will satisfy this requirement
        }
});

builder.Services.AddControllers();
builder.Services.AddScoped<ITokenService, TokenService>();

// Swagger with Bearer auth button
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(o =>
{
    o.SwaggerDoc("v1", new OpenApiInfo { Title = "IdentityUserImplementation", Version = "v1" });

    o.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        Description = "Enter: Bearer {your JWT}"
    });

    o.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme {
                Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "Bearer" }
            },
            Array.Empty<string>()
        }
    });
});

var app = builder.Build();

using (var scope = app.Services.CreateScope())
    await SeedData.EnsureSeedAsync(scope.ServiceProvider);

// Pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication(); // important: before UseAuthorization
app.UseAuthorization();

app.MapControllers();

app.Run();
