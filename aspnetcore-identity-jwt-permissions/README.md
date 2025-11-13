ASP.NET Core Identity JWT Permissions Boilerplate
=================================================

This project is a starter template for building secure ASP.NET Core Web APIs with **Identity**, **JWT bearer authentication**, and a flexible **claims-based permission system**.

It demonstrates how to:

- Use `AppUser` and `Role` with ASP.NET Core Identity and Entity Framework Core against SQL Server. :contentReference[oaicite:0]{index=0}  
- Issue JWT access tokens that include both **roles** and custom **Module/Action claims** via a dedicated `TokenService` and the `/api/auth/login` endpoint. :contentReference[oaicite:1]{index=1} :contentReference[oaicite:2]{index=2}  
- Define a **custom authorization policy system** where policies like `UsersRead`, `UsersUpdate`, etc. map to claims such as `Type = "Users", Value = "Read"` and can also be satisfied by a global `AllAll` permission. :contentReference[oaicite:3]{index=3} :contentReference[oaicite:4]{index=4} :contentReference[oaicite:5]{index=5}  
- Protect controller actions using `[AuthorizePolicy("UsersRead")]`, `[AuthorizePolicy("UsersUpdate")]`, and `[AuthorizePolicy("UsersDelete")]` on the `UsersController`. :contentReference[oaicite:6]{index=6}  
- Work with all major ASP.NET Identity tables through the `AuthController`:  
  - Users (create, login)  
  - Roles and user–role mapping  
  - User claims and role claims  
  - External logins  
  - Refresh tokens stored in `AspNetUserTokens` and exchanged for new access tokens  
  - A debug endpoint that shows roles, user claims, role claims, logins, and stored tokens for a user. :contentReference[oaicite:7]{index=7}  
- Enable **Swagger/OpenAPI** with a Bearer token input so you can test secured endpoints directly from the UI. :contentReference[oaicite:8]{index=8}  

Use this repo as a starting point whenever you need:

- JWT-based authentication
- Fine-grained, claim-driven permissions (module + action)
- A clean example of custom `IAuthorizationHandler` and policy requirements
- A ready-made API to explore how ASP.NET Core Identity tables work together.
