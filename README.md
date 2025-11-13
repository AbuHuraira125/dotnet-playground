# IdentityUserImplementation – ASP.NET Core Identity & JWT for Beginners

This project is a **beginner-friendly playground** for learning how authentication, authorization, roles, claims, and JWT tokens work in **ASP.NET Core Identity**.

Instead of just “magic” Identity scaffolding, this repo shows you **exactly which database table is touched by each API call** and how that becomes a JWT token your frontend can use. :contentReference[oaicite:0]{index=0}

---

## What you will learn as a beginner

By playing with the API (especially via Swagger), you’ll learn:

1. **How users are created and stored**  
   - `POST /api/auth/register` creates a row in `AspNetUsers`. :contentReference[oaicite:1]{index=1}  

2. **How login and JWT tokens work**  
   - `POST /api/auth/login` checks the password and returns a signed JWT that includes:
     - The user id
     - The username/email
     - All roles
     - All custom claims (e.g. `"Users" = "Read"`)  
   - The token is created in `TokenService` using `UserManager<AppUser>` to pull roles & claims, then signed with your configured secret.   

3. **How roles and role membership work**  
   - Create roles in `AspNetRoles` via `POST /api/auth/roles`.  
   - Add a user to a role via `POST /api/auth/users/{userId}/roles` (writes to `AspNetUserRoles`). :contentReference[oaicite:3]{index=3}  

4. **How claims are stored and enforced**  
   - Add user claims (e.g. Module = `Users`, Action = `Read`) via  
     `POST /api/auth/users/{userId}/claims` → rows in `AspNetUserClaims`.
