namespace IdentityUserImplementation.PolicyHandler
{
    public static class StaticAuthValues
    {
        private static readonly string[] Modules = { "All", "Users", "Menus" /* add more */ };
        private static readonly string[] Actions = { "All", "Read", "Create", "Update", "Delete" };

        public static IReadOnlyList<string> GetModules() => Modules;
        public static IReadOnlyList<string> GetActions() => Actions;

        public static bool IsValid(string module, string action) =>
            Modules.Contains(module, StringComparer.OrdinalIgnoreCase) &&
            Actions.Contains(action, StringComparer.OrdinalIgnoreCase);
    }
}
