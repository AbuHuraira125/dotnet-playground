using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace IdentityUserImplementation.Domain.UserEntities
{
    public class Menu
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public long Id { get; set; }
        public string Title { get; set; } = default!;
        public string? FrontendId { get; set; }
        public string? Key { get; set; }
        public string? Icon { get; set; }
        public string? Src { get; set; }
        public string? Type { get; set; }
        public string? Path { get; set; }
        public int? Level { get; set; }
        public long? ParentId { get; set; }
    }

    public class RoleMenu
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public long Id { get; set; }
        public long RoleId { get; set; }
        public long MenuId { get; set; }
    }
}
