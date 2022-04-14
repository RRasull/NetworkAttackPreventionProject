using System.ComponentModel.DataAnnotations;

namespace NetworkAttackPreventionProject.ViewModels.Authentication
{
    public class ResetPasswordVM
    {
        [Required, MaxLength(255), DataType(DataType.EmailAddress)]
        public string Email { get; set; }

        [Required, MaxLength(255), DataType(DataType.Password)]
        public string NewPassword { get; set; }

        [DataType(DataType.Password), Compare(nameof(NewPassword))]
        public string ConfirmPassword { get; set; }

        public string Token { get; set; }
    }
}
