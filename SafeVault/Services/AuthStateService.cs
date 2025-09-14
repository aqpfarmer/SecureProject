using System;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace SafeVault.Services
{
    public class AuthStateService
    {
        public event Action OnChange;
        private bool _isAuthenticated;
        private List<string> _roles = new List<string>();
        public bool IsAuthenticated => _isAuthenticated;
        public IReadOnlyList<string> Roles => _roles;

        public void SetAuthenticated(List<string> roles)
        {
            _isAuthenticated = true;
            _roles = roles ?? new List<string>();
            NotifyStateChanged();
        }

        public void SetLoggedOut()
        {
            _isAuthenticated = false;
            _roles = new List<string>();
            NotifyStateChanged();
        }

        private void NotifyStateChanged() => OnChange?.Invoke();
    }
}
