// Dark Mode Toggle JavaScript with Cookie Storage

class DarkModeManager {
    constructor() {
        this.init();
    }

    init() {
        // Apply saved theme on page load
        this.applyTheme(this.getTheme());
        
        // Create toggle button after DOM is loaded
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.createToggleButton());
        } else {
            this.createToggleButton();
        }
    }

    getTheme() {
        // Check for saved theme preference or default to 'light'
        const savedTheme = this.getCookie('theme');
        if (savedTheme) {
            return savedTheme;
        }
        
        // Check system preference if no saved preference
        if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
            return 'dark';
        }
        
        return 'light';
    }

    setTheme(theme) {
        // Save theme preference in cookie (expires in 1 year)
        this.setCookie('theme', theme, 365);
        this.applyTheme(theme);
    }

    applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        
        // Update toggle button icon if it exists
        const toggleButton = document.getElementById('darkModeToggle');
        if (toggleButton) {
            const icon = toggleButton.querySelector('i');
            if (icon) {
                if (theme === 'dark') {
                    icon.className = 'bi bi-sun-fill';
                    toggleButton.title = 'Switch to Light Mode';
                } else {
                    icon.className = 'bi bi-moon-fill';
                    toggleButton.title = 'Switch to Dark Mode';
                }
            }
        }
    }

    toggleTheme() {
        const currentTheme = this.getTheme();
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        this.setTheme(newTheme);
    }

    createToggleButton() {
        // Don't create if button already exists
        if (document.getElementById('darkModeToggle')) {
            return;
        }

        const toggleButton = document.createElement('button');
        toggleButton.id = 'darkModeToggle';
        toggleButton.className = 'dark-mode-toggle';
        toggleButton.innerHTML = '<i class="bi bi-moon-fill"></i>';
        toggleButton.title = 'Switch to Dark Mode';
        toggleButton.setAttribute('aria-label', 'Toggle dark mode');

        // Add click event listener
        toggleButton.addEventListener('click', () => this.toggleTheme());

        // Add to page
        document.body.appendChild(toggleButton);

        // Update icon based on current theme
        this.applyTheme(this.getTheme());
    }

    // Cookie utility functions
    setCookie(name, value, days) {
        const expires = new Date();
        expires.setTime(expires.getTime() + (days * 24 * 60 * 60 * 1000));
        document.cookie = `${name}=${value};expires=${expires.toUTCString()};path=/;SameSite=Strict`;
    }

    getCookie(name) {
        const nameEQ = name + "=";
        const ca = document.cookie.split(';');
        for (let i = 0; i < ca.length; i++) {
            let c = ca[i];
            while (c.charAt(0) === ' ') c = c.substring(1, c.length);
            if (c.indexOf(nameEQ) === 0) return c.substring(nameEQ.length, c.length);
        }
        return null;
    }

    // Public method to manually set theme (for use in other scripts)
    setThemeManually(theme) {
        if (theme === 'dark' || theme === 'light') {
            this.setTheme(theme);
        }
    }

    // Public method to get current theme (for use in other scripts)
    getCurrentTheme() {
        return this.getTheme();
    }
}

// Initialize dark mode manager
const darkModeManager = new DarkModeManager();

// Listen for system theme changes
if (window.matchMedia) {
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    mediaQuery.addEventListener('change', (e) => {
        // Only apply system preference if user hasn't manually set a theme
        if (!darkModeManager.getCookie('theme')) {
            darkModeManager.applyTheme(e.matches ? 'dark' : 'light');
        }
    });
}

// Global functions for external use
window.DarkMode = {
    toggle: () => darkModeManager.toggleTheme(),
    setTheme: (theme) => darkModeManager.setThemeManually(theme),
    getTheme: () => darkModeManager.getCurrentTheme()
};