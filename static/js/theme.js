document.addEventListener('DOMContentLoaded', () => {
    // Manejar el botón de volver arriba
    const backToTopButton = document.getElementById('back-to-top');
    window.addEventListener('scroll', () => {
        if (window.scrollY > 300) {
            backToTopButton.classList.add('is-visible');
        } else {
            backToTopButton.classList.remove('is-visible');
        }
    });

    backToTopButton.addEventListener('click', () => {
        window.scrollTo({
            top: 0,
            behavior: 'smooth'
        });
    });

    // Manejar el botón de cambio de tema
    const themeToggleButton = document.querySelector('.theme-toggle-button');
    if (themeToggleButton) {
        themeToggleButton.addEventListener('click', () => {
            document.body.classList.toggle('is-dark-mode');
            const isDarkMode = document.body.classList.contains('is-dark-mode');
            localStorage.setItem('is-dark-mode', isDarkMode);
        });

        // Aplicar el tema guardado en localStorage o el tema del sistema
        const savedTheme = localStorage.getItem('is-dark-mode');
        if (savedTheme === 'true') {
            document.body.classList.add('is-dark-mode');
        } else if (savedTheme === null && window.matchMedia('(prefers-color-scheme: dark)').matches) {
            document.body.classList.add('is-dark-mode');
        }
    }
});
