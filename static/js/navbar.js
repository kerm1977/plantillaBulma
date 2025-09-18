// Lógica del menú de hamburguesa
document.addEventListener('DOMContentLoaded', () => {
    const $navbarBurgers = Array.prototype.slice.call(document.querySelectorAll('.navbar-burger'), 0);
    const $navbarMenu = document.getElementById('navbarBasicExample');
    const $navbarClose = document.querySelector('.navbar-close');

    // Función para cerrar el menú
    const closeMenu = () => {
        $navbarBurgers.forEach(el => el.classList.remove('is-active'));
        $navbarMenu.classList.remove('is-active');
    };

    if ($navbarBurgers.length > 0) {
        $navbarBurgers.forEach(el => {
            el.addEventListener('click', () => {
                const target = el.dataset.target;
                const $target = document.getElementById(target);
                el.classList.toggle('is-active');
                $target.classList.toggle('is-active');
            });
        });
    }
    
    // Cierre del menú al hacer clic en el botón de cierre (X)
    if ($navbarClose) {
        $navbarClose.addEventListener('click', closeMenu);
    }

    // Cierre del menú al hacer clic fuera de él
    document.addEventListener('click', (event) => {
        const isClickInside = $navbarMenu.contains(event.target) || document.querySelector('.navbar-burger').contains(event.target);
        if ($navbarMenu.classList.contains('is-active') && !isClickInside) {
            closeMenu();
        }
    });
});

// Lógica para el cambio de tema
document.addEventListener('DOMContentLoaded', () => {
    const themeSwitcher = document.getElementById('theme-switcher');
    const body = document.body;
    const icon = themeSwitcher.querySelector('.icon i');

    // Función para aplicar el tema guardado
    const applyTheme = (theme) => {
        if (theme === 'dark') {
            body.classList.add('is-dark-mode');
            icon.classList.remove('fa-sun');
            icon.classList.add('fa-moon');
        } else {
            body.classList.remove('is-dark-mode');
            icon.classList.remove('fa-moon');
            icon.classList.add('fa-sun');
        }
    };

    // Cargar el tema desde localStorage
    const savedTheme = localStorage.getItem('is-dark-mode');
    if (savedTheme === 'true') {
        applyTheme('dark');
    } else {
        applyTheme('light');
    }

    // Event listener para el botón
    themeSwitcher.addEventListener('click', () => {
        if (body.classList.contains('is-dark-mode')) {
            // Cambiar a tema claro
            applyTheme('light');
            localStorage.setItem('is-dark-mode', 'false');
        } else {
            // Cambiar a tema oscuro
            applyTheme('dark');
            localStorage.setItem('is-dark-mode', 'true');
        }
    });
});