document.addEventListener('DOMContentLoaded', () => {
    // --- Lógica de Búsqueda y Responsive para ver_usuarios.html ---
    const searchInput = document.getElementById('search-input');
    const usersTable = document.getElementById('users-table');
    const userCards = document.querySelectorAll('.user-card-column');

    /**
     * Filtra la lista de usuarios (tarjetas y filas de tabla) basándose en el término de búsqueda.
     * @param {string} searchTerm - El texto a buscar.
     */
    function filterUsers(searchTerm) {
        const filterText = searchTerm.toLowerCase();

        // Filtrar tarjetas (vista móvil)
        userCards.forEach(card => {
            const cardContent = card.textContent.toLowerCase();
            if (cardContent.includes(filterText)) {
                card.style.display = 'block';
            } else {
                card.style.display = 'none';
            }
        });

        // Filtrar filas de la tabla (vista desktop)
        if (usersTable) {
            const tableRows = usersTable.querySelectorAll('tbody tr');
            tableRows.forEach(row => {
                const rowContent = row.textContent.toLowerCase();
                if (rowContent.includes(filterText)) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        }
    }

    if (searchInput) {
        searchInput.addEventListener('input', (event) => {
            filterUsers(event.target.value);
        });
    }

    // Oculta la tabla en móviles y las tarjetas en desktop (solo si existen)
    if (usersTable && document.getElementById('users-container')) {
        const mediaQuery = window.matchMedia('(max-width: 980px)');
        function handleMediaQuery(e) {
            if (e.matches) {
                // Móvil: Ocultar tabla, mostrar tarjetas
                usersTable.style.display = 'none';
                document.getElementById('users-container').style.display = 'flex';
            } else {
                // Desktop: Mostrar tabla, ocultar tarjetas
                usersTable.style.display = 'table';
                document.getElementById('users-container').style.display = 'none';
            }
        }
        
        // Ejecutar al cargar y cada vez que cambie el media query
        handleMediaQuery(mediaQuery);
        mediaQuery.addListener(handleMediaQuery);
    }

    // --- Lógica de Toggle de Contraseña para Formularios de Autenticación ---

    /**
     * Configura el evento de clic para alternar la visibilidad de un campo de contraseña.
     * @param {string} toggleId - El ID del elemento que activa el toggle (el icono).
     * @param {string} inputId - El ID del campo de entrada de la contraseña.
     */
    function setupPasswordToggle(toggleId, inputId) {
        const toggle = document.getElementById(toggleId);
        const input = document.getElementById(inputId);

        if (toggle && input) {
            toggle.addEventListener('click', () => {
                // Alterna el tipo de input entre 'password' y 'text'
                const type = input.getAttribute('type') === 'password' ? 'text' : 'password';
                input.setAttribute('type', type);

                // Alterna el icono (ojo abierto <-> ojo tachado)
                const icon = toggle.querySelector('i');
                if (icon) {
                    icon.classList.toggle('fa-eye');
                    icon.classList.toggle('fa-eye-slash');
                }
            });
        }
    }

    // --- Configuraciones para login.html y register.html ---
    setupPasswordToggle('toggle_password', 'password_input');
    setupPasswordToggle('toggle_confirm_password', 'confirm_password_input');
    
    // --- Configuraciones para passchange.html (Nuevos campos) ---
    // Usados para la vista de cambio de contraseña
    setupPasswordToggle('toggle_current_password', 'current_password_input');
    setupPasswordToggle('toggle_new_password', 'new_password_input');
    setupPasswordToggle('toggle_confirm_new_password', 'confirm_new_password_input');
});