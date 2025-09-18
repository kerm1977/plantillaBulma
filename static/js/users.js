document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('search-input');
    const usersTable = document.getElementById('users-table');
    const userCards = document.querySelectorAll('.user-card-column');

    function filterUsers(searchTerm) {
        const filterText = searchTerm.toLowerCase();

        // Filtrar tarjetas
        userCards.forEach(card => {
            const cardContent = card.textContent.toLowerCase();
            if (cardContent.includes(filterText)) {
                card.style.display = 'block';
            } else {
                card.style.display = 'none';
            }
        });

        // Filtrar filas de la tabla
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

    searchInput.addEventListener('input', (event) => {
        filterUsers(event.target.value);
    });

    // Oculta la tabla en móviles y las tarjetas en desktop
    const mediaQuery = window.matchMedia('(max-width: 980px)');
    function handleMediaQuery(e) {
        if (e.matches) {
            usersTable.style.display = 'none';
            document.getElementById('users-container').style.display = 'flex';
        } else {
            usersTable.style.display = 'table';
            document.getElementById('users-container').style.display = 'none';
        }
    }
    mediaQuery.addListener(handleMediaQuery);
    handleMediaQuery(mediaQuery); // Llama a la función al cargar para la configuración inicial
});