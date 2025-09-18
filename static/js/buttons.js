document.addEventListener("DOMContentLoaded", function() {

    // Lógica para el control de visibilidad de la contraseña
    const passwordToggles = document.querySelectorAll('[id^="toggle_"]');
    passwordToggles.forEach(toggle => {
        toggle.addEventListener('click', () => {
            const inputId = toggle.id === 'toggle_password' ? 'password_input' : 'confirm_password_input';
            const input = document.getElementById(inputId);
            const type = input.getAttribute('type') === 'password' ? 'text' : 'password';
            input.setAttribute('type', type);

            // Cambiar el ícono del ojo
            const icon = toggle.querySelector('i');
            if (type === 'password') {
                icon.classList.remove('fa-eye-slash');
                icon.classList.add('fa-eye');
            } else {
                icon.classList.remove('fa-eye');
                icon.classList.add('fa-eye-slash');
            }
        });
    });

    // Lógica para el control de entrada de teléfono (solo números)
    const telefonoInput = document.querySelector('input[name="telefono"]');
    if (telefonoInput) {
        telefonoInput.addEventListener('keypress', (event) => {
            const charCode = event.charCode;
            // Permitir solo números (0-9)
            if (charCode < 48 || charCode > 57) {
                event.preventDefault();
            }
        });
    }

    // Lógica para capitalizar automáticamente el primer carácter de los campos de nombre y evitar números
    const capitalizeInputs = document.querySelectorAll('input[name="nombre"], input[name="primer_apellido"], input[name="segundo_apellido"]');
    capitalizeInputs.forEach(input => {
        input.addEventListener('input', (event) => {
            let value = event.target.value;
            // Eliminar cualquier número del valor
            value = value.replace(/[0-9]/g, '');
            // Eliminar espacios en el primer y segundo apellido
            if (input.name === 'primer_apellido' || input.name === 'segundo_apellido') {
                value = value.replace(/\s/g, '');
            }
            if (value.length > 0) {
                event.target.value = value.charAt(0).toUpperCase() + value.slice(1).toLowerCase();
            } else {
                event.target.value = '';
            }
        });
    });

    // Lógica para convertir el campo de email a minúsculas
    const emailInput = document.querySelector('input[name="email"]');
    if (emailInput) {
        emailInput.addEventListener('input', (event) => {
            event.target.value = event.target.value.toLowerCase();
        });
    }
});
