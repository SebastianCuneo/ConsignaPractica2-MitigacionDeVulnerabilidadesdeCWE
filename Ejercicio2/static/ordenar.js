// Envía el formulario de búsqueda al cambiar el orden.
// Está en un archivo externo (y no en atributos onchange) para que la
// Content-Security-Policy pueda prohibir todo JavaScript inline.
document.querySelectorAll('select.auto-submit').forEach(function (select) {
    select.addEventListener('change', function () {
        select.form.submit();
    });
});
