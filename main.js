'use strict';

// Duenner Loader: schwere Implementierung erst beim Instanz-Start laden.
// Verhindert, dass grosser Modul-Code die adapter-core DB-Init blockiert.
function createAdapter(options) {
    return require('./lib/adapter.js').createAdapter(options);
}

if (require.main !== module) {
    module.exports = createAdapter;
} else {
    createAdapter();
}
