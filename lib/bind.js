'use strict';

// Nur Event-Verkabelung — laedt lib/adapter.js erst bei onReady/unload (nicht waehrend DB-Init).
function bindLogic(adapter) {
    adapter.on('ready', () => {
        const impl = require('./adapter.js');
        impl.initInstance(adapter);
        return impl.runReady(adapter);
    });
    adapter.on('unload', (cb) => require('./adapter.js').runUnload(adapter, cb));
    adapter.on('stateChange', (id, state) => {
        if (!adapter.adapterReady) return;
        require('./adapter.js').runStateChange(adapter, id, state);
    });
    adapter.on('message', (obj) => {
        if (!adapter.adapterReady) return true;
        return require('./adapter.js').runMessage(adapter, obj);
    });
}

module.exports = { bindLogic };
