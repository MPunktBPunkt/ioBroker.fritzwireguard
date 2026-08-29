'use strict';

const utils = require('@iobroker/adapter-core');

class FritzWireguard extends utils.Adapter {
    constructor(options = {}) {
        super({ ...options, name: 'fritzwireguard' });
    }
}

function createAdapter(options) {
    const adapter = new FritzWireguard(options);
    require('./lib/bind.js').bindLogic(adapter);
    return adapter;
}

if (require.main !== module) {
    module.exports = createAdapter;
} else {
    createAdapter();
}
