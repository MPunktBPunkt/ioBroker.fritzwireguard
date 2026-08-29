'use strict';

process.on('unhandledRejection', (e) => {
    throw e;
});

const sinonChai = require('sinon-chai');
const chaiAsPromised = require('chai-as-promised');
const { should, use } = require('chai');

should();
use(sinonChai);
use(chaiAsPromised);
