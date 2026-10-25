/*
 * generator.js — secure password generation (logic only, no DOM).
 * Uses crypto.getRandomValues() exclusively. Math.random() is never used.
 */
(function (global) {
  'use strict';

  var SETS = {
    upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lower: 'abcdefghijklmnopqrstuvwxyz',
    digits: '0123456789',
    symbols: '!@#$%^&*()-_=+[]{};:,.<>?/~'
  };
  var CONFUSING = 'lI1O0';
  var MIN_LEN = 12;
  var MAX_LEN = 64;

  /** Unbiased random integer in [0, max) using rejection sampling. */
  function randomInt(max) {
    var buf = new Uint32Array(1);
    var limit = Math.floor(0x100000000 / max) * max;
    do {
      global.crypto.getRandomValues(buf);
    } while (buf[0] >= limit);
    return buf[0] % max;
  }

  /** Remove visually confusing characters from a pool when requested. */
  function filterPool(chars, avoidConfusing) {
    if (!avoidConfusing) return chars;
    var out = '';
    for (var i = 0; i < chars.length; i++) {
      if (CONFUSING.indexOf(chars[i]) === -1) out += chars[i];
    }
    return out;
  }

  /** Build the list of selected character pools. */
  function buildPools(opts) {
    var pools = [];
    ['upper', 'lower', 'digits', 'symbols'].forEach(function (key) {
      if (opts[key]) {
        var p = filterPool(SETS[key], !!opts.avoidConfusing);
        if (p.length) pools.push(p);
      }
    });
    return pools;
  }

  /** Estimated entropy in bits: length * log2(pool size). */
  function entropyBits(length, poolSize) {
    return poolSize > 1 ? length * Math.log2(poolSize) : 0;
  }

  /**
   * Generate a password.
   * opts: { length, upper, lower, digits, symbols, avoidConfusing }
   * Returns { password, entropy, poolSize }.
   */
  function generate(opts) {
    if (!global.crypto || !global.crypto.getRandomValues) {
      throw new Error('Secure random number generator unavailable.');
    }
    var pools = buildPools(opts);
    if (pools.length === 0) throw new Error('Select at least one character type.');

    var length = Math.max(MIN_LEN, Math.min(MAX_LEN, parseInt(opts.length, 10) || MIN_LEN));
    var all = pools.join('');
    var chars = [];

    // Guarantee at least one character from every selected pool.
    pools.forEach(function (p) { chars.push(p[randomInt(p.length)]); });
    while (chars.length < length) chars.push(all[randomInt(all.length)]);

    // Fisher–Yates shuffle so guaranteed characters are not predictably placed.
    for (var i = chars.length - 1; i > 0; i--) {
      var j = randomInt(i + 1);
      var tmp = chars[i]; chars[i] = chars[j]; chars[j] = tmp;
    }

    return { password: chars.join(''), entropy: entropyBits(length, all.length), poolSize: all.length };
  }

  global.PassGenerator = { generate: generate, entropyBits: entropyBits, MIN_LEN: MIN_LEN, MAX_LEN: MAX_LEN };
})(window);
