"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sony4x4Solver = exports.sony4x4Keygen = exports.modularPow = void 0;
// based on dogbert's pwgen-sony-4x4.py
/* tslint:disable:no-bitwise */
/* tslint:disable:no-var-requires */
var jsbi_1 = require("jsbi");
var utils_1 = require("./utils");
var otpChars = "9DPK7V2F3RT6HX8J";
var pwdChars = "47592836";
var inputRe = new RegExp("^[" + otpChars + "]{16}$");
function arrayToNumber(arr) {
    // same as python struct.unpack("<I", arr)
    return (arr[3] << 24 | arr[2] << 16 | arr[1] << 8 | arr[0]) >>> 0;
}
function numberToArray(num) {
    return [num & 0xFF, (num >> 8) & 0xFF, (num >> 16) & 0xFF, (num >> 24) & 0xFF];
}
function decodeHash(hash) {
    var temp = [];
    for (var i = 0; i < hash.length; i += 2) {
        // TODO: check values
        temp.unshift(otpChars.indexOf(hash[i]) * 16 + otpChars.indexOf(hash[i + 1]));
    }
    return temp;
}
function encodePassword(pwd) {
    var n = arrayToNumber(pwd);
    var result = "";
    for (var i = 0; i < 8; i++) {
        result += pwdChars.charAt((n >> (21 - i * 3)) & 0x7);
    }
    return result;
}
// http://numericalrecipes.blogspot.com/2009/03/modular-multiplicative-inverse.html
function extEuclideanAlg(a, b) {
    if (jsbi_1.default.EQ(b, 0)) {
        return [jsbi_1.default.BigInt(1), jsbi_1.default.BigInt(0), a];
    }
    else {
        var _a = extEuclideanAlg(b, jsbi_1.default.remainder(a, b)), x = _a[0], y = _a[1], gcd = _a[2];
        return [y, jsbi_1.default.subtract(x, jsbi_1.default.multiply(y, jsbi_1.default.divide(a, b))), gcd];
    }
}
function modInvEuclid(a, m) {
    var _a = extEuclideanAlg(a, m), x = _a[0], gcd = _a[2];
    if (jsbi_1.default.EQ(gcd, 1)) {
        // hack for javascript modulo operation
        // https://stackoverflow.com/questions/4467539/javascript-modulo-gives-a-negative-result-for-negative-numbers
        var temp = jsbi_1.default.remainder(x, m);
        return jsbi_1.default.GE(temp, 0) ? temp : jsbi_1.default.ADD(temp, m);
    }
    else {
        return undefined;
    }
}
// https://en.wikipedia.org/wiki/Modular_exponentiation#Right-to-left_binary_method
function modularPow(base, exponent, modulus) {
    var result = jsbi_1.default.BigInt(1);
    if (!(modulus instanceof jsbi_1.default)) {
        modulus = jsbi_1.default.BigInt(modulus);
    }
    if (jsbi_1.default.EQ(modulus, 1)) {
        return 0;
    }
    base = jsbi_1.default.remainder(base, modulus);
    while (exponent > 0) {
        if ((exponent & 1) === 1) {
            result = jsbi_1.default.remainder(jsbi_1.default.multiply(result, base), modulus);
        }
        exponent = exponent >> 1;
        base = jsbi_1.default.remainder(jsbi_1.default.multiply(base, base), modulus);
    }
    return jsbi_1.default.toNumber(result);
}
exports.modularPow = modularPow;
function rsaDecrypt(code) {
    var low = jsbi_1.default.BigInt(arrayToNumber(code.slice(0, 4)));
    var high = jsbi_1.default.BigInt(arrayToNumber(code.slice(4, 8)));
    var c = jsbi_1.default.bitwiseOr(jsbi_1.default.leftShift(high, jsbi_1.default.BigInt(32)), low);
    var p = 2795287379;
    var q = 3544934711;
    var e = 41;
    var phi = jsbi_1.default.multiply(jsbi_1.default.BigInt(p - 1), jsbi_1.default.BigInt(q - 1));
    var d = modInvEuclid(jsbi_1.default.BigInt(e), phi);
    var dp = jsbi_1.default.remainder(d, jsbi_1.default.BigInt(p - 1));
    var dq = jsbi_1.default.remainder(d, jsbi_1.default.BigInt(q - 1));
    var qinv = modInvEuclid(jsbi_1.default.BigInt(q), jsbi_1.default.BigInt(p));
    var m1 = modularPow(c, jsbi_1.default.toNumber(dp), p);
    var m2 = modularPow(c, jsbi_1.default.toNumber(dq), q);
    var h;
    if (m1 < m2) {
        h = jsbi_1.default.remainder(jsbi_1.default.multiply(jsbi_1.default.add(jsbi_1.default.BigInt(m1 - m2), jsbi_1.default.BigInt(p)), qinv), jsbi_1.default.BigInt(p));
    }
    else {
        h = jsbi_1.default.remainder(jsbi_1.default.multiply(jsbi_1.default.BigInt(m1 - m2), qinv), jsbi_1.default.BigInt(p));
    }
    var m = jsbi_1.default.add(jsbi_1.default.multiply(h, jsbi_1.default.BigInt(q)), jsbi_1.default.BigInt(m2));
    return numberToArray(jsbi_1.default.toNumber(jsbi_1.default.asUintN(32, m))).concat(numberToArray(jsbi_1.default.toNumber(jsbi_1.default.signedRightShift(m, jsbi_1.default.BigInt(32)))));
}
function sony4x4Keygen(hash) {
    var numHash = decodeHash(hash);
    var pwd = rsaDecrypt(numHash);
    return encodePassword(pwd);
}
exports.sony4x4Keygen = sony4x4Keygen;
exports.sony4x4Solver = utils_1.makeSolver({
    name: "sony4x4",
    description: "Sony 4x4",
    examples: ["73KR-3FP9-PVKH-K29R"],
    cleaner: function (input) { return input.trim().replace(/[-\s]/gi, "").toUpperCase(); },
    inputValidator: function (s) { return inputRe.test(s); },
    fun: function (code) {
        var res = sony4x4Keygen(code);
        return res ? [res] : [];
    }
});
